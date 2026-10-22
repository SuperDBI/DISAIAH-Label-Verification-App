using PDFiumCore;
using System.IO.Compression;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using UglyToad.PdfPig.AcroForms;
using UglyToad.PdfPig;
using UglyToad.PdfPig.DocumentLayoutAnalysis.TextExtractor;

const int maximumPdfBytes = 25 * 1024 * 1024;
const int maximumPngBytes = 10 * 1024 * 1024;
const int maximumPages = 100;
const int maximumExtractedCharacters = 500_000;
const int maximumExtractedImages = 20;
const int maximumImageBytes = 2 * 1024 * 1024;
const int maximumTotalImageBytes = 6 * 1024 * 1024;
const int maximumImageDimension = 4096;
const long maximumImagePixels = 4_000_000;
const int maximumOcrImages = 5;
const int maximumOcrCharactersPerImage = 20_000;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = maximumPdfBytes);
builder.Services.AddSingleton<PdfiumRenderer>();
builder.Services.AddSingleton<PdfParsingGate>();
builder.Services.AddSingleton<ClamAvScanner>();
builder.Services.AddSingleton<TesseractOcrService>();
builder.Services.AddSingleton<IdleShutdown>();
var app = builder.Build();

// On-demand lifetime: exit 5 s after the last upload finishes (45 s grace after launch for the first one).
// A new upload cancels a pending exit. Health checks do not count as activity.
var idleShutdown = app.Services.GetRequiredService<IdleShutdown>();
if (builder.Configuration["PDF_PARSER_IDLE_EXIT"] == "1")
{
    app.Use(async (context, next) =>
    {
        if (context.Request.Path.StartsWithSegments("/health"))
        {
            await next();
            return;
        }
        idleShutdown.RequestStarted();
        try
        {
            await next();
        }
        finally
        {
            // Return the large PDF/image buffers to the OS before the idle timer runs out.
            System.Runtime.GCSettings.LargeObjectHeapCompactionMode = System.Runtime.GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
            idleShutdown.RequestFinished();
        }
    });
    idleShutdown.Arm();
}
app.Lifetime.ApplicationStopping.Register(() => app.Services.GetRequiredService<ClamAvScanner>().StopNow());

// No Azure SDK, cloud credentials, storage identity, or outbound networking belong in this service.
app.MapPost("/internal/render-first-page", async (HttpRequest request, PdfiumRenderer renderer, PdfParsingGate parsingGate, CancellationToken cancellationToken) =>
{
    var expectedToken = builder.Configuration["PDF_SANDBOX_TOKEN"] ?? string.Empty;
    if (expectedToken.Length < 32 || !request.Headers.TryGetValue("X-SecRev-Sandbox-Token", out var suppliedValues))
        return Results.Unauthorized();
    var suppliedToken = suppliedValues.ToString();
    if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expectedToken), Encoding.UTF8.GetBytes(suppliedToken)))
        return Results.Unauthorized();

    if (request.ContentLength is <= 0 or > maximumPdfBytes)
        return Results.Problem(statusCode: StatusCodes.Status413PayloadTooLarge, title: "PDF size limit exceeded.");

    if (!await parsingGate.TryAcquireAsync(cancellationToken))
        return Results.Problem(statusCode: StatusCodes.Status429TooManyRequests, title: "The parser is busy with another PDF; retry shortly.");
    byte[]? bytes = null;
    try
    {
        bytes = new byte[checked((int)request.ContentLength!.Value)];
        var total = 0;
        while (total < bytes.Length)
        {
            var read = await request.Body.ReadAsync(bytes.AsMemory(total, bytes.Length - total), cancellationToken);
            if (read == 0) break;
            total += read;
        }
        if (total != bytes.Length || total < 8 || !bytes.AsSpan(0, 5).SequenceEqual("%PDF-"u8))
            return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Invalid PDF header.");

        var png = renderer.RenderFirstPage(bytes.AsSpan(0, total));
        if (png.PageCount is <= 0 or > 100 || png.Png.Length > maximumPngBytes)
            return Results.Problem(statusCode: StatusCodes.Status422UnprocessableEntity, title: "PDF page or preview output limit exceeded.");
        request.HttpContext.Response.Headers["X-PDF-Page-Count"] = png.PageCount.ToString(System.Globalization.CultureInfo.InvariantCulture);
        request.HttpContext.Response.Headers["Cache-Control"] = "no-store";
        return Results.File(png.Png, "image/png");
    }
    catch (InvalidDataException ex)
    {
        return Results.Problem(statusCode: StatusCodes.Status422UnprocessableEntity, title: ex.Message);
    }
    finally
    {
        if (bytes is not null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
        parsingGate.Release();
    }
}).DisableAntiforgery();

app.MapPost("/internal/extract-text-pdfpig", async (HttpRequest request, PdfParsingGate parsingGate, ILoggerFactory loggerFactory, CancellationToken cancellationToken) =>
{
    if (!IsAuthorized(request, builder.Configuration["PDF_SANDBOX_TOKEN"]))
        return Results.Unauthorized();

    byte[]? bytes = null;
    var parserSlotAcquired = false;
    try
    {
        if (!await parsingGate.TryAcquireAsync(cancellationToken))
            return Results.Problem(statusCode: StatusCodes.Status429TooManyRequests, title: "The parser is busy with another PDF; retry shortly.");
        parserSlotAcquired = true;
        bytes = await ReadBoundedPdfAsync(request, cancellationToken);
        using var pdfStream = new MemoryStream(bytes, writable: false);
        using var document = PdfDocument.Open(pdfStream);
        if (document.NumberOfPages is <= 0 or > maximumPages)
            return Results.Problem(statusCode: StatusCodes.Status422UnprocessableEntity, title: "PDF page count is outside the configured limit.");

        var pages = new List<ExtractedPage>(document.NumberOfPages);
        var images = new List<ExtractedPdfImage>();
        var totalCharacters = 0;
        var totalImageBytes = 0;
        foreach (var page in document.GetPages())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var pageText = ContentOrderTextExtractor.GetText(page);
            totalCharacters = checked(totalCharacters + pageText.Length);
            if (totalCharacters > maximumExtractedCharacters)
                return Results.Problem(statusCode: StatusCodes.Status413PayloadTooLarge, title: "Extracted text exceeds the configured output limit.");
            pages.Add(new ExtractedPage(page.Number, pageText));

            foreach (var image in page.GetImages())
            {
                if (images.Count >= maximumExtractedImages)
                    return Results.Problem(statusCode: StatusCodes.Status413PayloadTooLarge, title: "PDF image count exceeds the configured output limit.");
                if (image is null)
                {
                    images.Add(new ExtractedPdfImage(page.Number, 0, 0, string.Empty, "", false, "PdfPig returned an invalid image entry."));
                    continue;
                }
                if (image.WidthInSamples <= 0 || image.HeightInSamples <= 0 ||
                    image.WidthInSamples > maximumImageDimension || image.HeightInSamples > maximumImageDimension ||
                    (long)image.WidthInSamples * image.HeightInSamples > maximumImagePixels)
                {
                    images.Add(new ExtractedPdfImage(page.Number, image.WidthInSamples, image.HeightInSamples, string.Empty, "", false, "Dimensions exceed configured decode limits."));
                    continue;
                }

                try
                {
                    if (image.RawBytes.Length > maximumImageBytes)
                    {
                        images.Add(new ExtractedPdfImage(page.Number, image.WidthInSamples, image.HeightInSamples, string.Empty, "", false, "Encoded image stream exceeds configured size limits."));
                        continue;
                    }
                    if (!image.TryGetPng(out var png) || png.Length == 0)
                    {
                        images.Add(new ExtractedPdfImage(page.Number, image.WidthInSamples, image.HeightInSamples, string.Empty, "", false, "PdfPig could not decode this image filter/color space."));
                        continue;
                    }
                    if (png.Length > maximumImageBytes || totalImageBytes + png.Length > maximumTotalImageBytes)
                    {
                        CryptographicOperations.ZeroMemory(png);
                        images.Add(new ExtractedPdfImage(page.Number, image.WidthInSamples, image.HeightInSamples, string.Empty, "", false, "Decoded image bytes exceed configured limits."));
                        continue;
                    }

                    totalImageBytes += png.Length;
                    images.Add(new ExtractedPdfImage(
                        page.Number,
                        image.WidthInSamples,
                        image.HeightInSamples,
                        "image/png",
                        Convert.ToBase64String(png),
                        true,
                        Convert.ToHexString(SHA256.HashData(png))));
                    CryptographicOperations.ZeroMemory(png);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    images.Add(new ExtractedPdfImage(page.Number, image.WidthInSamples, image.HeightInSamples, string.Empty, "", false, "Decode failed; stream was omitted."));
                }
            }
        }

        var text = string.Join("\n\n", pages.Select(page => page.Text));
        return Results.Json(new PdfPigExtractionResponse(pages.Count, text, pages, images));
    }
    catch (InvalidDataException ex)
    {
        return Results.Problem(statusCode: StatusCodes.Status422UnprocessableEntity, title: ex.Message);
    }
    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
    {
        throw;
    }
    catch (Exception ex)
    {
        loggerFactory.CreateLogger("PdfPigParser").LogWarning("PdfPig rejected a document ({ExceptionType}); document content omitted", ex.GetType().Name);
        return Results.Problem(statusCode: StatusCodes.Status422UnprocessableEntity, title: "PdfPig could not extract text from this PDF.");
    }
    finally
    {
        if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        if (parserSlotAcquired) parsingGate.Release();
    }
}).DisableAntiforgery();

app.MapPost("/local/scan-and-extract-pdf-images", async (
    HttpRequest request,
    PdfParsingGate parsingGate,
    ClamAvScanner scanner,
    ILoggerFactory loggerFactory,
    CancellationToken cancellationToken) =>
{
    if (!string.Equals(builder.Configuration["ENABLE_LOCAL_CLAMAV"], "true", StringComparison.OrdinalIgnoreCase))
        return Results.NotFound();
    if (!IsAuthorized(request, builder.Configuration["PDF_SANDBOX_TOKEN"]))
        return Results.Unauthorized();

    byte[]? bytes = null;
    var parserSlotAcquired = false;
    try
    {
        if (!await parsingGate.TryAcquireAsync(cancellationToken))
            return Results.Problem(statusCode: StatusCodes.Status429TooManyRequests, title: "The parser is busy with another PDF; retry shortly.");
        parserSlotAcquired = true;
        bytes = await ReadBoundedPdfAsync(request, cancellationToken);

        var verdict = await scanner.ScanAsync(bytes, cancellationToken);
        if (!string.Equals(verdict, ClamAvScanner.CleanVerdict, StringComparison.Ordinal))
        {
            return Results.Json(new LocalPdfImageExtractionResponse(
                "ThreatsDetected",
                verdict,
                0,
                "A local antivirus scan did not return the required clean result; PDF parsing was not run.",
                0,
                0,
                Array.Empty<ExtractedPdfImage>()), statusCode: StatusCodes.Status200OK);
        }

        var extraction = PdfPigImageExtractor.ExtractImages(bytes, cancellationToken);
        return Results.Json(new LocalPdfImageExtractionResponse(
            "No threats found",
            "ClamAV",
            extraction.Extraction.PageCount,
            extraction.Extraction.Images.Count == 0 ? "No supported image streams were decoded." : "Image streams were extracted after a clean local antivirus result.",
            extraction.ImageStreamCount,
            extraction.UndecodedCount,
            extraction.Extraction.Images));
    }
    catch (InvalidDataException ex)
    {
        return Results.Problem(statusCode: StatusCodes.Status422UnprocessableEntity, title: ex.Message);
    }
    catch (Exception ex) when (ex is SocketException or IOException or TimeoutException or InvalidOperationException)
    {
        loggerFactory.CreateLogger("LocalPdfScan").LogWarning("Local ClamAV scan unavailable ({ExceptionType}); PDF parsing was not run", ex.GetType().Name);
        return Results.Problem(statusCode: StatusCodes.Status503ServiceUnavailable, title: "Local antivirus scanner unavailable. PDF parsing was not run.");
    }
    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
    {
        throw;
    }
    catch (Exception ex)
    {
        loggerFactory.CreateLogger("LocalPdfScan").LogWarning("Local PDF scan/extraction failed ({ExceptionType}); document content omitted", ex.GetType().Name);
        return Results.Problem(statusCode: StatusCodes.Status422UnprocessableEntity, title: "Local PDF image extraction failed.");
    }
    finally
    {
        if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        if (parserSlotAcquired) parsingGate.Release();
    }
}).DisableAntiforgery();

app.MapPost("/local/scan-and-extract-pdf-review", async (
    HttpRequest request,
    PdfParsingGate parsingGate,
    ClamAvScanner scanner,
    PdfiumRenderer renderer,
    TesseractOcrService ocrService,
    ILoggerFactory loggerFactory,
    CancellationToken cancellationToken) =>
{
    if (!string.Equals(builder.Configuration["ENABLE_LOCAL_CLAMAV"], "true", StringComparison.OrdinalIgnoreCase))
        return Results.NotFound();
    if (!IsAuthorized(request, builder.Configuration["PDF_SANDBOX_TOKEN"]))
        return Results.Unauthorized();

    byte[]? bytes = null;
    List<byte[]>? ocrInputBuffers = null;
    var parserSlotAcquired = false;
    try
    {
        if (!await parsingGate.TryAcquireAsync(cancellationToken))
            return Results.Problem(statusCode: StatusCodes.Status429TooManyRequests, title: "The parser is busy with another PDF; retry shortly.");
        parserSlotAcquired = true;
        bytes = await ReadBoundedPdfAsync(request, cancellationToken);
            string verdict;
            try
            {
                verdict = await scanner.ScanAsync(bytes, cancellationToken);
            }
            catch (Exception ex) when (ex is SocketException or IOException or TimeoutException or InvalidOperationException)
            {
                loggerFactory.CreateLogger("LocalPdfReview").LogWarning("Local ClamAV scan unavailable ({ExceptionType}: {Reason}); PDF parsing was not run", ex.GetType().Name, SafeClamAvError(ex.Message));
                return Results.Problem(statusCode: StatusCodes.Status503ServiceUnavailable, title: "Local antivirus scanner unavailable. PDF parsing was not run.");
            }
        if (!string.Equals(verdict, ClamAvScanner.CleanVerdict, StringComparison.Ordinal))
        {
            return Results.Json(new LocalPdfReviewResponse(
                "ThreatsDetected", verdict, 0, "Non-clean malware result; PDF parsing was not run.",
                new PdfPigExtractionResponse(0, string.Empty, Array.Empty<ExtractedPage>(), Array.Empty<ExtractedPdfImage>()),
                0, 0, Array.Empty<PdfFormField>()));
        }

        var result = PdfPigReviewExtractor.Extract(bytes, cancellationToken);
        ocrInputBuffers = result.Images
            .Where(image => image.OcrInputBytes is not null)
            .Select(image => image.OcrInputBytes!)
            .ToList();
        var pages = result.Pages.ToList();
        var ocrCandidates = result.Images
            .Select((image, index) => (image, index))
            .Where(item => item.image.OcrInputBytes is not null && string.Equals(item.image.Source, "EmbeddedImageStream", StringComparison.Ordinal))
            .ToArray();
        var ocrImagesProcessed = 0;
        var ocrFailures = 0;
        var ocrImagesSkipped = Math.Max(0, ocrCandidates.Length - maximumOcrImages);
        foreach (var candidate in ocrCandidates.Take(maximumOcrImages))
        {
            cancellationToken.ThrowIfCancellationRequested();
            byte[]? imageBytes = null;
            try
            {
                imageBytes = candidate.image.OcrInputBytes;
                if (imageBytes is null) continue;
                var recognizedText = await ocrService.RecognizeAsync(imageBytes, maximumOcrCharactersPerImage, cancellationToken);
                ocrImagesProcessed++;
                if (!string.IsNullOrWhiteSpace(recognizedText))
                    result.Images[candidate.index] = candidate.image with { OcrText = recognizedText, OcrInputBytes = null };
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or InvalidOperationException or TimeoutException or System.ComponentModel.Win32Exception)
            {
                ocrFailures++;
                loggerFactory.CreateLogger("LocalPdfReview").LogInformation("OCR was unavailable for embedded image on page {PageNumber} ({ExceptionType}); other extraction results are retained", candidate.image.PageNumber, ex.GetType().Name);
            }
            finally
            {
                if (imageBytes is not null) CryptographicOperations.ZeroMemory(imageBytes);
                result.Images[candidate.index] = result.Images[candidate.index] with { OcrInputBytes = null };
            }
        }
        foreach (var image in result.Images)
        {
            if (image.OcrInputBytes is not null) CryptographicOperations.ZeroMemory(image.OcrInputBytes);
        }
        for (var index = 0; index < result.Images.Count; index++)
            result.Images[index] = result.Images[index] with { OcrInputBytes = null };
        ocrInputBuffers = null;
        foreach (var pageGroup in result.Images
                     .Where(image => !string.IsNullOrWhiteSpace(image.OcrText))
                     .GroupBy(image => image.PageNumber))
        {
            var pageIndex = pages.FindIndex(page => page.PageNumber == pageGroup.Key);
            if (pageIndex < 0) continue;
            var page = pages[pageIndex];
            var ocrText = string.Join("\n\n", pageGroup.Select((image, index) => $"[OCR from embedded image {index + 1}]\n{image.OcrText}"));
            var originalText = page.Text.Trim();
            pages[pageIndex] = page with
            {
                Text = string.IsNullOrEmpty(originalText) ? ocrText : $"{originalText}\n\n{ocrText}",
                SelectableText = originalText,
                OcrText = string.Join("\n\n", pageGroup.Select(image => image.OcrText).Where(text => !string.IsNullOrWhiteSpace(text))),
                Source = string.IsNullOrEmpty(originalText)
                    ? "Tesseract OCR (English) from embedded image(s)"
                    : "PdfPig + Tesseract OCR (English) from embedded image(s)"
            };
        }
        var extractedText = string.Join("\n\n", pages.Select(page => page.Text));
        if (extractedText.Length > maximumExtractedCharacters)
            throw new InvalidDataException("Text plus embedded-image OCR exceeds the configured output limit.");
        result = result with { Pages = pages, Content = extractedText };

        var previewedPages = new HashSet<int>();
        long fallbackPixels = 0;
        var fallbackBytes = 0;
        var pagesNeedingFallback = result.Images
            .Where(image => !image.Decoded && image.PageNumber > 0)
            .Select(image => image.PageNumber)
            .Distinct()
            .Take(5)
            .ToArray();
        foreach (var failedPage in pagesNeedingFallback)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!previewedPages.Add(failedPage)) continue;
            try
            {
                var preview = renderer.RenderPage(bytes, failedPage - 1);
                var png = preview.Png;
                if (png.Length < 24 || png.Length > 2 * 1024 * 1024 || !png.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }))
                {
                    CryptographicOperations.ZeroMemory(png);
                    continue;
                }
                var width = checked((int)BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(16, 4)));
                var height = checked((int)BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(20, 4)));
                var pixels = (long)width * height;
                if (width is <= 0 or > 1600 || height is <= 0 or > 2400 || pixels > 3_840_000 ||
                    fallbackPixels + pixels > 12_000_000 || fallbackBytes + png.Length > 6 * 1024 * 1024 || result.Images.Count >= 25)
                {
                    CryptographicOperations.ZeroMemory(png);
                    continue;
                }
                fallbackPixels += pixels;
                fallbackBytes += png.Length;
                result.Images.Add(new ExtractedPdfImage(
                    failedPage, width, height, "image/png", Convert.ToBase64String(png), true,
                    Convert.ToHexString(SHA256.HashData(png)),
                    "RenderedPageFallback"));
                CryptographicOperations.ZeroMemory(png);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                loggerFactory.CreateLogger("LocalPdfReview").LogInformation("Rendered-page fallback unavailable for page {PageNumber} ({ExceptionType}); clean-scan extraction results are retained", failedPage, ex.GetType().Name);
            }
        }
        var extraction = new PdfPigExtractionResponse(result.PageCount, result.Content, result.Pages, result.Images);
        var ocrSummary = $" Local OCR: Tesseract English reads extracted embedded image streams only; {ocrImagesProcessed} image(s) processed, {ocrFailures} failed, {ocrImagesSkipped} skipped by the image limit. Full-page renders and rendered-page fallbacks are not OCR inputs. OCR text is machine-generated and requires human verification.";
        return Results.Json(new LocalPdfReviewResponse(
            "No threats found", "ClamAV", extraction.PageCount,
            "Selectable text, read-only AcroForm fields, OCR of extracted embedded image streams, and image previews produced after a clean local scan. Unsupported streams use a clearly marked rendered-page fallback when bounded rendering succeeds; fallback pages are not OCR-scanned." + ocrSummary,
            extraction, result.ImageStreamCount, result.UndecodedImageCount, result.Forms));
    }
    catch (InvalidDataException ex)
    {
        return Results.Problem(statusCode: StatusCodes.Status422UnprocessableEntity, title: ex.Message);
    }
    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
    {
        throw;
    }
    catch (Exception ex)
    {
        loggerFactory.CreateLogger("LocalPdfReview").LogWarning("Local PDF review extraction failed ({ExceptionType}: {Reason}); document content omitted", ex.GetType().Name, SafeClamAvError(ex.Message));
        return Results.Problem(statusCode: StatusCodes.Status422UnprocessableEntity, title: "Local PDF review extraction failed.");
    }
    finally
    {
        if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        if (ocrInputBuffers is not null)
            foreach (var imageBytes in ocrInputBuffers) CryptographicOperations.ZeroMemory(imageBytes);
        if (parserSlotAcquired) parsingGate.Release();
    }
}).DisableAntiforgery();

app.MapGet("/health/live", () => Results.Ok(new { status = "live" }));
app.MapGet("/health/ready", async (ClamAvScanner scanner, CancellationToken cancellationToken) =>
{
    if (!string.Equals(builder.Configuration["ENABLE_LOCAL_CLAMAV"], "true", StringComparison.OrdinalIgnoreCase))
        return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);

    if (scanner.OnDemand)
        return scanner.CanStartOnDemand() ? Results.Ok(new { status = "ready" }) : Results.StatusCode(StatusCodes.Status503ServiceUnavailable);

    try
    {
        var verdict = await scanner.ScanAsync(Array.Empty<byte>(), cancellationToken);
        return string.Equals(verdict, ClamAvScanner.CleanVerdict, StringComparison.Ordinal)
            ? Results.Ok(new { status = "ready" })
            : Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }
    catch (Exception ex) when (ex is SocketException or IOException or TimeoutException or InvalidOperationException)
    {
        return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }
});
app.Run();

static bool IsAuthorized(HttpRequest request, string? expectedToken)
{
    if (string.IsNullOrEmpty(expectedToken) || expectedToken.Length < 32 || !request.Headers.TryGetValue("X-SecRev-Sandbox-Token", out var suppliedValues))
        return false;
    var suppliedToken = suppliedValues.ToString();
    return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expectedToken), Encoding.UTF8.GetBytes(suppliedToken));
}

static string SafeClamAvError(string message) => new(message.Where(ch => char.IsAsciiLetterOrDigit(ch) || ch is ' ' or ':' or '-' or '.').Take(160).ToArray());

static async Task<byte[]> ReadBoundedPdfAsync(HttpRequest request, CancellationToken cancellationToken)
{
    if (request.ContentLength is not > 0 or > maximumPdfBytes)
        throw new InvalidDataException("PDF size limit exceeded.");
    // Read straight into one exactly-sized buffer: no growing MemoryStream, no extra copy.
    var bytes = new byte[(int)request.ContentLength.Value];
    try
    {
        var total = 0;
        while (total < bytes.Length)
        {
            var read = await request.Body.ReadAsync(bytes.AsMemory(total), cancellationToken);
            if (read == 0) throw new InvalidDataException("PDF upload was incomplete.");
            total += read;
        }
        if (bytes.Length < 8 || !bytes.AsSpan(0, 5).SequenceEqual("%PDF-"u8))
            throw new InvalidDataException("Invalid PDF header.");
        return bytes;
    }
    catch
    {
        CryptographicOperations.ZeroMemory(bytes);
        throw;
    }
}

// One PDF is parsed at a time and at most one more may wait; further uploads are rejected so queued
// requests (e.g. repeated re-uploads) cannot pile up in memory. Request bodies are only read after the slot is held.
internal sealed class PdfParsingGate
{
    private readonly SemaphoreSlim _semaphore = new(1, 1);
    private int _inFlight;

    public async Task<bool> TryAcquireAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Increment(ref _inFlight) > 2)
        {
            Interlocked.Decrement(ref _inFlight);
            return false;
        }
        try
        {
            await _semaphore.WaitAsync(cancellationToken);
            return true;
        }
        catch
        {
            Interlocked.Decrement(ref _inFlight);
            throw;
        }
    }

    public void Release()
    {
        _semaphore.Release();
        Interlocked.Decrement(ref _inFlight);
    }
}

// Stops the parser process after it has been idle, so its memory returns to the container between uploads.
internal sealed class IdleShutdown
{
    private static readonly TimeSpan IdleAfterRequest = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan StartupGrace = TimeSpan.FromSeconds(45);
    private readonly object _lock = new();
    private readonly IHostApplicationLifetime _lifetime;
    private int _active;
    private long _generation;

    public IdleShutdown(IHostApplicationLifetime lifetime) => _lifetime = lifetime;

    public void Arm(TimeSpan? delay = null) => Schedule(delay ?? StartupGrace);

    public void RequestStarted()
    {
        lock (_lock)
        {
            _active++;
            _generation++;
        }
    }

    public void RequestFinished()
    {
        lock (_lock)
        {
            if (--_active > 0) return;
        }
        Schedule(IdleAfterRequest);
    }

    private void Schedule(TimeSpan delay)
    {
        long generation;
        lock (_lock) generation = ++_generation;
        _ = Task.Run(async () =>
        {
            await Task.Delay(delay);
            lock (_lock)
            {
                if (_generation != generation || _active > 0) return;
            }
            _lifetime.StopApplication();
        });
    }
}

internal sealed record ExtractedPage(int PageNumber, string Text, string Source = "PdfPig selectable text", string OcrText = "", string? SelectableText = null);
internal sealed record ExtractedPdfImage(int PageNumber, int Width, int Height, string MimeType, string Base64Data, bool Decoded, string Detail, string Source = "EmbeddedImageStream", string? OcrText = null)
{
    [JsonIgnore]
    public byte[]? OcrInputBytes { get; init; }
}
internal sealed record PdfPigExtractionResponse(int PageCount, string Content, IReadOnlyList<ExtractedPage> Pages, IReadOnlyList<ExtractedPdfImage> Images);
internal sealed record LocalPdfImageExtractionResponse(string ScanResult, string ScanProvider, int PageCount, string Detail, int ImageStreamCount, int UndecodedCount, IReadOnlyList<ExtractedPdfImage> Images);
internal sealed record LocalPdfReviewResponse(string ScanResult, string ScanProvider, int PageCount, string Detail, PdfPigExtractionResponse Extraction, int ImageStreamCount, int UndecodedImageCount, IReadOnlyList<PdfFormField> Forms);
internal sealed record PdfFormField(int? PageNumber, string Name, string Type, string Value, string? Bounds);
internal sealed record PdfPigImageExtractionResult(PdfPigExtractionResponse Extraction, int ImageStreamCount, int UndecodedCount);
internal sealed record PdfPigReviewExtraction(int PageCount, string Content, IReadOnlyList<ExtractedPage> Pages, List<ExtractedPdfImage> Images, int ImageStreamCount, int UndecodedImageCount, IReadOnlyList<PdfFormField> Forms);

internal static class PdfPigReviewExtractor
{
    private const int MaximumForms = 500;

    public static PdfPigReviewExtraction Extract(byte[] bytes, CancellationToken cancellationToken)
    {
        var imageExtraction = PdfPigImageExtractor.ExtractImages(bytes, cancellationToken);
        using var input = new MemoryStream(bytes, writable: false);
        using var document = PdfDocument.Open(input);
        var forms = new List<PdfFormField>();
        if (document.TryGetForm(out var form))
        {
            foreach (var field in form.GetFields())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (forms.Count >= MaximumForms)
                    throw new InvalidDataException("PDF form field count exceeds the configured limit.");
                var info = field.Information;
                var name = info?.MappingName;
                if (string.IsNullOrWhiteSpace(name)) name = info?.PartialName;
                name ??= "(unnamed field)";
                var fieldValue = AcroFormExtensions.GetFieldValue(field);
                var value = fieldValue.Value ?? string.Empty;
                if (name.Length > 512 || value.Length > 16_384)
                    throw new InvalidDataException("PDF form field data exceeds the configured limit.");
                forms.Add(new PdfFormField(
                    field.PageNumber,
                    name,
                    field.FieldType.ToString(),
                    value,
                    field.Bounds?.ToString()));
            }
        }

        var orderedForms = forms.OrderBy(field => field.PageNumber ?? int.MaxValue).ThenBy(field => field.Name, StringComparer.Ordinal).ToArray();
        return new PdfPigReviewExtraction(imageExtraction.Extraction.PageCount, imageExtraction.Extraction.Content,
            imageExtraction.Extraction.Pages, imageExtraction.Extraction.Images.ToList(), imageExtraction.ImageStreamCount,
            imageExtraction.UndecodedCount, orderedForms);
    }
}

internal static class PdfPigImageExtractor
{
    private const int MaximumPages = 100;
    private const int MaximumExtractedCharacters = 500_000;
    private const int MaximumExtractedImages = 20;
    private const int MaximumImageBytes = 2 * 1024 * 1024;
    private const int MaximumTotalImageBytes = 6 * 1024 * 1024;
    private const int MaximumImageDimension = 4096;
    private const long MaximumImagePixels = 4_000_000;
    private const long MaximumTotalImagePixels = 12_000_000;

    public static PdfPigImageExtractionResult ExtractImages(byte[] bytes, CancellationToken cancellationToken)
    {
        using var pdfStream = new MemoryStream(bytes, writable: false);
        using var document = PdfDocument.Open(pdfStream);
        if (document.NumberOfPages is <= 0 or > MaximumPages)
            throw new InvalidDataException("PDF page count is outside the configured limit.");

        var pages = new List<ExtractedPage>(document.NumberOfPages);
        var images = new List<ExtractedPdfImage>();
        var totalCharacters = 0;
        var totalImageBytes = 0;
        long totalImagePixels = 0;
        var imageStreamCount = 0;
        var undecodedCount = 0;
        foreach (var page in document.GetPages())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var pageText = ContentOrderTextExtractor.GetText(page);
            totalCharacters = checked(totalCharacters + pageText.Length);
            if (totalCharacters > MaximumExtractedCharacters)
                throw new InvalidDataException("Extracted text exceeds the configured output limit.");
            pages.Add(new ExtractedPage(page.Number, pageText));

            foreach (var image in page.GetImages())
            {
                cancellationToken.ThrowIfCancellationRequested();
                imageStreamCount++;
                if (images.Count >= MaximumExtractedImages)
                    throw new InvalidDataException("PDF image count exceeds the configured output limit.");
                if (image is null || image.WidthInSamples <= 0 || image.HeightInSamples <= 0 ||
                    image.WidthInSamples > MaximumImageDimension || image.HeightInSamples > MaximumImageDimension ||
                    (long)image.WidthInSamples * image.HeightInSamples > MaximumImagePixels)
                {
                    undecodedCount++;
                    images.Add(new ExtractedPdfImage(page.Number, 0, 0, string.Empty, "", false, "Image dimensions exceed decode limits."));
                    continue;
                }

                try
                {
                    if (image.RawBytes.Length > MaximumImageBytes)
                    {
                        undecodedCount++;
                        images.Add(new ExtractedPdfImage(page.Number, image.WidthInSamples, image.HeightInSamples, string.Empty, "", false, "Encoded image stream exceeds size limits."));
                        continue;
                    }
                    if (!image.TryGetPng(out var png) || png.Length == 0)
                    {
                        undecodedCount++;
                        var rawBytes = image.RawBytes;
                        var hasJpegSignature = rawBytes.Length >= 3 && rawBytes[0] == 0xFF && rawBytes[1] == 0xD8 && rawBytes[2] == 0xFF;
                        var ocrInput = hasJpegSignature ? rawBytes.ToArray() : null;
                        images.Add(new ExtractedPdfImage(page.Number, image.WidthInSamples, image.HeightInSamples, string.Empty, "", false,
                            hasJpegSignature ? "JPEG stream retained for image-only OCR; PdfPig PNG preview decode unavailable." : "Unsupported image filter or color space.")
                        {
                            OcrInputBytes = ocrInput
                        });
                        continue;
                    }
                    if (png.Length > MaximumImageBytes || totalImageBytes + png.Length > MaximumTotalImageBytes)
                    {
                        undecodedCount++;
                        CryptographicOperations.ZeroMemory(png);
                        images.Add(new ExtractedPdfImage(page.Number, image.WidthInSamples, image.HeightInSamples, string.Empty, "", false, "Decoded image data exceeds size limits."));
                        continue;
                    }
                    var imagePixels = (long)image.WidthInSamples * image.HeightInSamples;
                    if (totalImagePixels + imagePixels > MaximumTotalImagePixels)
                    {
                        undecodedCount++;
                        CryptographicOperations.ZeroMemory(png);
                        images.Add(new ExtractedPdfImage(page.Number, image.WidthInSamples, image.HeightInSamples, string.Empty, "", false, "Aggregate decoded pixel budget exceeded."));
                        continue;
                    }

                    totalImageBytes += png.Length;
                    totalImagePixels += imagePixels;
                    images.Add(new ExtractedPdfImage(
                        page.Number,
                        image.WidthInSamples,
                        image.HeightInSamples,
                        "image/png",
                        Convert.ToBase64String(png),
                        true,
                        Convert.ToHexString(SHA256.HashData(png)))
                    {
                        OcrInputBytes = png.ToArray()
                    });
                    CryptographicOperations.ZeroMemory(png);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    undecodedCount++;
                    images.Add(new ExtractedPdfImage(page.Number, image.WidthInSamples, image.HeightInSamples, string.Empty, "", false, "Image decode failed; stream omitted."));
                }
            }
        }

        return new PdfPigImageExtractionResult(
            new PdfPigExtractionResponse(pages.Count, string.Join("\n\n", pages.Select(page => page.Text)), pages, images),
            imageStreamCount,
            undecodedCount);
    }
}

internal sealed class ClamAvScanner
{
    public const string CleanVerdict = "stream: OK";
    private const int MaximumResponseLength = 4096;
    private readonly string _host = Environment.GetEnvironmentVariable("CLAMAV_HOST") ?? "127.0.0.1";
    private readonly int _port = int.TryParse(Environment.GetEnvironmentVariable("CLAMAV_PORT"), out var port) ? port : 3310;
    // On-demand mode: clamd (about 1 GB with signatures) only runs while scans are happening.
    private readonly string? _onDemandConfig = Environment.GetEnvironmentVariable("CLAMAV_ONDEMAND_CONF");
    private readonly string _clamdPath = Environment.GetEnvironmentVariable("CLAMAV_BINARY") ?? "/usr/sbin/clamd";
    private static readonly TimeSpan IdleStop = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(90);
    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private Process? _clamd;
    private int _activeScans;
    private long _idleToken;

    public bool OnDemand => !string.IsNullOrWhiteSpace(_onDemandConfig);

    // Ready when clamd can be started and signatures were downloaded; never starts clamd, so health checks stay cheap.
    public bool CanStartOnDemand()
    {
        if (!OnDemand || !File.Exists(_clamdPath) || !File.Exists(_onDemandConfig)) return false;
        var databaseDirectory = File.ReadLines(_onDemandConfig!)
            .Select(line => line.Split(' ', 2))
            .Where(parts => parts.Length == 2 && parts[0] == "DatabaseDirectory")
            .Select(parts => parts[1].Trim())
            .FirstOrDefault();
        return databaseDirectory is not null && Directory.Exists(databaseDirectory) &&
            Directory.EnumerateFiles(databaseDirectory).Any(f => f.EndsWith(".cvd", StringComparison.Ordinal) || f.EndsWith(".cld", StringComparison.Ordinal));
    }

    public async Task<string> ScanAsync(byte[] bytes, CancellationToken cancellationToken)
    {
        if (_port is <= 0 or > 65535 || string.IsNullOrWhiteSpace(_host))
            throw new InvalidOperationException("ClamAV endpoint configuration is invalid.");
        if (!OnDemand) return await ScanCoreAsync(bytes, cancellationToken);

        await EnsureRunningAsync(cancellationToken);
        try
        {
            return await ScanCoreAsync(bytes, cancellationToken);
        }
        finally
        {
            ReleaseScan();
        }
    }

    private async Task EnsureRunningAsync(CancellationToken cancellationToken)
    {
        await _lifecycle.WaitAsync(cancellationToken);
        try
        {
            Interlocked.Increment(ref _activeScans);
            Interlocked.Increment(ref _idleToken);
            if (_clamd is { HasExited: false }) return;
            _clamd?.Dispose();
            var startInfo = new ProcessStartInfo
            {
                FileName = _clamdPath,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            startInfo.ArgumentList.Add("--config-file=" + _onDemandConfig);
            var process = new Process { StartInfo = startInfo };
            if (!process.Start())
                throw new InvalidOperationException("ClamAV could not be started.");
            process.OutputDataReceived += (_, _) => { };
            process.ErrorDataReceived += (_, _) => { };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            _clamd = process;

            using var startup = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            startup.CancelAfter(StartupTimeout);
            while (true)
            {
                if (process.HasExited)
                    throw new InvalidOperationException("ClamAV exited during startup.");
                try
                {
                    using var probe = new TcpClient();
                    await probe.ConnectAsync(_host, _port, startup.Token);
                    return;
                }
                catch (SocketException)
                {
                    await Task.Delay(500, startup.Token);
                }
            }
        }
        catch
        {
            Interlocked.Decrement(ref _activeScans);
            StopClamd();
            throw;
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    private void ReleaseScan()
    {
        if (Interlocked.Decrement(ref _activeScans) > 0) return;
        var token = Interlocked.Increment(ref _idleToken);
        _ = Task.Run(async () =>
        {
            await Task.Delay(IdleStop);
            await _lifecycle.WaitAsync();
            try
            {
                if (Interlocked.Read(ref _idleToken) == token && Volatile.Read(ref _activeScans) == 0) StopClamd();
            }
            finally
            {
                _lifecycle.Release();
            }
        });
    }

    // Used at parser shutdown so clamd never outlives the parser.
    public void StopNow()
    {
        _lifecycle.Wait();
        try { StopClamd(); }
        finally { _lifecycle.Release(); }
    }

    private void StopClamd()
    {
        try
        {
            if (_clamd is { HasExited: false }) _clamd.Kill(entireProcessTree: true);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
        }
        _clamd?.Dispose();
        _clamd = null;
    }

    private async Task<string> ScanCoreAsync(byte[] bytes, CancellationToken cancellationToken)
    {

        using var client = new TcpClient();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(45));
        await client.ConnectAsync(_host, _port, timeout.Token);
        await using var stream = client.GetStream();
        await stream.WriteAsync("zINSTREAM\0"u8.ToArray(), timeout.Token);

        var lengthBuffer = new byte[sizeof(uint)];
        for (var offset = 0; offset < bytes.Length; offset += 64 * 1024)
        {
            var count = Math.Min(64 * 1024, bytes.Length - offset);
            BinaryPrimitives.WriteUInt32BigEndian(lengthBuffer, (uint)count);
            await stream.WriteAsync(lengthBuffer, timeout.Token);
            await stream.WriteAsync(bytes.AsMemory(offset, count), timeout.Token);
        }
        BinaryPrimitives.WriteUInt32BigEndian(lengthBuffer, 0);
        await stream.WriteAsync(lengthBuffer, timeout.Token);
        CryptographicOperations.ZeroMemory(lengthBuffer);

        var response = new byte[MaximumResponseLength];
        try
        {
            var count = 0;
            while (count < response.Length)
            {
                var read = await stream.ReadAsync(response.AsMemory(count, Math.Min(256, response.Length - count)), timeout.Token);
                if (read == 0) break;
                var terminator = Array.IndexOf(response, (byte)0, count, read) - count;
                count += terminator >= 0 ? terminator : read;
                if (terminator >= 0) break;
            }
            if (count == 0 || count == response.Length)
                throw new IOException("ClamAV returned an invalid scan response.");
            return Encoding.ASCII.GetString(response, 0, count).Trim();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(response);
        }
    }
}

internal sealed record PdfPreview(int PageCount, byte[] Png);

internal sealed class PdfiumRenderer
{
    private static readonly object InitializationLock = new();
    private static bool _initialized;

    public PdfPreview RenderFirstPage(ReadOnlySpan<byte> source)
        => RenderPage(source, 0);

    public PdfPreview RenderPage(ReadOnlySpan<byte> source, int pageIndex)
        => RenderPage(source, pageIndex, 1.5);

    private PdfPreview RenderPage(ReadOnlySpan<byte> source, int pageIndex, double maximumScale)
    {
        if (source.Length is <= 0 or > 25 * 1024 * 1024)
            throw new InvalidDataException("PDF size is outside the configured limit.");
        lock (InitializationLock)
        {
            if (!_initialized)
            {
                fpdfview.FPDF_InitLibrary();
                _initialized = true;
            }
        }
        unsafe
        {
            fixed (byte* pointer = source)
            {
                var document = fpdfview.FPDF_LoadMemDocument(new IntPtr(pointer), source.Length, null);
                if (document.__Instance == IntPtr.Zero)
                    throw new InvalidDataException("PDFium rejected this PDF; it might be damaged or password protected.");
                try
                {
                    var pageCount = fpdfview.FPDF_GetPageCount(document);
                    if (pageCount is <= 0 or > 100 || pageIndex < 0 || pageIndex >= pageCount)
                        throw new InvalidDataException("PDF page count is outside the configured worker limit.");
                    return new PdfPreview(pageCount, Render(document, pageIndex, maximumScale));
                }
                finally
                {
                    fpdfview.FPDF_CloseDocument(document);
                }
            }
        }
    }

    private static byte[] Render(FpdfDocumentT document, int pageIndex, double maximumScale)
    {
        double pageWidth = 0;
        double pageHeight = 0;
        if (fpdfview.FPDF_GetPageSizeByIndex(document, pageIndex, ref pageWidth, ref pageHeight) == 0 ||
            !double.IsFinite(pageWidth) || !double.IsFinite(pageHeight) || pageWidth <= 0 || pageHeight <= 0)
            throw new InvalidDataException("PDF page dimensions are invalid.");

        var scale = Math.Min(maximumScale, Math.Min(1600 / pageWidth, 2400 / pageHeight));
        var width = Math.Clamp((int)Math.Ceiling(pageWidth * scale), 1, 1600);
        var height = Math.Clamp((int)Math.Ceiling(pageHeight * scale), 1, 2400);
        if ((long)width * height > 3_840_000)
            throw new InvalidDataException("Raster exceeds the configured pixel budget.");

        var page = fpdfview.FPDF_LoadPage(document, pageIndex);
        if (page.__Instance == IntPtr.Zero) throw new InvalidDataException("PDFium could not load the first page.");
        try
        {
            var bitmap = fpdfview.FPDFBitmapCreateEx(width, height, (int)FPDFBitmapFormat.BGRA, IntPtr.Zero, 0);
            if (bitmap.__Instance == IntPtr.Zero) throw new InvalidDataException("PDFium could not allocate the preview bitmap.");
            try
            {
                if (fpdfview.FPDFBitmapFillRect(bitmap, 0, 0, width, height, 0xFFFFFFFF) == 0)
                    throw new InvalidDataException("PDFium could not initialize the preview surface.");

                using var matrix = new FS_MATRIX_();
                using var clip = new FS_RECTF_();
                matrix.A = (float)(width / pageWidth);
                matrix.B = matrix.C = matrix.E = matrix.F = 0;
                matrix.D = (float)(height / pageHeight);
                clip.Left = clip.Bottom = 0;
                clip.Right = width;
                clip.Top = height;
                // Do not render annotations/actions. The renderer never invokes form-fill or JavaScript APIs.
                fpdfview.FPDF_RenderPageBitmapWithMatrix(bitmap, page, matrix, clip, 0);
                var stride = fpdfview.FPDFBitmapGetStride(bitmap);
                var pointer = fpdfview.FPDFBitmapGetBuffer(bitmap);
                if (pointer == IntPtr.Zero || stride < checked(width * 4))
                    throw new InvalidDataException("PDFium returned an invalid bitmap.");
                var bgra = new byte[checked(stride * height)];
                try
                {
                    Marshal.Copy(pointer, bgra, 0, bgra.Length);
                    return EncodePng(width, height, stride, bgra);
                }
                finally
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(bgra);
                }
            }
            finally
            {
                fpdfview.FPDFBitmapDestroy(bitmap);
            }
        }
        finally
        {
            fpdfview.FPDF_ClosePage(page);
        }
    }

    private static byte[] EncodePng(int width, int height, int stride, byte[] bgra)
    {
        using var raw = new MemoryStream(checked((width * 4 + 1) * height));
        for (var y = 0; y < height; y++)
        {
            raw.WriteByte(0);
            var rowOffset = y * stride;
            for (var x = 0; x < width; x++)
            {
                var offset = rowOffset + x * 4;
                raw.WriteByte(bgra[offset + 2]);
                raw.WriteByte(bgra[offset + 1]);
                raw.WriteByte(bgra[offset]);
                raw.WriteByte(bgra[offset + 3]);
            }
        }

        using var compressed = new MemoryStream();
        raw.Position = 0;
        using (var zlib = new ZLibStream(compressed, CompressionLevel.Fastest, leaveOpen: true)) raw.CopyTo(zlib);
        using var output = new MemoryStream();
        output.Write(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 });
        Span<byte> header = stackalloc byte[13];
        WriteUInt32(header, 0, (uint)width);
        WriteUInt32(header, 4, (uint)height);
        header[8] = 8;
        header[9] = 6;
        WriteChunk(output, "IHDR", header);
        WriteChunk(output, "IDAT", compressed.ToArray());
        WriteChunk(output, "IEND", ReadOnlySpan<byte>.Empty);
        var result = output.ToArray();
        if (result.Length > 10 * 1024 * 1024)
            throw new InvalidDataException("PNG preview exceeds the configured output limit.");
        return result;
    }

    private static void WriteChunk(Stream output, string type, ReadOnlySpan<byte> data)
    {
        Span<byte> length = stackalloc byte[4];
        WriteUInt32(length, 0, checked((uint)data.Length));
        output.Write(length);
        Span<byte> typeBytes = stackalloc byte[4];
        System.Text.Encoding.ASCII.GetBytes(type, typeBytes);
        output.Write(typeBytes);
        output.Write(data);
        var bytes = new byte[4 + data.Length];
        typeBytes.CopyTo(bytes);
        data.CopyTo(bytes.AsSpan(4));
        Span<byte> crc = stackalloc byte[4];
        WriteUInt32(crc, 0, Crc32(bytes));
        output.Write(crc);
    }

    private static uint Crc32(ReadOnlySpan<byte> bytes)
    {
        var crc = uint.MaxValue;
        foreach (var b in bytes)
        {
            crc ^= b;
            for (var i = 0; i < 8; i++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
    }

    private static void WriteUInt32(Span<byte> span, int offset, uint value)
    {
        span[offset] = (byte)(value >> 24);
        span[offset + 1] = (byte)(value >> 16);
        span[offset + 2] = (byte)(value >> 8);
        span[offset + 3] = (byte)value;
    }
}

internal sealed class TesseractOcrService
{
    private const int MaximumImageBytes = 2 * 1024 * 1024;
    private const int MaximumCharactersPerImage = 20_000;
    private const int MaximumErrorCharacters = 4096;
    private static readonly TimeSpan PageTimeout = TimeSpan.FromSeconds(15);

    public async Task<string> RecognizeAsync(byte[] png, int maximumCharacters, CancellationToken cancellationToken)
    {
        var isPng = png.Length >= 8 && png.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 });
        var isJpeg = png.Length >= 3 && png[0] == 0xFF && png[1] == 0xD8 && png[2] == 0xFF;
        if (png.Length is <= 3 or > MaximumImageBytes || maximumCharacters is <= 0 or > MaximumCharactersPerImage || (!isPng && !isJpeg))
            throw new InvalidDataException("OCR input exceeded the configured image limits.");
        var executable = Environment.GetEnvironmentVariable("TESSERACT_PATH");
        if (string.IsNullOrWhiteSpace(executable) || !File.Exists(executable))
        {
            executable = new[] { "/opt/homebrew/bin/tesseract", "/usr/local/bin/tesseract", "/usr/bin/tesseract" }
                .FirstOrDefault(File.Exists);
        }
        if (string.IsNullOrWhiteSpace(executable))
            throw new InvalidOperationException("The local Tesseract OCR engine is not installed.");

        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        startInfo.ArgumentList.Add("stdin");
        startInfo.ArgumentList.Add("stdout");
        startInfo.ArgumentList.Add("-l");
        startInfo.ArgumentList.Add("eng");
        startInfo.ArgumentList.Add("--psm");
        startInfo.ArgumentList.Add("3");
        startInfo.Environment["OMP_THREAD_LIMIT"] = "1";
        startInfo.Environment["OMP_NUM_THREADS"] = "1";

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
            throw new InvalidOperationException("The local OCR process could not be started.");
        var outputTask = ReadBoundedAsync(process.StandardOutput, maximumCharacters);
        var errorTask = ReadBoundedAsync(process.StandardError, MaximumErrorCharacters);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(PageTimeout);
        try
        {
            await process.StandardInput.BaseStream.WriteAsync(png.AsMemory(), timeout.Token);
            process.StandardInput.Close();
            await process.WaitForExitAsync(timeout.Token);
            var (output, outputExceeded) = await outputTask;
            _ = await errorTask;
            if (outputExceeded)
                throw new InvalidDataException("OCR text exceeded the per-page output limit.");
            if (process.ExitCode != 0)
                throw new IOException("The local OCR engine failed to recognize this page.");
            return output.Trim();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            throw new TimeoutException("Local OCR exceeded the per-page time limit.");
        }
        finally
        {
            TryKill(process);
        }
    }

    private static async Task<(string Text, bool Exceeded)> ReadBoundedAsync(StreamReader reader, int maximumCharacters)
    {
        var output = new StringBuilder(Math.Min(maximumCharacters, 4096));
        var buffer = new char[4096];
        var exceeded = false;
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory());
            if (read == 0) break;
            var remaining = maximumCharacters - output.Length;
            if (remaining > 0) output.Append(buffer, 0, Math.Min(read, remaining));
            if (read > remaining) exceeded = true;
        }
        Array.Clear(buffer);
        return (output.ToString(), exceeded);
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException) { }
        catch (System.ComponentModel.Win32Exception) { }
    }
}
