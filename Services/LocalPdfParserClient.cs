using SecRev.Models;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SecRev.Services;

internal sealed class LocalPdfParserClient : IDisposable
{
    private const int MaximumResponseBytes = 24 * 1024 * 1024;
    private const int MaximumImages = 25;
    private const int MaximumImageBytes = 2 * 1024 * 1024;
    private const int MaximumTotalImageBytes = 6 * 1024 * 1024;
    private const long MaximumTotalImagePixels = 12_000_000;
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };
    private readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromMinutes(2) };

    public async Task<LocalPdfImageExtractionResult> ScanAndExtractImagesAsync(byte[] pdfBytes, CancellationToken cancellationToken = default)
    {
        var endpointValue = Environment.GetEnvironmentVariable("SECREV_PDF_PARSER_ENDPOINT");
        var token = Environment.GetEnvironmentVariable("SECREV_PDF_PARSER_TOKEN");
        if (!Uri.TryCreate(endpointValue, UriKind.Absolute, out var endpoint) ||
            (endpoint.Scheme != Uri.UriSchemeHttp && endpoint.Scheme != Uri.UriSchemeHttps) ||
            !(endpoint.IsLoopback || string.Equals(endpoint.Host, "localhost", StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("Configure SECREV_PDF_PARSER_ENDPOINT to the loopback-only local parser URL.");
        }
        if (string.IsNullOrWhiteSpace(token) || token.Length < 32)
            throw new InvalidOperationException("Configure SECREV_PDF_PARSER_TOKEN with the local parser's 32+ character token.");
        if (pdfBytes.Length is <= 0 or > 25 * 1024 * 1024)
            throw new InvalidDataException("PDF size exceeds the local parser limit.");

        var requestUri = new Uri(new Uri(endpoint.AbsoluteUri.TrimEnd('/') + "/"), "local/scan-and-extract-pdf-images");
        using var content = new ByteArrayContent(pdfBytes);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pdf");
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUri) { Content = content };
        if (!request.Headers.TryAddWithoutValidation("X-SecRev-Sandbox-Token", token))
            throw new InvalidOperationException("The local parser authentication header could not be configured.");
        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidDataException($"The local scanner/parser returned HTTP {(int)response.StatusCode}; extraction was not accepted.");
        if (response.Content.Headers.ContentLength is > MaximumResponseBytes)
            throw new InvalidDataException("Scanner/parser response exceeded the configured size limit.");

        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = new byte[32 * 1024];
        try
        {
            while (true)
            {
                var read = await input.ReadAsync(buffer.AsMemory(), cancellationToken);
                if (read == 0) break;
                if (output.Length + read > MaximumResponseBytes)
                    throw new InvalidDataException("Scanner/parser response exceeded the configured size limit.");
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }

        var responseBytes = output.ToArray();
        try
        {
            var result = JsonSerializer.Deserialize<ParserResponse>(responseBytes, JsonOptions)
                ?? throw new InvalidDataException("The local parser returned an empty response.");
            if (result.Images is null || result.PageCount is < 0 or > 100 || result.Images.Length > MaximumImages ||
                result.Images.Any(image => image?.OcrText is { Length: > 20_000 }))
                throw new InvalidDataException("The parser response exceeded configured image/page limits.");

            var extraction = new LocalPdfImageExtractionResult
            {
                ScanResult = result.ScanResult,
                ScanProvider = result.ScanProvider,
                Detail = result.Detail,
                PageCount = result.PageCount,
                UndecodedCount = result.Images.Count(image => image is null || !image.Decoded)
            };
            if (!string.Equals(result.ScanResult, "No threats found", StringComparison.Ordinal))
                return extraction;
            if (!string.Equals(result.ScanProvider, "ClamAV", StringComparison.Ordinal))
                throw new InvalidDataException("A recognized local ClamAV clean result was not supplied.");

            var aggregate = 0;
            long aggregatePixels = 0;
            foreach (var image in result.Images)
            {
                if (image is null) continue;
                if (!image.Decoded) continue;
                if (image.PageNumber is <= 0 || image.PageNumber > result.PageCount || image.Width is <= 0 or > 4096 || image.Height is <= 0 or > 4096 ||
                    !string.Equals(image.MimeType, "image/png", StringComparison.Ordinal) || image.Base64Data is null || image.Detail is null ||
                    image.Detail.Length != 64 || !image.Detail.All(Uri.IsHexDigit) ||
                    (!string.Equals(image.Source, "EmbeddedImageStream", StringComparison.Ordinal) && !string.Equals(image.Source, "RenderedPageFallback", StringComparison.Ordinal)))
                    throw new InvalidDataException("The parser returned invalid image metadata.");

                byte[] imageBytes;
                try { imageBytes = Convert.FromBase64String(image.Base64Data); }
                catch (FormatException ex) { throw new InvalidDataException("The parser returned malformed encoded image data.", ex); }
                try
                {
                    if (imageBytes.Length is <= 0 or > MaximumImageBytes || imageBytes.Length < 8 ||
                        !imageBytes.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }) ||
                        !string.Equals(Convert.ToHexString(SHA256.HashData(imageBytes)), image.Detail, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("An extracted image failed PNG signature, size, or digest validation.");
                    aggregate = checked(aggregate + imageBytes.Length);
                    if (aggregate > MaximumTotalImageBytes)
                        throw new InvalidDataException("Extracted images exceeded the aggregate size limit.");
                    aggregatePixels += (long)image.Width * image.Height;
                    if (aggregatePixels > MaximumTotalImagePixels)
                        throw new InvalidDataException("Extracted images exceeded the aggregate decoded-pixel limit.");
                    extraction.Images.Add(new ExtractedImage
                    {
                        MimeType = image.MimeType!,
                        ByteLength = imageBytes.Length,
                        Sha256 = image.Detail,
                        Base64Data = Convert.ToBase64String(imageBytes),
                        ExtractionSource = image.Source,
                        PageNumber = image.PageNumber,
                        Width = image.Width,
                        Height = image.Height,
                        OcrText = image.OcrText ?? string.Empty
                    });
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(imageBytes);
                }
            }
            return extraction;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(responseBytes);
        }
    }

    public async Task<LocalPdfReviewResult> ScanAndExtractReviewAsync(byte[] pdfBytes, CancellationToken cancellationToken = default)
    {
        var endpoint = GetConfiguredEndpoint();
        var token = GetConfiguredToken();
        if (pdfBytes.Length is <= 0 or > 25 * 1024 * 1024)
            throw new InvalidDataException("PDF size exceeds the local parser limit.");

        var uri = new Uri(new Uri(endpoint.AbsoluteUri.TrimEnd('/') + "/"), "local/scan-and-extract-pdf-review");
        using var content = new ByteArrayContent(pdfBytes);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pdf");
        using var request = new HttpRequestMessage(HttpMethod.Post, uri) { Content = content };
        if (!request.Headers.TryAddWithoutValidation("X-SecRev-Sandbox-Token", token))
            throw new InvalidOperationException("The local parser authentication header could not be configured.");
        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidDataException($"The local scanner/parser returned HTTP {(int)response.StatusCode}; extraction was not accepted.");

        var responseBytes = await ReadBoundedResponseAsync(response.Content, cancellationToken);
        ParserReviewResponse result;
        try
        {
            result = JsonSerializer.Deserialize<ParserReviewResponse>(responseBytes, JsonOptions)
                ?? throw new InvalidDataException("The local PDF review parser returned an empty response.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(responseBytes);
        }
        if (result.Extraction?.Pages is null || result.Forms is null || result.PageCount is < 0 or > 100 ||
            result.Forms.Count > 500 || result.Extraction.Pages.Count > 100 ||
            result.Extraction.Images is null || result.Extraction.Images.Length > MaximumImages ||
            result.Extraction.Images.Any(image => image?.OcrText is { Length: > 20_000 }) ||
            result.Extraction.Content is { Length: > 500_000 } || result.Forms.Any(field => field is null || field.Name is null || field.Value is null || field.Name.Length > 512 || field.Value.Length > 16_384) ||
            result.Extraction.Pages.Any(page => page is null || page.PageNumber is <= 0 || page.PageNumber > result.PageCount || page.Text is null || page.Text.Length > 500_000))
            throw new InvalidDataException("The local PDF review parser response exceeded its limits or was incomplete.");

        var images = result.Extraction.Images ?? Array.Empty<ParserImage?>();
        var imageResult = new ParserResponse(result.ScanResult, result.ScanProvider, result.PageCount, result.Detail,
            result.ImageStreamCount, result.UndecodedImageCount, images.ToArray());
        var validated = ValidateImageResponse(imageResult);
        var text = result.Extraction.Pages
            .Select(page => $"===== PAGE {page.PageNumber} · PdfPig selectable text =====\n{page.SelectableText ?? page.Text}")
            .ToArray();
        var searchableText = result.Extraction.Pages
            .Select(page => $"===== PAGE {page.PageNumber} · {page.Source ?? "PdfPig + embedded-image OCR"} =====\n{page.Text}")
            .ToArray();
        var imageOcrText = string.Join("\n\n", result.Extraction.Pages
            .Where(page => !string.IsNullOrWhiteSpace(page.OcrText))
            .Select(page => $"PAGE {page.PageNumber}\n{page.OcrText}"));
        if (string.IsNullOrWhiteSpace(imageOcrText))
            imageOcrText = string.Join("\n\n", validated.Images
            .Where(image => image.ExtractionSource == "EmbeddedImageStream" && !string.IsNullOrWhiteSpace(image.OcrText))
            .Select((image, index) => $"IMAGE {index + 1} · PAGE {image.PageNumber}\n{image.OcrText}"));
        return new LocalPdfReviewResult
        {
            ScanResult = validated.ScanResult,
            ScanProvider = validated.ScanProvider,
            Detail = validated.Detail,
            PageCount = validated.PageCount,
            ImageStreamCount = validated.ImageStreamCount,
            UndecodedCount = validated.UndecodedCount,
            Images = validated.Images,
            TextAndForms = FormatTextAndForms(searchableText, result.Forms),
            SelectableTextAndForms = FormatTextAndForms(text, result.Forms),
            EmbeddedImageOcrText = imageOcrText,
            Pages = result.Extraction.Pages.Select(page => new LocalPdfExtractedPage(page.PageNumber, page.SelectableText ?? page.Text, page.Source ?? "PdfPig selectable text", page.OcrText ?? string.Empty)).ToList(),
            Forms = result.Forms.Select(field => new LocalPdfFormField(field.PageNumber, field.Name, field.Type, field.Value, field.Bounds)).ToList(),
            PdfTextVerified = false
        };
    }

    private Uri GetConfiguredEndpoint()
    {
        var endpointValue = Environment.GetEnvironmentVariable("SECREV_PDF_PARSER_ENDPOINT");
        if (!Uri.TryCreate(endpointValue, UriKind.Absolute, out var endpoint) ||
            (endpoint.Scheme != Uri.UriSchemeHttp && endpoint.Scheme != Uri.UriSchemeHttps) ||
            !(endpoint.IsLoopback || string.Equals(endpoint.Host, "localhost", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Configure SECREV_PDF_PARSER_ENDPOINT to the loopback-only local parser URL.");
        return endpoint;
    }

    private static string GetConfiguredToken()
    {
        var token = Environment.GetEnvironmentVariable("SECREV_PDF_PARSER_TOKEN");
        if (string.IsNullOrWhiteSpace(token) || token.Length < 32)
            throw new InvalidOperationException("Configure SECREV_PDF_PARSER_TOKEN with the local parser's 32+ character token.");
        return token;
    }

    private static async Task<byte[]> ReadBoundedResponseAsync(HttpContent content, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > MaximumResponseBytes)
            throw new InvalidDataException("Scanner/parser response exceeded the configured size limit.");

        await using var input = await content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = new byte[32 * 1024];
        try
        {
            while (true)
            {
                var read = await input.ReadAsync(buffer.AsMemory(), cancellationToken);
                if (read == 0) break;
                if (output.Length + read > MaximumResponseBytes)
                    throw new InvalidDataException("Scanner/parser response exceeded the configured size limit.");
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static string FormatTextAndForms(IReadOnlyList<string> pages, IReadOnlyList<ParserFormField> forms)
    {
        var output = new System.Text.StringBuilder();
        if (forms.Count > 0)
        {
            output.AppendLine("READ-ONLY ACROFORM FIELDS");
            foreach (var field in forms)
                output.AppendLine($"Page {field.PageNumber?.ToString() ?? "?"} · {field.Type} · {field.Name}: {field.Value}" + (string.IsNullOrEmpty(field.Bounds) ? "" : $" · bounds {field.Bounds}"));
            output.AppendLine();
        }
        else
        {
            output.AppendLine("No supported AcroForm fields were returned.");
        }

        foreach (var page in pages)
        {
            output.AppendLine(page);
            output.AppendLine();
            if (output.Length > 500_000)
                throw new InvalidDataException("Combined PDF text/form review exceeds the display limit.");
        }
        return output.ToString();
    }

    private LocalPdfImageExtractionResult ValidateImageResponse(ParserResponse result)
    {
        if (result.Images is null || result.PageCount is < 0 or > 100 || result.Images.Length > MaximumImages)
            throw new InvalidDataException("The parser response exceeded configured image/page limits.");

        var extraction = new LocalPdfImageExtractionResult
        {
            ScanResult = result.ScanResult,
            ScanProvider = result.ScanProvider,
            Detail = result.Detail,
            PageCount = result.PageCount,
            ImageStreamCount = result.ImageStreamCount,
            UndecodedCount = Math.Max(0, Math.Max(result.UndecodedCount, result.Images.Count(image => image is null || !image.Decoded)))
        };
        if (!string.Equals(result.ScanResult, "No threats found", StringComparison.Ordinal))
            return extraction;
        if (!string.Equals(result.ScanProvider, "ClamAV", StringComparison.Ordinal))
            throw new InvalidDataException("A recognized local ClamAV clean result was not supplied.");

        var aggregate = 0;
        long aggregatePixels = 0;
        var imageWarnings = new List<string>();
        foreach (var image in result.Images)
        {
            if (image is null)
            {
                extraction.UndecodedCount++;
                imageWarnings.Add("An image entry was skipped: metadata was missing.");
                continue;
            }
            if (!image.Decoded) continue;
            if (image.PageNumber is <= 0 || image.PageNumber > result.PageCount || image.Width is <= 0 or > 4096 || image.Height is <= 0 or > 4096 ||
                !string.Equals(image.MimeType, "image/png", StringComparison.Ordinal) || image.Base64Data is null || image.Detail is null ||
                image.Detail.Length != 64 || !image.Detail.All(Uri.IsHexDigit) ||
                (image.Source != "EmbeddedImageStream" && image.Source != "RenderedPageFallback"))
            {
                extraction.UndecodedCount++;
                imageWarnings.Add($"Image on page {Math.Max(1, image.PageNumber)} was skipped: metadata was invalid.");
                continue;
            }

            byte[] imageBytes;
            try { imageBytes = Convert.FromBase64String(image.Base64Data); }
            catch (FormatException)
            {
                extraction.UndecodedCount++;
                imageWarnings.Add($"Image on page {image.PageNumber} was skipped: encoded image data was invalid.");
                continue;
            }
            try
            {
                if (imageBytes.Length is <= 0 or > MaximumImageBytes || imageBytes.Length < 8 ||
                    !imageBytes.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }) ||
                    !string.Equals(Convert.ToHexString(SHA256.HashData(imageBytes)), image.Detail, StringComparison.OrdinalIgnoreCase) ||
                    imageBytes.Length < 24 ||
                    BinaryPrimitives.ReadUInt32BigEndian(imageBytes.AsSpan(16, 4)) != image.Width ||
                    BinaryPrimitives.ReadUInt32BigEndian(imageBytes.AsSpan(20, 4)) != image.Height)
                {
                    extraction.UndecodedCount++;
                    imageWarnings.Add($"Image on page {image.PageNumber} was skipped: PNG signature, dimensions, size, or digest did not validate.");
                    continue;
                }
                aggregate = checked(aggregate + imageBytes.Length);
                aggregatePixels += (long)image.Width * image.Height;
                if (aggregate > MaximumTotalImageBytes || aggregatePixels > MaximumTotalImagePixels)
                {
                    aggregate -= imageBytes.Length;
                    aggregatePixels -= (long)image.Width * image.Height;
                    extraction.UndecodedCount++;
                    imageWarnings.Add($"Image on page {image.PageNumber} was skipped: aggregate image display limit reached.");
                    continue;
                }
                extraction.Images.Add(new ExtractedImage
                {
                    MimeType = image.MimeType!,
                    ByteLength = imageBytes.Length,
                    Sha256 = image.Detail,
                    Base64Data = Convert.ToBase64String(imageBytes),
                    ExtractionSource = image.Source,
                    PageNumber = image.PageNumber,
                    Width = image.Width,
                    Height = image.Height,
                    OcrText = image.OcrText ?? string.Empty
                });
            }
            finally
            {
                CryptographicOperations.ZeroMemory(imageBytes);
            }
        }
        if (imageWarnings.Count > 0)
            extraction.Detail = $"{extraction.Detail} {string.Join(" ", imageWarnings.Take(20))}";
        return extraction;
    }

    public void Dispose() => _httpClient.Dispose();

    private sealed record ParserResponse(string ScanResult, string ScanProvider, int PageCount, string Detail, int ImageStreamCount, int UndecodedCount, ParserImage?[]? Images);
    private sealed record ParserReviewResponse(string ScanResult, string ScanProvider, int PageCount, string Detail, PdfPigExtractionResponse Extraction, int ImageStreamCount, int UndecodedImageCount, IReadOnlyList<ParserFormField> Forms);
    private sealed record PdfPigExtractionResponse(string? Content, IReadOnlyList<ParserPage> Pages, ParserImage?[]? Images);
    private sealed record ParserPage(int PageNumber, string Text, string? Source = "PdfPig selectable text", string? OcrText = "", string? SelectableText = null);
    private sealed record ParserFormField(int? PageNumber, string Name, string Type, string Value, string? Bounds);
    private sealed record ParserImage(int PageNumber, int Width, int Height, string? MimeType, string? Base64Data, bool Decoded, string? Detail, string Source = "EmbeddedImageStream", string? OcrText = null);
}

internal class LocalPdfImageExtractionResult
{
    public string ScanResult { get; init; } = "";
    public string ScanProvider { get; init; } = "";
    public string Detail { get; set; } = "";
    public int PageCount { get; init; }
    public int ImageStreamCount { get; init; }
    public int UndecodedCount { get; set; }
    public string TextAndForms { get; init; } = string.Empty;
    public List<ExtractedImage> Images { get; set; } = new();
}

internal sealed class LocalPdfReviewResult : LocalPdfImageExtractionResult
{
    public bool PdfTextVerified { get; set; }
    public string SelectableTextAndForms { get; set; } = string.Empty;
    public string EmbeddedImageOcrText { get; set; } = string.Empty;
    public List<LocalPdfExtractedPage> Pages { get; set; } = new();
    public List<LocalPdfFormField> Forms { get; set; } = new();
}

internal sealed record LocalPdfExtractedPage(int PageNumber, string Text, string Source, string OcrText);
internal sealed record LocalPdfFormField(int? PageNumber, string Name, string Type, string Value, string? Bounds);
