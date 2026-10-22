using Azure;
using Azure.AI.DocumentIntelligence;
using Azure.Messaging.ServiceBus;
using Azure.Search.Documents;
using Azure.Search.Documents.Models;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Identity;
using Microsoft.Azure.Cosmos;
using Microsoft.Extensions.Options;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.Configure<PipelineOptions>(builder.Configuration.GetSection("Pipeline"));
builder.Services.AddSingleton<DefaultAzureCredential>();
builder.Services.AddHttpClient<IPdfSandboxClient, PdfSandboxClient>(client => client.Timeout = TimeSpan.FromMinutes(2));
builder.Services.AddSingleton(sp => new DocumentIntelligenceClient(
    new Uri(sp.GetRequiredService<IOptions<PipelineOptions>>().Value.DocumentIntelligenceEndpoint),
    sp.GetRequiredService<DefaultAzureCredential>()));
builder.Services.AddSingleton<IDocumentExtractionProvider, AzureDocumentIntelligenceProvider>();
builder.Services.AddTransient<IDocumentExtractionProvider, PdfPigComparisonProvider>();
builder.Services.AddSingleton<ScanResultGate>();
builder.Services.AddHostedService<ScanResultWorker>();
await builder.Build().RunAsync();

internal sealed class PipelineOptions
{
    public string StorageAccountUrl { get; set; } = "";
    public string QuarantineContainer { get; set; } = "quarantine";
    public string ProcessedContainer { get; set; } = "processed";
    public string ServiceBusNamespace { get; set; } = "";
    public string ServiceBusQueue { get; set; } = "pdf-scan-results";
    public string DocumentIntelligenceEndpoint { get; set; } = "";
    public string SearchEndpoint { get; set; } = "";
    public string SearchIndex { get; set; } = "pdf-records";
    public string PdfSandboxEndpoint { get; set; } = "";
    public string PdfSandboxToken { get; set; } = "";
    public int MaxExtractedTextCharacters { get; set; } = 500_000;
    public string CosmosEndpoint { get; set; } = "";
    public string CosmosDatabase { get; set; } = "secrev";
    public string CosmosContainer { get; set; } = "documents";
    public int MaxPdfBytes { get; set; } = 25 * 1024 * 1024;
    public int MaxPages { get; set; } = 100;
    public int MaxPreviewWidth { get; set; } = 1600;
    public int MaxPreviewHeight { get; set; } = 2400;
}

internal sealed class ScanResultWorker(
    IOptions<PipelineOptions> options,
    DefaultAzureCredential credential,
    IPdfSandboxClient pdfSandbox,
    IEnumerable<IDocumentExtractionProvider> extractionProviders,
    ScanResultGate gate,
    ILogger<ScanResultWorker> logger) : BackgroundService
{
    private readonly PipelineOptions _options = options.Value;
    private ServiceBusClient? _bus;
    private ServiceBusProcessor? _processor;
    private BlobServiceClient? _blobs;
    private SearchClient? _search;
    private Container? _cosmos;
    private readonly IDocumentExtractionProvider _primaryExtraction = extractionProviders.Single(provider => provider.ProviderName == AzureDocumentIntelligenceProvider.ProviderId);
    private readonly IDocumentExtractionProvider _comparisonExtraction = extractionProviders.Single(provider => provider.ProviderName == PdfPigComparisonProvider.ProviderId);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        ValidateConfiguration(_options);
        _blobs = new BlobServiceClient(new Uri(_options.StorageAccountUrl), credential);
        _bus = new ServiceBusClient(_options.ServiceBusNamespace, credential);
        _processor = _bus.CreateProcessor(_options.ServiceBusQueue, new ServiceBusProcessorOptions
        {
            AutoCompleteMessages = false,
            MaxConcurrentCalls = 1,
            MaxAutoLockRenewalDuration = TimeSpan.FromMinutes(15)
        });
        _search = new SearchClient(new Uri(_options.SearchEndpoint), _options.SearchIndex, credential);
        var cosmosClient = new CosmosClient(_options.CosmosEndpoint, credential);
        _cosmos = cosmosClient.GetContainer(_options.CosmosDatabase, _options.CosmosContainer);

        _processor.ProcessMessageAsync += HandleMessageAsync;
        _processor.ProcessErrorAsync += args =>
        {
            logger.LogError(args.Exception, "PDF scan-result queue error from {Namespace}/{Entity}", args.FullyQualifiedNamespace, args.EntityPath);
            return Task.CompletedTask;
        };

        await _processor.StartProcessingAsync(stoppingToken);
        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            await _processor.StopProcessingAsync(CancellationToken.None);
        }
    }

    private async Task HandleMessageAsync(ProcessMessageEventArgs args)
    {
        var message = args.Message;
        try
        {
            using var json = JsonDocument.Parse(message.Body.ToMemory());
            var root = json.RootElement.ValueKind == JsonValueKind.Array
                ? json.RootElement.EnumerateArray().FirstOrDefault()
                : json.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !gate.TryReadScanResult(root, _options.QuarantineContainer, out var scan))
            {
                await args.DeadLetterMessageAsync(message, "InvalidScanResultEvent", "Event did not match the expected Defender scan result schema or quarantine path.", args.CancellationToken);
                return;
            }

            if (!string.Equals(scan.Result, "No threats found", StringComparison.Ordinal))
            {
                var blockedStatus = string.Equals(scan.Result, "Malicious", StringComparison.Ordinal)
                    ? "QuarantinedMalicious"
                    : "QuarantinedScanUnavailable";
                await _cosmos!.PatchItemAsync<object>(
                    scan.DocumentId,
                    new PartitionKey(scan.TenantId),
                    new[]
                    {
                        PatchOperation.Set("/Status", blockedStatus),
                        PatchOperation.Set("/ScanResult", scan.Result),
                        PatchOperation.Set("/ScanFinishedUtc", scan.ScanFinishedUtc)
                    },
                    cancellationToken: args.CancellationToken);
                logger.LogWarning("PDF remains quarantined with scan result {ScanResult}; document {DocumentId}", scan.Result, scan.DocumentId);
                await args.CompleteMessageAsync(message);
                return;
            }

            var blobClient = GetAuthorizedQuarantineBlob(scan.BlobUri);
            var properties = await blobClient.GetPropertiesAsync(cancellationToken: args.CancellationToken);
            if (!string.Equals(properties.Value.ETag.ToString(), scan.ETag, StringComparison.Ordinal))
            {
                logger.LogWarning("Scan result ETag no longer matches blob; refusing stale event {CorrelationId}", scan.CorrelationId);
                await args.CompleteMessageAsync(message);
                return;
            }

            if (properties.Value.ContentLength <= 0 || properties.Value.ContentLength > _options.MaxPdfBytes)
            {
                throw new InvalidDataException("PDF size is outside the worker's configured limit.");
            }

            var tempPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.pdf");
            try
            {
                await DownloadBoundedAsync(blobClient, tempPath, _options.MaxPdfBytes, args.CancellationToken);
                var bytes = await File.ReadAllBytesAsync(tempPath, args.CancellationToken);
                try
                {
                    var sha = Convert.ToHexString(SHA256.HashData(bytes));
                    if (!string.Equals(sha, scan.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException("Downloaded content hash did not match the Defender result.");
                    }

                    PdfSandboxPreview inspection;
                    try
                    {
                        inspection = await pdfSandbox.RenderFirstPageAsync(bytes, args.CancellationToken);
                    }
                    catch (InvalidDataException ex)
                    {
                        logger.LogWarning("Isolated preview unavailable for document {DocumentId}: {Reason}", scan.DocumentId, ex.Message);
                        inspection = new PdfSandboxPreview(0, Array.Empty<byte>());
                    }
                    var analysis = await _primaryExtraction.ExtractAsync(bytes, args.CancellationToken);
                    PdfExtractionComparisonSummary comparisonSummary;
                    IReadOnlyList<ExtractedPdfImage> pdfPigImages = Array.Empty<ExtractedPdfImage>();
                    try
                    {
                        var comparison = await _comparisonExtraction.ExtractAsync(bytes, args.CancellationToken);
                        pdfPigImages = comparison.Images;
                        comparisonSummary = PdfExtractionComparison.Compare(analysis, comparison);
                    }
                    catch (Exception ex) when (ex is InvalidDataException or HttpRequestException or JsonException ||
                                              ex is TaskCanceledException && !args.CancellationToken.IsCancellationRequested)
                    {
                        logger.LogWarning("PdfPig comparison was unavailable for document {DocumentId} ({ExceptionType}); primary extraction continues", scan.DocumentId, ex.GetType().Name);
                        comparisonSummary = PdfExtractionComparisonSummary.Unavailable(ex.GetType().Name);
                    }
                    var processedContainer = _blobs!.GetBlobContainerClient(_options.ProcessedContainer);
                    var previewBlob = processedContainer.GetBlobClient($"{scan.TenantId}/{scan.DocumentId}/page-1.png");
                    if (inspection.Png.Length > 0)
                    {
                        try
                        {
                            await using var previewStream = new MemoryStream(inspection.Png, writable: false);
                            await previewBlob.UploadAsync(previewStream, overwrite: true, args.CancellationToken);
                            await previewBlob.SetHttpHeadersAsync(new BlobHttpHeaders { ContentType = "image/png" }, cancellationToken: args.CancellationToken);
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(inspection.Png);
                        }
                    }

                    var textBlob = processedContainer.GetBlobClient($"{scan.TenantId}/{scan.DocumentId}/extracted.txt");
                    var textBytes = System.Text.Encoding.UTF8.GetBytes(analysis.Content);
                    try
                    {
                        await using var textStream = new MemoryStream(textBytes, writable: false);
                        await textBlob.UploadAsync(textStream, overwrite: true, args.CancellationToken);
                        await textBlob.SetHttpHeadersAsync(new BlobHttpHeaders { ContentType = "text/plain; charset=utf-8" }, cancellationToken: args.CancellationToken);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(textBytes);
                    }

                    var structuredBytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new ExtractionArtifact(analysis, comparisonSummary, pdfPigImages));
                    var structuredBlob = processedContainer.GetBlobClient($"{scan.TenantId}/{scan.DocumentId}/extraction.json");
                    try
                    {
                        await using var structuredStream = new MemoryStream(structuredBytes, writable: false);
                        await structuredBlob.UploadAsync(structuredStream, overwrite: true, args.CancellationToken);
                        await structuredBlob.SetHttpHeadersAsync(new BlobHttpHeaders { ContentType = "application/json" }, cancellationToken: args.CancellationToken);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(structuredBytes);
                    }

                    var processedAt = DateTimeOffset.UtcNow;
                    var extractedText = analysis.Content;
                    await _cosmos!.PatchItemAsync<object>(
                        scan.DocumentId,
                        new PartitionKey(scan.TenantId),
                        new[]
                        {
                            PatchOperation.Set("/Status", "ProcessedNeedsHumanReview"),
                            PatchOperation.Set("/ProcessedAtUtc", processedAt),
                            PatchOperation.Set("/Sha256", sha),
                            PatchOperation.Set("/ScanResult", scan.Result),
                            PatchOperation.Set("/ScanFinishedUtc", scan.ScanFinishedUtc),
                            PatchOperation.Set("/PdfiumPageCount", inspection.PageCount),
                            PatchOperation.Set("/PreviewBlobUri", inspection.Png.Length == 0 ? null : previewBlob.Uri.ToString()),
                            PatchOperation.Set("/ExtractedTextBlobUri", textBlob.Uri.ToString()),
                            PatchOperation.Set("/StructuredExtractionBlobUri", structuredBlob.Uri.ToString()),
                            PatchOperation.Set("/ExtractedText", extractedText[..Math.Min(extractedText.Length, 500_000)]),
                            PatchOperation.Set("/ModelId", analysis.ModelId),
                            PatchOperation.Set("/ExtractionProvider", analysis.ProviderName),
                            PatchOperation.Set("/PdfPigComparison", comparisonSummary)
                        },
                        cancellationToken: args.CancellationToken);
                    var searchRecord = new SearchDocument
                    {
                        ["id"] = scan.DocumentId,
                        ["tenantId"] = scan.TenantId,
                        ["fileName"] = Path.GetFileName(new Uri(scan.BlobUri).AbsolutePath),
                        ["content"] = extractedText[..Math.Min(extractedText.Length, 500_000)],
                        ["status"] = "ProcessedNeedsHumanReview",
                        ["sha256"] = sha
                    };
                    var searchResponse = await _search!.MergeOrUploadDocumentsAsync(new[] { searchRecord }, cancellationToken: args.CancellationToken);
                    if (searchResponse.Value.Results.Any(result => !result.Succeeded))
                    {
                        throw new InvalidOperationException("Azure AI Search rejected the indexed document.");
                    }
                    logger.LogInformation("PDF processed for tenant {TenantId}; page count {PageCount}; document ID {DocumentId}", scan.TenantId, inspection.PageCount, scan.DocumentId);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }
            finally
            {
                try { File.Delete(tempPath); } catch (IOException ex) { logger.LogWarning(ex, "Could not remove worker temp file"); }
            }

            await args.CompleteMessageAsync(message);
        }
        catch (HttpRequestException ex)
        {
            logger.LogWarning(ex, "Transient internal sandbox connection failure; allowing queue retry for message {MessageId}", message.MessageId);
            await args.AbandonMessageAsync(message, cancellationToken: args.CancellationToken);
        }
        catch (TaskCanceledException ex) when (!args.CancellationToken.IsCancellationRequested)
        {
            logger.LogWarning(ex, "Internal sandbox timeout; allowing queue retry for message {MessageId}", message.MessageId);
            await args.AbandonMessageAsync(message, cancellationToken: args.CancellationToken);
        }
        catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            // Defender can publish the scan event before the upload API finishes creating its status row.
            logger.LogWarning(ex, "Upload status record is not visible yet; allowing queue retry for message {MessageId}", message.MessageId);
            await args.AbandonMessageAsync(message, cancellationToken: args.CancellationToken);
        }
        catch (RequestFailedException ex) when (ex.Status == 408 || ex.Status == 429 || ex.Status >= 500)
        {
            logger.LogWarning(ex, "Transient Azure dependency failure; allowing queue retry for message {MessageId}", message.MessageId);
            await args.AbandonMessageAsync(message, cancellationToken: args.CancellationToken);
        }
        catch (Exception ex) when (ex is InvalidDataException or UnauthorizedAccessException or IOException or RequestFailedException or JsonException or FormatException)
        {
            logger.LogError(ex, "PDF processing rejected/failed for scan event {MessageId}; content excluded from logs", message.MessageId);
            await args.DeadLetterMessageAsync(message, "PdfProcessingFailed", "Processing failed validation or an upstream dependency; investigate the job logs.", args.CancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unexpected PDF worker failure for message {MessageId}; content excluded from logs", message.MessageId);
            await args.AbandonMessageAsync(message, cancellationToken: args.CancellationToken);
        }
    }

    private BlobClient GetAuthorizedQuarantineBlob(string blobUri)
    {
        if (!Uri.TryCreate(blobUri, UriKind.Absolute, out var uri) || !string.Equals(uri.Host, new Uri(_options.StorageAccountUrl).Host, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Scan event points to an unexpected storage account.");
        }
        var parts = Uri.UnescapeDataString(uri.AbsolutePath).Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3 || !string.Equals(parts[0], _options.QuarantineContainer, StringComparison.Ordinal) || !Guid.TryParseExact(parts[1], "N", out _) || !Guid.TryParseExact(Path.GetFileNameWithoutExtension(parts[2]), "N", out _))
        {
            throw new InvalidDataException("Scan event does not name an allowed quarantine PDF blob.");
        }
        return _blobs!.GetBlobContainerClient(_options.QuarantineContainer).GetBlobClient(string.Join('/', parts.Skip(1)));
    }

    private static async Task DownloadBoundedAsync(BlobClient blob, string path, int limit, CancellationToken cancellationToken)
    {
        var download = await blob.DownloadStreamingAsync(new BlobDownloadOptions
        {
            Conditions = new BlobRequestConditions { IfMatch = (await blob.GetPropertiesAsync(cancellationToken: cancellationToken)).Value.ETag }
        }, cancellationToken);
        await using var source = download.Value.Content;
        await using var destination = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var buffer = new byte[64 * 1024];
        var total = 0;
        while (true)
        {
            var read = await source.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (read == 0) break;
            total = checked(total + read);
            if (total > limit) throw new InvalidDataException("PDF exceeded the configured download limit.");
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
        CryptographicOperations.ZeroMemory(buffer);
    }

    private static void ValidateConfiguration(PipelineOptions value)
    {
        if (!Uri.TryCreate(value.StorageAccountUrl, UriKind.Absolute, out _) ||
            !Uri.TryCreate(value.DocumentIntelligenceEndpoint, UriKind.Absolute, out _) ||
            !Uri.TryCreate(value.SearchEndpoint, UriKind.Absolute, out _) ||
            !Uri.TryCreate(value.CosmosEndpoint, UriKind.Absolute, out _) ||
            !Uri.TryCreate(value.PdfSandboxEndpoint, UriKind.Absolute, out _) ||
            string.IsNullOrWhiteSpace(value.ServiceBusNamespace) || value.PdfSandboxToken.Length < 32 || value.MaxPdfBytes is <= 0 or > 50 * 1024 * 1024 ||
            value.MaxExtractedTextCharacters is <= 0 or > 2_000_000 ||
            value.MaxPages is <= 0 or > 200 || value.MaxPreviewWidth is <= 0 or > 2400 || value.MaxPreviewHeight is <= 0 or > 3600)
        {
            throw new InvalidOperationException("Required Azure endpoints or safe worker limits are missing/invalid.");
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_processor is not null) await _processor.DisposeAsync();
        if (_bus is not null) await _bus.DisposeAsync();
        await base.StopAsync(cancellationToken);
    }
}

internal sealed class ScanResultGate
{
    public bool TryReadScanResult(JsonElement root, string quarantineContainer, out CleanScanResult result)
    {
        result = default!;
        if (!root.TryGetProperty("eventType", out var eventType) || eventType.GetString() != "Microsoft.Security.MalwareScanningResult" ||
            !root.TryGetProperty("data", out var data) ||
            !ReadString(data, "scanResultType", out var scanStatus) ||
            !ReadString(data, "blobUri", out var uri) || !ReadString(data, "eTag", out var etag) ||
            !ReadString(data, "scanFinishedTimeUtc", out var finished))
        {
            return false;
        }

        var sha = string.Empty;
        if (string.Equals(scanStatus, "No threats found", StringComparison.Ordinal))
        {
            if (!data.TryGetProperty("scanResultDetails", out var details) || !ReadString(details, "sha256", out sha) || sha.Length != 64 || !sha.All(Uri.IsHexDigit))
                return false;
        }

        var pathSegments = Uri.UnescapeDataString(new Uri(uri).AbsolutePath).Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (pathSegments.Length != 3 || !string.Equals(pathSegments[0], quarantineContainer, StringComparison.Ordinal) || !Guid.TryParseExact(pathSegments[1], "N", out var tenantId) || !Guid.TryParseExact(Path.GetFileNameWithoutExtension(pathSegments[2]), "N", out var documentId)) return false;

        var subject = root.TryGetProperty("subject", out var subjectElement) ? subjectElement.GetString() ?? string.Empty : string.Empty;
        var expectedSubjectSuffix = $"/containers/{quarantineContainer}/blobs/{tenantId:N}/{documentId:N}.pdf";
        if (!subject.EndsWith(expectedSubjectSuffix, StringComparison.Ordinal)) return false;
        var correlationId = root.TryGetProperty("id", out var eventIdElement) && eventIdElement.ValueKind == JsonValueKind.String
            ? eventIdElement.GetString() ?? ""
            : "";
        if (correlationId.Length == 0) return false;
        result = new CleanScanResult(documentId.ToString("N"), tenantId.ToString("N"), correlationId, uri, etag, sha, scanStatus, DateTimeOffset.Parse(finished, System.Globalization.CultureInfo.InvariantCulture));
        return true;
    }

    private static bool ReadString(JsonElement element, string name, out string value)
    {
        value = string.Empty;
        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String) return false;
        value = property.GetString() ?? string.Empty;
        return value.Length > 0;
    }
}

internal sealed record CleanScanResult(string DocumentId, string TenantId, string CorrelationId, string BlobUri, string ETag, string Sha256, string Result, DateTimeOffset ScanFinishedUtc);

internal sealed class ProcessedPdfRecord
{
    public required string Id { get; init; }
    public required string PartitionKey { get; init; }
    public required string TenantId { get; init; }
    public required string Status { get; init; }
    public required string OriginalBlobUri { get; init; }
    public required string ETag { get; init; }
    public required string Sha256 { get; init; }
    public required string ScanResult { get; init; }
    public DateTimeOffset ScanFinishedUtc { get; init; }
    public int PdfiumPageCount { get; init; }
    public string? PreviewBlobUri { get; init; }
    public required string ExtractedTextBlobUri { get; init; }
    public required string ExtractedText { get; init; }
    public required string ModelId { get; init; }
    public DateTimeOffset ProcessedUtc { get; init; }
}

internal sealed record PdfSandboxPreview(int PageCount, byte[] Png);
internal interface IPdfSandboxClient
{
    Task<PdfSandboxPreview> RenderFirstPageAsync(byte[] bytes, CancellationToken cancellationToken);
    Task<DocumentExtractionResult> ExtractTextWithPdfPigAsync(byte[] bytes, CancellationToken cancellationToken);
}

internal sealed class PdfSandboxClient(HttpClient httpClient, IOptions<PipelineOptions> options, ILogger<PdfSandboxClient> logger) : IPdfSandboxClient
{
    private const int MaximumPngBytes = 10 * 1024 * 1024;
    private static readonly System.Text.Json.JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public async Task<PdfSandboxPreview> RenderFirstPageAsync(byte[] bytes, CancellationToken cancellationToken)
    {
        var endpoint = new Uri(new Uri(options.Value.PdfSandboxEndpoint.TrimEnd('/') + "/"), "internal/render-first-page");
        using var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pdf");
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = content };
        request.Headers.TryAddWithoutValidation("X-SecRev-Sandbox-Token", options.Value.PdfSandboxToken);
        using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            logger.LogWarning("PDF sandbox declined file with HTTP status {Status}; content excluded from logs", (int)response.StatusCode);
            throw new InvalidDataException("The isolated PDF sandbox rejected or could not render this file.");
        }

        if (!response.Headers.TryGetValues("X-PDF-Page-Count", out var values) ||
            !int.TryParse(values.FirstOrDefault(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var pageCount) ||
            pageCount is <= 0 or > 100)
        {
            throw new InvalidDataException("PDF sandbox returned invalid page-count metadata.");
        }

        await using var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = new byte[32 * 1024];
        try
        {
            while (true)
            {
                var read = await responseStream.ReadAsync(buffer.AsMemory(), cancellationToken);
                if (read == 0) break;
                if (output.Length + read > MaximumPngBytes) throw new InvalidDataException("PDF sandbox preview response exceeded the output limit.");
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
            return new PdfSandboxPreview(pageCount, output.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public async Task<DocumentExtractionResult> ExtractTextWithPdfPigAsync(byte[] bytes, CancellationToken cancellationToken)
    {
        const int maximumJsonResponseBytes = 16 * 1024 * 1024;
        var endpoint = new Uri(new Uri(options.Value.PdfSandboxEndpoint.TrimEnd('/') + "/"), "internal/extract-text-pdfpig");
        using var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pdf");
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = content };
        request.Headers.TryAddWithoutValidation("X-SecRev-Sandbox-Token", options.Value.PdfSandboxToken);
        using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            logger.LogWarning("PdfPig comparison service declined file with HTTP status {Status}; content excluded from logs", (int)response.StatusCode);
            if (response.StatusCode is System.Net.HttpStatusCode.InternalServerError or System.Net.HttpStatusCode.ServiceUnavailable or System.Net.HttpStatusCode.GatewayTimeout)
                throw new HttpRequestException("PdfPig comparison service is temporarily unavailable.", null, response.StatusCode);
            throw new InvalidDataException("The isolated PdfPig comparison service rejected this file.");
        }

        if (response.Content.Headers.ContentLength is > maximumJsonResponseBytes)
            throw new InvalidDataException("PdfPig comparison response exceeded the configured byte limit.");
        await using var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var responseBuffer = new MemoryStream();
        var responseChunk = new byte[32 * 1024];
        try
        {
            while (true)
            {
                var read = await responseStream.ReadAsync(responseChunk.AsMemory(), cancellationToken);
                if (read == 0) break;
                if (responseBuffer.Length + read > maximumJsonResponseBytes)
                    throw new InvalidDataException("PdfPig comparison response exceeded the configured byte limit.");
                await responseBuffer.WriteAsync(responseChunk.AsMemory(0, read), cancellationToken);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(responseChunk);
        }
        PdfPigExtractionResponse result;
        try
        {
            result = System.Text.Json.JsonSerializer.Deserialize<PdfPigExtractionResponse>(responseBuffer.ToArray(), JsonOptions)
                ?? throw new InvalidDataException("PdfPig comparison service returned an empty response.");
        }
        catch (System.Text.Json.JsonException ex)
        {
            throw new InvalidDataException("PdfPig comparison service returned invalid data.", ex);
        }
        if (result.Pages is null || result.Images is null || result.Content is null)
            throw new InvalidDataException("PdfPig comparison service returned incomplete data.");
        var extractedCharacters = result.Pages.Sum(page => page is null || page.Text is null ? 0 : (long)page.Text.Length);
        var extractedImageBytes = 0L;
        if (result.Pages.Count is <= 0 or > 100 || result.PageCount != result.Pages.Count ||
            result.Content.Length > options.Value.MaxExtractedTextCharacters || extractedCharacters > options.Value.MaxExtractedTextCharacters ||
            result.Pages.Any(page => page is null || page.Text is null || page.PageNumber <= 0 || page.Text.Length > options.Value.MaxExtractedTextCharacters) ||
            result.Images.Count > 20 || result.Images.Any(image => image is null || image.PageNumber <= 0 || image.Width is <= 0 or > 4096 || image.Height is <= 0 or > 4096 || image.Base64Data is null || image.Detail is null))
        {
            throw new InvalidDataException("PdfPig comparison response exceeded configured output limits.");
        }

        foreach (var image in result.Images.Where(image => image is not null && image.Decoded))
        {
            var encodedLimit = 4 * ((2 * 1024 * 1024 + 2) / 3);
            if (!string.Equals(image.MimeType, "image/png", StringComparison.Ordinal) || image.Base64Data.Length > encodedLimit ||
                image.Detail.Length != 64 || !image.Detail.All(Uri.IsHexDigit))
                throw new InvalidDataException("PdfPig image output exceeded the configured per-image limit.");
            byte[] png;
            try { png = Convert.FromBase64String(image.Base64Data); }
            catch (FormatException ex) { throw new InvalidDataException("PdfPig returned invalid image encoding.", ex); }
            try
            {
                if (png.Length is <= 0 or > 2 * 1024 * 1024 || png.Length < 8 ||
                    !png.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }) ||
                    !string.Equals(Convert.ToHexString(SHA256.HashData(png)), image.Detail, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("PdfPig image bytes failed size, signature, or digest validation.");
                extractedImageBytes += png.Length;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(png);
            }
        }
        if (extractedImageBytes > 6 * 1024 * 1024)
            throw new InvalidDataException("PdfPig image output exceeded the configured aggregate limit.");

        return new DocumentExtractionResult(PdfPigComparisonProvider.ProviderId, "PdfPig 0.1.16", result.Content, result.Pages, null, result.Images);
    }
}
