using Azure.AI.DocumentIntelligence;
using Azure;
using Microsoft.Extensions.Options;
using System.Text.Json;

internal interface IDocumentExtractionProvider
{
    string ProviderName { get; }
    Task<DocumentExtractionResult> ExtractAsync(byte[] pdfBytes, CancellationToken cancellationToken);
}

internal sealed class AzureDocumentIntelligenceProvider(
    DocumentIntelligenceClient client,
    IOptions<PipelineOptions> options) : IDocumentExtractionProvider
{
    public const string ProviderId = "Azure.AI.DocumentIntelligence";
    public string ProviderName => ProviderId;

    public async Task<DocumentExtractionResult> ExtractAsync(byte[] pdfBytes, CancellationToken cancellationToken)
    {
        var response = await client.AnalyzeDocumentAsync(
            WaitUntil.Completed,
            "prebuilt-layout",
            BinaryData.FromBytes(pdfBytes),
            cancellationToken: cancellationToken);
        var result = response.Value;
        var content = result.Content ?? string.Empty;
        var pageTextLength = result.Pages.Sum(page => page.Lines.Sum(line => (long)line.Content.Length));
        if (content.Length > options.Value.MaxExtractedTextCharacters || pageTextLength > options.Value.MaxExtractedTextCharacters ||
            result.Pages.Count > options.Value.MaxPages)
        {
            throw new InvalidDataException("Azure Document Intelligence extraction exceeded configured output limits.");
        }

        var pages = result.Pages.Select(page => new ExtractionPage(
            page.PageNumber,
            string.Join("\n", page.Lines.Select(line => line.Content)))).ToArray();
        var paragraphs = result.Paragraphs.Select(paragraph => new ExtractedParagraphSnapshot(paragraph.Content, paragraph.Role?.ToString())).ToArray();
        var tables = result.Tables.Select(table => new ExtractedTableSnapshot(
            table.RowCount,
            table.ColumnCount,
            table.Cells.Select(cell => new ExtractedTableCellSnapshot(cell.RowIndex, cell.ColumnIndex, cell.Kind?.ToString(), cell.Content)).ToArray())).ToArray();
        var documents = result.Documents.Select(document => new ExtractedDocumentSnapshot(
            document.DocumentType,
            document.Confidence,
            document.Fields.ToDictionary(
                field => field.Key,
                field => new ExtractedFieldSnapshot(field.Value.FieldType.ToString(), field.Value.Content, field.Value.Confidence),
                StringComparer.Ordinal))).ToArray();
        var structured = new AzureExtractionSnapshot(
            result.ModelId,
            content,
            result.Pages.Select(page => new AzurePageSnapshot(
                page.PageNumber,
                page.Width,
                page.Height,
                page.Unit?.ToString(),
                page.Lines.Select(line => new ExtractedLineSnapshot(line.Content, line.Polygon.ToArray())).ToArray(),
                page.SelectionMarks.Select(mark => new ExtractedSelectionMarkSnapshot(mark.State.ToString(), mark.Confidence, mark.Polygon.ToArray())).ToArray())).ToArray(),
            paragraphs,
            tables,
            documents);

        return new DocumentExtractionResult(ProviderId, result.ModelId, content, pages, structured, Array.Empty<ExtractedPdfImage>());
    }
}

internal sealed class PdfPigComparisonProvider(IPdfSandboxClient sandbox) : IDocumentExtractionProvider
{
    public const string ProviderId = "PdfPig";
    public string ProviderName => ProviderId;

    public Task<DocumentExtractionResult> ExtractAsync(byte[] pdfBytes, CancellationToken cancellationToken) =>
        sandbox.ExtractTextWithPdfPigAsync(pdfBytes, cancellationToken);
}

internal sealed record DocumentExtractionResult(
    string ProviderName,
    string ModelId,
    string Content,
    IReadOnlyList<ExtractionPage> Pages,
    object? ProviderData,
    IReadOnlyList<ExtractedPdfImage> Images);
internal sealed record ExtractionPage(int PageNumber, string Text);
internal sealed record PdfPigExtractionResponse(int PageCount, string Content, IReadOnlyList<ExtractionPage> Pages, IReadOnlyList<ExtractedPdfImage> Images);
internal sealed record ExtractedPdfImage(int PageNumber, int Width, int Height, string MimeType, string Base64Data, bool Decoded, string Detail);
internal sealed record ExtractionArtifact(DocumentExtractionResult Primary, PdfExtractionComparisonSummary PdfPigComparison, IReadOnlyList<ExtractedPdfImage> PdfPigImages);
internal sealed record PdfExtractionComparisonSummary(
    bool Available,
    string? FailureCategory,
    string Interpretation,
    int PrimaryPageCount,
    int ComparisonPageCount,
    int MatchingPageCount,
    IReadOnlyList<int> DifferingPageNumbers,
    int PrimaryCharacterCount,
    int ComparisonCharacterCount,
    bool NormalizedTextMatches)
{
    public static PdfExtractionComparisonSummary Unavailable(string failureCategory) => new(
        false, failureCategory, "PdfPig comparison unavailable; primary extraction was retained.",
        0, 0, 0, Array.Empty<int>(), 0, 0, false);
}

internal static class PdfExtractionComparison
{
    public static PdfExtractionComparisonSummary Compare(DocumentExtractionResult primary, DocumentExtractionResult comparison)
    {
        var primaryPages = primary.Pages.ToDictionary(page => page.PageNumber, page => Normalize(page.Text));
        var comparisonPages = comparison.Pages.ToDictionary(page => page.PageNumber, page => Normalize(page.Text));
        var pageNumbers = primaryPages.Keys.Union(comparisonPages.Keys).Order().ToArray();
        var differingPages = pageNumbers
            .Where(page => !primaryPages.TryGetValue(page, out var first) ||
                           !comparisonPages.TryGetValue(page, out var second) ||
                           !string.Equals(first, second, StringComparison.Ordinal))
            .ToArray();
        var matchingPages = pageNumbers.Length - differingPages.Length;
        var primaryText = Normalize(primary.Content);
        var comparisonText = Normalize(comparison.Content);
        var noText = primaryText.Length == 0 && comparisonText.Length == 0;
        return new PdfExtractionComparisonSummary(
            true,
            null,
            noText ? "No extractable text returned by either engine; OCR may be required." : "Diagnostic comparison only; differences are not a safety or accuracy verdict.",
            primary.Pages.Count,
            comparison.Pages.Count,
            matchingPages,
            differingPages,
            primaryText.Length,
            comparisonText.Length,
            string.Equals(primaryText, comparisonText, StringComparison.Ordinal));
    }

    private static string Normalize(string text) =>
        string.Join(' ', text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).ToUpperInvariant();
}

internal sealed record AzureExtractionSnapshot(
    string ModelId,
    string Content,
    IReadOnlyList<AzurePageSnapshot> Pages,
    IReadOnlyList<ExtractedParagraphSnapshot> Paragraphs,
    IReadOnlyList<ExtractedTableSnapshot> Tables,
    IReadOnlyList<ExtractedDocumentSnapshot> Documents);
internal sealed record AzurePageSnapshot(int PageNumber, float? Width, float? Height, string? Unit, IReadOnlyList<ExtractedLineSnapshot> Lines, IReadOnlyList<ExtractedSelectionMarkSnapshot> SelectionMarks);
internal sealed record ExtractedLineSnapshot(string Content, IReadOnlyList<float> Polygon);
internal sealed record ExtractedSelectionMarkSnapshot(string State, float? Confidence, IReadOnlyList<float> Polygon);
internal sealed record ExtractedParagraphSnapshot(string Content, string? Role);
internal sealed record ExtractedTableSnapshot(int RowCount, int ColumnCount, IReadOnlyList<ExtractedTableCellSnapshot> Cells);
internal sealed record ExtractedTableCellSnapshot(int RowIndex, int ColumnIndex, string? Kind, string Content);
internal sealed record ExtractedDocumentSnapshot(string? DocumentType, float? Confidence, IReadOnlyDictionary<string, ExtractedFieldSnapshot> Fields);
internal sealed record ExtractedFieldSnapshot(string Type, string? Content, float? Confidence);
