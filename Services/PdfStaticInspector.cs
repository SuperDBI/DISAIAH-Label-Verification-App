using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SecRev.Services;

internal static class PdfStaticInspector
{
    public const int MaxPdfBytes = 25 * 1024 * 1024;
    private static readonly (string Name, string Token)[] Indicators =
    {
        ("JavaScript action", "/JavaScript"),
        ("JavaScript name", "/JS"),
        ("automatic open action", "/OpenAction"),
        ("additional action", "/AA"),
        ("launch action", "/Launch"),
        ("embedded file", "/EmbeddedFile"),
        ("rich media", "/RichMedia"),
        ("remote navigation action", "/GoToR"),
        ("form submission action", "/SubmitForm"),
        ("XFA form data", "/XFA"),
        ("AcroForm dictionary", "/AcroForm"),
        ("encryption dictionary reference", "/Encrypt"),
        ("compressed object stream", "/ObjStm")
    };

    public static PdfInspection Inspect(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0 || bytes.Length > MaxPdfBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(bytes), $"PDF size must be between 1 byte and {MaxPdfBytes / (1024 * 1024)} MiB.");
        }

        var hasHeader = bytes.Length >= 8 && bytes[..5].SequenceEqual("%PDF-"u8);
        var decoded = Encoding.Latin1.GetString(bytes);
        var hasEof = decoded.AsSpan(Math.Max(0, decoded.Length - 2048)).Contains("%%EOF", StringComparison.Ordinal);
        var findings = new List<string>();
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var (name, token) in Indicators)
        {
            var count = Regex.Matches(decoded, Regex.Escape(token), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)).Count;
            counts[token] = count;
            if (count > 0 && token != "/AcroForm" && token != "/ObjStm")
            {
                findings.Add($"{name} ({count})");
            }
        }

        var pageObjects = Regex.Matches(decoded, @"/Type\s*/Page(?!s)\b", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)).Count;
        var encrypted = counts["/Encrypt"] > 0;
        var riskMarkerCategories = findings.Count;
        var report = new StringBuilder()
            .AppendLine("STATIC PDF INSPECTION — NOT AN ANTIVIRUS RESULT")
            .AppendLine($"Size: {bytes.Length:N0} bytes")
            .AppendLine($"SHA-256: {Convert.ToHexString(SHA256.HashData(bytes))}")
            .AppendLine($"PDF header: {(hasHeader ? "present" : "not found at byte 0")}")
            .AppendLine($"EOF marker near end: {(hasEof ? "present" : "not found")}")
            .AppendLine($"Raw page object markers: {pageObjects} (may undercount compressed/encrypted PDFs)")
            .AppendLine($"AcroForm marker: {(counts["/AcroForm"] > 0 ? "present" : "not found")}")
            .AppendLine($"Encryption marker: {(encrypted ? "present; contents may not be readable without a password" : "not found in raw bytes")}")
            .AppendLine($"Configured risk-marker categories present: {riskMarkerCategories}")
            .AppendLine()
            .AppendLine("Indicators are byte-string heuristics only. Compressed, encoded, encrypted, or obfuscated content can be missed; normal PDFs may contain benign action markers.")
            .AppendLine("No Defender/antivirus engine or isolated PDF renderer is configured. The file was not opened, rendered, or executed.")
            .AppendLine()
            .AppendLine("Detected indicators:");

        if (findings.Count == 0)
        {
            report.AppendLine("None of the configured raw-byte indicators were detected. This is not a clean bill of health.");
        }
        else
        {
            foreach (var finding in findings) report.AppendLine("• " + finding);
        }

        return new PdfInspection(
            Convert.ToHexString(SHA256.HashData(bytes)),
            encrypted,
            hasHeader,
            hasEof,
            riskMarkerCategories,
            pageObjects,
            counts["/AcroForm"] > 0,
            report.ToString());
    }
}

internal sealed record PdfInspection(
    string Sha256,
    bool LooksEncrypted,
    bool HasPdfHeader,
    bool HasEofMarker,
    int RiskMarkerCategoryCount,
    int RawPageMarkerCount,
    bool HasAcroFormMarker,
    string Report);
