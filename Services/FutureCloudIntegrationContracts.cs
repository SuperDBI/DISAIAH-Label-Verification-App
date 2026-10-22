using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SecRev.Models;

namespace SecRev.Services;

/// <summary>
/// Contract for an approved malware-scanning provider. No provider is registered
/// by the desktop today; current PDF scanning remains in the local parser flow.
/// A future adapter must fail closed unless the provider returns Clean for the
/// exact SHA-256 digest supplied with the request.
/// </summary>
internal interface IUntrustedDocumentScanProvider
{
    string ProviderId { get; }
    Task<DocumentThreatScanOutcome> ScanAsync(
        ReadOnlyMemory<byte> documentBytes,
        string expectedSha256,
        CancellationToken cancellationToken);
}

internal enum DocumentThreatScanVerdict
{
    Unknown = 0,
    Clean = 1,
    ThreatDetected = 2,
    Unavailable = 3,
    Error = 4
}

internal sealed record DocumentThreatScanOutcome(
    string ProviderId,
    DocumentThreatScanVerdict Verdict,
    string ScannedSha256,
    DateTimeOffset CompletedAtUtc,
    string? FindingCategory = null);

/// <summary>
/// Contract for a cloud document assistant. It returns advisory findings only;
/// it cannot modify a vault record, advance workflow state, sign, or decide.
/// Implementations must acquire short-lived Entra tokens through an approved
/// authentication broker and must not accept static tokens in configuration.
/// </summary>
internal interface ICloudDocumentAssistant
{
    string AssistantId { get; }
    Task<CloudDocumentAssistantResult> GetSuggestionsAsync(
        CloudDocumentAssistantRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Data transfer contract intentionally carries extracted text, not source PDF
/// bytes or local keys. The text remains sensitive content and is sent only after
/// explicit per-operation consent and a verified clean scan.
/// </summary>
internal sealed record CloudDocumentAssistantRequest(
    string RecordId,
    string TenantId,
    string ContentSha256,
    string ScanProviderId,
    string ScanResult,
    string ExtractedText,
    DateTimeOffset RequestedAtUtc);

internal sealed record CloudDocumentAssistantResult(
    string AssistantId,
    string ModelVersion,
    DateTimeOffset CompletedAtUtc,
    IReadOnlyList<CloudDocumentSuggestion> Suggestions,
    string Disclaimer);

internal sealed record CloudDocumentSuggestion(
    string Category,
    string Summary,
    string? EvidenceReference,
    double? Confidence);

/// <summary>
/// Central preflight for a future cloud assistant. It is deliberately not wired
/// into the application until Entra auth, consent UI, tenant authorization,
/// transport protection, retention, and audit requirements are implemented.
/// </summary>
internal static class FutureCloudIntegrationPolicy
{
    public const int MaximumAssistantTextCharacters = 500_000;

    public static bool CanRequestAssistantSuggestions(
        VaultAccount? account,
        VaultDocument document,
        bool explicitPerRequestConsent,
        DocumentThreatScanOutcome? scanOutcome,
        string extractedText)
    {
        if (!explicitPerRequestConsent || account is null || !account.IsEnabled ||
            account.Role is not (VaultRole.Analyst or VaultRole.Custodian))
            return false;

        if (document.WorkflowStatus == "InReview")
        {
            if (document.WorkflowStage is not (1 or 2) || account.Role != VaultRole.Analyst)
                return false;
        }
        else if (document.WorkflowStatus == "Submitted")
        {
            if (document.WorkflowStage < 3 || !DocumentWorkflow.VerifyReviewCompletion(document))
                return false;
        }
        else
        {
            // Do not send returned, rejected, approved, duplicate, or incomplete records.
            return false;
        }

        if (string.IsNullOrWhiteSpace(document.ContentSha256) ||
            document.ContentSha256.Length != 64 || string.IsNullOrWhiteSpace(extractedText) ||
            extractedText.Length > MaximumAssistantTextCharacters || scanOutcome is null)
            return false;

        return scanOutcome.Verdict == DocumentThreatScanVerdict.Clean &&
               !string.IsNullOrWhiteSpace(scanOutcome.ProviderId) &&
             string.Equals(scanOutcome.ScannedSha256, document.ContentSha256, StringComparison.OrdinalIgnoreCase);
    }
}
