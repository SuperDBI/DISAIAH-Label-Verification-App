using SecRev.Models;
using SecRev.Services;
using Xunit;

namespace SecRev.Tests;

public sealed class FutureIntegrationPolicyTests
{
    private const string Digest = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    [Fact]
    public void CloudAssistantPolicy_RequiresExplicitConsentAndCleanMatchingScan()
    {
        var analyst = new VaultAccount { Role = VaultRole.Analyst, IsEnabled = true };
        var document = new VaultDocument
        {
            ContentSha256 = Digest,
            WorkflowStatus = "InReview",
            WorkflowStage = 1
        };
        var cleanScan = new DocumentThreatScanOutcome("approved-scanner", DocumentThreatScanVerdict.Clean,
            Digest, DateTimeOffset.UtcNow);

        Assert.True(FutureCloudIntegrationPolicy.CanRequestAssistantSuggestions(
            analyst, document, true, cleanScan, "bounded extracted text"));
        Assert.False(FutureCloudIntegrationPolicy.CanRequestAssistantSuggestions(
            analyst, document, false, cleanScan, "bounded extracted text"));
        Assert.False(FutureCloudIntegrationPolicy.CanRequestAssistantSuggestions(
            analyst, document, true, cleanScan with { Verdict = DocumentThreatScanVerdict.Unavailable }, "bounded extracted text"));
        Assert.False(FutureCloudIntegrationPolicy.CanRequestAssistantSuggestions(
            analyst, document, true, cleanScan with { ScannedSha256 = new string('A', 64) }, "bounded extracted text"));
    }

    [Fact]
    public void CloudAssistantPolicy_RejectsFinalOrReturnedRecordsAndOversizedContent()
    {
        var analyst = new VaultAccount { Role = VaultRole.Analyst, IsEnabled = true };
        var scan = new DocumentThreatScanOutcome("approved-scanner", DocumentThreatScanVerdict.Clean,
            Digest, DateTimeOffset.UtcNow);
        var document = new VaultDocument { ContentSha256 = Digest, WorkflowStatus = "ReturnedForReview", WorkflowStage = 4 };

        Assert.False(FutureCloudIntegrationPolicy.CanRequestAssistantSuggestions(analyst, document, true, scan, "text"));
        document.WorkflowStatus = "Approved";
        Assert.False(FutureCloudIntegrationPolicy.CanRequestAssistantSuggestions(analyst, document, true, scan, "text"));

        document.WorkflowStatus = "InReview";
        document.WorkflowStage = 1;
        Assert.False(FutureCloudIntegrationPolicy.CanRequestAssistantSuggestions(analyst, document, true, scan,
            new string('x', FutureCloudIntegrationPolicy.MaximumAssistantTextCharacters + 1)));
    }
}
