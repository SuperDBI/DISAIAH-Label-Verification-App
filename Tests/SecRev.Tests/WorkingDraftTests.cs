using System.Security.Cryptography;
using System.Text;
using SecRev.Models;
using SecRev.Services;
using Xunit;

namespace SecRev.Tests;

public sealed class WorkingDraftTests
{
    [Fact]
    public void TimeManagementPrompt_IsAnalystOnlyQueuedAndOneTimeAtFiveMinutes()
    {
        Assert.False(AnalystTimeManagementPolicy.ShouldPrompt(VaultRole.Analyst, "InReview", true, true,
            TimeSpan.FromMinutes(4).Add(TimeSpan.FromSeconds(59)), false));
        Assert.True(AnalystTimeManagementPolicy.ShouldPrompt(VaultRole.Analyst, "InReview", true, true,
            TimeSpan.FromMinutes(5), false));
        Assert.False(AnalystTimeManagementPolicy.ShouldPrompt(VaultRole.Analyst, "InReview", true, true,
            TimeSpan.FromMinutes(8), true));
        Assert.False(AnalystTimeManagementPolicy.ShouldPrompt(VaultRole.Custodian, "InReview", true, true,
            TimeSpan.FromMinutes(8), false));
        Assert.False(AnalystTimeManagementPolicy.ShouldPrompt(VaultRole.Analyst, "InReview", false, true,
            TimeSpan.FromMinutes(8), false));
        Assert.False(AnalystTimeManagementPolicy.ShouldPrompt(VaultRole.Analyst, "Submitted", true, true,
            TimeSpan.FromMinutes(8), false));
    }

    [Fact]
    public void TimeManagementPrompt_UsesCurrentSessionElapsedNotHistoricalRecordTime()
    {
        // ReviewElapsedSeconds may already exceed five minutes when a draft is resumed.
        // The reminder receives only the current in-process Stopwatch duration.
        Assert.False(AnalystTimeManagementPolicy.ShouldPrompt(VaultRole.Analyst, "InReview", true, true,
            TimeSpan.FromSeconds(12), false));
        Assert.True(AnalystTimeManagementPolicy.ShouldPrompt(VaultRole.Analyst, "InReview", true, true,
            TimeSpan.FromMinutes(5), false));
    }

    [Fact]
    public void WorkingDraft_RoundTripsOnlyThroughAuthenticatedEncryption_AndClearsAtStageTwo()
    {
        var document = new VaultDocument { WorkflowStatus = "InReview" };
        var source = Encoding.UTF8.GetBytes("encrypted working draft test source");
        try
        {
            DocumentWorkflow.ImportSource(document, source);
            var draft = new ReviewDraft
            {
                MatchQuery = "sample query",
                AccuracyPercent = 83,
                ReviewNotes = "Working notes not yet submitted",
                ScanCompleted = true,
                ScanFindings = "No configured string signatures found."
            };

            DocumentWorkflow.EncryptWorkingDraft(document, draft);
            Assert.NotEmpty(document.EncryptedWorkingDraft);
            Assert.Empty(document.EncryptedReview);

            document.Draft = new ReviewDraft();
            var restored = DocumentWorkflow.ReadWorkingDraft(document);
            Assert.Equal("sample query", restored.MatchQuery);
            Assert.Equal(83, restored.AccuracyPercent);
            Assert.Equal("Working notes not yet submitted", restored.ReviewNotes);
            Assert.True(restored.ScanCompleted);

            var tampered = document.WorkingDraftTag[0] == 'A' ? 'B' : 'A';
            document.WorkingDraftTag = tampered + document.WorkingDraftTag[1..];
            Assert.ThrowsAny<CryptographicException>(() => DocumentWorkflow.ReadWorkingDraft(document));

            DocumentWorkflow.EncryptWorkingDraft(document, restored);
            DocumentWorkflow.EncryptStageTwo(document, restored);
            Assert.Empty(document.EncryptedWorkingDraft);
            Assert.Empty(document.WorkingDraftNonce);
            Assert.Empty(document.WorkingDraftTag);
            Assert.NotEmpty(document.EncryptedReview);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(source);
        }
    }

    [Fact]
    public void WorkingDraft_SurvivesEncryptedVaultSaveAndReload()
    {
        var directory = Path.Combine(Path.GetTempPath(), "secrev-working-draft-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var vaultPath = Path.Combine(directory, "vault.enc");
        const string passphrase = "Working draft vault test passphrase!";
        var source = Encoding.UTF8.GetBytes("queued Analyst document");
        var document = new VaultDocument { WorkflowStatus = "InReview" };
        try
        {
            DocumentWorkflow.ImportSource(document, source);
            DocumentWorkflow.EncryptWorkingDraft(document, new ReviewDraft
            {
                MatchQuery = "organization",
                AccuracyPercent = 72,
                ReviewNotes = "Unfinished human review notes"
            });

            using (var vault = new EncryptedVault(vaultPath))
            {
                vault.UnlockOrCreate(passphrase);
                vault.Documents.Add(document);
                vault.Save();
            }

            using var reopened = new EncryptedVault(vaultPath);
            reopened.UnlockOrCreate(passphrase);
            var restoredRecord = Assert.Single(reopened.Documents);
            Assert.NotEmpty(restoredRecord.EncryptedWorkingDraft);
            var restoredDraft = DocumentWorkflow.ReadWorkingDraft(restoredRecord);
            Assert.Equal("organization", restoredDraft.MatchQuery);
            Assert.Equal(72, restoredDraft.AccuracyPercent);
            Assert.Equal("Unfinished human review notes", restoredDraft.ReviewNotes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(source);
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }
}
