using System.Security.Cryptography;
using System.Text;
using SecRev.Models;
using SecRev.Services;
using Xunit;

namespace SecRev.Tests;

public sealed class WorkflowSecurityTests
{
    [Theory]
    [InlineData("Approved", true)]
    [InlineData("Rejected", true)]
    [InlineData("ReturnedForReview", false)]
    public void CustodianDecision_SignsOutcome_AndOnlyFinalDecisionsArePermanent(string decision, bool permanent)
    {
        var (document, analyst, custodian) = CreateSubmittedRecord();

        DocumentWorkflow.ApplyCustodianDecision(document, decision, "Reviewed and documented decision", custodian);

        Assert.Equal(4, document.WorkflowStage);
        Assert.Equal(decision, document.WorkflowStatus);
        Assert.Equal(permanent, document.IsPermanentlyStored);
        Assert.True(DocumentWorkflow.VerifyReviewCompletion(document));
        Assert.True(DocumentWorkflow.VerifyCustodianDecision(document));
        Assert.Equal(permanent, WorkflowEligibility.IsPermanentlyStoredRecord(document));
    }

    [Fact]
    public void StageThreeSubmission_RequiresAndVerifiesAnalystSignature()
    {
        var (document, analyst, _) = CreateStageTwoRecord();

        DocumentWorkflow.SubmitReview(document, analyst);

        Assert.Equal(3, document.WorkflowStage);
        Assert.Equal("Submitted", document.WorkflowStatus);
        Assert.False(document.IsPermanentlyStored);
        Assert.True(DocumentWorkflow.VerifyReviewCompletion(document));

        document.ReviewAnalystName = "tampered name";
        Assert.False(DocumentWorkflow.VerifyReviewCompletion(document));
    }

    [Fact]
    public void CustodianDecisionSignature_CoversDecisionAndNote()
    {
        var (document, _, custodian) = CreateSubmittedRecord();
        DocumentWorkflow.ApplyCustodianDecision(document, "Approved", "Evidence reviewed and approved", custodian);
        Assert.True(DocumentWorkflow.VerifyCustodianDecision(document));

        document.CustodianDecisionNote = "Changed after signing";
        Assert.False(DocumentWorkflow.VerifyCustodianDecision(document));
    }

    [Fact]
    public void ReturnedRecord_RemainsNonPermanentAndQueueableAfterVaultReload()
    {
        var (document, analyst, custodian) = CreateSubmittedRecord();
        DocumentWorkflow.ApplyCustodianDecision(document, "ReturnedForReview", "Please correct the record", custodian);
        Assert.False(document.IsPermanentlyStored);
        Assert.True(WorkflowEligibility.CanAddToQueue(analyst, document));

        var directory = Path.Combine(Path.GetTempPath(), "secrev-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var vaultPath = Path.Combine(directory, "vault.enc");
        const string passphrase = "A test-only passphrase 123!";
        try
        {
            using (var vault = new EncryptedVault(vaultPath))
            {
                vault.UnlockOrCreate(passphrase);
                vault.Documents.Add(document);
                vault.Save();
            }

            using var reopened = new EncryptedVault(vaultPath);
            reopened.UnlockOrCreate(passphrase);
            var restored = Assert.Single(reopened.Documents);

            Assert.Equal("ReturnedForReview", restored.WorkflowStatus);
            Assert.Equal(4, restored.WorkflowStage);
            Assert.False(restored.IsPermanentlyStored);
            Assert.True(DocumentWorkflow.VerifyReviewCompletion(restored));
            Assert.True(DocumentWorkflow.VerifyCustodianDecision(restored));
            Assert.True(WorkflowEligibility.CanAddToQueue(analyst, restored));
            Assert.False(WorkflowEligibility.IsPermanentlyStoredRecord(restored));
            Assert.Throws<InvalidOperationException>(() => VaultRecordTransfer.ExportOriginalSource(restored));

            var returnedDraft = DocumentWorkflow.ReadReview(restored);
            returnedDraft.ReviewNotes = "Corrected per Custodian feedback";
            DocumentWorkflow.EncryptStageTwo(restored, returnedDraft);
            DocumentWorkflow.SubmitReview(restored, analyst);
            Assert.Equal("Submitted", restored.WorkflowStatus);
            Assert.Equal(3, restored.WorkflowStage);
            Assert.False(restored.IsPermanentlyStored);
            Assert.True(DocumentWorkflow.VerifyReviewCompletion(restored));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Theory]
    [InlineData("Approved")]
    [InlineData("Rejected")]
    public void FinalCustodianDecision_RemainsPermanentAndExportableAfterVaultReload(string decision)
    {
        var (document, _, custodian) = CreateSubmittedRecord();
        DocumentWorkflow.ApplyCustodianDecision(document, decision, "Final signed decision note", custodian);
        Assert.True(document.IsPermanentlyStored);

        var directory = Path.Combine(Path.GetTempPath(), "secrev-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var vaultPath = Path.Combine(directory, "vault.enc");
        const string passphrase = "A test-only passphrase 123!";
        try
        {
            using (var vault = new EncryptedVault(vaultPath))
            {
                vault.UnlockOrCreate(passphrase);
                vault.Documents.Add(document);
                vault.Save();
            }

            using var reopened = new EncryptedVault(vaultPath);
            reopened.UnlockOrCreate(passphrase);
            var restored = Assert.Single(reopened.Documents);

            Assert.Equal(decision, restored.WorkflowStatus);
            Assert.True(restored.IsPermanentlyStored);
            Assert.True(WorkflowEligibility.IsPermanentlyStoredRecord(restored));
            var exportedSource = VaultRecordTransfer.ExportOriginalSource(restored);
            try { Assert.Equal("sample review source document", Encoding.UTF8.GetString(exportedSource)); }
            finally { CryptographicOperations.ZeroMemory(exportedSource); }
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void CustodianEligibility_RequiresSubmittedValidSignatureAndQueueMembershipForDecision()
    {
        var (document, _, custodian) = CreateSubmittedRecord();

        Assert.True(WorkflowEligibility.CanCustodianReviewSubmission(custodian, document));
        Assert.False(WorkflowEligibility.CanCustodianDecide(custodian, document, isQueued: false));
        Assert.True(WorkflowEligibility.CanCustodianDecide(custodian, document, isQueued: true));
        Assert.True(WorkflowEligibility.IsCustodianDecisionReady(custodian, document, isQueued: true));

        document.ReviewAnalystName = "tampered";
        Assert.False(WorkflowEligibility.CanCustodianReviewSubmission(custodian, document));
    }

    [Fact]
    public void PdfCustodianDecisionRequiresCustodianAttestationAndAnalystAttestations()
    {
        var (document, analyst, custodian) = CreateSubmittedRecord(isPdf: true);
        document.Draft.ImageExtractionCompleted = true;
        document.Draft.PdfBrandNameVerified = true;
        document.Draft.PdfAlcoholVolumeVerified = true;
        document.Draft.PdfGovernmentWarningVerified = true;
        document.Draft.PdfVisibleVerified = true;
        document.Draft.PdfVisualInspectionConfirmed = true;

        Assert.True(WorkflowEligibility.CanCustodianReviewSubmission(custodian, document));
        Assert.False(WorkflowEligibility.IsCustodianDecisionReady(custodian, document, isQueued: true));
        document.CustodianVisualInspectionConfirmed = true;
        Assert.True(WorkflowEligibility.IsCustodianDecisionReady(custodian, document, isQueued: true));

        document.Draft.PdfVisibleVerified = false;
        Assert.False(WorkflowEligibility.IsCustodianDecisionReady(custodian, document, isQueued: true));
        Assert.False(WorkflowEligibility.CanAddToQueue(analyst, document));
    }

    private static (VaultDocument Document, VaultAccount Analyst, VaultAccount Custodian) CreateSubmittedRecord(bool isPdf = false)
    {
        var (document, analyst, custodian) = CreateStageTwoRecord(isPdf);
        DocumentWorkflow.SubmitReview(document, analyst);
        return (document, analyst, custodian);
    }

    private static (VaultDocument Document, VaultAccount Analyst, VaultAccount Custodian) CreateStageTwoRecord(bool isPdf = false)
    {
        var analyst = new VaultAccount { Name = "test-analyst", Role = VaultRole.Analyst, IsEnabled = true };
        var custodian = new VaultAccount { Name = "test-custodian", Role = VaultRole.Custodian, IsEnabled = true };
        var source = Encoding.UTF8.GetBytes("sample review source document");
        var document = new VaultDocument
        {
            IsPdf = isPdf,
            WorkflowStatus = "InReview"
        };
        DocumentWorkflow.ImportSource(document, source);
        CryptographicOperations.ZeroMemory(source);
        var draft = new ReviewDraft
        {
            ScanCompleted = true,
            ImageExtractionCompleted = true,
            MatchQuery = "sample",
            AccuracyPercent = 95,
            ReviewNotes = "Reviewed sample source"
        };
        DocumentWorkflow.EncryptStageTwo(document, draft);
        return (document, analyst, custodian);
    }
}
