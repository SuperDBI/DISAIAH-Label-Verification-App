using SecRev.Models;

namespace SecRev.Services;

/// <summary>
/// Centralized eligibility rules for Analyst and Custodian workflow actions.
/// These rules improve consistency and testability; they are local client policy,
/// not an independent authorization boundary.
/// </summary>
internal static class WorkflowEligibility
{
    public static bool CanAddToQueue(VaultAccount? account, VaultDocument document)
    {
        if (account is null || !account.IsEnabled || document.WorkflowStatus == "DuplicateConfirmed")
            return false;

        return account.Role switch
        {
            VaultRole.Analyst => (document.WorkflowStatus is "InReview" or "ReturnedForReview") &&
                                 (document.DuplicateResolution != "PendingCustodianReview" || document.WorkflowStatus == "InReview"),
            VaultRole.Custodian => CanCustodianReviewSubmission(account, document),
            _ => false
        };
    }

    public static bool CanCustodianReviewSubmission(VaultAccount? account, VaultDocument document) =>
        account is { IsEnabled: true, Role: VaultRole.Custodian } &&
        document.WorkflowStatus == "Submitted" && document.WorkflowStage >= 3 &&
        document.DuplicateResolution != "PendingCustodianReview" &&
        DocumentWorkflow.VerifyReviewCompletion(document);

    public static bool CanCustodianReviewSubmission(VaultAccount? account, VaultDocument document, bool isAccessible) =>
        isAccessible && CanCustodianReviewSubmission(account, document);

    public static bool CanCustodianDecide(VaultAccount? account, VaultDocument document, bool isQueued) =>
        isQueued && CanCustodianReviewSubmission(account, document);

    public static bool IsCustodianDecisionReady(VaultAccount? account, VaultDocument document, bool isQueued) =>
        CanCustodianDecide(account, document, isQueued) &&
        (!document.IsPdf || (document.Draft.ImageExtractionCompleted &&
                             IsAnalystPdfAttestationComplete(document) &&
                             document.CustodianVisualInspectionConfirmed));

    public static bool IsAnalystPdfAttestationComplete(VaultDocument document) =>
        document.Draft.PdfBrandNameVerified &&
        document.Draft.PdfAlcoholVolumeVerified &&
        document.Draft.PdfGovernmentWarningVerified &&
        document.Draft.PdfVisibleVerified &&
        document.Draft.PdfVisualInspectionConfirmed;

    public static bool IsFinalDecision(string? status) => status is "Approved" or "Rejected";

    public static bool IsPermanentlyStoredRecord(VaultDocument document) =>
        document.WorkflowStatus switch
        {
            "Approved" or "Rejected" => document.WorkflowStage >= 4 && document.IsPermanentlyStored &&
                                          DocumentWorkflow.VerifyReviewCompletion(document) &&
                                          DocumentWorkflow.VerifyCustodianDecision(document),
            "DuplicateConfirmed" => document.WorkflowStage >= 4 && document.IsPermanentlyStored &&
                                    DocumentWorkflow.VerifyDuplicateResolution(document),
            _ => false
        };
}