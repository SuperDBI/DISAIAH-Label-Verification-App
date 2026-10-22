using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Avalonia.Media;

namespace SecRev.Models;

public sealed class VaultDocument
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "";
    public string ImportedAtUtc { get; set; } = DateTimeOffset.UtcNow.ToString("O");
    public int RequiredPriority { get; set; } = 1;
    // Legacy plaintext fields are read only for one-time vault migration. New imports
    // are encrypted before AddDocument can persist them.
    public string Text { get; set; } = "";
    public bool IsPdf { get; set; }
    public bool SourceMaterialDestroyed { get; set; }
    public string PdfPayloadBase64 { get; set; } = "";
    public string PdfSha256 { get; set; } = "";
    public string ContentSha256 { get; set; } = "";
    public string DuplicateOfRecordId { get; set; } = "";
    public string DuplicateResolution { get; set; } = "";
    public string DuplicateResolvedAtUtc { get; set; } = "";
    public string DuplicateResolvedByAccountId { get; set; } = "";
    public string DuplicateResolutionSignature { get; set; } = "";
    public string DuplicateResolutionPublicKey { get; set; } = "";
    public string PdfStaticScanReport { get; set; } = "";
    public bool PdfLooksEncrypted { get; set; }
    public int PdfImageStreamCount { get; set; }
    public string PdfMalwareScanResult { get; set; } = "";
    public string PdfMalwareScanProvider { get; set; } = "";
    // Extraction output is persisted only inside the outer AES-GCM vault envelope.
    public string PdfImageExtractionJson { get; set; } = "";
    public string PdfComparisonReport { get; set; } = "";
    public string PdfSelectableTextAndForms { get; set; } = "";
    public string PdfEmbeddedImageOcrText { get; set; } = "";
    public bool PdfExtractedTextVerified { get; set; }
    public int WordCount { get; set; }
    public int EmailCandidates { get; set; }
    public int NumberGroups { get; set; }

    // Stage 1 protects source text with a random record key. These fields are
    // themselves persisted only inside the vault's authenticated ciphertext.
    public int WorkflowStage { get; set; }
    public string RecordKeyId { get; set; } = "";
    public string RecordKeyMaterial { get; set; } = "";
    public string EncryptedSource { get; set; } = "";
    public string SourceNonce { get; set; } = "";
    public string SourceTag { get; set; } = "";
    public string EncryptedReview { get; set; } = "";
    public string ReviewNonce { get; set; } = "";
    public string ReviewTag { get; set; } = "";
    public string EncryptedWorkingDraft { get; set; } = "";
    public string WorkingDraftNonce { get; set; } = "";
    public string WorkingDraftTag { get; set; } = "";
    public string UserIdentityStamp { get; set; } = "";
    public string IdentityStampUtc { get; set; } = "";
    public string IdentityStampSignature { get; set; } = "";
    public string IdentitySigningPrivateKey { get; set; } = "";
    public string IdentitySigningPublicKey { get; set; } = "";
    public double ReviewElapsedSeconds { get; set; }
    public string ReviewStartedAtUtc { get; set; } = "";
    public string ReviewCompletedAtUtc { get; set; } = "";
    public bool ReviewTimerActive { get; set; }
    public string WorkflowStatus { get; set; } = "";
    public bool IsPermanentlyStored { get; set; }
    public bool IsSavedForLater { get; set; }
    public bool PdfBrandNameVerified { get; set; }
    public bool PdfAlcoholVolumeVerified { get; set; }
    public bool PdfGovernmentWarningVerified { get; set; }
    public bool PdfVisibleVerified { get; set; }
    public bool PdfVisualInspectionConfirmed { get; set; }
    public bool CustodianVisualInspectionConfirmed { get; set; }
    public string PdfMatchQuery { get; set; } = "";
    public int PdfMatchCount { get; set; }
    [JsonIgnore]
    public bool IsSelectedForBulkDelete { get; set; }
    [JsonIgnore]
    public bool CanSelectForBulkDelete { get; set; }
    public string ReviewAnalystAccountId { get; set; } = "";
    public string ReviewAnalystName { get; set; } = "";
    public string EncryptedReviewDigest { get; set; } = "";
    public string ReviewCompletionSignature { get; set; } = "";
    public string ReviewCompletionPublicKey { get; set; } = "";
    public string CustodianDecision { get; set; } = "";
    public string CustodianDecisionNote { get; set; } = "";
    public string CustodianDecisionUtc { get; set; } = "";
    public string CustodianAccountId { get; set; } = "";
    public string CustodianName { get; set; } = "";
    public string CustodianDecisionSignature { get; set; } = "";
    public string CustodianDecisionPublicKey { get; set; } = "";
    public string Stage3SignatureDigest { get; set; } = "";

    [JsonIgnore]
    public IBrush CustodianReviewStatusBrush => WorkflowStatus switch
    {
        "Approved" => Brushes.ForestGreen,
        "Rejected" => Brushes.Firebrick,
        _ => Brushes.Goldenrod
    };

    [JsonIgnore]
    public string CustodianReviewStatusLabel => WorkflowStatus switch
    {
        "Approved" => "Custodian approved",
        "Rejected" => "Custodian rejected",
        "Submitted" => "Awaiting Custodian review",
        "ReturnedForReview" => "Returned to Analyst · decision pending",
        _ => "Analyst-created · not yet Custodian-reviewed"
    };

    [JsonIgnore]
    public ReviewDraft Draft { get; set; } = new();
}

public sealed class ReviewDraft
{
    public bool ScanCompleted { get; set; }
    public int ScanFindingCount { get; set; }
    public string ScanFindings { get; set; } = "Not scanned";
    public bool ImageExtractionCompleted { get; set; }
    public List<ExtractedImage> Images { get; set; } = new();
    public string PdfMalwareScanResult { get; set; } = "";
    public string PdfMalwareScanProvider { get; set; } = "";
    public int PdfImageStreamUndecodedCount { get; set; }
    public string PdfExtractedTextAndForms { get; set; } = "";
    public string PdfSelectableTextAndForms { get; set; } = "";
    public string PdfEmbeddedImageOcrText { get; set; } = "";
    public string PdfComparisonReport { get; set; } = "";
    public bool PdfTextVerified { get; set; }
    public int WordCount { get; set; }
    public int EmailCandidates { get; set; }
    public int NumberGroups { get; set; }
    public string MatchQuery { get; set; } = "";
    public int MatchCount { get; set; }
    public bool TextVerified { get; set; }
    public bool ImagesVerified { get; set; }
    public bool PdfBrandNameVerified { get; set; }
    public bool PdfAlcoholVolumeVerified { get; set; }
    public bool PdfGovernmentWarningVerified { get; set; }
    public bool PdfVisibleVerified { get; set; }
    public bool PdfVisualInspectionConfirmed { get; set; }
    public int AccuracyPercent { get; set; }
    public string ReviewNotes { get; set; } = "";
}

public sealed class ExtractedImage
{
    public string MimeType { get; set; } = "";
    public int ByteLength { get; set; }
    public string Sha256 { get; set; } = "";
    public string Base64Data { get; set; } = "";
    public string ExtractionSource { get; set; } = "EmbeddedImageStream";
    public int PageNumber { get; set; }
    public int Width { get; set; }
    public int Height { get; set; }
    public string OcrText { get; set; } = string.Empty;
    public string ComparisonNotes { get; set; } = string.Empty;
}
