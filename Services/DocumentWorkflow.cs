using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecRev.Models;

namespace SecRev.Services;

internal static class DocumentWorkflow
{
    private const int MaxExtractedImages = 20;
    private const int MaxImageBytes = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new();
    private static readonly Regex DataImagePattern = new(
        @"data:image/(png|jpeg|jpg|gif|webp);base64,([A-Za-z0-9+/=\r\n]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    public static void EncryptStageOne(VaultDocument document)
    {
        if (document.WorkflowStage != 0 || (document.IsPdf ? string.IsNullOrEmpty(document.PdfPayloadBase64) : string.IsNullOrEmpty(document.Text)))
            throw new InvalidOperationException("Stage 1 requires an imported, unencrypted source document.");

        var plaintext = ReadSourceBytes(document);
        try { EncryptSource(document, plaintext); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public static void ImportSource(VaultDocument document, byte[] originalBytes)
    {
        if (originalBytes.Length == 0)
            throw new ArgumentException("The imported source cannot be empty.", nameof(originalBytes));
        document.ContentSha256 = Convert.ToHexString(SHA256.HashData(originalBytes));
        if (document.IsPdf) document.PdfSha256 = document.ContentSha256;
        EncryptSource(document, originalBytes);
    }

    public static bool MigrateLegacySource(VaultDocument document)
    {
        if (document.WorkflowStage != 0 || (string.IsNullOrEmpty(document.Text) && string.IsNullOrEmpty(document.PdfPayloadBase64)))
            return false;
        var plaintext = ReadSourceBytes(document);
        try
        {
            if (string.IsNullOrEmpty(document.ContentSha256))
                document.ContentSha256 = Convert.ToHexString(SHA256.HashData(plaintext));
            if (document.IsPdf && string.IsNullOrEmpty(document.PdfSha256))
                document.PdfSha256 = document.ContentSha256;
            EncryptSource(document, plaintext);
            return true;
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public static bool EnsureContentHash(VaultDocument document)
    {
        if (!string.IsNullOrEmpty(document.ContentSha256)) return false;
        if (!string.IsNullOrEmpty(document.PdfSha256))
        {
            document.ContentSha256 = document.PdfSha256;
            return true;
        }
        if (document.SourceMaterialDestroyed || string.IsNullOrEmpty(document.EncryptedSource)) return false;
        var plaintext = ReadSourceBytes(document);
        try
        {
            document.ContentSha256 = Convert.ToHexString(SHA256.HashData(plaintext));
            return true;
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static void EncryptSource(VaultDocument document, byte[] plaintext)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        try
        {
            using var aes = new AesGcm(key, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(document.Id + ":source:v1"));
            document.RecordKeyMaterial = Convert.ToBase64String(key);
            document.RecordKeyId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            document.EncryptedSource = Convert.ToBase64String(ciphertext);
            document.SourceNonce = Convert.ToBase64String(nonce);
            document.SourceTag = Convert.ToBase64String(tag);
            document.Text = string.Empty;
            document.PdfPayloadBase64 = string.Empty;
            document.SourceMaterialDestroyed = false;
            document.WorkflowStage = 1;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public static string ReadSourceText(VaultDocument document)
    {
        if (document.IsPdf)
        {
            throw new InvalidOperationException("PDF source bytes are not text; use a PDF parser or isolated preview service.");
        }
        var plaintext = ReadSourceBytes(document);
        try
        {
            return new UTF8Encoding(false, true).GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public static byte[] ReadSourceBytes(VaultDocument document)
    {
        if (document.SourceMaterialDestroyed)
        {
            throw new InvalidOperationException("The imported source was removed after processing. Re-import it to process the original again.");
        }
        if (document.WorkflowStage == 0)
        {
            return document.IsPdf
                ? Convert.FromBase64String(document.PdfPayloadBase64)
                : Encoding.UTF8.GetBytes(document.Text);
        }
        if (string.IsNullOrEmpty(document.RecordKeyMaterial) || string.IsNullOrEmpty(document.EncryptedSource))
        {
            throw new InvalidDataException("The encrypted source record is incomplete.");
        }

        var key = Convert.FromBase64String(document.RecordKeyMaterial);
        var nonce = Convert.FromBase64String(document.SourceNonce);
        var tag = Convert.FromBase64String(document.SourceTag);
        var ciphertext = Convert.FromBase64String(document.EncryptedSource);
        var plaintext = new byte[ciphertext.Length];
        try
        {
            if (key.Length != 32 || nonce.Length != 12 || tag.Length != 16)
            {
                throw new InvalidDataException("The encrypted source record has invalid cryptographic parameters.");
            }
            using var aes = new AesGcm(key, tag.Length);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, Encoding.UTF8.GetBytes(document.Id + ":source:v1"));
            return plaintext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public static void EncryptStageTwo(VaultDocument document, ReviewDraft draft)
    {
        var isReturnedDraft = document.WorkflowStage >= 3 &&
                      document.WorkflowStatus == "ReturnedForReview" &&
                      !string.IsNullOrEmpty(document.EncryptedReview);
        var isResumedDraft = document.WorkflowStage >= 3 &&
                     document.WorkflowStatus == "InReview" &&
                     !string.IsNullOrEmpty(document.EncryptedReview);
        if (document.WorkflowStage != 1 && !isReturnedDraft && !isResumedDraft)
        {
            throw new InvalidOperationException("Stage 2 requires completed source processing and a validated review draft.");
        }

        if (string.IsNullOrEmpty(document.RecordKeyMaterial))
        {
            document.RecordKeyMaterial = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            document.RecordKeyId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        }

        var recordKey = Convert.FromBase64String(document.RecordKeyMaterial);
        var key = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            recordKey,
            32,
            Encoding.UTF8.GetBytes(document.Id),
            Encoding.UTF8.GetBytes("SecRev.Stage2.Review.AES-256-GCM.v1"));
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(draft, JsonOptions);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        try
        {
            using var aes = new AesGcm(key, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(document.Id + ":review:v1"));
            document.EncryptedReview = Convert.ToBase64String(ciphertext);
            document.ReviewNonce = Convert.ToBase64String(nonce);
            document.ReviewTag = Convert.ToBase64String(tag);
            document.EncryptedWorkingDraft = string.Empty;
            document.WorkingDraftNonce = string.Empty;
            document.WorkingDraftTag = string.Empty;
            document.Draft = draft;
            if (isReturnedDraft)
                document.WorkflowStatus = "InReview";
            if (document.IsPdf)
            {
                document.PdfImageExtractionJson = string.Empty;
            }
            document.WorkflowStage = 2;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recordKey);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public static void EncryptWorkingDraft(VaultDocument document, ReviewDraft draft)
    {
        if (document.WorkflowStatus != "InReview" || document.WorkflowStage < 1 || string.IsNullOrEmpty(document.RecordKeyMaterial))
            throw new InvalidOperationException("Only an active, source-encrypted review can save working progress.");

        var recordKey = Convert.FromBase64String(document.RecordKeyMaterial);
        var key = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            recordKey,
            32,
            Encoding.UTF8.GetBytes(document.Id),
            Encoding.UTF8.GetBytes("SecRev.WorkingDraft.AES-256-GCM.v1"));
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(draft, JsonOptions);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        try
        {
            using var aes = new AesGcm(key, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(document.Id + ":working-draft:v1"));
            document.EncryptedWorkingDraft = Convert.ToBase64String(ciphertext);
            document.WorkingDraftNonce = Convert.ToBase64String(nonce);
            document.WorkingDraftTag = Convert.ToBase64String(tag);
            document.Draft = draft;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recordKey);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public static ReviewDraft ReadWorkingDraft(VaultDocument document)
    {
        if (string.IsNullOrEmpty(document.EncryptedWorkingDraft))
            return document.Draft;
        if (string.IsNullOrEmpty(document.RecordKeyMaterial))
            throw new InvalidDataException("The encrypted working draft has no record key.");

        var recordKey = Convert.FromBase64String(document.RecordKeyMaterial);
        var key = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            recordKey,
            32,
            Encoding.UTF8.GetBytes(document.Id),
            Encoding.UTF8.GetBytes("SecRev.WorkingDraft.AES-256-GCM.v1"));
        var nonce = Convert.FromBase64String(document.WorkingDraftNonce);
        var tag = Convert.FromBase64String(document.WorkingDraftTag);
        var ciphertext = Convert.FromBase64String(document.EncryptedWorkingDraft);
        var plaintext = new byte[ciphertext.Length];
        try
        {
            if (key.Length != 32 || nonce.Length != 12 || tag.Length != 16)
                throw new InvalidDataException("The encrypted working draft has invalid cryptographic parameters.");
            using var aes = new AesGcm(key, tag.Length);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, Encoding.UTF8.GetBytes(document.Id + ":working-draft:v1"));
            return JsonSerializer.Deserialize<ReviewDraft>(plaintext, JsonOptions)
                ?? throw new InvalidDataException("The encrypted working draft could not be decoded.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recordKey);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public static void SubmitReview(VaultDocument document, VaultAccount analyst)
    {
        if (analyst.Role != VaultRole.Analyst || !analyst.IsEnabled)
            throw new UnauthorizedAccessException("Only an active Analyst can submit a review.");
        var returnedDraft = document.WorkflowStatus == "InReview" && document.WorkflowStage >= 3 &&
                            !string.IsNullOrEmpty(document.EncryptedReview);
        if (document.WorkflowStatus != "InReview" || (document.WorkflowStage != 2 && !returnedDraft) || string.IsNullOrEmpty(document.EncryptedReview))
            throw new InvalidOperationException("Stage 3 submission requires a completed Stage 2 review encryption step.");
        document.CustodianDecision = string.Empty;
        document.CustodianDecisionNote = string.Empty;
        document.CustodianDecisionUtc = string.Empty;
        document.CustodianAccountId = string.Empty;
        document.CustodianName = string.Empty;
        document.CustodianDecisionSignature = string.Empty;
        document.CustodianDecisionPublicKey = string.Empty;
        document.CustodianVisualInspectionConfirmed = false;
        document.ReviewCompletedAtUtc = DateTimeOffset.UtcNow.ToString("O");
        document.ReviewAnalystAccountId = analyst.Id;
        document.ReviewAnalystName = analyst.Name;
        document.EncryptedReviewDigest = ComputeEncryptedReviewDigest(document);
        var payload = ReviewCompletionPayload(document);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        try
        {
            document.ReviewCompletionSignature = Convert.ToBase64String(signer.SignData(payload, HashAlgorithmName.SHA384));
            document.ReviewCompletionPublicKey = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo());
            document.Stage3SignatureDigest = Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(document.ReviewCompletionSignature)));
            document.WorkflowStatus = "Submitted";
            document.WorkflowStage = 3;
            document.IsPermanentlyStored = false;
            document.ReviewTimerActive = false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    public static bool VerifyReviewCompletion(VaultDocument document)
    {
        if (string.IsNullOrEmpty(document.ReviewCompletionSignature) ||
            string.IsNullOrEmpty(document.ReviewCompletionPublicKey) ||
            string.IsNullOrEmpty(document.EncryptedReviewDigest)) return false;
        byte[] payload;
        try
        {
            if (!string.Equals(document.EncryptedReviewDigest, ComputeEncryptedReviewDigest(document), StringComparison.Ordinal)) return false;
            payload = ReviewCompletionPayload(document);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException or InvalidOperationException) { return false; }
        byte[]? publicKey = null;
        byte[]? signature = null;
        try
        {
            publicKey = Convert.FromBase64String(document.ReviewCompletionPublicKey);
            signature = Convert.FromBase64String(document.ReviewCompletionSignature);
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
            return bytesRead == publicKey.Length && verifier.KeySize == 384 &&
                   verifier.VerifyData(payload, signature, HashAlgorithmName.SHA384);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            if (publicKey is not null) CryptographicOperations.ZeroMemory(publicKey);
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
        }
    }

    public static void ApplyCustodianDecision(VaultDocument document, string decision, string note, VaultAccount custodian)
    {
        if (document.WorkflowStatus != "Submitted" || document.WorkflowStage < 3 || !VerifyReviewCompletion(document))
            throw new InvalidOperationException("A custodian decision requires a valid Stage 3 Analyst submission.");
        if (document.DuplicateResolution == "PendingCustodianReview")
            throw new InvalidOperationException("Resolve the duplicate candidate before making the final record decision.");
        if (decision is not ("Approved" or "Rejected" or "ReturnedForReview"))
            throw new ArgumentException("Choose Approve, Reject, or Return for further review.", nameof(decision));
        if (string.IsNullOrWhiteSpace(note) || note.Trim().Length < 5 || note.Trim().Length > 4000)
            throw new ArgumentException("Enter a decision note of 5 to 4,000 characters.", nameof(note));
        if (custodian.Role != VaultRole.Custodian || !custodian.IsEnabled)
            throw new UnauthorizedAccessException("An active Custodian is required for this decision.");
        if (document.IsPdf && !document.CustodianVisualInspectionConfirmed)
            throw new InvalidOperationException("The Custodian must confirm visual inspection of the PDF before signing a Stage 4 decision.");

        var timestamp = DateTimeOffset.UtcNow.ToString("O");
        var normalizedNote = note.Trim();
        var stage3Digest = Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(document.ReviewCompletionSignature)));
        var payload = DecisionPayload(document.Id, decision, normalizedNote, timestamp, custodian.Id, custodian.Name,
            stage3Digest, document.CustodianVisualInspectionConfirmed);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        try
        {
            document.CustodianDecision = decision;
            document.CustodianDecisionNote = normalizedNote;
            document.CustodianDecisionUtc = timestamp;
            document.CustodianAccountId = custodian.Id;
            document.CustodianName = custodian.Name;
            document.CustodianDecisionSignature = Convert.ToBase64String(signer.SignData(payload, HashAlgorithmName.SHA384));
            document.CustodianDecisionPublicKey = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo());
            document.Stage3SignatureDigest = stage3Digest;
            document.WorkflowStatus = decision;
            document.WorkflowStage = 4;
            document.IsPermanentlyStored = decision is "Approved" or "Rejected";
            document.ReviewTimerActive = false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    public static bool VerifyCustodianDecision(VaultDocument document)
    {
        if (string.IsNullOrEmpty(document.CustodianDecisionSignature) || string.IsNullOrEmpty(document.CustodianDecisionPublicKey))
            return false;
        if (document.WorkflowStage < 4 || !VerifyReviewCompletion(document)) return false;
        var stage3Digest = string.Empty;
        byte[] payload;
        try
        {
            stage3Digest = Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(document.ReviewCompletionSignature)));
            if (!string.Equals(stage3Digest, document.Stage3SignatureDigest, StringComparison.Ordinal)) return false;
            payload = DecisionPayload(document.Id, document.CustodianDecision, document.CustodianDecisionNote,
                document.CustodianDecisionUtc, document.CustodianAccountId, document.CustodianName, stage3Digest,
                document.CustodianVisualInspectionConfirmed);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or CryptographicException) { return false; }
        byte[]? publicKey = null;
        byte[]? signature = null;
        try
        {
            publicKey = Convert.FromBase64String(document.CustodianDecisionPublicKey);
            signature = Convert.FromBase64String(document.CustodianDecisionSignature);
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
            if (bytesRead != publicKey.Length || verifier.KeySize != 384) return false;
            if (verifier.VerifyData(payload, signature, HashAlgorithmName.SHA384)) return true;
            if (document.CustodianVisualInspectionConfirmed) return false;

            // Existing records were signed before the Custodian visual-attestation
            // field was added to the Stage 4 decision payload.
            var legacyPayload = LegacyDecisionPayload(document.Id, document.CustodianDecision, document.CustodianDecisionNote,
                document.CustodianDecisionUtc, document.CustodianAccountId, document.CustodianName, stage3Digest);
            try { return verifier.VerifyData(legacyPayload, signature, HashAlgorithmName.SHA384); }
            finally { CryptographicOperations.ZeroMemory(legacyPayload); }
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            if (publicKey is not null) CryptographicOperations.ZeroMemory(publicKey);
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static string ComputeEncryptedReviewDigest(VaultDocument document)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(document.Id + ":review:v1"));
        hash.AppendData(Convert.FromBase64String(document.ReviewNonce));
        hash.AppendData(Convert.FromBase64String(document.ReviewTag));
        hash.AppendData(Convert.FromBase64String(document.EncryptedReview));
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static byte[] ReviewCompletionPayload(VaultDocument document) =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            recordId = document.Id,
            analystAccountId = document.ReviewAnalystAccountId,
            analystName = document.ReviewAnalystName,
            completedAtUtc = document.ReviewCompletedAtUtc,
            encryptedReviewSha256 = document.EncryptedReviewDigest,
            elapsedSeconds = document.ReviewElapsedSeconds
        }, JsonOptions);

    private static byte[] DecisionPayload(string recordId, string decision, string note, string timestamp, string accountId, string accountName,
        string stage3SignatureDigest, bool custodianVisualInspectionConfirmed) =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            recordId,
            decision,
            note,
            decidedAtUtc = timestamp,
            custodianAccountId = accountId,
            custodianName = accountName,
            stage3SignatureDigest,
            custodianVisualInspectionConfirmed
        }, JsonOptions);

    private static byte[] LegacyDecisionPayload(string recordId, string decision, string note, string timestamp, string accountId,
        string accountName, string stage3SignatureDigest) =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            recordId,
            decision,
            note,
            decidedAtUtc = timestamp,
            custodianAccountId = accountId,
            custodianName = accountName,
            stage3SignatureDigest
        }, JsonOptions);

    public static void ResolveDuplicate(VaultDocument document, string resolution, VaultAccount custodian)
    {
        if (document.DuplicateResolution != "PendingCustodianReview" || string.IsNullOrWhiteSpace(document.DuplicateOfRecordId) ||
            document.WorkflowStatus != "Submitted" || document.WorkflowStage < 3 || !VerifyReviewCompletion(document))
            throw new InvalidOperationException("A duplicate can be resolved only after Analyst submission has a valid Stage 3 signature.");
        if (resolution is not ("ConfirmedDuplicate" or "NotDuplicate"))
            throw new ArgumentException("Choose Confirm duplicate or Mark not duplicate.", nameof(resolution));
        if (custodian.Role != VaultRole.Custodian || !custodian.IsEnabled)
            throw new UnauthorizedAccessException("An active Custodian is required to resolve duplicates.");

        var timestamp = DateTimeOffset.UtcNow.ToString("O");
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            recordId = document.Id,
            duplicateOfRecordId = document.DuplicateOfRecordId,
            contentSha256 = document.ContentSha256,
            resolution,
            resolvedAtUtc = timestamp,
            custodianAccountId = custodian.Id
        }, JsonOptions);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        try
        {
            document.DuplicateResolution = resolution;
            document.DuplicateResolvedAtUtc = timestamp;
            document.DuplicateResolvedByAccountId = custodian.Id;
            document.DuplicateResolutionSignature = Convert.ToBase64String(signer.SignData(payload, HashAlgorithmName.SHA384));
            document.DuplicateResolutionPublicKey = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo());
            if (resolution == "ConfirmedDuplicate")
            {
                document.WorkflowStatus = "DuplicateConfirmed";
                document.WorkflowStage = 4;
                document.IsPermanentlyStored = true;
            }
        }
        finally { CryptographicOperations.ZeroMemory(payload); }
    }

    public static bool VerifyDuplicateResolution(VaultDocument document)
    {
        if (string.IsNullOrEmpty(document.DuplicateResolutionSignature) ||
            string.IsNullOrEmpty(document.DuplicateResolutionPublicKey) ||
            string.IsNullOrEmpty(document.DuplicateResolvedByAccountId) ||
            string.IsNullOrEmpty(document.DuplicateResolvedAtUtc))
            return false;

        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            recordId = document.Id,
            duplicateOfRecordId = document.DuplicateOfRecordId,
            contentSha256 = document.ContentSha256,
            resolution = document.DuplicateResolution,
            resolvedAtUtc = document.DuplicateResolvedAtUtc,
            custodianAccountId = document.DuplicateResolvedByAccountId
        }, JsonOptions);
        byte[]? publicKey = null;
        byte[]? signature = null;
        try
        {
            publicKey = Convert.FromBase64String(document.DuplicateResolutionPublicKey);
            signature = Convert.FromBase64String(document.DuplicateResolutionSignature);
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
            return bytesRead == publicKey.Length && verifier.KeySize == 384 &&
                   verifier.VerifyData(payload, signature, HashAlgorithmName.SHA384);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            if (publicKey is not null) CryptographicOperations.ZeroMemory(publicKey);
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
        }
    }

    public static ReviewDraft ReadReview(VaultDocument document)
    {
        if (document.WorkflowStage < 2 || string.IsNullOrEmpty(document.EncryptedReview))
        {
            return document.Draft;
        }

        var recordKey = Convert.FromBase64String(document.RecordKeyMaterial);
        var key = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            recordKey,
            32,
            Encoding.UTF8.GetBytes(document.Id),
            Encoding.UTF8.GetBytes("SecRev.Stage2.Review.AES-256-GCM.v1"));
        var nonce = Convert.FromBase64String(document.ReviewNonce);
        var tag = Convert.FromBase64String(document.ReviewTag);
        var ciphertext = Convert.FromBase64String(document.EncryptedReview);
        var plaintext = new byte[ciphertext.Length];
        try
        {
            if (key.Length != 32 || nonce.Length != 12 || tag.Length != 16)
            {
                throw new InvalidDataException("The review record has invalid cryptographic parameters.");
            }
            using var aes = new AesGcm(key, tag.Length);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, Encoding.UTF8.GetBytes(document.Id + ":review:v1"));
            return JsonSerializer.Deserialize<ReviewDraft>(plaintext, JsonOptions)
                ?? throw new InvalidDataException("The encrypted review record could not be decoded.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recordKey);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public static void FinalizeStageThree(VaultDocument document, string identity)
    {
        if (document.WorkflowStage != 2 || string.IsNullOrWhiteSpace(identity))
        {
            throw new InvalidOperationException("Stage 3 requires encrypted review data and an authenticated identity.");
        }

        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        document.UserIdentityStamp = identity.Trim();
        document.IdentityStampUtc = DateTimeOffset.UtcNow.ToString("O");
        var stampPayload = Encoding.UTF8.GetBytes(string.Join("|", document.Id, document.RecordKeyId, document.UserIdentityStamp, document.IdentityStampUtc));
        byte[]? privateKey = null;
        try
        {
            document.IdentityStampSignature = Convert.ToBase64String(signer.SignData(stampPayload, HashAlgorithmName.SHA384));
            privateKey = signer.ExportPkcs8PrivateKey();
            document.IdentitySigningPrivateKey = Convert.ToBase64String(privateKey);
            document.IdentitySigningPublicKey = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo());
            document.WorkflowStage = 3;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(stampPayload);
            if (privateKey is not null) CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    public static bool VerifyIdentityStamp(VaultDocument document)
    {
        if (document.WorkflowStage < 3 || string.IsNullOrEmpty(document.IdentityStampSignature)) return false;
        var stampPayload = Encoding.UTF8.GetBytes(string.Join("|", document.Id, document.RecordKeyId, document.UserIdentityStamp, document.IdentityStampUtc));
        byte[]? publicKey = null;
        try
        {
            var actual = Convert.FromBase64String(document.IdentityStampSignature);
            try
            {
                using var verifier = ECDsa.Create();
                publicKey = Convert.FromBase64String(document.IdentitySigningPublicKey);
                verifier.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
                return bytesRead == publicKey.Length && verifier.KeySize == 384 && verifier.VerifyData(stampPayload, actual, HashAlgorithmName.SHA384);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actual);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(stampPayload);
            if (publicKey is not null) CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    public static List<ExtractedImage> ExtractEmbeddedImages(string text)
    {
        var images = new List<ExtractedImage>();
        foreach (Match match in DataImagePattern.Matches(text))
        {
            if (images.Count >= MaxExtractedImages)
            {
                break;
            }

            var encoded = Regex.Replace(match.Groups[2].Value, @"\s", string.Empty);
            if (encoded.Length == 0 || encoded.Length > ((MaxImageBytes + 2) / 3) * 4 + 8)
            {
                continue;
            }

            try
            {
                var bytes = Convert.FromBase64String(encoded);
                if (bytes.Length == 0 || bytes.Length > MaxImageBytes || !HasExpectedSignature(match.Groups[1].Value, bytes))
                {
                    CryptographicOperations.ZeroMemory(bytes);
                    continue;
                }
                images.Add(new ExtractedImage
                {
                    MimeType = "image/" + match.Groups[1].Value.ToLowerInvariant(),
                    ByteLength = bytes.Length,
                    Sha256 = Convert.ToHexString(SHA256.HashData(bytes)),
                    Base64Data = Convert.ToBase64String(bytes)
                });
                CryptographicOperations.ZeroMemory(bytes);
            }
            catch (FormatException)
            {
                // Ignore malformed data URIs; extraction never executes embedded content.
            }
        }
        return images;
    }

    private static bool HasExpectedSignature(string declaredMime, byte[] bytes)
    {
        var mime = declaredMime.ToLowerInvariant();
        return mime switch
        {
            "png" => bytes.Length >= 8 && bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47 && bytes[4] == 0x0D && bytes[5] == 0x0A && bytes[6] == 0x1A && bytes[7] == 0x0A,
            "jpg" or "jpeg" => bytes.Length >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF,
            "gif" => bytes.Length >= 6 && Encoding.ASCII.GetString(bytes, 0, 3) == "GIF",
            "webp" => bytes.Length >= 12 && Encoding.ASCII.GetString(bytes, 0, 4) == "RIFF" && Encoding.ASCII.GetString(bytes, 8, 4) == "WEBP",
            _ => false
        };
    }
}
