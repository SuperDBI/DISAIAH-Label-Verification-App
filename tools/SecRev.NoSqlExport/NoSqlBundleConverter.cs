using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecRev.Models;
using SecRev.Services;

namespace SecRev.NoSqlExport;

public static class NoSqlBundleConverter
{
    private const int MaximumRecords = 100;
    private const int MaximumManifestBytes = 5 * 1024 * 1024;
    private const long MaximumBundleBytes = 500L * 1024 * 1024;
    private static readonly JsonSerializerOptions OutputJsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static void Convert(string bundlePath, string outputPath, Guid tenantId, string archivePassphrase)
    {
        var inputRoot = Path.GetFullPath(bundlePath);
        var outputRoot = Path.GetFullPath(outputPath);
        if (!Directory.Exists(inputRoot))
            throw new DirectoryNotFoundException("The Custodian export bundle directory does not exist.");
        if (Directory.Exists(outputRoot) || File.Exists(outputRoot))
            throw new IOException("The output path must not already exist; choose a new destination to prevent accidental overwrite.");
        if (IsSameOrChildPath(outputRoot, inputRoot) || IsSameOrChildPath(inputRoot, outputRoot))
            throw new InvalidDataException("The input bundle and output destination must be separate directories.");
        if (tenantId == Guid.Empty)
            throw new ArgumentException("A non-empty Entra tenant ID is required for the Cosmos partition key.", nameof(tenantId));
        if (string.IsNullOrWhiteSpace(archivePassphrase) || archivePassphrase.Length is < 12 or > 1024)
            throw new ArgumentException("The Custodian export passphrase must be 12–1,024 characters.", nameof(archivePassphrase));

        var bundleFiles = VaultRecordTransfer.EnumerateRegularFilesWithoutLinks(inputRoot);
        var manifestRelativePath = "manifest.json";
        if (!bundleFiles.Contains(manifestRelativePath, StringComparer.Ordinal))
            throw new InvalidDataException("The signed Custodian manifest.json is missing.");
        var manifestPath = VaultRecordTransfer.ResolveSafePathWithinRoot(inputRoot, manifestRelativePath);
        var manifestInfo = new FileInfo(manifestPath);
        if (manifestInfo.Length is <= 0 or > MaximumManifestBytes)
            throw new InvalidDataException("Custodian export manifest is empty or exceeds 5 MiB.");
        var manifestBytes = File.ReadAllBytes(manifestPath);
        var packageBuffers = new List<(VaultTransferManifestEntry Entry, byte[] Package, byte[] Source)>();
        var stagingRoot = outputRoot + ".partial-" + Guid.NewGuid().ToString("N");

        try
        {
            var manifest = System.Text.Json.JsonSerializer.Deserialize<VaultTransferManifest>(manifestBytes)
                ?? throw new InvalidDataException("Custodian export manifest is malformed.");
            if (manifest.Version != 1 || manifest.Receipt is null || manifest.Records is null ||
                !string.Equals(manifest.Receipt.Operation, "Export", StringComparison.Ordinal) ||
                !VaultTransferReceipt.Verify(manifest.Receipt))
                throw new CryptographicException("A valid signed Custodian export manifest is required.");
            if (manifest.Records.Count is <= 0 or > MaximumRecords)
                throw new InvalidDataException($"Export conversion supports 1–{MaximumRecords} records per batch.");

            long totalBytes = manifestBytes.Length;
            foreach (var entry in manifest.Records)
            {
                var packagePath = VaultRecordTransfer.ResolveSafePathWithinRoot(inputRoot, entry.PackageFileName);
                var sourcePath = VaultRecordTransfer.ResolveSafePathWithinRoot(inputRoot, entry.SourceFileName);
                var packageInfo = new FileInfo(packagePath);
                var sourceInfo = new FileInfo(sourcePath);
                if (packageInfo.Length is <= 0 or > VaultRecordTransfer.MaxPackageBytes ||
                    sourceInfo.Length is <= 0 or > VaultRecordTransfer.MaxPackageBytes)
                    throw new InvalidDataException($"Record {entry.RecordId} package or source file is outside the supported size limit.");

                totalBytes = checked(totalBytes + packageInfo.Length + sourceInfo.Length);
                if (totalBytes > MaximumBundleBytes)
                    throw new InvalidDataException("Custodian export bundle exceeds the 500 MiB conversion limit.");

                var packageBytes = File.ReadAllBytes(packagePath);
                var sourceBytes = File.ReadAllBytes(sourcePath);
                packageBuffers.Add((entry, packageBytes, sourceBytes));
            }

            var expectedPaths = packageBuffers
                .SelectMany(item => new[] { item.Entry.PackageFileName, item.Entry.SourceFileName })
                .Append(manifestRelativePath)
                .ToHashSet(StringComparer.Ordinal);
            if (!expectedPaths.SetEquals(bundleFiles))
                throw new InvalidDataException("Bundle has missing, extra, or unlisted files. Convert only an unmodified Custodian export bundle.");

            var allManifestFiles = packageBuffers
                .SelectMany(item => new[]
                {
                    (item.Entry.PackageFileName, item.Package),
                    (item.Entry.SourceFileName, item.Source)
                }).ToArray();
            var verifiedManifest = VaultRecordTransfer.ParseAndVerifyManifest(manifestBytes, allManifestFiles);
            if (verifiedManifest.Receipt.Id != manifest.Receipt.Id || verifiedManifest.Records.Count != manifest.Records.Count)
                throw new CryptographicException("Custodian manifest validation returned inconsistent record counts.");

            var tenant = tenantId.ToString("N");
            Directory.CreateDirectory(Path.Combine(stagingRoot, "records", tenant));
            Directory.CreateDirectory(Path.Combine(stagingRoot, "payloads", tenant));
            var outputEntries = new List<NoSqlManifestEntry>(packageBuffers.Count);

            foreach (var item in packageBuffers)
            {
                var record = VaultRecordTransfer.ImportPermanentRecord(item.Package, archivePassphrase);
                try
                {
                    if (!string.Equals(record.Id, item.Entry.RecordId, StringComparison.Ordinal) ||
                        !string.Equals(record.Name, item.Entry.OriginalFileName, StringComparison.Ordinal) ||
                        !string.Equals(record.ContentSha256, item.Entry.SourceFileSha256, StringComparison.OrdinalIgnoreCase))
                        throw new CryptographicException($"Record {item.Entry.RecordId} metadata does not match its signed manifest and source digest.");

                    if (!WorkflowEligibility.IsFinalDecision(record.WorkflowStatus) ||
                        !WorkflowEligibility.IsPermanentlyStoredRecord(record) ||
                        !DocumentWorkflow.VerifyReviewCompletion(record) || !DocumentWorkflow.VerifyCustodianDecision(record))
                        throw new InvalidDataException($"Record {record.Id} is pending, incomplete, or lacks valid Analyst and Custodian signatures. Only permanently approved/rejected records are accepted.");

                    var sourceHash = System.Convert.ToHexString(SHA256.HashData(item.Source));
                    if (!string.Equals(sourceHash, record.ContentSha256, StringComparison.OrdinalIgnoreCase))
                        throw new CryptographicException($"Plaintext source in the export bundle does not match permanent record {record.Id}.");

                    var packageHash = System.Convert.ToHexString(SHA256.HashData(item.Package));
                    var documentPath = $"records/{tenant}/{record.Id}.json";
                    var encryptedPackagePath = $"payloads/{tenant}/{record.Id}.secrev-record.json";
                    var cosmosDocument = new CosmosRecordDocument
                    {
                        Id = record.Id,
                        PartitionKey = tenant,
                        TenantId = tenant,
                        RecordType = "SecRevPermanentRecord",
                        SchemaVersion = 1,
                        WorkflowStatus = record.WorkflowStatus,
                        Decision = record.CustodianDecision,
                        DecisionUtc = record.CustodianDecisionUtc,
                        CustodianAccountId = record.CustodianAccountId,
                        CustodianName = record.CustodianName,
                        CustodianDecisionSignature = record.CustodianDecisionSignature,
                        CustodianDecisionPublicKey = record.CustodianDecisionPublicKey,
                        AnalystAccountId = record.ReviewAnalystAccountId,
                        AnalystName = record.ReviewAnalystName,
                        AnalystSubmittedAtUtc = record.ReviewCompletedAtUtc,
                        AnalystReviewSignature = record.ReviewCompletionSignature,
                        AnalystReviewPublicKey = record.ReviewCompletionPublicKey,
                        Stage3SignatureDigest = record.Stage3SignatureDigest,
                        ContentSha256 = record.ContentSha256,
                        IsPermanentlyStored = true,
                        EncryptedPackagePath = encryptedPackagePath,
                        EncryptedPackageSha256 = packageHash,
                        EncryptedPackageBytes = item.Package.LongLength,
                        ExportReceiptId = manifest.Receipt.Id,
                        ExportedByCustodianAccountId = manifest.Receipt.CustodianAccountId,
                        ExportedAtUtc = manifest.Receipt.OccurredAtUtc
                    };

                    var documentFullPath = Path.Combine(stagingRoot, documentPath.Replace('/', Path.DirectorySeparatorChar));
                    var packageFullPath = Path.Combine(stagingRoot, encryptedPackagePath.Replace('/', Path.DirectorySeparatorChar));
                    Directory.CreateDirectory(Path.GetDirectoryName(documentFullPath)!);
                    Directory.CreateDirectory(Path.GetDirectoryName(packageFullPath)!);
                    File.WriteAllBytes(documentFullPath, JsonSerializer.SerializeToUtf8Bytes(cosmosDocument, OutputJsonOptions));
                    File.WriteAllBytes(packageFullPath, item.Package);
                    outputEntries.Add(new NoSqlManifestEntry(record.Id, record.WorkflowStatus, documentPath,
                        encryptedPackagePath, packageHash, item.Package.LongLength));
                }
                finally
                {
                    ClearDecryptedRecord(record);
                }
            }

            var exportManifest = new NoSqlExportManifest
            {
                Format = "SecRev Cosmos-compatible encrypted record archive",
                SchemaVersion = 1,
                TenantId = tenant,
                PartitionKeyPath = "/PartitionKey",
                SourceExportReceiptId = manifest.Receipt.Id,
                SourceExportCustodianAccountId = manifest.Receipt.CustodianAccountId,
                SourceExportCustodianName = manifest.Receipt.CustodianName,
                SourceExportedAtUtc = manifest.Receipt.OccurredAtUtc,
                SourceExportReceiptSignature = manifest.Receipt.Signature,
                SourceExportReceiptPublicKey = manifest.Receipt.PublicKey,
                SourceExportManifestSha256 = System.Convert.ToHexString(SHA256.HashData(manifestBytes)),
                CreatedAtUtc = DateTimeOffset.UtcNow,
                RecordCount = outputEntries.Count,
                OriginalPlaintextSourcesIncluded = false,
                Records = outputEntries
            };
            File.WriteAllBytes(Path.Combine(stagingRoot, "nosql-export-manifest.json"),
                JsonSerializer.SerializeToUtf8Bytes(exportManifest, OutputJsonOptions));
            Directory.Move(stagingRoot, outputRoot);
        }
        catch
        {
            if (Directory.Exists(stagingRoot))
                Directory.Delete(stagingRoot, recursive: true);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(manifestBytes);
            foreach (var item in packageBuffers)
            {
                CryptographicOperations.ZeroMemory(item.Package);
                CryptographicOperations.ZeroMemory(item.Source);
            }
        }
    }

    private static bool IsSameOrChildPath(string candidate, string root)
    {
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return string.Equals(Path.GetFullPath(candidate).TrimEnd(Path.DirectorySeparatorChar),
                   Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar), comparison) ||
               Path.GetFullPath(candidate).StartsWith(fullRoot, comparison);
    }

    private static void ClearDecryptedRecord(VaultDocument record)
    {
        record.RecordKeyMaterial = string.Empty;
        record.EncryptedSource = string.Empty;
        record.SourceNonce = string.Empty;
        record.SourceTag = string.Empty;
        record.EncryptedReview = string.Empty;
        record.ReviewNonce = string.Empty;
        record.ReviewTag = string.Empty;
        record.PdfImageExtractionJson = string.Empty;
        record.PdfSelectableTextAndForms = string.Empty;
        record.PdfEmbeddedImageOcrText = string.Empty;
        record.Draft = new ReviewDraft();
    }

    private sealed class CosmosRecordDocument
    {
        public required string Id { get; init; }
        [JsonPropertyName("PartitionKey")]
        public required string PartitionKey { get; init; }
        public required string TenantId { get; init; }
        public required string RecordType { get; init; }
        public int SchemaVersion { get; init; }
        public required string WorkflowStatus { get; init; }
        public required string Decision { get; init; }
        public required string DecisionUtc { get; init; }
        public required string CustodianAccountId { get; init; }
        public required string CustodianName { get; init; }
        public required string CustodianDecisionSignature { get; init; }
        public required string CustodianDecisionPublicKey { get; init; }
        public required string AnalystAccountId { get; init; }
        public required string AnalystName { get; init; }
        public required string AnalystSubmittedAtUtc { get; init; }
        public required string AnalystReviewSignature { get; init; }
        public required string AnalystReviewPublicKey { get; init; }
        public required string Stage3SignatureDigest { get; init; }
        public required string ContentSha256 { get; init; }
        public bool IsPermanentlyStored { get; init; }
        public required string EncryptedPackagePath { get; init; }
        public required string EncryptedPackageSha256 { get; init; }
        public long EncryptedPackageBytes { get; init; }
        public required string ExportReceiptId { get; init; }
        public required string ExportedByCustodianAccountId { get; init; }
        public required string ExportedAtUtc { get; init; }
    }

    private sealed class NoSqlExportManifest
    {
        public required string Format { get; init; }
        public int SchemaVersion { get; init; }
        public required string TenantId { get; init; }
        public required string PartitionKeyPath { get; init; }
        public required string SourceExportReceiptId { get; init; }
        public required string SourceExportCustodianAccountId { get; init; }
        public required string SourceExportCustodianName { get; init; }
        public required string SourceExportedAtUtc { get; init; }
        public required string SourceExportReceiptSignature { get; init; }
        public required string SourceExportReceiptPublicKey { get; init; }
        public required string SourceExportManifestSha256 { get; init; }
        public DateTimeOffset CreatedAtUtc { get; init; }
        public int RecordCount { get; init; }
        public bool OriginalPlaintextSourcesIncluded { get; init; }
        public required IReadOnlyList<NoSqlManifestEntry> Records { get; init; }
    }

    private sealed record NoSqlManifestEntry(string Id, string Decision, string DocumentPath, string EncryptedPackagePath,
        string EncryptedPackageSha256, long EncryptedPackageBytes);
}
