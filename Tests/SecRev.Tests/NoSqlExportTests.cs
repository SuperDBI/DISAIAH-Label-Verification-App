using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecRev.Models;
using SecRev.NoSqlExport;
using SecRev.Services;
using Xunit;

namespace SecRev.Tests;

public sealed class NoSqlExportTests
{
    private const string ArchivePassphrase = "Custodian export test passphrase!";

    [Fact]
    public void Convert_ValidCustodianBundle_ProducesTenantPartitionedMetadataAndEncryptedPackageOnly()
    {
        var directory = Path.Combine(Path.GetTempPath(), "secrev-nosql-test-" + Guid.NewGuid().ToString("N"));
        var bundle = Path.Combine(directory, "bundle");
        var output = Path.Combine(directory, "nosql");
        var tenantId = Guid.NewGuid();
        Directory.CreateDirectory(bundle);
        var (document, custodian, source) = CreateApprovedRecord();
        byte[]? packageBytes = null;
        byte[]? manifestBytes = null;
        try
        {
            packageBytes = VaultRecordTransfer.ExportPermanentRecord(document, ArchivePassphrase, custodian);
            var packagePath = VaultRecordTransfer.GetPackageFileName(document);
            var sourcePath = VaultRecordTransfer.GetOriginalFileRelativePath(document);
            var packageDiskPath = VaultRecordTransfer.ResolveSafePathWithinRoot(bundle, packagePath);
            var sourceDiskPath = VaultRecordTransfer.ResolveSafePathWithinRoot(bundle, sourcePath);
            Directory.CreateDirectory(Path.GetDirectoryName(packageDiskPath)!);
            Directory.CreateDirectory(Path.GetDirectoryName(sourceDiskPath)!);
            File.WriteAllBytes(packageDiskPath, packageBytes);
            File.WriteAllBytes(sourceDiskPath, source);

            var manifestFiles = new[] { (packagePath, packageBytes), (sourcePath, source) };
            var manifestHash = VaultRecordTransfer.ComputeManifestHash(manifestFiles);
            var receipt = CreateSignedReceipt(custodian, manifestHash, 1);
            manifestBytes = VaultRecordTransfer.CreateManifest(receipt,
                new[] { (packagePath, packageBytes, document.Id, document.Name, sourcePath, source) });
            File.WriteAllBytes(Path.Combine(bundle, "manifest.json"), manifestBytes);

            NoSqlBundleConverter.Convert(bundle, output, tenantId, ArchivePassphrase);

            var tenant = tenantId.ToString("N");
            var metadataPath = Path.Combine(output, "records", tenant, document.Id + ".json");
            var encryptedPath = Path.Combine(output, "payloads", tenant, document.Id + ".secrev-record.json");
            Assert.True(File.Exists(metadataPath));
            Assert.True(File.Exists(encryptedPath));
            Assert.False(File.Exists(Path.Combine(output, "records", tenant, document.Name)));

            using var metadata = JsonDocument.Parse(File.ReadAllBytes(metadataPath));
            var root = metadata.RootElement;
            Assert.Equal(document.Id, root.GetProperty("id").GetString());
            Assert.Equal(tenant, root.GetProperty("PartitionKey").GetString());
            Assert.Equal(tenant, root.GetProperty("tenantId").GetString());
            Assert.Equal("Approved", root.GetProperty("decision").GetString());
            Assert.True(root.GetProperty("isPermanentlyStored").GetBoolean());
            Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("custodianDecisionSignature").GetString()));
            Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("analystReviewSignature").GetString()));
            Assert.Equal(Convert.ToHexString(SHA256.HashData(packageBytes)), root.GetProperty("encryptedPackageSha256").GetString());

            var exportedManifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(output, "nosql-export-manifest.json")));
            Assert.Equal(1, exportedManifest.RootElement.GetProperty("recordCount").GetInt32());
            Assert.False(exportedManifest.RootElement.GetProperty("originalPlaintextSourcesIncluded").GetBoolean());
            Assert.Equal("/PartitionKey", exportedManifest.RootElement.GetProperty("partitionKeyPath").GetString());
            Assert.False(string.IsNullOrWhiteSpace(exportedManifest.RootElement.GetProperty("sourceExportReceiptSignature").GetString()));
            Assert.Equal(packageBytes, File.ReadAllBytes(encryptedPath));
        }
        finally
        {
            if (packageBytes is not null) CryptographicOperations.ZeroMemory(packageBytes);
            if (manifestBytes is not null) CryptographicOperations.ZeroMemory(manifestBytes);
            CryptographicOperations.ZeroMemory(source);
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Convert_RejectsBundleWithMissingManifest_WithoutCreatingOutput()
    {
        var directory = Path.Combine(Path.GetTempPath(), "secrev-nosql-test-" + Guid.NewGuid().ToString("N"));
        var bundle = Path.Combine(directory, "bundle");
        var output = Path.Combine(directory, "nosql");
        Directory.CreateDirectory(bundle);
        try
        {
            Assert.Throws<InvalidDataException>(() =>
                NoSqlBundleConverter.Convert(bundle, output, Guid.NewGuid(), ArchivePassphrase));
            Assert.False(Directory.Exists(output));
            Assert.False(Directory.Exists(output));
            Assert.Single(Directory.GetFileSystemEntries(directory));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static (VaultDocument Document, VaultAccount Custodian, byte[] Source) CreateApprovedRecord()
    {
        var analyst = new VaultAccount { Name = "export-analyst", Role = VaultRole.Analyst, IsEnabled = true };
        var custodian = new VaultAccount { Name = "export-custodian", Role = VaultRole.Custodian, IsEnabled = true };
        var source = Encoding.UTF8.GetBytes("permanent reviewed source content");
        var document = new VaultDocument { Name = "review.txt", WorkflowStatus = "InReview" };
        DocumentWorkflow.ImportSource(document, source);
        var draft = new ReviewDraft
        {
            ScanCompleted = true,
            ImageExtractionCompleted = true,
            MatchQuery = "reviewed",
            AccuracyPercent = 100,
            ReviewNotes = "Analyst reviewed content"
        };
        DocumentWorkflow.EncryptStageTwo(document, draft);
        DocumentWorkflow.SubmitReview(document, analyst);
        DocumentWorkflow.ApplyCustodianDecision(document, "Approved", "Custodian approved after review", custodian);
        return (document, custodian, source);
    }

    private static VaultTransferReceipt CreateSignedReceipt(VaultAccount custodian, string manifestHash, int count)
    {
        var receipt = new VaultTransferReceipt
        {
            Operation = "Export",
            CustodianAccountId = custodian.Id,
            CustodianName = custodian.Name,
            OccurredAtUtc = DateTimeOffset.UtcNow.ToString("O"),
            RecordCount = count,
            ManifestSha256 = manifestHash
        };
        var payload = VaultTransferReceipt.Payload(receipt);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        try
        {
            receipt.Signature = Convert.ToBase64String(signer.SignData(payload, HashAlgorithmName.SHA384));
            receipt.PublicKey = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo());
            return receipt;
        }
        finally { CryptographicOperations.ZeroMemory(payload); }
    }
}
