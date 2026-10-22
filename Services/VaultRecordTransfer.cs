using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecRev.Models;

namespace SecRev.Services;

internal static class VaultRecordTransfer
{
    private const int PackageVersion = 1;
    private const int KdfIterations = 600_000;
    public const int MaxPackageBytes = 100 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new();

    public static byte[] ExportPermanentRecord(VaultDocument document, string archivePassphrase, VaultAccount custodian)
    {
        if (!WorkflowEligibility.IsPermanentlyStoredRecord(document))
            throw new InvalidOperationException("Only Custodian-finalized permanent records can be exported.");
        if (!DocumentWorkflow.VerifyReviewCompletion(document))
            throw new CryptographicException("The Analyst Stage 3 submission signature is invalid.");
        var decisionIsValid = document.WorkflowStatus is "Approved" or "Rejected" && DocumentWorkflow.VerifyCustodianDecision(document);
        var duplicateIsValid = document.WorkflowStatus == "DuplicateConfirmed" && DocumentWorkflow.VerifyDuplicateResolution(document);
        if (!decisionIsValid && !duplicateIsValid)
            throw new CryptographicException("The record has no valid Custodian Stage 4 signature.");
        ValidatePassphrase(archivePassphrase);
        if (custodian.Role != VaultRole.Custodian || !custodian.IsEnabled)
            throw new UnauthorizedAccessException("An active Custodian is required to export records.");

        var recordJson = JsonSerializer.SerializeToUtf8Bytes(document, JsonOptions);
        var salt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var key = DeriveKey(archivePassphrase, salt);
        var ciphertext = new byte[recordJson.Length];
        var tag = new byte[16];
        try
        {
            using var aes = new AesGcm(key, tag.Length);
            aes.Encrypt(nonce, recordJson, ciphertext, tag);
            var package = new VaultRecordPackage
            {
                Version = PackageVersion,
                OriginalFileName = SafeFileName(document.Name),
                RecordId = document.Id,
                ContentSha256 = document.ContentSha256,
                ExportedAtUtc = DateTimeOffset.UtcNow.ToString("O"),
                ExportedByCustodianAccountId = custodian.Id,
                ExportedByCustodianName = custodian.Name,
                KdfIterations = KdfIterations,
                Salt = Convert.ToBase64String(salt),
                Nonce = Convert.ToBase64String(nonce),
                Tag = Convert.ToBase64String(tag),
                Ciphertext = Convert.ToBase64String(ciphertext)
            };
            var signingPayload = PackageSigningPayload(package);
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            try
            {
                package.Signature = Convert.ToBase64String(signer.SignData(signingPayload, HashAlgorithmName.SHA384));
                package.PublicKey = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo());
                return JsonSerializer.SerializeToUtf8Bytes(package, JsonOptions);
            }
            finally { CryptographicOperations.ZeroMemory(signingPayload); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recordJson);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public static VaultDocument ImportPermanentRecord(ReadOnlySpan<byte> packageBytes, string archivePassphrase)
    {
        if (packageBytes.Length is <= 0 or > MaxPackageBytes)
            throw new InvalidDataException($"Record package must be between 1 byte and {MaxPackageBytes / (1024 * 1024)} MiB.");
        ValidatePassphrase(archivePassphrase);

        var package = JsonSerializer.Deserialize<VaultRecordPackage>(packageBytes, JsonOptions)
            ?? throw new InvalidDataException("The encrypted record package is invalid.");
        if (package.Version != PackageVersion || package.KdfIterations != KdfIterations ||
            !Guid.TryParseExact(package.RecordId, "N", out _) || package.ContentSha256.Length != 64 ||
            !package.ContentSha256.All(Uri.IsHexDigit) || string.IsNullOrWhiteSpace(package.ExportedByCustodianAccountId) ||
            string.IsNullOrWhiteSpace(package.ExportedByCustodianName) ||
            !string.Equals(package.OriginalFileName, SafeFileName(package.OriginalFileName), StringComparison.Ordinal))
            throw new InvalidDataException("The record package metadata is invalid or unsupported.");

        var signingPayload = PackageSigningPayload(package);
        byte[]? publicKey = null;
        byte[]? signature = null;
        byte[]? ciphertext = null;
        byte[]? salt = null;
        byte[]? nonce = null;
        byte[]? tag = null;
        byte[]? key = null;
        byte[]? plaintext = null;
        try
        {
            publicKey = Convert.FromBase64String(package.PublicKey);
            signature = Convert.FromBase64String(package.Signature);
            using (var verifier = ECDsa.Create())
            {
                verifier.ImportSubjectPublicKeyInfo(publicKey, out var publicKeyBytesRead);
                if (publicKeyBytesRead != publicKey.Length || verifier.KeySize != 384 ||
                    !verifier.VerifyData(signingPayload, signature, HashAlgorithmName.SHA384))
                    throw new CryptographicException("The Custodian transfer signature is invalid.");
            }

            ciphertext = Convert.FromBase64String(package.Ciphertext);
            salt = Convert.FromBase64String(package.Salt);
            nonce = Convert.FromBase64String(package.Nonce);
            tag = Convert.FromBase64String(package.Tag);
            if (salt.Length != 16 || nonce.Length != 12 || tag.Length != 16)
                throw new InvalidDataException("The package cryptographic parameters are invalid.");
            key = DeriveKey(archivePassphrase, salt);
            plaintext = new byte[ciphertext.Length];
            using (var aes = new AesGcm(key, tag.Length))
                aes.Decrypt(nonce, ciphertext, tag, plaintext);

            var document = JsonSerializer.Deserialize<VaultDocument>(plaintext, JsonOptions)
                ?? throw new InvalidDataException("The encrypted record payload is invalid.");
            if (document.Id != package.RecordId ||
                !string.Equals(document.Name, package.OriginalFileName, StringComparison.Ordinal) ||
                !string.Equals(document.ContentSha256, package.ContentSha256, StringComparison.OrdinalIgnoreCase) ||
                !document.IsPermanentlyStored || document.WorkflowStage < 4 ||
                string.IsNullOrEmpty(document.EncryptedSource) || !string.IsNullOrEmpty(document.Text) ||
                !string.IsNullOrEmpty(document.PdfPayloadBase64) || !DocumentWorkflow.VerifyReviewCompletion(document))
                throw new InvalidDataException("The decrypted payload does not match a finalized encrypted record.");

            var validDecision = document.WorkflowStatus is "Approved" or "Rejected" && DocumentWorkflow.VerifyCustodianDecision(document);
            var validDuplicate = document.WorkflowStatus == "DuplicateConfirmed" && DocumentWorkflow.VerifyDuplicateResolution(document);
            if (!validDecision && !validDuplicate)
                throw new CryptographicException("The record does not contain a valid Custodian Stage 4 signature.");

            var source = DocumentWorkflow.ReadSourceBytes(document);
            try
            {
                var actualHash = Convert.ToHexString(SHA256.HashData(source));
                if (!string.Equals(actualHash, document.ContentSha256, StringComparison.OrdinalIgnoreCase))
                    throw new CryptographicException("The decrypted source hash does not match the record metadata.");
            }
            finally { CryptographicOperations.ZeroMemory(source); }
            return document;
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException("The record package contains malformed encoded data.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingPayload);
            if (publicKey is not null) CryptographicOperations.ZeroMemory(publicKey);
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
            if (salt is not null) CryptographicOperations.ZeroMemory(salt);
            if (nonce is not null) CryptographicOperations.ZeroMemory(nonce);
            if (tag is not null) CryptographicOperations.ZeroMemory(tag);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public static byte[] ExportOriginalSource(VaultDocument document)
    {
        if (!WorkflowEligibility.IsPermanentlyStoredRecord(document) || string.IsNullOrEmpty(document.ContentSha256))
            throw new InvalidOperationException("Only a Custodian-finalized record can export its original file.");
        var source = DocumentWorkflow.ReadSourceBytes(document);
        try
        {
            var hash = Convert.ToHexString(SHA256.HashData(source));
            if (!string.Equals(hash, document.ContentSha256, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("Original source bytes do not match the record content digest.");
            return source.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(source); }
    }

    public static string GetPackageFileName(VaultDocument document) => Path.Combine(document.Id, "record.secrev-record.json").Replace(Path.DirectorySeparatorChar, '/');
    public static string GetOriginalFileRelativePath(VaultDocument document) => Path.Combine(document.Id, SafeFileName(document.Name)).Replace(Path.DirectorySeparatorChar, '/');

    public static byte[] CreateManifest(VaultTransferReceipt receipt,
        System.Collections.Generic.IEnumerable<(string Name, byte[] Bytes, string RecordId, string OriginalFileName, string OriginalPath, byte[] OriginalBytes)> entries)
    {
        var materializedEntries = entries.ToArray();
        if (!VaultTransferReceipt.Verify(receipt))
            throw new CryptographicException("The Custodian transfer receipt did not verify.");
        var allFiles = materializedEntries.SelectMany(entry => new[] { (entry.Name, entry.Bytes), (entry.OriginalPath, entry.OriginalBytes) }).ToArray();
        var manifest = new VaultTransferManifest
        {
            Receipt = receipt,
            Records = materializedEntries.OrderBy(entry => entry.Name, StringComparer.Ordinal)
                .Select(entry => new VaultTransferManifestEntry
                {
                    PackageFileName = entry.Name,
                    PackageSha256 = Convert.ToHexString(SHA256.HashData(entry.Bytes)),
                    SourceFileName = entry.OriginalPath,
                    SourceFileSha256 = Convert.ToHexString(SHA256.HashData(entry.OriginalBytes)),
                    RecordId = entry.RecordId,
                    OriginalFileName = entry.OriginalFileName
                }).ToList()
        };
        if (manifest.Records.Count != receipt.RecordCount)
            throw new InvalidDataException("Manifest record count does not match the signed Custodian receipt.");
        var manifestHash = ComputeManifestHash(allFiles);
        if (!string.Equals(manifestHash, receipt.ManifestSha256, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("Manifest package/source hashes do not match the Custodian receipt.");
        return JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);
    }

    public static VaultTransferManifest ParseAndVerifyManifest(ReadOnlySpan<byte> manifestBytes,
        System.Collections.Generic.IReadOnlyCollection<(string Name, byte[] Bytes)> files)
    {
        if (manifestBytes.Length is <= 0 or > 5 * 1024 * 1024)
            throw new InvalidDataException("Transfer manifest size is invalid.");
        var manifest = JsonSerializer.Deserialize<VaultTransferManifest>(manifestBytes, JsonOptions)
            ?? throw new InvalidDataException("Transfer manifest is malformed.");
        if (manifest.Version != 1 || manifest.Receipt is null || manifest.Records is null ||
            !VaultTransferReceipt.Verify(manifest.Receipt) || manifest.Records.Count != manifest.Receipt.RecordCount ||
            files.Count != checked(manifest.Records.Count * 2))
            throw new CryptographicException("Transfer manifest receipt/count verification failed.");

        Dictionary<string, (byte[] Bytes, string Hash)> listedFiles;
        try
        {
            listedFiles = files.ToDictionary(
                file => NormalizeRelativePath(file.Name),
                file => (file.Bytes, Convert.ToHexString(SHA256.HashData(file.Bytes))),
                StringComparer.Ordinal);
        }
        catch (ArgumentException ex) { throw new InvalidDataException("Transfer folder contains duplicate paths.", ex); }

        var expectedPaths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in manifest.Records)
        {
            ValidateRecordPaths(entry);
            if (!expectedPaths.Add(entry.PackageFileName) || !expectedPaths.Add(entry.SourceFileName))
                throw new InvalidDataException("Manifest contains duplicate package/source paths.");
            if (!listedFiles.TryGetValue(entry.PackageFileName, out var package) ||
                !string.Equals(entry.PackageSha256, package.Hash, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException($"Encrypted package '{entry.PackageFileName}' is missing or its digest does not match the signed manifest.");
            if (!listedFiles.TryGetValue(entry.SourceFileName, out var source) ||
                !string.Equals(entry.SourceFileSha256, source.Hash, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException($"Original source '{entry.SourceFileName}' is missing or its digest does not match the manifest.");
        }
        if (expectedPaths.Count != listedFiles.Count || expectedPaths.Any(path => !listedFiles.ContainsKey(path)))
            throw new InvalidDataException("Transfer folder contains unlisted or missing files.");

        var manifestHash = ComputeManifestHash(files.Select(file => (NormalizeRelativePath(file.Name), file.Bytes)));
        if (!string.Equals(manifestHash, manifest.Receipt.ManifestSha256, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("Transfer files do not match the signed Custodian manifest.");
        return manifest;
    }

    public static string ComputeManifestHash(System.Collections.Generic.IEnumerable<(string Name, byte[] Bytes)> entries)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var entry in entries.OrderBy(item => item.Name, StringComparer.Ordinal))
        {
            hash.AppendData(Encoding.UTF8.GetBytes(entry.Name));
            hash.AppendData(new byte[] { 0 });
            hash.AppendData(SHA256.HashData(entry.Bytes));
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static byte[] PackageSigningPayload(VaultRecordPackage package) => JsonSerializer.SerializeToUtf8Bytes(new
    {
        package.Version,
        package.OriginalFileName,
        package.RecordId,
        package.ContentSha256,
        package.ExportedAtUtc,
        package.ExportedByCustodianAccountId,
        package.ExportedByCustodianName,
        package.KdfIterations,
        package.Salt,
        package.Nonce,
        package.Tag,
        ciphertextSha256 = Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(package.Ciphertext)))
    }, JsonOptions);

    private static byte[] DeriveKey(string passphrase, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, KdfIterations, HashAlgorithmName.SHA256, 32);

    private static void ValidatePassphrase(string passphrase)
    {
        if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length < 12 || passphrase.Length > 1024)
            throw new ArgumentException("Use an export passphrase of 12–1,024 characters.", nameof(passphrase));
    }

    private static string SafeFileName(string value)
    {
        var name = Path.GetFileName(value ?? string.Empty);
        if (string.IsNullOrWhiteSpace(name) || name is "." or ".." || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new InvalidDataException("The record filename is invalid.");
        return name;
    }

    private static string NormalizeRelativePath(string path)
    {
        var normalized = path.Replace('\\', '/');
        if (string.IsNullOrWhiteSpace(normalized) || normalized.StartsWith('/') || Path.IsPathRooted(normalized) ||
            normalized.Split('/').Any(part => string.IsNullOrEmpty(part) || part is "." or ".."))
            throw new InvalidDataException("Transfer manifest path is not a safe relative path.");
        return normalized;
    }

    private static void ValidateRecordPaths(VaultTransferManifestEntry entry)
    {
        var packagePath = NormalizeRelativePath(entry.PackageFileName);
        var sourcePath = NormalizeRelativePath(entry.SourceFileName);
        if (!Guid.TryParseExact(entry.RecordId, "N", out _) ||
            !string.Equals(packagePath, $"{entry.RecordId}/record.secrev-record.json", StringComparison.Ordinal) ||
            !string.Equals(sourcePath, $"{entry.RecordId}/{SafeFileName(entry.OriginalFileName)}", StringComparison.Ordinal) ||
            entry.PackageSha256.Length != 64 || !entry.PackageSha256.All(Uri.IsHexDigit) ||
            entry.SourceFileSha256.Length != 64 || !entry.SourceFileSha256.All(Uri.IsHexDigit))
            throw new InvalidDataException("Transfer manifest record paths or digests are invalid.");
    }

    public static string ResolveSafePathWithinRoot(string rootPath, string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        var root = Path.GetFullPath(rootPath);
        var full = Path.GetFullPath(Path.Combine(root, normalized.Replace('/', Path.DirectorySeparatorChar)));
        var prefix = root.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
            ? root
            : root + Path.DirectorySeparatorChar;
        if (!full.StartsWith(prefix, StringComparison.Ordinal))
            throw new InvalidDataException("Transfer path escapes the selected folder.");

        var current = root;
        foreach (var segment in normalized.Split('/'))
        {
            current = Path.Combine(current, segment);
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Symbolic links are not allowed in record transfer folders.");
        }
        return full;
    }

    public static IReadOnlyList<string> EnumerateRegularFilesWithoutLinks(string rootPath, int maxEntries = 400)
    {
        var root = Path.GetFullPath(rootPath);
        if (!Directory.Exists(root) || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Transfer root must be an existing directory, not a symbolic link.");

        var files = new List<string>();
        var pending = new Stack<string>();
        pending.Push(root);
        var visitedEntries = 0;
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            foreach (var path in Directory.EnumerateFileSystemEntries(directory))
            {
                if (++visitedEntries > maxEntries)
                    throw new InvalidDataException("Transfer folder contains too many filesystem entries.");
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("Symbolic links are not allowed in record transfer folders.");
                if ((attributes & FileAttributes.Directory) != 0)
                    pending.Push(path);
                else
                    files.Add(Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/'));
            }
        }
        return files;
    }
}

internal sealed class VaultRecordPackage
{
    public int Version { get; set; }
    public string OriginalFileName { get; set; } = string.Empty;
    public string RecordId { get; set; } = string.Empty;
    public string ContentSha256 { get; set; } = string.Empty;
    public string ExportedAtUtc { get; set; } = string.Empty;
    public string ExportedByCustodianAccountId { get; set; } = string.Empty;
    public string ExportedByCustodianName { get; set; } = string.Empty;
    public int KdfIterations { get; set; }
    public string Salt { get; set; } = string.Empty;
    public string Nonce { get; set; } = string.Empty;
    public string Tag { get; set; } = string.Empty;
    public string Ciphertext { get; set; } = string.Empty;
    public string Signature { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
}
