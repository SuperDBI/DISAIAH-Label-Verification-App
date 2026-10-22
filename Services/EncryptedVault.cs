using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecRev.Models;

namespace SecRev.Services;

internal sealed class EncryptedVault : IDisposable
{
    private const int KeyIterations = 600_000;
    private const string BootstrapTokenEnvironmentVariable = "SECREV_BOOTSTRAP_TOKEN";
    private readonly string _vaultPath;
    private string UnlockLimiterPath => _vaultPath + ".unlock-limiter.json";
    private readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = false };
    private byte[]? _key;
    private byte[]? _salt;
    private string? _bootstrapTokenSalt;
    private string? _bootstrapTokenVerifier;
    private int _accountFailedAttempts;
    private string _accountLockoutUntilUtc = string.Empty;
    private string _lastLogoutReason = string.Empty;
    private string _lastLogoutAtUtc = string.Empty;

    public EncryptedVault()
        : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SecRev", "vault.enc"))
    {
    }

    internal EncryptedVault(string vaultPath)
    {
        if (string.IsNullOrWhiteSpace(vaultPath))
            throw new ArgumentException("A vault file path is required.", nameof(vaultPath));
        _vaultPath = Path.GetFullPath(vaultPath);
    }

    public List<VaultDocument> Documents { get; private set; } = new();
    public List<VaultAccount> Accounts { get; private set; } = new();
    public List<VaultTransferReceipt> TransferReceipts { get; private set; } = new();
    public bool IsUnlocked => _key is not null;
    public bool RequiresBootstrap => IsUnlocked && Accounts.Count == 0;
    public string VaultPath => _vaultPath;
    public string LastLogoutReason => _lastLogoutReason;
    public string LastLogoutAtUtc => _lastLogoutAtUtc;
    public int RemainingAccountAttempts => Math.Max(0, 5 - _accountFailedAttempts);
    public TimeSpan AccountLockoutRemaining => RemainingUntil(_accountLockoutUntilUtc);
    public TimeSpan VaultUnlockLockoutRemaining => RemainingUntil(ReadUnlockLimiter().LockoutUntilUtc);

    public void RecordVaultUnlockFailure()
    {
        var state = ReadUnlockLimiter();
        if (RemainingUntil(state.LockoutUntilUtc) > TimeSpan.Zero) return;
        var failures = state.FailedAttempts + 1;
        var until = failures >= 5 ? DateTimeOffset.UtcNow.AddSeconds(900).ToString("O") : string.Empty;
        WriteUnlockLimiter(new UnlockLimiterState(failures >= 5 ? 0 : failures, until));
    }

    public void ResetVaultUnlockFailures()
    {
        try { if (File.Exists(UnlockLimiterPath)) File.Delete(UnlockLimiterPath); }
        catch (IOException) { }
    }

    public void UnlockOrCreate(string passphrase)
    {
        if (VaultUnlockLockoutRemaining > TimeSpan.Zero)
            throw new InvalidOperationException($"Vault unlock is temporarily locked. Try again in {(int)Math.Ceiling(VaultUnlockLockoutRemaining.TotalSeconds)} seconds.");
        if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length < 12)
        {
            throw new ArgumentException("Use a passphrase with at least 12 characters.");
        }

        Lock();
        Directory.CreateDirectory(Path.GetDirectoryName(_vaultPath)!);
        if (!File.Exists(_vaultPath))
        {
            _salt = RandomNumberGenerator.GetBytes(16);
            _key = DeriveKey(passphrase, _salt);
            Documents = new List<VaultDocument>();
            Accounts = new List<VaultAccount>();
            ResetVaultUnlockFailures();
            Save();
            return;
        }

        var envelope = JsonSerializer.Deserialize<EncryptedEnvelope>(File.ReadAllText(_vaultPath), _jsonOptions)
            ?? throw new InvalidDataException("The vault envelope is invalid.");
        if (envelope.Version is not (1 or 2))
        {
            throw new InvalidDataException("This vault format version is not supported.");
        }

        var salt = Convert.FromBase64String(envelope.Salt);
        var nonce = Convert.FromBase64String(envelope.Nonce);
        var tag = Convert.FromBase64String(envelope.Tag);
        var ciphertext = Convert.FromBase64String(envelope.Ciphertext);
        var key = DeriveKey(passphrase, salt);
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            List<VaultDocument> docs;
            List<VaultAccount> accounts;
            if (envelope.Version == 1)
            {
                docs = JsonSerializer.Deserialize<List<VaultDocument>>(plaintext, _jsonOptions) ?? new List<VaultDocument>();
                accounts = new List<VaultAccount>();
            }
            else
            {
                var data = JsonSerializer.Deserialize<VaultData>(plaintext, _jsonOptions)
                    ?? throw new InvalidDataException("The encrypted vault payload is invalid.");
                docs = data.Documents ?? new List<VaultDocument>();
                accounts = data.Accounts ?? new List<VaultAccount>();
                TransferReceipts = data.TransferReceipts ?? new List<VaultTransferReceipt>();
                _bootstrapTokenSalt = data.BootstrapTokenSalt;
                _bootstrapTokenVerifier = data.BootstrapTokenVerifier;
                _accountFailedAttempts = data.AccountFailedAttempts;
                _accountLockoutUntilUtc = data.AccountLockoutUntilUtc ?? string.Empty;
                _lastLogoutReason = data.LastLogoutReason ?? string.Empty;
                _lastLogoutAtUtc = data.LastLogoutAtUtc ?? string.Empty;
            }
            ClearKey();
            _key = key;
            key = Array.Empty<byte>();
            _salt = salt;
            Documents = docs;
            Accounts = accounts;
            var migrated = false;
            foreach (var document in Documents)
            {
                if (document.WorkflowStage >= 2 && !string.IsNullOrEmpty(document.ReviewCompletionSignature))
                    document.WorkflowStage = string.IsNullOrEmpty(document.CustodianDecisionSignature) ? 3 : 4;
                if (document.WorkflowStatus == "DuplicatePendingCustodianReview")
                {
                    document.WorkflowStatus = "InReview";
                    document.DuplicateResolution = "PendingCustodianReview";
                    migrated = true;
                }
                if (string.IsNullOrEmpty(document.WorkflowStatus))
                    document.WorkflowStatus = document.WorkflowStage >= 3 ? "Submitted" : "InReview";
                                // Stage 4 means a Custodian decision was recorded, not necessarily
                                // that it was final. ReturnedForReview remains pending after reload.
                                document.IsPermanentlyStored = WorkflowEligibility.IsFinalDecision(document.WorkflowStatus)
                                        ? document.WorkflowStage >= 4 && DocumentWorkflow.VerifyReviewCompletion(document) &&
                                            DocumentWorkflow.VerifyCustodianDecision(document)
                                        : document.WorkflowStatus == "DuplicateConfirmed" && document.WorkflowStage >= 4 &&
                                            DocumentWorkflow.VerifyDuplicateResolution(document);
                document.ReviewTimerActive = false;
                migrated |= DocumentWorkflow.MigrateLegacySource(document);
                migrated |= DocumentWorkflow.EnsureContentHash(document);
            }
            ResetVaultUnlockFailures();
            if (migrated) Save();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (key.Length > 0)
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }

    public void Save()
    {
        if (_key is null || _salt is null)
        {
            throw new InvalidOperationException("Unlock the vault before saving.");
        }

        EnsureUnlocked();
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(
            new VaultData(Documents, Accounts, TransferReceipts, _bootstrapTokenSalt, _bootstrapTokenVerifier,
                _accountFailedAttempts, _accountLockoutUntilUtc, _lastLogoutReason, _lastLogoutAtUtc), _jsonOptions);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];

        try
        {
            using var aes = new AesGcm(_key, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
            var envelope = new EncryptedEnvelope(
                2,
                Convert.ToBase64String(_salt),
                Convert.ToBase64String(nonce),
                Convert.ToBase64String(tag),
                Convert.ToBase64String(ciphertext));
            var json = JsonSerializer.Serialize(envelope, _jsonOptions);
            var temporaryPath = _vaultPath + ".tmp";
            File.WriteAllText(temporaryPath, json, Encoding.UTF8);
            File.Move(temporaryPath, _vaultPath, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public void Dispose() => Lock();

    public VaultAccount ProvisionInitialCustodian(string bootstrapToken, string accountName, string password)
    {
        EnsureUnlocked();
        if (Accounts.Count != 0 || !string.IsNullOrEmpty(_bootstrapTokenVerifier))
            throw new InvalidOperationException("Initial custodian provisioning has already been completed.");
        ValidateBootstrapToken(bootstrapToken);
        ValidateAccountName(accountName);
        ValidatePassword(password);
        var externallyProvisionedToken = Environment.GetEnvironmentVariable(BootstrapTokenEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(externallyProvisionedToken) || !TokensMatch(bootstrapToken.Trim(), externallyProvisionedToken.Trim()))
            throw new UnauthorizedAccessException($"The entered token does not match the externally provisioned {BootstrapTokenEnvironmentVariable}.");
        var tokenSalt = RandomNumberGenerator.GetBytes(16);
        _bootstrapTokenSalt = Convert.ToBase64String(tokenSalt);
        _bootstrapTokenVerifier = HashSecret(bootstrapToken.Trim(), tokenSalt, KeyIterations);
        var account = CreateAccount(accountName, password, VaultRole.Custodian);
        Accounts.Add(account);
        try
        {
            Save();
        }
        catch
        {
            Accounts.Remove(account);
            _bootstrapTokenSalt = null;
            _bootstrapTokenVerifier = null;
            throw;
        }
        Environment.SetEnvironmentVariable(BootstrapTokenEnvironmentVariable, null);
        return account;
    }

    private static bool TokensMatch(string entered, string provisioned)
    {
        byte[]? enteredBytes = null;
        byte[]? provisionedBytes = null;
        try
        {
            enteredBytes = DecodeToken(entered);
            provisionedBytes = DecodeToken(provisioned);
            return enteredBytes.Length == provisionedBytes.Length &&
                   CryptographicOperations.FixedTimeEquals(enteredBytes, provisionedBytes);
        }
        catch (FormatException) { return false; }
        finally
        {
            if (enteredBytes is not null) CryptographicOperations.ZeroMemory(enteredBytes);
            if (provisionedBytes is not null) CryptographicOperations.ZeroMemory(provisionedBytes);
        }
    }

    private static byte[] DecodeToken(string token) =>
        token.Length >= 64 && token.Length % 2 == 0 && token.All(Uri.IsHexDigit)
            ? Convert.FromHexString(token)
            : Convert.FromBase64String(token);

    public VaultAccount AuthenticateAccount(string name, string password)
    {
        EnsureUnlocked();
        if (AccountLockoutRemaining > TimeSpan.Zero)
            throw new InvalidOperationException($"Local account sign-in is temporarily locked. Try again in {(int)Math.Ceiling(AccountLockoutRemaining.TotalSeconds)} seconds.");
        if (_accountFailedAttempts >= 5)
        {
            _accountFailedAttempts = 0;
            _accountLockoutUntilUtc = string.Empty;
        }
        var account = Accounts.FirstOrDefault(item => string.Equals(item.Name, name?.Trim(), StringComparison.OrdinalIgnoreCase));
        if (account is null || !account.IsEnabled || !VerifyPasswordVerifier(account, password))
        {
            _accountFailedAttempts++;
            if (_accountFailedAttempts >= 5)
                _accountLockoutUntilUtc = DateTimeOffset.UtcNow.AddSeconds(900).ToString("O");
            Save();
            throw new UnauthorizedAccessException("Account name or password is incorrect, or the account is disabled.");
        }
        _accountFailedAttempts = 0;
        _accountLockoutUntilUtc = string.Empty;
        Save();
        return account;
    }

    public void SetLastLogout(string reason)
    {
        EnsureUnlocked();
        _lastLogoutReason = string.IsNullOrWhiteSpace(reason) ? "unspecified" : reason.Trim();
        _lastLogoutAtUtc = DateTimeOffset.UtcNow.ToString("O");
        Save();
    }

    public void EncryptReviewStageTwo(VaultAccount actor, VaultDocument document, ReviewDraft draft)
    {
        EnsureUnlocked();
        DemandCurrentAnalyst(actor);
        var current = Accounts.First(item => item.Id == actor.Id);
        if (current.Role != VaultRole.Analyst)
            throw new UnauthorizedAccessException("Only an Analyst can encrypt a review.");
        DemandDocumentAccess(current, document);
        if (document.WorkflowStatus != "InReview")
            throw new InvalidOperationException("Only an active review draft can be encrypted at Stage 2.");
        DocumentWorkflow.EncryptStageTwo(document, draft);
        Save();
    }

    public void SubmitReview(VaultAccount actor, VaultDocument document)
    {
        EnsureUnlocked();
        DemandCurrentAnalyst(actor);
        var current = Accounts.First(item => item.Id == actor.Id);
        if (current.Role != VaultRole.Analyst)
            throw new UnauthorizedAccessException("Only an Analyst can submit a review.");
        DemandDocumentAccess(current, document);
        DocumentWorkflow.SubmitReview(document, current);
        Save();
    }

    public void ResumeReturnedReview(VaultAccount actor, VaultDocument document)
    {
        EnsureUnlocked();
        DemandCurrentAnalyst(actor);
        var current = Accounts.First(item => item.Id == actor.Id);
        if (current.Role != VaultRole.Analyst)
            throw new UnauthorizedAccessException("Only an Analyst can resume a returned review.");
        DemandDocumentAccess(current, document);
        if (document.WorkflowStatus == "ReturnedForReview")
        {
            document.WorkflowStatus = "InReview";
            Save();
        }
    }

    public void ApplyCustodianDecision(VaultAccount actor, VaultDocument document, string decision, string note, string password)
    {
        EnsureUnlocked();
        DemandCurrentCustodian(actor);
        var current = Accounts.First(item => item.Id == actor.Id);
        if (!VerifyAccountPassword(current, password))
            throw new UnauthorizedAccessException("The Custodian account password could not be verified.");
        DemandDocumentAccess(current, document);
        DocumentWorkflow.ApplyCustodianDecision(document, decision, note, current);
        document.IsPermanentlyStored = WorkflowEligibility.IsFinalDecision(decision) &&
                           DocumentWorkflow.VerifyReviewCompletion(document) &&
                           DocumentWorkflow.VerifyCustodianDecision(document);
        Save();
    }

    public VaultAccount CreateAccount(VaultAccount actor, string name, string password, VaultRole role)
    {
        EnsureUnlocked();
        DemandCurrentCustodian(actor);
        ValidateAccountName(name);
        ValidatePassword(password);
        if (role is not (VaultRole.Analyst or VaultRole.Custodian))
            throw new ArgumentException("Choose Analyst or Custodian.", nameof(role));
        if (Accounts.Any(item => string.Equals(item.Name, name.Trim(), StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("An account with that name already exists.");
        var account = CreateAccount(name, password, role);
        Accounts.Add(account);
        Save();
        return account;
    }

    public void SetAccountEnabled(VaultAccount actor, string accountId, bool enabled)
    {
        EnsureUnlocked();
        DemandCurrentCustodian(actor);
        var account = Accounts.FirstOrDefault(item => item.Id == accountId)
            ?? throw new InvalidOperationException("The selected account no longer exists.");
        if (!enabled && account.IsEnabled && account.Role == VaultRole.Custodian &&
            Accounts.Count(item => item.IsEnabled && item.Role == VaultRole.Custodian) <= 1)
            throw new InvalidOperationException("The last active custodian cannot be disabled.");
        account.IsEnabled = enabled;
        Save();
    }

    public void AddDocument(VaultAccount actor, VaultDocument document)
    {
        EnsureUnlocked();
        DemandCurrentAnalyst(actor);
        if (string.IsNullOrEmpty(document.ContentSha256) || document.ContentSha256.Length != 64 ||
            string.IsNullOrEmpty(document.EncryptedSource) || !string.IsNullOrEmpty(document.Text) ||
            !string.IsNullOrEmpty(document.PdfPayloadBase64) || document.WorkflowStage != 1)
            throw new InvalidOperationException("Imported source must be hash-identified and encrypted before it is added to the persistent vault.");
        var prior = Documents.FirstOrDefault(item =>
            string.Equals(item.ContentSha256, document.ContentSha256, StringComparison.OrdinalIgnoreCase));
        if (prior is not null)
        {
            document.DuplicateOfRecordId = prior.Id;
            document.DuplicateResolution = "PendingCustodianReview";
        }
        Documents.Add(document);
        Save();
    }

    public void ResolveDuplicate(VaultAccount actor, string documentId, string resolution)
    {
        EnsureUnlocked();
        DemandCurrentCustodian(actor);
        var current = Accounts.First(item => item.Id == actor.Id);
        var document = GetDocument(documentId);
        DemandDocumentAccess(current, document);
        if (document.DuplicateResolution != "PendingCustodianReview" || document.WorkflowStatus != "Submitted" ||
            document.WorkflowStage < 3 || !DocumentWorkflow.VerifyReviewCompletion(document))
            throw new InvalidOperationException("A duplicate candidate can be resolved after the Analyst submits a valid Stage 3 review.");
        DocumentWorkflow.ResolveDuplicate(document, resolution, current);
        Save();
    }

    public void RenameDocument(VaultAccount actor, string documentId, string name)
    {
        EnsureUnlocked();
        DemandCurrentAnalyst(actor);
        if (string.IsNullOrWhiteSpace(name) || name.Trim().Length > 240)
            throw new ArgumentException("Record name must be between 1 and 240 characters.", nameof(name));
        GetDocument(documentId).Name = name.Trim();
        Save();
    }

    public void SetDocumentPriority(VaultAccount actor, string documentId, int priority)
    {
        EnsureUnlocked();
        DemandCurrentCustodian(actor);
        if (priority is < 0 or > 2) throw new ArgumentOutOfRangeException(nameof(priority));
        GetDocument(documentId).RequiredPriority = priority;
        Save();
    }

    public void DeleteDocument(VaultAccount actor, string documentId)
    {
        EnsureUnlocked();
        DemandCurrentCustodian(actor);
        Documents.Remove(GetDocument(documentId));
        Save();
    }

    public int DeleteDocuments(VaultAccount actor, IEnumerable<string> documentIds)
    {
        EnsureUnlocked();
        DemandCurrentCustodian(actor);
        var ids = new HashSet<string>(documentIds.Where(id => !string.IsNullOrWhiteSpace(id)), StringComparer.Ordinal);
        if (ids.Count == 0) return 0;

        var selectedRecords = Documents.Where(document => ids.Contains(document.Id)).ToArray();
        if (selectedRecords.Length != ids.Count)
            throw new InvalidOperationException("One or more selected records no longer exist in the vault.");

        foreach (var document in selectedRecords)
            Documents.Remove(document);
        Save();
        return selectedRecords.Length;
    }

    public bool VerifyAccountPassword(VaultAccount account, string password)
    {
        var stored = Accounts.FirstOrDefault(item => item.Id == account.Id);
        return IsUnlocked && stored is { IsEnabled: true } && account.IsEnabled &&
               stored.Role == account.Role && VerifyPasswordVerifier(stored, password);
    }

    public void VerifyCustodianCredentials(VaultAccount actor, string password)
    {
        EnsureUnlocked();
        DemandCurrentCustodian(actor);
        var current = Accounts.FirstOrDefault(item => item.Id == actor.Id)
            ?? throw new UnauthorizedAccessException("Custodian account is unavailable.");
        if (!VerifyAccountPassword(current, password))
            throw new UnauthorizedAccessException("Custodian password re-authentication failed.");
    }

    public void ImportPermanentRecord(VaultAccount actor, VaultDocument document)
    {
        EnsureUnlocked();
        DemandCurrentCustodian(actor);
        if (!document.IsPermanentlyStored || document.WorkflowStage < 4 ||
            string.IsNullOrEmpty(document.ContentSha256) || string.IsNullOrEmpty(document.EncryptedSource) ||
            !string.IsNullOrEmpty(document.Text) || !string.IsNullOrEmpty(document.PdfPayloadBase64))
            throw new InvalidDataException("Only signed Stage 4 permanent records with encrypted source content can be imported.");
        if (Documents.Any(item => item.Id == document.Id))
            throw new InvalidOperationException("A record with this ID already exists in the vault.");
        Documents.Add(document);
        try { Save(); }
        catch
        {
            Documents.Remove(document);
            throw;
        }
    }

    public int ImportPermanentRecords(VaultAccount actor, IReadOnlyCollection<VaultDocument> importedRecords, string manifestSha256, string password)
    {
        EnsureUnlocked();
        DemandCurrentCustodian(actor);
        VerifyCustodianCredentials(actor, password);
        if (importedRecords.Count == 0) return 0;
        var importedIds = importedRecords.Select(record => record.Id).ToArray();
        if (importedIds.Distinct(StringComparer.Ordinal).Count() != importedIds.Length ||
            importedIds.Any(id => Documents.Any(existing => existing.Id == id)))
            throw new InvalidOperationException("The import contains duplicate record IDs or IDs already present in this vault.");
        foreach (var record in importedRecords)
        {
            if (!record.IsPermanentlyStored || record.WorkflowStage < 4 ||
                string.IsNullOrEmpty(record.ContentSha256) || string.IsNullOrEmpty(record.EncryptedSource) ||
                !string.IsNullOrEmpty(record.Text) || !string.IsNullOrEmpty(record.PdfPayloadBase64))
                throw new InvalidDataException("Every imported record must be a finalized Stage 4 record with encrypted source content.");
            if (!DocumentWorkflow.VerifyReviewCompletion(record))
                throw new CryptographicException($"Analyst Stage 3 signature did not verify for record {record.Id}.");
            var hasValidCustodianDecision = record.WorkflowStatus is "Approved" or "Rejected" &&
                                            DocumentWorkflow.VerifyCustodianDecision(record);
            var hasValidDuplicateResolution = record.WorkflowStatus == "DuplicateConfirmed" &&
                                              DocumentWorkflow.VerifyDuplicateResolution(record);
            if (!hasValidCustodianDecision && !hasValidDuplicateResolution)
                throw new CryptographicException($"Custodian Stage 4 signature did not verify for record {record.Id}.");

            var originalBytes = DocumentWorkflow.ReadSourceBytes(record);
            try
            {
                var contentHash = Convert.ToHexString(SHA256.HashData(originalBytes));
                if (!string.Equals(contentHash, record.ContentSha256, StringComparison.OrdinalIgnoreCase))
                    throw new CryptographicException($"Original content digest did not verify for record {record.Id}.");
            }
            finally { CryptographicOperations.ZeroMemory(originalBytes); }
        }

        var receipt = CreateTransferReceipt(actor, "Import", importedRecords.Count, manifestSha256);
        Documents.AddRange(importedRecords);
        TransferReceipts.Add(receipt);
        try { Save(); }
        catch
        {
            foreach (var record in importedRecords) Documents.Remove(record);
            TransferReceipts.Remove(receipt);
            throw;
        }
        return importedRecords.Count;
    }

    public VaultTransferReceipt CreateSignedTransferReceipt(VaultAccount actor, string operation, int count, string manifestSha256, string password)
    {
        EnsureUnlocked();
        DemandCurrentCustodian(actor);
        VerifyCustodianCredentials(actor, password);
        return CreateTransferReceipt(actor, operation, count, manifestSha256);
    }

    public void StoreExportReceipt(VaultAccount actor, VaultTransferReceipt receipt)
    {
        EnsureUnlocked();
        DemandCurrentCustodian(actor);
        if (receipt.Operation != "Export" || receipt.CustodianAccountId != actor.Id || !VaultTransferReceipt.Verify(receipt))
            throw new CryptographicException("The export receipt does not verify as this Custodian's signature.");
        TransferReceipts.Add(receipt);
        try { Save(); }
        catch
        {
            TransferReceipts.Remove(receipt);
            throw;
        }
    }

    private static VaultTransferReceipt CreateTransferReceipt(VaultAccount actor, string operation, int count, string manifestSha256)
    {
        if (count < 0 || manifestSha256.Length != 64 || !manifestSha256.All(Uri.IsHexDigit))
            throw new ArgumentException("Transfer manifest is invalid.");
        var receipt = new VaultTransferReceipt
        {
            Operation = operation,
            CustodianAccountId = actor.Id,
            CustodianName = actor.Name,
            OccurredAtUtc = DateTimeOffset.UtcNow.ToString("O"),
            RecordCount = count,
            ManifestSha256 = manifestSha256
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

    public void DemandDocumentAccess(VaultAccount actor, VaultDocument document)
    {
        EnsureUnlocked();
        DemandCurrentAnalyst(actor);
        VaultAccessPolicy.DemandDocumentAccess(Accounts.First(item => item.Id == actor.Id), document);
    }

    public void Lock()
    {
        ClearKey();
        _salt = null;
        Documents = new List<VaultDocument>();
        Accounts = new List<VaultAccount>();
        TransferReceipts = new List<VaultTransferReceipt>();
        _bootstrapTokenSalt = null;
        _bootstrapTokenVerifier = null;
        _accountFailedAttempts = 0;
        _accountLockoutUntilUtc = string.Empty;
        _lastLogoutReason = string.Empty;
        _lastLogoutAtUtc = string.Empty;
    }

    private static VaultAccount CreateAccount(string name, string password, VaultRole role)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        return new VaultAccount
        {
            Name = name.Trim(), Role = role,
            PasswordSalt = Convert.ToBase64String(salt),
            PasswordVerifier = HashSecret(password, salt, KeyIterations),
            PasswordIterations = KeyIterations
        };
    }

    private static bool VerifyPasswordVerifier(VaultAccount account, string password)
    {
        try
        {
            if (string.IsNullOrEmpty(password) || account.PasswordIterations < KeyIterations || account.PasswordIterations > 2_000_000) return false;
            var salt = Convert.FromBase64String(account.PasswordSalt);
            var expected = Convert.FromBase64String(account.PasswordVerifier);
            var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, account.PasswordIterations, HashAlgorithmName.SHA256, 32);
            try { return expected.Length == 32 && CryptographicOperations.FixedTimeEquals(actual, expected); }
            finally { CryptographicOperations.ZeroMemory(actual); CryptographicOperations.ZeroMemory(expected); }
        }
        catch (FormatException) { return false; }
    }

    private static string HashSecret(string secret, byte[] salt, int iterations) =>
        Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(secret, salt, iterations, HashAlgorithmName.SHA256, 32));

    private static void ValidateAccountName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Trim().Length > 120)
            throw new ArgumentException("Account name must be between 1 and 120 characters.", nameof(name));
    }

    private static void ValidatePassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 12 || password.Length > 1024)
            throw new ArgumentException("Account passwords must be at least 12 characters.", nameof(password));
    }

    private static void ValidateBootstrapToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 4096)
            throw new ArgumentException("Enter the externally generated bootstrap token.", nameof(token));
        var value = token.Trim();
        byte[] decoded;
        try
        {
            decoded = value.Length >= 64 && value.Length % 2 == 0 && value.All(Uri.IsHexDigit)
                ? Convert.FromHexString(value)
                : Convert.FromBase64String(value);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("The bootstrap token must be hex or Base64 encoding of at least 32 random bytes.", nameof(token), ex);
        }
        try
        {
            if (decoded.Length < 32) throw new ArgumentException("The bootstrap token must encode at least 32 random bytes.", nameof(token));
        }
        finally { CryptographicOperations.ZeroMemory(decoded); }
    }

    private VaultDocument GetDocument(string id) => Documents.FirstOrDefault(item => item.Id == id)
        ?? throw new InvalidOperationException("The selected record no longer exists.");

    private void DemandCurrentAnalyst(VaultAccount actor)
    {
        var stored = Accounts.FirstOrDefault(item => item.Id == actor.Id);
        if (stored is null || !stored.IsEnabled || !actor.IsEnabled || stored.Role != actor.Role)
            throw new UnauthorizedAccessException("The account is no longer active in this vault.");
        VaultAccessPolicy.DemandAnalyst(stored);
    }

    private void DemandCurrentCustodian(VaultAccount actor)
    {
        DemandCurrentAnalyst(actor);
        VaultAccessPolicy.DemandCustodian(Accounts.First(item => item.Id == actor.Id));
    }

    private void EnsureUnlocked()
    {
        if (!IsUnlocked || _salt is null) throw new InvalidOperationException("Unlock the vault before performing this action.");
    }

    private static byte[] DeriveKey(string passphrase, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, KeyIterations, HashAlgorithmName.SHA256, 32);

    private static TimeSpan RemainingUntil(string value) =>
        DateTimeOffset.TryParse(value, out var until) && until > DateTimeOffset.UtcNow
            ? until - DateTimeOffset.UtcNow
            : TimeSpan.Zero;

    private UnlockLimiterState ReadUnlockLimiter()
    {
        try
        {
            if (File.Exists(UnlockLimiterPath))
                return JsonSerializer.Deserialize<UnlockLimiterState>(File.ReadAllText(UnlockLimiterPath), _jsonOptions)
                       ?? new UnlockLimiterState(0, string.Empty);
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or UnauthorizedAccessException) { }
        return new UnlockLimiterState(0, string.Empty);
    }

    private void WriteUnlockLimiter(UnlockLimiterState state)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_vaultPath)!);
        var temporaryPath = UnlockLimiterPath + ".tmp";
        File.WriteAllText(temporaryPath, JsonSerializer.Serialize(state, _jsonOptions), Encoding.UTF8);
        File.Move(temporaryPath, UnlockLimiterPath, overwrite: true);
    }

    private void ClearKey()
    {
        if (_key is not null)
        {
            CryptographicOperations.ZeroMemory(_key);
            _key = null;
        }
    }

    private sealed record EncryptedEnvelope(int Version, string Salt, string Nonce, string Tag, string Ciphertext);
    private sealed record VaultData(
        List<VaultDocument>? Documents,
        List<VaultAccount>? Accounts,
        List<VaultTransferReceipt>? TransferReceipts,
        string? BootstrapTokenSalt,
        string? BootstrapTokenVerifier,
        int AccountFailedAttempts = 0,
        string? AccountLockoutUntilUtc = null,
        string? LastLogoutReason = null,
        string? LastLogoutAtUtc = null);
    private sealed record UnlockLimiterState(int FailedAttempts, string LockoutUntilUtc);
}
