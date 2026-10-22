using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using SecRev.Models;
using SecRev.Services;
using System;
using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Avalonia.Media.Imaging;

namespace SecRev;

public partial class MainWindow : Window
{
    private const int MaxDocumentBytes = 5_000_000;
    private const int MaxDisplayCharacters = 120_000;
    private const string DefaultLocalPdfParserEndpoint = "http://127.0.0.1:5080";
    private static readonly System.Text.Json.JsonSerializerOptions ExtractionJsonOptions = new() { PropertyNameCaseInsensitive = true };
    private readonly EncryptedVault _vault = new();
    private readonly RuntimeLog _runtimeLog = new();
    private readonly LocalPdfParserClient _localPdfParser = new();
    private readonly System.Collections.Generic.List<Bitmap> _pdfImageBitmaps = new();
        private readonly System.Collections.Generic.List<(ExtractedImage Item, Bitmap Bitmap)> _pdfImagePreviews = new();
    private readonly System.Collections.Generic.Dictionary<string, ReviewTimerState> _reviewTimers = new(StringComparer.Ordinal);
    private readonly System.Collections.Generic.HashSet<string> _sessionQueueIds = new(StringComparer.Ordinal);
    private readonly System.Collections.Generic.HashSet<string> _analystTimePromptedIds = new(StringComparer.Ordinal);
    private readonly DispatcherTimer _uiTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private Process? _localPdfServicesProcess;
    private Task? _localPdfServicesStartup;
    private bool _localPdfServicesUsesContainers;
    private long _lastActivityTimestamp;
    private string _sessionIdentity = string.Empty;
    private string? _reviewInputDocumentId;
    private int _roleLevel = 1;
    private VaultAccount? _currentAccount;
    private bool _authenticated;
    private bool _syncingSelection;
    private bool _loadingPdfVisualChecklist;
    private bool _settingVisualInspectionConfirmation;
    private bool _settingCustodianVisualInspection;
    private DateTimeOffset _lastClipboardPolicyLogUtc = DateTimeOffset.MinValue;
    private int _blockedClipboardActionCount;
    private bool _analystTimePromptOpen;
    private VaultDocument? _selectedDocument;

    public MainWindow()
    {
        InitializeComponent();
        AttachRuntimeProtections(this);
        ClipboardProtectionStatus.Text = "Active: copy, cut, and paste shortcuts and context menus are blocked inside SecRev TextBoxes. Clipboard contents are never read.";
        RuntimeLogList.ItemsSource = _runtimeLog.Entries;
        DocumentsList.ItemsSource = new ObservableCollection<VaultDocument>();
        VaultRecordsList.ItemsSource = new ObservableCollection<VaultDocument>();
        var parserEndpoint = Environment.GetEnvironmentVariable("SECREV_PDF_PARSER_ENDPOINT");
        if (string.IsNullOrWhiteSpace(parserEndpoint))
        {
            parserEndpoint = DefaultLocalPdfParserEndpoint;
            Environment.SetEnvironmentVariable("SECREV_PDF_PARSER_ENDPOINT", parserEndpoint);
        }
        PdfParserStatus.Text = IsLocalPdfParserConfigured()
            ? "Local PDF services are configured for this session."
            : "Local PDF services start automatically when you scan a PDF. No endpoint or token setup is required.";
        var version = typeof(MainWindow).Assembly.GetName().Version?.ToString(3) ?? "0.1.0";
        PrototypeFooter.Text = $"Prototype: {version} // {DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}";
        DocumentsList.IsEnabled = false;
        ImportDocumentButtonState(false);
        _uiTimer.Tick += (_, _) =>
        {
            if (_authenticated && Stopwatch.GetElapsedTime(_lastActivityTimestamp) >= TimeSpan.FromSeconds(600))
            {
                LockSession("600-second inactivity timeout", inactivityTimeout: true);
                return;
            }
            PersistRunningTimer();
            UpdateTimerDisplay();
            _ = CheckAnalystTimeManagementPromptAsync();
        };
        PointerPressed += (_, _) => MarkActivity();
        KeyDown += (_, _) => MarkActivity();
        _uiTimer.Start();
        UpdatePdfExtractionButtonState();
        ManageAccountsButton.IsVisible = false;
        AccountSessionPanel.IsVisible = false;
        ImagesVerifiedCheck.IsCheckedChanged += (_, _) => UpdateVerificationStatus();
        UpdatePdfVisualChecklistState(null, loadValues: true);
        SavePdfForLaterButton.IsVisible = false;
        AccuracyBox.TextChanged += (_, _) => RefreshStageButtons();
        ReviewNotesBox.TextChanged += (_, _) => RefreshStageButtons();
        _runtimeLog.Add("Application started. Runtime events omit document text and extracted contents.");
        NavigateTo("Unlock");
        RefreshStageButtons();
        UpdatePdfExtractionButtonState();
    }

    private void AttachRuntimeProtections(Window window)
    {
        RuntimeApplicationProtection.Attach(
            window,
            status =>
            {
                CaptureProtectionStatus.Text = status;
                _runtimeLog.Add(status);
            },
            RecordBlockedClipboardAction);
    }

    private void RecordBlockedClipboardAction(string action)
    {
        _blockedClipboardActionCount++;
        ClipboardProtectionStatus.Text = $"Active: blocked {action} in a SecRev TextBox ({_blockedClipboardActionCount} attempted action(s)); clipboard contents were not read.";
        var now = DateTimeOffset.UtcNow;
        if (now - _lastClipboardPolicyLogUtc < TimeSpan.FromSeconds(5)) return;
        _lastClipboardPolicyLogUtc = now;
        _runtimeLog.Add($"RASP blocked an in-app clipboard {action} action; clipboard contents were not accessed.");
    }

    private void UpdatePdfExtractionButtonState()
    {
        if (this.FindControl<Button>("PdfImageExtractionButton") is not { } button) return;
        var isPdfSelected = SelectedDocument is { IsPdf: true };
        button.IsEnabled = _authenticated && isPdfSelected;
        ToolTip.SetTip(button, IsLocalPdfParserConfigured()
            ? "Run the local ClamAV-gated PDF extraction."
            : "Automatically start local ClamAV/PDF extraction services, then scan and extract text, forms, and images for review.");
    }

    private bool IsLocalPdfParserConfigured()
    {
        var endpointValue = Environment.GetEnvironmentVariable("SECREV_PDF_PARSER_ENDPOINT");
        var token = Environment.GetEnvironmentVariable("SECREV_PDF_PARSER_TOKEN");
        return Uri.TryCreate(endpointValue, UriKind.Absolute, out var endpoint) && endpoint.IsLoopback &&
               (endpoint.Scheme == Uri.UriSchemeHttp || endpoint.Scheme == Uri.UriSchemeHttps) &&
               token is { Length: >= 32 };
    }

    private async Task EnsureLocalPdfServicesAsync()
    {
        if (IsLocalPdfParserConfigured())
        {
            var endpoint = Environment.GetEnvironmentVariable("SECREV_PDF_PARSER_ENDPOINT")!.TrimEnd('/');
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
                        using var response = await client.GetAsync(endpoint + "/health/ready");
                if (response.IsSuccessStatusCode) return;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException) { }
            if (Environment.GetEnvironmentVariable("SECREV_PDF_SERVICES_MANAGED") == "1")
                throw new InvalidOperationException("The container's PDF/ClamAV services are still starting (virus signatures download on each start). Retry in a minute or two.");
            Environment.SetEnvironmentVariable("SECREV_PDF_PARSER_ENDPOINT", null);
            Environment.SetEnvironmentVariable("SECREV_PDF_PARSER_TOKEN", null);
        }
        if (_localPdfServicesStartup is null || _localPdfServicesStartup.IsFaulted)
            _localPdfServicesStartup = StartLocalPdfServicesAsync();
        try
        {
            await _localPdfServicesStartup;
        }
        catch
        {
            _localPdfServicesStartup = null;
            throw;
        }
    }

    private async Task StartLocalPdfServicesAsync()
    {
        if (!OperatingSystem.IsMacOS() && !OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
            throw new InvalidOperationException("Automatic local PDF services are not supported on this operating system.");

        var scriptPath = FindLocalPdfServicesScript();
        if (scriptPath is null)
            throw new InvalidOperationException("The local PDF service launcher was not found. Run SecRev from its repository workspace, including the Azure/PdfPipeline/PdfSandbox folder.");

        if (await IsLocalPdfServiceHealthyAsync())
            throw new InvalidOperationException("A local PDF parser is already listening but does not have this app session's authentication token. Close the other parser instance and retry the scan.");

        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        Environment.SetEnvironmentVariable("SECREV_PDF_PARSER_ENDPOINT", DefaultLocalPdfParserEndpoint);
        Environment.SetEnvironmentVariable("SECREV_PDF_PARSER_TOKEN", token);
        var isContainerPlatform = OperatingSystem.IsWindows() || OperatingSystem.IsLinux();
        _localPdfServicesUsesContainers = isContainerPlatform;
        var startInfo = OperatingSystem.IsWindows()
            ? new ProcessStartInfo("powershell.exe")
            : new ProcessStartInfo("/bin/bash");
        startInfo.UseShellExecute = false;
        startInfo.CreateNoWindow = true;
        startInfo.RedirectStandardOutput = true;
        startInfo.RedirectStandardError = true;
        if (OperatingSystem.IsWindows())
        {
            startInfo.ArgumentList.Add("-NoProfile");
            startInfo.ArgumentList.Add("-ExecutionPolicy");
            startInfo.ArgumentList.Add("Bypass");
            startInfo.ArgumentList.Add("-File");
            startInfo.ArgumentList.Add(scriptPath);
            startInfo.ArgumentList.Add("-ServicesOnly");
        }
        else
        {
            startInfo.ArgumentList.Add(scriptPath);
            startInfo.ArgumentList.Add("--services-only");
        }
        startInfo.Environment["PDF_SANDBOX_TOKEN"] = token;
        startInfo.Environment["SECREV_PDF_PARSER_ENDPOINT"] = DefaultLocalPdfParserEndpoint;
        startInfo.Environment["SECREV_PDF_PARSER_TOKEN"] = token;
        _localPdfServicesProcess = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The local PDF service launcher could not be started.");
        _localPdfServicesProcess.OutputDataReceived += (_, _) => { };
        _localPdfServicesProcess.ErrorDataReceived += (_, _) => { };
        _localPdfServicesProcess.BeginOutputReadLine();
        _localPdfServicesProcess.BeginErrorReadLine();
        PdfParserStatus.Text = isContainerPlatform
            ? "Building and starting the local PDF and ClamAV containers. The first setup may take several minutes..."
            : "Starting local ClamAV and PDF extraction services. This can take a minute on first launch while signatures are prepared...";
        _runtimeLog.Add("Local PDF services startup requested; service output and document contents are not logged.");

        var deadline = DateTimeOffset.UtcNow.AddMinutes(isContainerPlatform ? 10 : 3);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (_localPdfServicesProcess.HasExited)
                throw new InvalidOperationException(isContainerPlatform
                    ? "Local PDF containers did not start. Confirm Docker Desktop (Windows) or Docker Engine (Linux) is running with Compose and Linux containers enabled."
                    : "Local PDF services did not start. Check that Homebrew ClamAV and Tesseract with English data are installed and that local ClamAV signatures are available.");
            if (await IsLocalPdfServiceHealthyAsync())
            {
                PdfParserStatus.Text = "Local ClamAV-gated PDF parser is ready. Extracted text, forms, and images are available for human review.";
                _runtimeLog.Add("Local PDF services are ready for ClamAV-gated extraction.");
                return;
            }
            await Task.Delay(TimeSpan.FromSeconds(1));
        }

        try { _localPdfServicesProcess.Kill(entireProcessTree: true); }
        catch (InvalidOperationException) { }
        throw new InvalidOperationException(isContainerPlatform
            ? "Local PDF containers did not become ready within ten minutes. Confirm Docker is running and retry."
            : "Local PDF services did not become ready within three minutes. Confirm the local ClamAV/Tesseract dependencies and signature database, then retry.");
    }

    private static async Task<bool> IsLocalPdfServiceHealthyAsync()
    {
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
                    using var response = await client.GetAsync(DefaultLocalPdfParserEndpoint + "/health/ready");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return false;
        }
    }

    private static string? FindLocalPdfServicesScript()
    {
        var scriptName = OperatingSystem.IsWindows()
            ? "run-local-container-windows.ps1"
            : OperatingSystem.IsLinux()
                ? "run-local-container-linux.sh"
                : "run-local-no-docker.sh";
        var candidates = new[] { AppContext.BaseDirectory, Environment.CurrentDirectory };
        foreach (var candidate in candidates)
        {
            var directory = new DirectoryInfo(candidate);
            while (directory is not null)
            {
                var path = Path.Combine(directory.FullName, "Azure", "PdfPipeline", "PdfSandbox", scriptName);
                if (File.Exists(path)) return path;
                directory = directory.Parent;
            }
        }
        return null;
    }

    private void StopLocalPdfContainers()
    {
        if (!_localPdfServicesUsesContainers)
            return;

        try
        {
            var scriptPath = FindLocalPdfServicesScript();
            if (scriptPath is null)
                return;

            var stopInfo = OperatingSystem.IsWindows()
                ? new ProcessStartInfo("powershell.exe")
                : new ProcessStartInfo("/bin/bash");
            stopInfo.UseShellExecute = false;
            stopInfo.CreateNoWindow = true;
            if (OperatingSystem.IsWindows())
            {
                stopInfo.ArgumentList.Add("-NoProfile");
                stopInfo.ArgumentList.Add("-ExecutionPolicy");
                stopInfo.ArgumentList.Add("Bypass");
                stopInfo.ArgumentList.Add("-File");
                stopInfo.ArgumentList.Add(scriptPath);
                stopInfo.ArgumentList.Add("-Stop");
            }
            else
            {
                stopInfo.ArgumentList.Add(scriptPath);
                stopInfo.ArgumentList.Add("--stop");
            }
            if (Process.Start(stopInfo) is { } stopProcess)
            {
                using (stopProcess)
                {
                    if (!stopProcess.WaitForExit(15_000))
                        stopProcess.Kill(entireProcessTree: true);
                }
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or IOException)
        {
            _runtimeLog.Add("Could not stop the local PDF containers automatically.");
        }
        finally
        {
            _localPdfServicesUsesContainers = false;
        }
    }

    private void OnNavigateClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string screen })
        {
            var document = SelectedDocument;
            if (screen == "Review" && document is { IsPdf: true } pdf &&
                (pdf.WorkflowStage != 1 || !pdf.Draft.ImageExtractionCompleted || !IsPdfVisualChecklistComplete(pdf.Draft)))
            {
                _ = MessageBoxAsync("Review step is not ready", "Complete the PDF extraction and required visual attestations in Inspect before opening Review.");
                return;
            }
            if (screen == "Protect" && document is { WorkflowStage: < 2 })
            {
                _ = MessageBoxAsync("Protect step is not ready", "Confirm visual inspection, complete the required review fields, and encrypt the review from Step 4 first.");
                return;
            }
            if (screen == "Complete" && document is { WorkflowStage: < 3 })
            {
                _ = MessageBoxAsync("Completion step is not ready", "Finalize and sign the Analyst review in Protect before opening Complete.");
                return;
            }
            NavigateTo(screen);
        }
    }

    private void NavigateTo(string screen)
    {
        if (screen != "Unlock" && !_authenticated)
        {
            screen = "Unlock";
        }
        UnlockScreen.IsVisible = screen == "Unlock";
        WorkspaceScreen.IsVisible = screen == "Workspace";
        InspectScreen.IsVisible = screen == "Inspect";
        ReviewScreen.IsVisible = screen == "Review";
        ProtectScreen.IsVisible = screen == "Protect";
        CompleteScreen.IsVisible = screen == "Complete";

        var steps = new[]
        {
            ("Unlock", NavUnlock, "Unlock vault"),
            ("Workspace", NavWorkspace, "Import document"),
            ("Inspect", NavInspect, "Inspect and analyze"),
            ("Review", NavReview, "Human review"),
            ("Protect", NavProtect, "Encrypt and finalize"),
            ("Complete", NavComplete, "Completion summary")
        };
        var index = Array.FindIndex(steps, step => step.Item1 == screen);
        if (index < 0)
        {
            index = 0;
            screen = "Unlock";
        }

        foreach (var step in steps)
        {
            step.Item2.Classes.Remove("active");
        }
        steps[index].Item2.Classes.Add("active");
        WorkflowProgress.Value = index;
        ProgressStepText.Text = $"Step {index + 1} of {steps.Length} · {steps[index].Item3}";
    }

    private async void OnUnlockClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            _vault.UnlockOrCreate(PassphraseBox.Text ?? string.Empty);
            PassphraseBox.Text = string.Empty;
            PassphraseBox.IsEnabled = false;
            UnlockButton.IsEnabled = false;
            AccountSessionPanel.IsVisible = true;
            BootstrapTokenBox.IsVisible = _vault.RequiresBootstrap;
            BootstrapPasswordConfirmBox.IsVisible = _vault.RequiresBootstrap;
            PrefillDemoBootstrapToken();
            AccountPrompt.Text = _vault.RequiresBootstrap
                ? "First-use setup: enter the externally generated one-time token and create the initial Custodian account."
                : "Sign in with your named local account.";
            AccountActionButton.Content = _vault.RequiresBootstrap ? "Provision first Custodian" : "Sign in";
            SessionStatus.Text = "Vault unlocked · account authentication required";
            _runtimeLog.Add("Vault passphrase accepted; waiting for local account authentication.");
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException or InvalidDataException or IOException or System.Text.Json.JsonException or FormatException)
        {
            if (ex is CryptographicException)
            {
                try { _vault.RecordVaultUnlockFailure(); }
                catch (IOException) { }
            }
            PassphraseBox.Text = string.Empty;
            SessionStatus.Text = "Vault unlock failed";
            _runtimeLog.Add("Vault unlock failed; no document content was exposed.");
            await MessageBoxAsync("Vault not unlocked", ex is CryptographicException
                ? _vault.VaultUnlockLockoutRemaining > TimeSpan.Zero
                    ? $"The passphrase could not authenticate the vault. Unlock is temporarily locked for {(int)Math.Ceiling(_vault.VaultUnlockLockoutRemaining.TotalSeconds)} seconds."
                    : "The passphrase could not authenticate the vault."
                : ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            PassphraseBox.Text = string.Empty;
            await MessageBoxAsync("Vault temporarily locked", ex.Message);
        }
    }

    // Demo-only convenience, enabled solely by the Codespaces start script; never logged.
    private void PrefillDemoBootstrapToken()
    {
        if (!_vault.RequiresBootstrap
            || Environment.GetEnvironmentVariable("SECREV_PREFILL_BOOTSTRAP_TOKEN") != "1")
            return;
        var token = Environment.GetEnvironmentVariable("SECREV_BOOTSTRAP_TOKEN");
        if (!string.IsNullOrWhiteSpace(token))
        {
            BootstrapTokenBox.Text = token.Trim();
            DemoTokenNotice.IsVisible = true;
        }
    }

    private async void OnAccountActionClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (_vault.RequiresBootstrap && !string.Equals(AccountPasswordBox.Text, BootstrapPasswordConfirmBox.Text, StringComparison.Ordinal))
                throw new ArgumentException("The initial Custodian passwords do not match.");
            var account = _vault.RequiresBootstrap
                ? _vault.ProvisionInitialCustodian(BootstrapTokenBox.Text ?? string.Empty, AccountNameBox.Text ?? string.Empty, AccountPasswordBox.Text ?? string.Empty)
                : _vault.AuthenticateAccount(AccountNameBox.Text ?? string.Empty, AccountPasswordBox.Text ?? string.Empty);
            BootstrapTokenBox.Text = string.Empty;
            AccountPasswordBox.Text = string.Empty;
            BootstrapPasswordConfirmBox.Text = string.Empty;
            AccountSessionPanel.IsVisible = false;
            StartAuthenticatedSession(account);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or UnauthorizedAccessException or CryptographicException or IOException)
        {
            BootstrapTokenBox.Text = string.Empty;
            AccountPasswordBox.Text = string.Empty;
            BootstrapPasswordConfirmBox.Text = string.Empty;
            PrefillDemoBootstrapToken();
            SessionStatus.Text = "Account authentication failed";
            _runtimeLog.Add("Local account authentication or provisioning failed.");
            await MessageBoxAsync("Account sign-in failed", ex is UnauthorizedAccessException
                ? "Account name or password is incorrect, or the account is disabled."
                : ex.Message);
        }
    }

    private void StartAuthenticatedSession(VaultAccount account)
    {
        VaultAccessPolicy.DemandAnalyst(account);
        _sessionQueueIds.Clear();
        _analystTimePromptedIds.Clear();
        _currentAccount = account;
        _sessionIdentity = account.Name;
        _roleLevel = account.Role == VaultRole.Custodian ? 2 : 1;
        _authenticated = true;
        MarkActivity();
        foreach (var record in _vault.Documents)
        {
            record.IsSelectedForBulkDelete = false;
            record.CanSelectForBulkDelete = account.Role == VaultRole.Custodian;
        }
        DocumentsList.IsEnabled = true;
        VaultRecordsList.IsVisible = account.Role == VaultRole.Custodian;
        ExportPermanentRecordsButton.IsVisible = account.Role == VaultRole.Custodian;
        ImportRecordsFolderButton.IsVisible = account.Role == VaultRole.Custodian;
        ImportDocumentButtonState(true);
        ManageAccountsButton.IsVisible = account.Role == VaultRole.Custodian;
        SessionStatus.Text = $"Signed in · {account.Name} · {account.Role}";
        if (!string.IsNullOrEmpty(_vault.LastLogoutReason))
            SessionStatus.Text += $" · previous lock: {_vault.LastLogoutReason}";
        UpdatePdfExtractionButtonState();
        RefreshDocuments();
        _runtimeLog.Add("Local account authentication succeeded; role loaded from the encrypted account record.");
        UpdateSelection();
        NavigateTo("Workspace");
    }

    private async void OnAddDocumentClick(object? sender, RoutedEventArgs e)
    {
        if (!RequireSession()) return;

        var selected = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
                    {
                        Title = "Import PDF or UTF-8 text document",
                        AllowMultiple = false,
                        FileTypeFilter = new[]
                        {
                            new FilePickerFileType("PDF and text documents") { Patterns = new[] { "*.pdf", "*.txt", "*.md", "*.csv", "*.json" } }
                        }
                    });
        if (selected.Count == 0) return;

        try
        {
            var filePath = selected[0].Path.LocalPath;
            var info = new FileInfo(filePath);
            var isPdf = string.Equals(info.Extension, ".pdf", StringComparison.OrdinalIgnoreCase);
            var maxBytes = isPdf ? PdfStaticInspector.MaxPdfBytes : MaxDocumentBytes;
            if (info.Length > maxBytes)
            {
                await MessageBoxAsync("Document too large", isPdf
                    ? $"PDF files must be {PdfStaticInspector.MaxPdfBytes / (1024 * 1024)} MiB or smaller."
                    : "Imported UTF-8 text documents must be 5 MB or smaller.");
                return;
            }
            var bytes = await File.ReadAllBytesAsync(filePath);
            try
            {
                if (isPdf)
                {
                    var inspection = PdfStaticInspector.Inspect(bytes);
                    if (!inspection.HasPdfHeader || !inspection.HasEofMarker)
                    {
                        await MessageBoxAsync("PDF validation failed", "The selected file is missing a PDF header or EOF marker. It was not imported.");
                        return;
                    }
                    var pdfDocument = new VaultDocument
                    {
                        Name = Path.GetFileName(filePath),
                        IsPdf = true,
                        PdfSha256 = inspection.Sha256,
                        PdfStaticScanReport = inspection.Report,
                        PdfLooksEncrypted = inspection.LooksEncrypted,
                        RequiredPriority = _roleLevel,
                        WorkflowStatus = "InReview"
                    };
                    DocumentWorkflow.ImportSource(pdfDocument, bytes);
                    _vault.AddDocument(_currentAccount!, pdfDocument);
                    _sessionQueueIds.Add(pdfDocument.Id);
                    RefreshDocuments();
                    DocumentsList.SelectedItem = pdfDocument;
                    SyncReviewTimer(pdfDocument);
                    _runtimeLog.Add(pdfDocument.WorkflowStatus == "DuplicatePendingCustodianReview"
                        ? "Duplicate candidate imported encrypted; custodian review is pending."
                        : $"PDF source encrypted on import; static heuristic scan recorded {inspection.RiskMarkerCategoryCount} risk-marker categor(y/ies), encrypted-marker={inspection.LooksEncrypted}.");
                    NavigateTo("Inspect");
                    if (AutoScanPdfAfterImportCheck.IsChecked == true)
                        await RunLocalPdfExtractionAsync(pdfDocument);
                    return;
                }

                _ = new UTF8Encoding(false, true).GetCharCount(bytes);
                var document = new VaultDocument
                {
                    Name = Path.GetFileName(filePath),
                    RequiredPriority = _roleLevel,
                    WorkflowStatus = "InReview"
                };
                DocumentWorkflow.ImportSource(document, bytes);
                _vault.AddDocument(_currentAccount!, document);
                _sessionQueueIds.Add(document.Id);
                RefreshDocuments();
                DocumentsList.SelectedItem = document;
                SyncReviewTimer(document);
                _runtimeLog.Add(document.WorkflowStatus == "DuplicatePendingCustodianReview"
                    ? "Duplicate candidate imported encrypted; custodian review is pending."
                    : $"UTF-8 source encrypted on import ({bytes.Length:N0} bytes); saved in the persistent vault.");
                NavigateTo("Inspect");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        catch (DecoderFallbackException)
        {
            await MessageBoxAsync("Unsupported file encoding", "Choose a valid UTF-8 text file.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or DllNotFoundException or ArgumentException or TimeoutException)
        {
            _runtimeLog.Add("Document import failed; content was not written to the runtime log.");
            await MessageBoxAsync("Import failed", ex is DllNotFoundException ? "Native analysis core is unavailable. Build the app again." : ex.Message);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _runtimeLog.Add($"Document import failed ({ex.GetType().Name}); content was not written to the runtime log.");
            await MessageBoxAsync("Import failed", "The file could not be imported or scanned due to an unexpected local error. Any imported source remains encrypted; no PDF extraction was accepted.");
        }
    }

    private void OnDocumentSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (_syncingSelection) return;
        _syncingSelection = true;
        VaultRecordsList.SelectedItem = null;
        _selectedDocument = DocumentsList.SelectedItem as VaultDocument;
        _syncingSelection = false;
        UpdateSelection();
    }

    private void OnVaultRecordSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (_syncingSelection) return;
        var selected = VaultRecordsList.SelectedItem as VaultDocument;
        var analystMayInspectDuplicate = _currentAccount?.Role == VaultRole.Analyst &&
                                         (selected?.DuplicateResolution == "PendingCustodianReview" ||
                                          selected?.WorkflowStatus == "DuplicatePendingCustodianReview");
        if (_currentAccount?.Role != VaultRole.Custodian && !analystMayInspectDuplicate)
        {
            _syncingSelection = true;
            VaultRecordsList.SelectedItem = null;
            _syncingSelection = false;
            return;
        }
        _syncingSelection = true;
        DocumentsList.SelectedItem = null;
        _selectedDocument = selected;
        _syncingSelection = false;
        UpdateSelection();
    }

    private void OnRecordBulkSelectionChanged(object? sender, RoutedEventArgs e)
    {
        if (_currentAccount?.Role != VaultRole.Custodian || sender is not CheckBox { DataContext: VaultDocument record })
            return;
        record.IsSelectedForBulkDelete = sender is CheckBox { IsChecked: true };
        BulkDeleteRecordsButton.IsEnabled = _vault.Documents.Any(item => item.IsSelectedForBulkDelete);
    }

    private VaultDocument? SelectedDocument => _selectedDocument;

    private void UpdateSelection()
    {
        var selectedId = SelectedDocument?.Id;
        if (!string.Equals(_reviewInputDocumentId, selectedId, StringComparison.Ordinal))
        {
            ClearAnalystReviewInputs();
            _reviewInputDocumentId = selectedId;
        }

        SavePdfForLaterButton.IsVisible = false;
        ComparePdfFormsButton.IsEnabled = _authenticated &&
            SelectedDocument is { IsPdf: true, WorkflowStage: < 2 } selectedPdf &&
            _sessionQueueIds.Contains(selectedPdf.Id);
        if (!_authenticated || SelectedDocument is not VaultDocument document)
        {
            SelectedRecordStatusDot.Fill = Avalonia.Media.Brushes.Gray;
            ToolTip.SetTip(SelectedRecordStatusDot, "No record selected");
            UpdatePdfVisualChecklistState(null, loadValues: true);
            MatchQueryBox.IsEnabled = false;
            SelectedDocumentTitle.Text = "No document selected";
            RecordKeyStatus.Text = "Record key: —";
            IdentityStampStatus.Text = "Identity stamp: pending";
            PolicyStatus.Text = _authenticated ? "Select a document" : "Authenticate to unlock the vault first.";
            TextDataBox.Text = PdfOcrDataBox.Text = AnalysisDataBox.Text = AnalysisReportText.Text = string.Empty;
            ClearPdfImagePreviews(string.Empty);
            ScanResult.Text = "Scan: pending";
            RefreshStageButtons();
            return;
        }

        SelectedRecordStatusDot.Fill = document.CustodianReviewStatusBrush;
        ToolTip.SetTip(SelectedRecordStatusDot, document.CustodianReviewStatusLabel);

        if (document.WorkflowStatus == "DuplicateConfirmed")
        {
            UpdatePdfVisualChecklistState(null, loadValues: true);
            MatchQueryBox.IsEnabled = false;
            SelectedDocumentTitle.Text = document.Name;
            RecordKeyStatus.Text = $"Original content SHA-256: {document.ContentSha256}";
            PolicyStatus.Text = $"Confirmed duplicate · references record {document.DuplicateOfRecordId}. No automatic deletion occurred.";
            IdentityStampStatus.Text = "Confirmed duplicate; content inspection is closed.";
            TextDataBox.Text = PdfOcrDataBox.Text = AnalysisDataBox.Text = AnalysisReportText.Text = string.Empty;
            ClearPdfImagePreviews("Confirmed duplicate. The encrypted source remains retained in the vault.");
            ScanResult.Text = "Duplicate confirmed";
            RefreshStageButtons();
            return;
        }

        var pendingDuplicate = document.DuplicateResolution == "PendingCustodianReview" ||
                       document.WorkflowStatus == "DuplicatePendingCustodianReview";
        var custodianCanReviewFromVault = _currentAccount?.Role == VaultRole.Custodian;
        if (!_sessionQueueIds.Contains(document.Id) && !pendingDuplicate && !custodianCanReviewFromVault)
        {
            UpdatePdfVisualChecklistState(null, loadValues: true);
            MatchQueryBox.IsEnabled = false;
            SelectedDocumentTitle.Text = document.Name;
            PolicyStatus.Text = "Persistent vault record · read-only until explicitly added to this session's work queue.";
            RecordKeyStatus.Text = $"Original content SHA-256: {document.ContentSha256}";
            IdentityStampStatus.Text = $"Workflow status: {document.WorkflowStatus}";
            TextDataBox.Text = PdfOcrDataBox.Text = AnalysisDataBox.Text = AnalysisReportText.Text = string.Empty;
            ClearPdfImagePreviews("Add this record to the session queue before opening source or review data.");
            ScanResult.Text = "Not in session queue";
            RefreshStageButtons();
            return;
        }

        try
        {
            _vault.DemandDocumentAccess(_currentAccount!, document);
            if (!NativeCore.CanAccess(_roleLevel, document.RequiredPriority))
            {
                UpdatePdfVisualChecklistState(null, loadValues: true);
                MatchQueryBox.IsEnabled = false;
                SelectedDocumentTitle.Text = "Access denied by native policy";
                PolicyStatus.Text = $"Denied · {_currentAccount?.Role} account, required priority P{document.RequiredPriority}.";
                var denial = $"This record requires priority P{document.RequiredPriority}; the authenticated account has priority P{_roleLevel}. Contact a custodian to review the record priority.";
                TextDataBox.Text = AnalysisDataBox.Text = AnalysisReportText.Text = denial;
                PdfOcrDataBox.Text = string.Empty;
                ClearPdfImagePreviews("Access denied by the local workflow policy.");
                ScanResult.Text = $"Access denied · required P{document.RequiredPriority}";
                RefreshStageButtons();
                return;
            }

            if (_sessionQueueIds.Contains(document.Id))
                SyncReviewTimer(document);
            MatchQueryBox.IsEnabled = true;

            SelectedDocumentTitle.Text = document.Name;
            PolicyStatus.Text = pendingDuplicate
                ? $"DUPLICATE CANDIDATE · references record {document.DuplicateOfRecordId}. Analyst analysis and Stage 3 submission are allowed before Custodian resolution. {(_sessionQueueIds.Contains(document.Id) ? "In current queue." : "Add to queue to submit.")}"
                : $"Granted · {_currentAccount?.Role} account meets required priority P{document.RequiredPriority}";
            RecordKeyStatus.Text = string.IsNullOrEmpty(document.RecordKeyId) ? "Record key: pending Stage 1" : $"Record key: {document.RecordKeyId}";
            IdentityStampStatus.Text = document.WorkflowStage >= 3
                ? $"Stage 3 Analyst completion signature {(DocumentWorkflow.VerifyReviewCompletion(document) ? "verifies" : "INVALID")} · {document.ReviewAnalystName} · {FormatStampDate(document.ReviewCompletedAtUtc)}"
                : $"Review status: {document.WorkflowStatus} · Stage 3 submission pending";
            if (document.IsPdf)
            {
                if (document.WorkflowStage >= 2) LoadReviewDraft(document);
                UpdatePdfVisualChecklistState(document, loadValues: true);
                RenderDocument(document);
                RefreshStageButtons();
                return;
            }
            UpdatePdfVisualChecklistState(null, loadValues: true);
            MatchQueryBox.IsEnabled = _sessionQueueIds.Contains(document.Id);
            LoadReviewDraft(document);
            RenderDocument(document);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or InvalidDataException or DllNotFoundException or System.Text.Json.JsonException or UnauthorizedAccessException)
        {
            UpdatePdfVisualChecklistState(null, loadValues: true);
            MatchQueryBox.IsEnabled = false;
            PolicyStatus.Text = "Document data could not be authenticated or decoded.";
            TextDataBox.Text = AnalysisDataBox.Text = AnalysisReportText.Text = "The selected record failed integrity validation.";
            PdfOcrDataBox.Text = string.Empty;
            ClearPdfImagePreviews("The selected record failed integrity validation.");
            _runtimeLog.Add("Selected record validation failed.");
        }
        RefreshStageButtons();
    }

    private void ClearAnalystReviewInputs()
    {
        AccuracyBox.Text = string.Empty;
        ReviewNotesBox.Text = string.Empty;
        MatchQueryBox.Text = string.Empty;
        AnalysisStatus.Text = "Analysis not run";
    }

    private void OnPreviewClick(object? sender, RoutedEventArgs e)
    {
        if (SelectedDocument is { DuplicateResolution: "PendingCustodianReview", IsPdf: false } textDuplicate)
        {
            if (!TryGetSelectedAccessible(out _, allowPendingDuplicateInspection: true)) return;
            TextDataBox.Text = FormatDisplay(DocumentWorkflow.ReadSourceText(textDuplicate), "Duplicate candidate source preview");
            return;
        }
        if (SelectedDocument is VaultDocument { IsPdf: true } pdf)
        {
            if (!TryGetSelectedAccessible(out _, allowPendingDuplicateInspection: true)) return;
            TextDataBox.Text = pdf.Draft.ImageExtractionCompleted
                ? (string.IsNullOrEmpty(pdf.Draft.PdfSelectableTextAndForms) ? pdf.Draft.PdfExtractedTextAndForms : pdf.Draft.PdfSelectableTextAndForms)
                : "PDF page preview is not implemented. Run clean-scan extraction to view extracted text and images. The PDF was not rendered.";
            PdfOcrDataBox.Text = pdf.Draft.PdfEmbeddedImageOcrText;
            AnalysisReportText.Text = pdf.PdfStaticScanReport;
            _runtimeLog.Add("PDF review panel opened; no source-PDF rendering was attempted.");
            return;
        }
        if (TryGetReadableDocument(out var document, out _))
        {
            RenderDocument(document);
            _runtimeLog.Add("Document preview opened after policy evaluation.");
        }
    }

    private void OnViewTextDataClick(object? sender, RoutedEventArgs e)
    {
        if (SelectedDocument is { DuplicateResolution: "PendingCustodianReview", IsPdf: false } textDuplicate)
        {
            if (!TryGetSelectedAccessible(out _, allowPendingDuplicateInspection: true)) return;
            TextDataBox.Text = FormatDisplay(DocumentWorkflow.ReadSourceText(textDuplicate), "Duplicate candidate source data");
            return;
        }
        if (SelectedDocument is VaultDocument { IsPdf: true } pdf)
        {
            if (!TryGetSelectedAccessible(out _, allowPendingDuplicateInspection: true)) return;
            TextDataBox.Text = pdf.Draft.ImageExtractionCompleted
                ? (string.IsNullOrEmpty(pdf.Draft.PdfSelectableTextAndForms) ? pdf.Draft.PdfExtractedTextAndForms : pdf.Draft.PdfSelectableTextAndForms)
                : "PDF text/form extraction requires the optional local ClamAV clean-scan flow. The static marker report is not extracted text or antivirus.\n\n" + pdf.PdfStaticScanReport;
            PdfOcrDataBox.Text = pdf.Draft.PdfEmbeddedImageOcrText;
            return;
        }
        if (!TryGetReadableDocument(out var document, out var text)) return;
        TextDataBox.Text = FormatDisplay(text, "Document text data");
        _runtimeLog.Add("Document text data displayed after policy evaluation.");
    }

    private async void OnExploitScanClick(object? sender, RoutedEventArgs e)
    {
        if (SelectedDocument is VaultDocument { IsPdf: true } pdf)
        {
            if (!TryGetSelectedAccessible(out _, allowPendingDuplicateInspection: true)) return;
            ScanResult.Text = $"Static PDF indicators: {CountPdfIndicators(pdf.PdfStaticScanReport)} · NOT ANTIVIRUS";
            AnalysisDataBox.Text = AnalysisReportText.Text = pdf.PdfStaticScanReport;
            _runtimeLog.Add("Static PDF marker report displayed; it is not an antivirus result.");
            return;
        }
        if (!TryGetReadableDocument(out var document, out var text)) return;
        try
        {
            var scan = NativeCore.Scan(text);
            document.Draft.ScanCompleted = true;
            document.Draft.ScanFindingCount = scan.FindingCount;
            document.Draft.ScanFindings = scan.FindingCount == 0
                ? "No configured string signatures found."
                : string.Join(", ", scan.Findings);
            ScanResult.Text = scan.FindingCount == 0
                ? "Heuristic scan: no configured indicators"
                : $"Heuristic scan: {scan.FindingCount} indicator(s) · {string.Join(", ", scan.Findings)}";
            _runtimeLog.Add($"Non-executing defensive signature scan completed; {scan.FindingCount} configured indicator(s).");
            RefreshReviewData(document);
            RefreshStageButtons();
        }
        catch (Exception ex) when (ex is InvalidOperationException or DllNotFoundException)
        {
            ScanResult.Text = "Scan unavailable";
            await MessageBoxAsync("Scan unavailable", ex.Message);
        }
    }

    private async void OnImageExtractionClick(object? sender, RoutedEventArgs e)
    {
        if (SelectedDocument is VaultDocument { IsPdf: true } pdf)
        {
            UpdatePdfExtractionButtonState();
            await RunLocalPdfExtractionAsync(pdf);
            return;
        }
        if (!TryGetReadableDocument(out var document, out var text)) return;
        document.Draft.Images = DocumentWorkflow.ExtractEmbeddedImages(text);
        document.Draft.ImageExtractionCompleted = true;
                AnalysisDataBox.Text = FormatImageData(document.Draft.Images);
                AnalysisReportText.Text = AnalysisDataBox.Text;
        _runtimeLog.Add($"Embedded image extraction completed; {document.Draft.Images.Count} verified image(s) found.");
        RefreshReviewData(document);
        RefreshVerificationStatus();
        RefreshStageButtons();
    }

    private async Task RunLocalPdfExtractionAsync(VaultDocument pdf)
    {
        if (!TryGetSelectedAccessible(out var selected, allowPendingDuplicateInspection: true) || selected.Id != pdf.Id) return;
        if (pdf.WorkflowStage >= 2)
        {
            await MessageBoxAsync("Review is already protected", "PDF extraction is not rerun automatically after Stage 2 encryption.");
            return;
        }

        try
        {
            await EnsureLocalPdfServicesAsync();
            ScanResult.Text = "Local ClamAV scan in progress…";
            TextDataBox.Text = "Waiting for the local antivirus clean result. Text, forms, and images are extracted only after an exact clean result.";
            var sourceBytes = DocumentWorkflow.ReadSourceBytes(pdf);
            try
            {
                var extraction = await _localPdfParser.ScanAndExtractReviewAsync(sourceBytes);
                var draft = pdf.Draft;
                draft.Images = extraction.Images;
                draft.PdfExtractedTextAndForms = extraction.TextAndForms;
                draft.PdfSelectableTextAndForms = extraction.SelectableTextAndForms;
                draft.PdfEmbeddedImageOcrText = extraction.EmbeddedImageOcrText;
                ResetPdfVisualChecklist(draft);
                ResetPdfVisualChecklist(pdf, draft);
                draft.ImageExtractionCompleted = string.Equals(extraction.ScanResult, "No threats found", StringComparison.Ordinal);
                draft.PdfMalwareScanResult = extraction.ScanResult;
                draft.PdfMalwareScanProvider = extraction.ScanProvider;
                draft.PdfImageStreamUndecodedCount = extraction.UndecodedCount;
                draft.PdfTextVerified = false;
                pdf.PdfExtractedTextVerified = false;
                pdf.PdfMalwareScanResult = extraction.ScanResult;
                pdf.PdfMalwareScanProvider = extraction.ScanProvider;
                pdf.PdfImageStreamCount = extraction.ImageStreamCount;
                pdf.PdfSelectableTextAndForms = extraction.SelectableTextAndForms;
                pdf.PdfEmbeddedImageOcrText = extraction.EmbeddedImageOcrText;
                pdf.PdfImageExtractionJson = System.Text.Json.JsonSerializer.Serialize(extraction);
                _vault.Save();
                UpdatePdfVisualChecklistState(pdf, loadValues: true);
                TextDataBox.Text = AppendOcrReference(extraction.SelectableTextAndForms, extraction.EmbeddedImageOcrText);
                PdfOcrDataBox.Text = extraction.EmbeddedImageOcrText;
                AnalysisReportText.Text = $"Local PDF extraction report\nMalware gate: {extraction.ScanResult} ({extraction.ScanProvider})\nPages: {extraction.PageCount}\nImage streams found: {extraction.ImageStreamCount}\nImages not decoded: {extraction.UndecodedCount}\n{extraction.Detail}";
                SyncReviewScreenContent(pdf);
                ScanResult.Text = $"Local malware scan: {extraction.ScanResult} · {extraction.ScanProvider}";
                RenderPdfImagePreviews(draft);
                if (draft.ImageExtractionCompleted && draft.Images.Count == 0)
                    ExtractedPdfImagesPanel.Children.Add(new TextBlock { Text = extraction.ImageStreamCount == 0
                        ? "Clean scan completed; no embedded image streams were found."
                        : $"Clean scan completed; {extraction.ImageStreamCount} stream(s) were found but no bounded preview was produced." });
                _runtimeLog.Add($"Local antivirus result recorded from {extraction.ScanProvider}; clean={draft.ImageExtractionCompleted}; decoded PDF images={draft.Images.Count}.");
                RefreshVerificationStatus();
                RefreshStageButtons();
                if (!draft.ImageExtractionCompleted)
                    await MessageBoxAsync("PDF parsing blocked", $"The local scanner did not report the required clean result. No extraction was accepted. Result: {extraction.ScanResult}.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sourceBytes);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or InvalidDataException or IOException or HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
            _runtimeLog.Add("Local malware scan/image extraction was unavailable; the PDF was not parsed.");
            await MessageBoxAsync("Local scan unavailable", ex.Message);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _runtimeLog.Add($"Local PDF operation failed ({ex.GetType().Name}); document content was not logged.");
            PdfParserStatus.Text = "Local PDF scan failed; the imported source remains encrypted.";
            await MessageBoxAsync("Local scan failed", "The local PDF/ClamAV operation failed unexpectedly. The source remains encrypted and extraction was not accepted. Check the local PDF service setup, then retry.");
        }
    }

    private async void OnComparePdfFormsClick(object? sender, RoutedEventArgs e)
    {
        if (SelectedDocument is not { IsPdf: true } filledPdf ||
            !TryGetSelectedAccessible(out var accessible, allowPendingDuplicateInspection: true) ||
            accessible.Id != filledPdf.Id)
            return;
        if (!_sessionQueueIds.Contains(filledPdf.Id))
        {
            await MessageBoxAsync("Add PDF to the session queue", "Add the filled PDF to the current session queue before comparing it with a blank reference.");
            return;
        }
        if (filledPdf.WorkflowStage >= 2)
        {
            await MessageBoxAsync("Review already protected", "Comparison is available before Stage 2 review encryption. Do not modify an already protected review.");
            return;
        }

        var references = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Select the blank reference PDF",
            AllowMultiple = false,
            FileTypeFilter = new[] { new FilePickerFileType("PDF files") { Patterns = new[] { "*.pdf" } } }
        });
        if (references.Count == 0) return;

        byte[]? blankBytes = null;
        byte[]? filledBytes = null;
        try
        {
            var blankPath = references[0].Path.LocalPath;
            var blankInfo = new FileInfo(blankPath);
            if (blankInfo.Length is <= 0 or > PdfStaticInspector.MaxPdfBytes)
                throw new InvalidDataException($"The blank reference must be between 1 byte and {PdfStaticInspector.MaxPdfBytes / (1024 * 1024)} MiB.");
            blankBytes = await File.ReadAllBytesAsync(blankPath);
            _ = PdfStaticInspector.Inspect(blankBytes);

            await EnsureLocalPdfServicesAsync();
            ScanResult.Text = "Scanning blank reference and filled PDF with local ClamAV…";
            filledBytes = DocumentWorkflow.ReadSourceBytes(filledPdf);
            if (CryptographicOperations.FixedTimeEquals(SHA256.HashData(blankBytes), SHA256.HashData(filledBytes)))
                throw new InvalidDataException("The selected reference is byte-for-byte identical to the filled PDF.");
            var blankExtraction = await _localPdfParser.ScanAndExtractReviewAsync(blankBytes);
            if (!string.Equals(blankExtraction.ScanResult, "No threats found", StringComparison.Ordinal) ||
                !string.Equals(blankExtraction.ScanProvider, "ClamAV", StringComparison.Ordinal))
                throw new InvalidDataException("The blank reference did not pass the required local ClamAV clean gate; no comparison was produced.");
            var filledExtraction = await _localPdfParser.ScanAndExtractReviewAsync(filledBytes);
            if (!string.Equals(filledExtraction.ScanResult, "No threats found", StringComparison.Ordinal) ||
                !string.Equals(filledExtraction.ScanProvider, "ClamAV", StringComparison.Ordinal))
                throw new InvalidDataException("The filled PDF did not pass the required local ClamAV clean gate; no comparison was produced.");

            var report = BuildPdfFormComparisonReport(Path.GetFileName(blankPath), blankExtraction, filledExtraction);
            var draft = filledPdf.Draft;
            draft.Images = filledExtraction.Images;
            ResetPdfVisualChecklist(draft);
            ResetPdfVisualChecklist(filledPdf, draft);
            AddPdfImageComparisonNotes(blankExtraction, filledExtraction);
            draft.PdfExtractedTextAndForms = filledExtraction.TextAndForms;
            draft.PdfSelectableTextAndForms = BuildPdfInputDifferenceText(blankExtraction, filledExtraction);
            draft.PdfEmbeddedImageOcrText = BuildPdfOcrDifferenceText(blankExtraction, filledExtraction);
            draft.ImageExtractionCompleted = true;
            draft.PdfMalwareScanResult = filledExtraction.ScanResult;
            draft.PdfMalwareScanProvider = filledExtraction.ScanProvider;
            draft.PdfImageStreamUndecodedCount = filledExtraction.UndecodedCount;
            draft.PdfComparisonReport = report;
            filledPdf.PdfComparisonReport = report;
            draft.PdfTextVerified = false;
            filledPdf.PdfExtractedTextVerified = false;
            filledPdf.PdfMalwareScanResult = filledExtraction.ScanResult;
            filledPdf.PdfMalwareScanProvider = filledExtraction.ScanProvider;
            filledPdf.PdfImageStreamCount = filledExtraction.ImageStreamCount;
            filledPdf.PdfSelectableTextAndForms = draft.PdfSelectableTextAndForms;
            filledPdf.PdfEmbeddedImageOcrText = draft.PdfEmbeddedImageOcrText;
            filledPdf.PdfImageExtractionJson = System.Text.Json.JsonSerializer.Serialize(filledExtraction);
            _vault.Save();
            UpdatePdfVisualChecklistState(filledPdf, loadValues: true);
            TextDataBox.Text = AppendOcrReference(draft.PdfSelectableTextAndForms, draft.PdfEmbeddedImageOcrText);
            PdfOcrDataBox.Text = draft.PdfEmbeddedImageOcrText;
            AnalysisReportText.Text = report;
            SyncReviewScreenContent(filledPdf);
            ScanResult.Text = $"Comparison complete · local ClamAV clean · {filledExtraction.ScanProvider}";
            RenderPdfImagePreviews(draft);
            RefreshVerificationStatus();
            RefreshStageButtons();
            _runtimeLog.Add("Blank-reference PDF comparison completed after clean local ClamAV gates; contents omitted from runtime log.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or InvalidDataException or CryptographicException or HttpRequestException or TaskCanceledException or System.Text.Json.JsonException or ArgumentException)
        {
            ScanResult.Text = "Blank/filled comparison unavailable";
            _runtimeLog.Add("Blank-reference PDF comparison failed or was blocked; contents omitted from runtime log.");
            await MessageBoxAsync("PDF comparison unavailable", ex.Message);
        }
        finally
        {
            if (blankBytes is not null) CryptographicOperations.ZeroMemory(blankBytes);
            if (filledBytes is not null) CryptographicOperations.ZeroMemory(filledBytes);
        }
    }

    private static string BuildPdfFormComparisonReport(string blankFileName, LocalPdfReviewResult blank, LocalPdfReviewResult filled)
    {
        var output = new StringBuilder();
        var blankOcr = string.Join("\n", blank.Pages.Select(page => page.OcrText));
        var filledOcr = string.Join("\n", filled.Pages.Select(page => page.OcrText));
        var blankOcrTokens = GetNormalizedPdfTokens(blankOcr);
        var filledOcrTokens = GetNormalizedPdfTokens(filledOcr);
        var newOcrTokens = filledOcrTokens.Except(blankOcrTokens, StringComparer.Ordinal).OrderBy(token => token, StringComparer.Ordinal).ToArray();
        var changedFields = GetChangedPdfFormFields(blank, filled);

        output.AppendLine("BLANK VS FILLED PDF COMPARISON · HUMAN CONFIRMATION REQUIRED");
        output.AppendLine($"Blank baseline: {blankFileName}");
        output.AppendLine($"Pages: blank {blank.PageCount} · filled {filled.PageCount}");
        output.AppendLine($"Supported AcroForm fields: blank {blank.Forms.Count} · filled {filled.Forms.Count} · changed/entered {changedFields.Length}");
        output.AppendLine($"Embedded-image OCR tokens: blank {blankOcrTokens.Count} · filled {filledOcrTokens.Count} · newly observed {newOcrTokens.Length}");
        output.AppendLine("OCR is machine-generated evidence from supported embedded images only. All OCR-matched text and form differences below require Analyst visual confirmation; this is not a semantic match or confidence score.");
        output.AppendLine();
        output.AppendLine("FORM FIELD CHANGES AND IMAGE-OCR CROSS-CHECK");
        if (changedFields.Length == 0)
        {
            output.AppendLine("No changed non-empty AcroForm values were identified. The PDF may be flattened or use unsupported form features.");
        }
        foreach (var item in changedFields)
        {
            var value = item.Field.Value ?? string.Empty;
            var normalizedValue = NormalizePdfComparisonValue(value);
            var ocrMatch = normalizedValue.Length >= 3 && NormalizePdfComparisonValue(filledOcr).Contains(normalizedValue, StringComparison.Ordinal);
            output.AppendLine($"• {(string.IsNullOrEmpty(item.Before) ? "New field" : "Changed field")} {item.Field.Name}: {(string.IsNullOrEmpty(item.Before) ? "(blank)" : item.Before)} → {(string.IsNullOrEmpty(value) ? "(cleared)" : value)} · embedded-image OCR {(ocrMatch ? "contains this value" : normalizedValue.Length < 3 ? "value is too short to cross-check reliably" : "does not contain this value; inspect the image")}");
        }

        output.AppendLine();
        output.AppendLine("NEW OCR TEXT OBSERVED AGAINST BLANK BASELINE");
        if (newOcrTokens.Length == 0)
            output.AppendLine("No new normalized OCR tokens were detected, or no embedded-image OCR was available.");
        else
            output.AppendLine(string.Join(" · ", newOcrTokens));
        output.AppendLine();
        output.AppendLine("NEW OCR TEXT BY IMAGE · review against the visible preview");
        var newOcrByImage = filled.Images
            .Where(image => image.ExtractionSource == "EmbeddedImageStream" && !string.IsNullOrWhiteSpace(image.OcrText))
            .Select((image, index) => (Image: image, Index: index + 1, NewTokens: GetNormalizedPdfTokens(image.OcrText)
                .Except(blankOcrTokens, StringComparer.Ordinal).OrderBy(token => token, StringComparer.Ordinal).ToArray()))
            .Where(item => item.NewTokens.Length > 0)
            .ToArray();
        if (newOcrByImage.Length == 0)
            output.AppendLine("No per-image OCR text differed from the blank baseline, or embedded-image OCR was unavailable.");
        foreach (var item in newOcrByImage)
            output.AppendLine($"Image {item.Index} · page {item.Image.PageNumber}: {string.Join(" · ", item.NewTokens)}");
        output.AppendLine();
        output.AppendLine("Analyze and match searches the complete extracted selectable text, supported AcroForm field names/values, and complete embedded-image OCR from the filled PDF. The image preview cards show OCR and per-image form cross-checks. Confirm any changed/new field values and OCR text against the previews before submission.");
        return output.ToString();
    }

    private void OnProceedToReviewClick(object? sender, RoutedEventArgs e)
    {
        if (SelectedDocument is not { IsPdf: true } document)
        {
            _ = MessageBoxAsync("Select a PDF", "Select an active PDF record from the Session Work Queue before proceeding to Review.");
            return;
        }
        var missing = GetMissingStageTwoRequirements(document, includeReviewFields: false);
        if (missing.Count > 0)
        {
            _ = MessageBoxAsync("PDF review checks incomplete", "Complete these items in Inspect before proceeding:\n\n• " + string.Join("\n• ", missing));
            return;
        }
        SyncReviewScreenContent(document);
        _settingVisualInspectionConfirmation = true;
        ConfirmVisualInspectionCheck.IsChecked = document.Draft.PdfVisualInspectionConfirmed;
        ConfirmVisualInspectionCheck.IsVisible = document.IsPdf;
        _settingVisualInspectionConfirmation = false;
        NavigateTo("Review");
    }

    private async void OnProceedToCustodianReviewClick(object? sender, RoutedEventArgs e)
    {
        if (!RequireSession() || _currentAccount?.Role != VaultRole.Custodian || SelectedDocument is not { } document)
            return;
        if (!WorkflowEligibility.CanCustodianReviewSubmission(_currentAccount, document, _sessionQueueIds.Contains(document.Id)))
        {
            await MessageBoxAsync("Submission not ready for Custodian review", "Add a valid Stage 3 Analyst submission to the review queue. Resolve duplicate candidates through the separate duplicate-review workflow first.");
            return;
        }

        if (document.IsPdf && (!IsPdfVisualChecklistComplete(document.Draft) || !document.Draft.PdfVisualInspectionConfirmed))
        {
            await MessageBoxAsync("Analyst attestations are incomplete", "The Custodian review transition requires the Analyst's existing PDF checklist and visual-inspection attestation to be present in the signed submission.");
            return;
        }

        SyncReviewScreenContent(document);
        ConfirmVisualInspectionCheck.IsVisible = false;
        AnalystVisualAttestationStatus.IsVisible = document.IsPdf;
        AnalystVisualAttestationStatus.Text = document.IsPdf
            ? $"Analyst Stage 3 attestations: signature valid · PDF checklist {(IsPdfVisualChecklistComplete(document.Draft) ? "complete" : "incomplete")} · visual inspection {(document.Draft.PdfVisualInspectionConfirmed ? "confirmed" : "not confirmed")}. These signed Analyst attestations are retained; the Custodian performs a separate visual confirmation below."
            : "Analyst Stage 3 submission signature is valid. Review the submitted record before the Custodian decision (persisted Stage 4).";
        CustodianVisualInspectionCheck.IsVisible = document.IsPdf;
        _settingCustodianVisualInspection = true;
        CustodianVisualInspectionCheck.IsChecked = document.CustodianVisualInspectionConfirmed;
        _settingCustodianVisualInspection = false;
        NavigateTo("Review");
    }

    private void OnCustodianVisualInspectionChanged(object? sender, RoutedEventArgs e)
    {
        if (_settingCustodianVisualInspection || _currentAccount?.Role != VaultRole.Custodian ||
            SelectedDocument is not { IsPdf: true } document || !_sessionQueueIds.Contains(document.Id))
            return;

        document.CustodianVisualInspectionConfirmed = CustodianVisualInspectionCheck.IsChecked == true;
        if (_vault.IsUnlocked) _vault.Save();
        RefreshStageButtons();
    }

    private async void OnProceedToCustodianDecisionClick(object? sender, RoutedEventArgs e)
    {
        if (!RequireSession() || _currentAccount?.Role != VaultRole.Custodian || SelectedDocument is not { } document)
            return;
        if (!WorkflowEligibility.IsCustodianDecisionReady(_currentAccount, document, _sessionQueueIds.Contains(document.Id)))
        {
            await MessageBoxAsync("Custodian review incomplete", document.IsPdf
                ? "Verify the Analyst submission and confirm your visual inspection of the PDF before proceeding to the Custodian decision (persisted Stage 4)."
                : "Select a valid Stage 3 Analyst submission in the review queue before proceeding to the Custodian decision (persisted Stage 4).");
            return;
        }

        NavigateTo("Protect");
    }

    private void OnVisualInspectionConfirmedChanged(object? sender, RoutedEventArgs e)
    {
        if (_settingVisualInspectionConfirmation || _currentAccount?.Role != VaultRole.Analyst || SelectedDocument is not { IsPdf: true } document ||
            !_sessionQueueIds.Contains(document.Id)) return;
        document.Draft.PdfVisualInspectionConfirmed = ConfirmVisualInspectionCheck.IsChecked == true;
        document.PdfVisualInspectionConfirmed = document.Draft.PdfVisualInspectionConfirmed;
        _vault.Save();
        RefreshStageButtons();
        var missing = GetMissingStageTwoRequirements(document, includeReviewFields: true);
        EncryptReviewStatus.Text = missing.Count == 0
            ? "All review requirements are complete. Confirm review and encrypt is ready."
            : "Still required:\n• " + string.Join("\n• ", missing);
    }

    private void CopyChecklistToDocument(VaultDocument document)
    {
        document.PdfBrandNameVerified = document.Draft.PdfBrandNameVerified = PdfBrandNameCheck.IsChecked == true;
        document.PdfAlcoholVolumeVerified = document.Draft.PdfAlcoholVolumeVerified = PdfAlcoholVolumeCheck.IsChecked == true;
        document.PdfGovernmentWarningVerified = document.Draft.PdfGovernmentWarningVerified = PdfGovernmentWarningCheck.IsChecked == true;
        document.PdfVisibleVerified = document.Draft.PdfVisibleVerified = PdfVisibleCheck.IsChecked == true;
        if (_vault.IsUnlocked) _vault.Save();
    }

    private void SyncReviewScreenContent(VaultDocument document)
    {
        var draft = document.Draft;
        ReviewOcrText.Text = draft.PdfEmbeddedImageOcrText;
        RefreshReviewImagesPanel(draft);
    }

    private void RefreshReviewImagesPanel(ReviewDraft draft)
    {
        ReviewImagesPanel.Children.Clear();
        foreach (var preview in _pdfImagePreviews)
        {
            ReviewImagesPanel.Children.Add(CreatePdfImagePreviewCard(preview.Item, preview.Bitmap, 150, 150));
        }
    }

    private static string BuildPdfInputDifferenceText(LocalPdfReviewResult blank, LocalPdfReviewResult filled)
    {
        var output = new StringBuilder();
        output.AppendLine("SELECTABLE TEXT DIFFERENCES FROM BLANK REFERENCE");
        var blankLines = blank.Pages.SelectMany(page => page.Text.Split('\n'))
            .Select(NormalizePdfComparisonValue).Where(line => line.Length > 0).ToHashSet(StringComparer.Ordinal);
        var differingLines = filled.Pages.SelectMany(page => page.Text.Split('\n'))
            .Where(line => NormalizePdfComparisonValue(line) is { Length: > 0 } normalized && !blankLines.Contains(normalized))
            .Distinct(StringComparer.Ordinal).ToArray();
        if (differingLines.Length == 0) output.AppendLine("No selectable-text lines differed from the blank reference.");
        else foreach (var line in differingLines) output.AppendLine(line);

        output.AppendLine();
        output.AppendLine("NEW OR CHANGED FORM FIELD VALUES");
        var changedFields = GetChangedPdfFormFields(blank, filled);
        if (changedFields.Length == 0) output.AppendLine("No changed non-empty AcroForm values were detected.");
        else foreach (var item in changedFields) output.AppendLine($"{item.Field.Name}: {item.Field.Value}");
        return output.ToString();
    }

    private static string BuildPdfOcrDifferenceText(LocalPdfReviewResult blank, LocalPdfReviewResult filled)
    {
        var output = new StringBuilder();
        output.AppendLine("TESSERACT OCR DIFFERENCES FROM BLANK REFERENCE · EMBEDDED IMAGES ONLY");
        var baselineTokens = GetNormalizedPdfTokens(string.Join("\n", blank.Images
            .Where(image => image.ExtractionSource == "EmbeddedImageStream")
            .Select(image => image.OcrText)));
        var changedCount = 0;
        var images = filled.Images
            .Where(image => image.ExtractionSource == "EmbeddedImageStream" && !string.IsNullOrWhiteSpace(image.OcrText))
            .ToArray();
        for (var index = 0; index < images.Length; index++)
        {
            var image = images[index];
            var differingTokens = System.Text.RegularExpressions.Regex.Matches(image.OcrText.ToUpperInvariant(), "[\\p{L}\\p{N}]+")
                .Select(match => match.Value)
                .Where(token => !baselineTokens.Contains(token))
                .ToArray();
            if (differingTokens.Length == 0) continue;
            changedCount++;
            output.AppendLine($"IMAGE {index + 1} · PAGE {image.PageNumber}");
            output.AppendLine(string.Join(" ", differingTokens));
        }
        if (changedCount == 0) output.AppendLine("No new OCR text differed from the blank embedded-image baseline.");
        return output.ToString();
    }

    private static string AppendOcrReference(string inputText, string ocrText) =>
        string.IsNullOrWhiteSpace(ocrText)
            ? inputText
            : $"{inputText.TrimEnd()}\n\n===== TESSERACT OCR · EMBEDDED IMAGE REFERENCE =====\n{ocrText}";

    private static (LocalPdfFormField Field, string Before)[] GetChangedPdfFormFields(LocalPdfReviewResult blank, LocalPdfReviewResult filled)
    {
        var baseline = blank.Forms
            .GroupBy(field => NormalizePdfComparisonValue(field.Name), StringComparer.Ordinal)
            .Where(group => group.Key.Length > 0)
            .ToDictionary(group => group.Key, group => group.First().Value, StringComparer.Ordinal);
        return filled.Forms
            .Select(field =>
            {
                baseline.TryGetValue(NormalizePdfComparisonValue(field.Name), out var before);
                return (Field: field, Before: before ?? string.Empty,
                    Changed: !string.Equals(NormalizePdfComparisonValue(before ?? string.Empty), NormalizePdfComparisonValue(field.Value), StringComparison.Ordinal));
            })
            .Where(item => item.Changed && !string.IsNullOrWhiteSpace(item.Field.Value))
            .Select(item => (item.Field, item.Before))
            .ToArray();
    }

    private static void AddPdfImageComparisonNotes(LocalPdfReviewResult blank, LocalPdfReviewResult filled)
    {
        var blankOcrTokens = GetNormalizedPdfTokens(string.Join("\n", blank.Pages.Select(page => page.OcrText)));
        var changedFields = GetChangedPdfFormFields(blank, filled);
        foreach (var image in filled.Images.Where(item => item.ExtractionSource == "EmbeddedImageStream"))
        {
            if (string.IsNullOrWhiteSpace(image.OcrText))
            {
                image.ComparisonNotes = "No OCR text was returned for this image. Compare the visible image manually with the extracted form values.";
                continue;
            }

            var imageTokens = GetNormalizedPdfTokens(image.OcrText);
            var newTokens = imageTokens.Except(blankOcrTokens, StringComparer.Ordinal).OrderBy(token => token, StringComparer.Ordinal).ToArray();
            var normalizedOcr = NormalizePdfComparisonValue(image.OcrText);
            var applicableFields = changedFields.Where(item => item.Field.PageNumber is null || item.Field.PageNumber == image.PageNumber).ToArray();
            var matchedFields = applicableFields
                .Where(item => NormalizePdfComparisonValue(item.Field.Value).Length >= 3 &&
                               normalizedOcr.Contains(NormalizePdfComparisonValue(item.Field.Value), StringComparison.Ordinal))
                .Select(item => $"{item.Field.Name}={item.Field.Value}")
                .ToArray();
            var unmatchedFields = applicableFields
                .Where(item => NormalizePdfComparisonValue(item.Field.Value).Length < 3 ||
                               !normalizedOcr.Contains(NormalizePdfComparisonValue(item.Field.Value), StringComparison.Ordinal))
                .Select(item => $"{item.Field.Name}={item.Field.Value}")
                .ToArray();

            image.ComparisonNotes = $"New OCR tokens vs blank: {(newTokens.Length == 0 ? "none detected" : string.Join(" · ", newTokens))}\n" +
                $"Changed form values visible in this image OCR: {(matchedFields.Length == 0 ? "none detected" : string.Join("; ", matchedFields))}\n" +
                $"Changed form values not confirmed by this image OCR: {(unmatchedFields.Length == 0 ? "none" : string.Join("; ", unmatchedFields))}. Human visual confirmation required.";
        }
    }

    private static HashSet<string> GetNormalizedPdfTokens(string text) =>
        System.Text.RegularExpressions.Regex.Matches(text.ToUpperInvariant(), "[\\p{L}\\p{N}]+")
            .Select(match => match.Value)
            .Where(token => token.Length >= 2)
            .ToHashSet(StringComparer.Ordinal);

    private static string NormalizePdfComparisonValue(string value) =>
        new(value.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

    private async void OnAnalyzeMatchClick(object? sender, RoutedEventArgs e)
    {
        var query = MatchQueryBox.Text?.Trim() ?? string.Empty;
        if (query.Length is 0 or > 256)
        {
            AnalysisStatus.Text = "Enter a match term";
            await MessageBoxAsync("Match term required", "Enter a term between 1 and 256 characters, then choose Analyze and match.");
            MatchQueryBox.Focus();
            return;
        }

        if (SelectedDocument is VaultDocument { IsPdf: true } pdf)
        {
            if (!TryGetSelectedAccessible(out _)) return;
            if (!pdf.Draft.ImageExtractionCompleted || string.IsNullOrWhiteSpace(pdf.Draft.PdfExtractedTextAndForms))
            {
                await MessageBoxAsync("PDF extraction required", "Run the local ClamAV-gated text/form/image extraction before analyzing PDF text. The static scan report is not extracted content.");
                return;
            }
            try
            {
                // TextAndForms already contains page text with embedded-image OCR appended by the parser.
                var extractedPdfText = pdf.Draft.PdfExtractedTextAndForms;
                var analysis = NativeCore.Analyze(extractedPdfText);
                var matches = NativeCore.CountMatches(extractedPdfText, query);
                pdf.Draft.WordCount = analysis.Words;
                pdf.Draft.EmailCandidates = analysis.EmailCandidates;
                pdf.Draft.NumberGroups = analysis.NumberGroups;
                pdf.Draft.MatchQuery = query;
                pdf.Draft.MatchCount = matches;
                pdf.PdfMatchQuery = query;
                pdf.PdfMatchCount = matches;
                pdf.WordCount = analysis.Words;
                pdf.EmailCandidates = analysis.EmailCandidates;
                pdf.NumberGroups = analysis.NumberGroups;
                AnalysisStatus.Text = $"{analysis.Words:N0} words · {matches:N0} match(es) across selectable text, forms & embedded-image OCR";
                AnalysisDataBox.Text = BuildAnalysisText(pdf.Draft);
                AnalysisReportText.Text = BuildAnalysisText(pdf.Draft);
                _vault.Save();
                _runtimeLog.Add("Extracted PDF text/form analysis and exact-term matching completed locally.");
                RefreshStageButtons();
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or DllNotFoundException or IOException)
            {
                AnalysisStatus.Text = "Analysis failed";
                await MessageBoxAsync("PDF analysis unavailable", ex is DllNotFoundException ? "Native analysis core is unavailable." : ex.Message);
            }
            return;
        }
        if (!TryGetReadableDocument(out var document, out var text)) return;
        try
        {
            var analysis = NativeCore.Analyze(text);
            var matches = NativeCore.CountMatches(text, query);
            document.Draft.WordCount = analysis.Words;
            document.Draft.EmailCandidates = analysis.EmailCandidates;
            document.Draft.NumberGroups = analysis.NumberGroups;
            document.Draft.MatchQuery = query;
            document.Draft.MatchCount = matches;
            document.WordCount = analysis.Words;
            document.EmailCandidates = analysis.EmailCandidates;
            document.NumberGroups = analysis.NumberGroups;
            AnalysisStatus.Text = $"{analysis.Words:N0} words · {matches:N0} exact match(es)";
            AnalysisDataBox.Text = BuildAnalysisText(document.Draft);
            AnalysisReportText.Text = BuildAnalysisText(document.Draft);
            _runtimeLog.Add("Native text analysis and case-insensitive exact-term matching completed.");
            RefreshStageButtons();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or DllNotFoundException)
        {
            AnalysisStatus.Text = "Analysis failed";
            await MessageBoxAsync("Analysis unavailable", ex is DllNotFoundException ? "Native analysis core is unavailable." : ex.Message);
        }
    }

    private async void OnEncryptStageOneClick(object? sender, RoutedEventArgs e)
    {
        if (!TryGetSelectedAccessible(out var document)) return;
        if (document.SourceMaterialDestroyed)
        {
            await MessageBoxAsync("Stage 1 already completed", "Source bytes are encrypted immediately during import; this stage cannot be repeated from the UI.");
            return;
        }
        try
        {
            DocumentWorkflow.EncryptStageOne(document);
            _vault.Save();
            RenderDocument(document);
            RecordKeyStatus.Text = $"Record key: {document.RecordKeyId}";
            _runtimeLog.Add("Stage 1 source encryption verified and saved in the encrypted vault.");
            RefreshStageButtons();
        }
        catch (Exception ex) when (ex is InvalidOperationException or CryptographicException)
        {
            await MessageBoxAsync("Stage 1 failed", ex.Message);
        }
    }

    private async void OnEncryptStageTwoClick(object? sender, RoutedEventArgs e)
    {
        if (!TryGetSelectedAccessible(out var document)) return;
        var missingRequirements = GetMissingStageTwoRequirements(document, includeReviewFields: true);
        if (missingRequirements.Count > 0)
        {
            await MessageBoxAsync("Review incomplete", "Complete these items before confirming and encrypting the review:\n\n• " + string.Join("\n• ", missingRequirements));
            return;
        }
        var accuracyText = AccuracyBox.Text?.Trim() ?? string.Empty;
        _ = int.TryParse(accuracyText, NumberStyles.None, CultureInfo.InvariantCulture, out var accuracy);
        var notes = ReviewNotesBox.Text?.Trim() ?? string.Empty;

        document.Draft.TextVerified = true;
        document.Draft.PdfTextVerified = document.IsPdf;
        document.Draft.ImagesVerified = true;
        if (document.IsPdf)
        {
            document.Draft.PdfVisualInspectionConfirmed = ConfirmVisualInspectionCheck.IsChecked == true;
            document.PdfVisualInspectionConfirmed = document.Draft.PdfVisualInspectionConfirmed;
            document.Draft.PdfBrandNameVerified = PdfBrandNameCheck.IsChecked == true;
            document.Draft.PdfAlcoholVolumeVerified = PdfAlcoholVolumeCheck.IsChecked == true;
            document.Draft.PdfGovernmentWarningVerified = PdfGovernmentWarningCheck.IsChecked == true;
            document.Draft.PdfVisibleVerified = PdfVisibleCheck.IsChecked == true;
            document.PdfBrandNameVerified = document.Draft.PdfBrandNameVerified;
            document.PdfAlcoholVolumeVerified = document.Draft.PdfAlcoholVolumeVerified;
            document.PdfGovernmentWarningVerified = document.Draft.PdfGovernmentWarningVerified;
            document.PdfVisibleVerified = document.Draft.PdfVisibleVerified;
        }
        document.Draft.AccuracyPercent = accuracy;
        document.Draft.ReviewNotes = notes;
        try
        {
            if (_currentAccount?.Role != VaultRole.Analyst)
                throw new UnauthorizedAccessException("Only an Analyst can encrypt review data.");
            _vault.EncryptReviewStageTwo(_currentAccount!, document, document.Draft);
            AnalysisDataBox.Text = BuildAnalysisText(document.Draft);
            AnalysisReportText.Text = BuildAnalysisText(document.Draft);
            _runtimeLog.Add("Stage 2 review data encrypted and saved; Analyst Stage 3 submission is still required.");
            RefreshStageButtons();
            NavigateTo("Protect");
            await MessageBoxAsync("Stage 2 complete", "Review data is encrypted. Continue in Protect to finalize and sign the Analyst submission at Stage 3.");
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or CryptographicException or System.Text.Json.JsonException or IOException)
        {
            await MessageBoxAsync("Stage 2 encryption failed", ex.Message);
        }
    }

    private async void OnSubmitReviewStageThreeClick(object? sender, RoutedEventArgs e)
    {
        if (!TryGetSelectedAccessible(out var document)) return;
        if (_currentAccount?.Role != VaultRole.Analyst)
        {
            await MessageBoxAsync("Analyst access required", "Only an Analyst can sign and submit a completed review at Stage 3.");
            return;
        }
        try
        {
            if (document.WorkflowStage != 2 || document.EncryptedReview.Length == 0)
                throw new InvalidOperationException("Encrypt the completed review at Stage 2 before Stage 3 submission.");
            var password = await PromptAccountPasswordAsync("Finalize and sign review", "Re-enter your Analyst account password to authorize the Stage 3 signature.");
            if (password is null) return;
            var passwordValid = _vault.VerifyAccountPassword(_currentAccount!, password);
            password = string.Empty;
            if (!passwordValid)
            {
                await MessageBoxAsync("Authentication failed", "The Analyst password could not be verified. The review has not been signed.");
                return;
            }
            StopTimerAndSave(document);
            _vault.SubmitReview(_currentAccount!, document);
            AnalysisDataBox.Text = BuildAnalysisText(document.Draft);
            AnalysisReportText.Text = BuildAnalysisText(document.Draft);
            _runtimeLog.Add("Analyst completed Stage 3 submission signature; review timer stopped and record awaits Custodian resolution.");
            RefreshStageButtons();
            NavigateTo("Complete");
            await MessageBoxAsync("Stage 3 submitted", "The Analyst completion signature is saved. The encrypted record is awaiting Custodian resolution and Stage 4 signature before it is marked permanent.");
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or CryptographicException or System.Text.Json.JsonException or IOException)
        {
            await MessageBoxAsync("Stage 3 submission failed", ex.Message);
        }
    }

    private async void OnCustodianDecisionClick(object? sender, RoutedEventArgs e)
    {
        if (!TryGetSelectedAccessible(out var document)) return;
        if (_currentAccount?.Role != VaultRole.Custodian)
        {
            await MessageBoxAsync("Custodian access required", "Only a Custodian can decide a submitted review.");
            return;
        }
        if (!_sessionQueueIds.Contains(document.Id))
        {
            await MessageBoxAsync("Add submission to the review queue", "Add this submitted record to the Session Work Queue before signing a Custodian decision.");
            return;
        }
        var decision = (sender as Button)?.Tag as string ?? string.Empty;
        var note = CustodianDecisionNoteBox.Text ?? string.Empty;
        var password = CustodianPasswordBox.Text ?? string.Empty;
        CustodianPasswordBox.Text = string.Empty;
        try
        {
            StopTimerAndSave(document);
            _vault.ApplyCustodianDecision(_currentAccount!, document, decision, note, password);
            _sessionQueueIds.Remove(document.Id);
            CustodianDecisionNoteBox.Text = string.Empty;
            IdentityStampStatus.Text = DocumentWorkflow.VerifyCustodianDecision(document)
                ? $"Stage 4 Custodian decision signature verifies · {decision} · {FormatStampDate(document.CustodianDecisionUtc)}"
                : "Stage 4 Custodian decision signature: INVALID";
            _runtimeLog.Add($"Custodian decision recorded and signed locally: {decision}; review timer stopped.");
            RefreshDocuments();
            _selectedDocument = document;
            UpdateSelection();
            RefreshStageButtons();
            await MessageBoxAsync("Custodian decision saved", $"The Stage 4 {decision} decision and note were signed locally after a valid Stage 3 Analyst submission. This is not a trusted identity or timestamp.");
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or UnauthorizedAccessException or CryptographicException or IOException or FormatException or System.Text.Json.JsonException)
        {
            _runtimeLog.Add("Custodian decision failed.");
            await MessageBoxAsync("Custodian decision failed", ex.Message);
        }
    }

    private async void OnDuplicateResolutionClick(object? sender, RoutedEventArgs e)
    {
        if (_currentAccount?.Role != VaultRole.Custodian || SelectedDocument is not { } document ||
            document.DuplicateResolution != "PendingCustodianReview" || document.WorkflowStatus != "Submitted" ||
            document.WorkflowStage < 3 || !DocumentWorkflow.VerifyReviewCompletion(document))
        {
            await MessageBoxAsync("Custodian review required", "The Analyst must finish and sign Stage 3 submission before Custodian duplicate resolution.");
            return;
        }

        var resolution = (sender as Button)?.Tag as string ?? string.Empty;
        try
        {
            _vault.ResolveDuplicate(_currentAccount, document.Id, resolution);
            if (resolution == "ConfirmedDuplicate") _sessionQueueIds.Remove(document.Id);
            _runtimeLog.Add(resolution == "ConfirmedDuplicate"
                ? "Custodian confirmed a duplicate record; no record was deleted."
                : "Custodian marked a duplicate candidate as not duplicate; its encrypted source remains available.");
            if (resolution == "NotDuplicate") _sessionQueueIds.Remove(document.Id);
            RefreshDocuments();
            VaultRecordsList.SelectedItem = document;
            await MessageBoxAsync("Duplicate review saved", resolution == "ConfirmedDuplicate"
                ? "The duplicate resolution was signed at Stage 4. The encrypted record is now marked permanent and no data was deleted."
                : "The record was signed as not a duplicate. It remains submitted, awaiting the Custodian's Stage 4 approve/reject/return decision.");
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or IOException or CryptographicException)
        {
            await MessageBoxAsync("Duplicate review failed", ex.Message);
        }
    }

    private void OnRemoveFromQueueClick(object? sender, RoutedEventArgs e)
    {
        if (SelectedDocument is not { } document || !_sessionQueueIds.Remove(document.Id)) return;
        StopTimerAndSave(document);
        _selectedDocument = null;
        RefreshDocuments();
        UpdateSelection();
        _runtimeLog.Add("A record ID was removed from the transient session queue; the persistent vault record was retained.");
    }

    private async void OnCustodianReviewClick(object? sender, RoutedEventArgs e)
    {
        if (!RequireSession() || _currentAccount?.Role != VaultRole.Custodian || SelectedDocument is not { } document)
            return;
        if (document.WorkflowStatus != "Submitted" || document.WorkflowStage < 3 ||
            !DocumentWorkflow.VerifyReviewCompletion(document) || document.DuplicateResolution == "PendingCustodianReview")
        {
            await MessageBoxAsync("Submission not ready for Custodian review", "Select a valid Stage 3 Analyst submission. Resolve duplicate candidates using the duplicate-review controls before an approve/reject decision.");
            return;
        }

        _sessionQueueIds.Add(document.Id);
        RefreshDocuments();
        DocumentsList.SelectedItem = document;
        _selectedDocument = document;
        UpdateSelection();
        NavigateTo("Inspect");
        _runtimeLog.Add("Custodian opened a valid submitted record for review.");
    }

    private async void OnSavePdfForLaterClick(object? sender, RoutedEventArgs e)
    {
        if (!RequireSession() || _currentAccount?.Role != VaultRole.Analyst ||
            SelectedDocument is not { IsPdf: true } document || !_sessionQueueIds.Contains(document.Id))
            return;

        if (!document.Draft.ImageExtractionCompleted || document.WorkflowStage != 1 || document.WorkflowStatus != "InReview")
        {
            await MessageBoxAsync("Cannot save this review for later", "Save For Later is available for an active Stage 1 PDF review. The encrypted record remains in the vault.");
            return;
        }

        document.PdfBrandNameVerified = PdfBrandNameCheck.IsChecked == true;
        document.PdfAlcoholVolumeVerified = PdfAlcoholVolumeCheck.IsChecked == true;
        document.PdfGovernmentWarningVerified = PdfGovernmentWarningCheck.IsChecked == true;
        document.PdfVisibleVerified = PdfVisibleCheck.IsChecked == true;
        document.Draft.PdfBrandNameVerified = document.PdfBrandNameVerified;
        document.Draft.PdfAlcoholVolumeVerified = document.PdfAlcoholVolumeVerified;
        document.Draft.PdfGovernmentWarningVerified = document.PdfGovernmentWarningVerified;
        document.Draft.PdfVisibleVerified = document.PdfVisibleVerified;
        document.IsSavedForLater = true;

        try
        {
            StopTimerAndSave(document);
            _vault.Save();
            _sessionQueueIds.Remove(document.Id);
            _selectedDocument = null;
            DocumentsList.SelectedItem = null;
            RefreshDocuments();
            UpdateSelection();
            NavigateTo("Workspace");
            _runtimeLog.Add("Analyst saved an incomplete PDF review for later; the encrypted record and extraction data remain in the persistent vault.");
            await MessageBoxAsync("PDF review saved for later", "This record and its encrypted source, extraction results, match data, and checked review items remain in the vault. It was removed from the current queue. Select it in the saved-draft list and choose Add selected to queue to resume; you can now import another document.");
            OnAddDocumentClick(sender, e);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            await MessageBoxAsync("Could not save PDF review", ex.Message);
        }
    }

    private async void OnBulkDeleteRecordsClick(object? sender, RoutedEventArgs e)
    {
        if (!RequireSession()) return;
        if (_currentAccount?.Role != VaultRole.Custodian)
        {
            await MessageBoxAsync("Custodian access required", "Only a Custodian can delete records from the persistent vault.");
            return;
        }

        var selected = _vault.Documents.Where(record => record.IsSelectedForBulkDelete).ToArray();
        if (selected.Length == 0)
        {
            await MessageBoxAsync("No records selected", "Select one or more records in the Persistent Records Vault before bulk deletion.");
            return;
        }

        var confirmed = await ConfirmAsync(
            "Delete selected vault records",
            $"Permanently remove {selected.Length} selected record(s), including any duplicate candidates, from the current encrypted vault? This cannot be undone here and does not guarantee secure erasure from backups or filesystem history.");
        if (!confirmed) return;

        try
        {
            VaultAccessPolicy.DemandCustodian(_currentAccount);
            foreach (var record in selected)
            {
                StopTimerAndSave(record);
                _sessionQueueIds.Remove(record.Id);
            }
            var deletedCount = _vault.DeleteDocuments(_currentAccount!, selected.Select(record => record.Id));
            if (_selectedDocument is not null && selected.Any(record => record.Id == _selectedDocument.Id))
                _selectedDocument = null;
            _runtimeLog.Add($"Custodian bulk-deleted {deletedCount} record(s) from the persistent vault, including any selected duplicate records.");
            RefreshDocuments();
            UpdateSelection();
            await MessageBoxAsync("Vault records deleted", $"Deleted {deletedCount} record(s). No records were deleted without this Custodian confirmation.");
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or IOException)
        {
            await MessageBoxAsync("Bulk delete failed", ex.Message);
        }
    }

    private async void OnAddToQueueClick(object? sender, RoutedEventArgs e)
    {
        if (!RequireSession() || SelectedDocument is not { } document) return;
        if (document.WorkflowStatus == "DuplicateConfirmed")
        {
            await MessageBoxAsync("Duplicate review only", "A duplicate must be resolved by a Custodian before it can enter ordinary work.");
            return;
        }
        try
        {
            _vault.DemandDocumentAccess(_currentAccount!, document);
            if (_currentAccount?.Role == VaultRole.Analyst && document.WorkflowStatus == "ReturnedForReview")
                _vault.ResumeReturnedReview(_currentAccount!, document);
            var canAddForAnalysis = _currentAccount?.Role == VaultRole.Analyst && document.WorkflowStatus == "InReview";
            var canAddForDuplicateInspection = _currentAccount?.Role == VaultRole.Analyst &&
                                               document.DuplicateResolution == "PendingCustodianReview" &&
                                               document.WorkflowStatus == "InReview";
            var canAddForDecision = _currentAccount?.Role == VaultRole.Custodian && document.WorkflowStatus == "Submitted" &&
                                    document.WorkflowStage >= 3 && DocumentWorkflow.VerifyReviewCompletion(document);
            if (!canAddForAnalysis && !canAddForDuplicateInspection && !canAddForDecision)
            {
                await MessageBoxAsync("Record is not available for this session", "Analysts can queue active/returned drafts or inspect pending duplicate candidates. Custodians can queue only valid Stage 3 submissions awaiting a decision.");
                return;
            }
            _sessionQueueIds.Add(document.Id);
            if (document.IsSavedForLater)
            {
                document.IsSavedForLater = false;
                _vault.Save();
            }
            RefreshDocuments();
            DocumentsList.SelectedItem = document;
            _selectedDocument = document;
            UpdateSelection();
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or IOException)
        {
            await MessageBoxAsync("Could not add record to queue", ex.Message);
        }
    }

    private async void OnExportPermanentRecordsClick(object? sender, RoutedEventArgs e)
    {
        if (!RequireSession()) return;
        if (_currentAccount?.Role != VaultRole.Custodian)
        {
            await MessageBoxAsync("Custodian access required", "Only a Custodian can export permanent records.");
            return;
        }
        var records = _vault.Documents.Where(record => record.IsPermanentlyStored).ToArray();
        if (records.Length == 0)
        {
            await MessageBoxAsync("No permanent records", "Only Custodian-finalized records can be exported.");
            return;
        }

        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Choose external records destination",
            AllowMultiple = false
        });
        if (folders.Count == 0) return;
        var credentials = await PromptTransferCredentialsAsync(
            "Export permanent records",
            $"Export {records.Length} record(s). Original files are exported as plaintext under their original filenames. Analysis/review packages remain encrypted. Re-enter Custodian password to sign the manifest.");
        if (credentials is null) return;

        var entries = new List<(string Name, byte[] Bytes, string RecordId, string OriginalFileName, string OriginalPath, byte[] OriginalBytes)>();
        byte[]? manifestBytes = null;
        var stagingPath = string.Empty;
        try
        {
            VaultAccessPolicy.DemandCustodian(_currentAccount);
            _vault.VerifyCustodianCredentials(_currentAccount!, credentials[2]);
            foreach (var record in records)
            {
                entries.Add((VaultRecordTransfer.GetPackageFileName(record),
                    VaultRecordTransfer.ExportPermanentRecord(record, credentials[0], _currentAccount!),
                    record.Id, record.Name, VaultRecordTransfer.GetOriginalFileRelativePath(record),
                    VaultRecordTransfer.ExportOriginalSource(record)));
            }

            var manifestFiles = entries.SelectMany(entry => new[]
            {
                (entry.Name, entry.Bytes),
                (entry.OriginalPath, entry.OriginalBytes)
            }).ToArray();
            var manifestHash = VaultRecordTransfer.ComputeManifestHash(manifestFiles);
            var receipt = _vault.CreateSignedTransferReceipt(_currentAccount!, "Export", entries.Count, manifestHash, credentials[2]);
            manifestBytes = VaultRecordTransfer.CreateManifest(receipt, entries);

            var root = folders[0].Path.LocalPath;
            var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            var folderName = $"SecRev-export-{stamp}-{Guid.NewGuid():N}";
            var destinationPath = VaultRecordTransfer.ResolveSafePathWithinRoot(root, folderName + ".bundle");
            stagingPath = VaultRecordTransfer.ResolveSafePathWithinRoot(root, folderName + ".partial");
            Directory.CreateDirectory(stagingPath);
            foreach (var entry in entries)
            {
                var packagePath = VaultRecordTransfer.ResolveSafePathWithinRoot(stagingPath, entry.Name);
                var originalPath = VaultRecordTransfer.ResolveSafePathWithinRoot(stagingPath, entry.OriginalPath);
                Directory.CreateDirectory(Path.GetDirectoryName(packagePath)!);
                Directory.CreateDirectory(Path.GetDirectoryName(originalPath)!);
                await File.WriteAllBytesAsync(packagePath, entry.Bytes);
                await File.WriteAllBytesAsync(originalPath, entry.OriginalBytes);
            }
            await File.WriteAllBytesAsync(Path.Combine(stagingPath, "manifest.json"), manifestBytes);
            Directory.Move(stagingPath, destinationPath);
            stagingPath = string.Empty;
            _vault.StoreExportReceipt(_currentAccount!, receipt);
            _runtimeLog.Add($"Custodian exported {entries.Count} permanent record(s) with originals and encrypted analysis packages.");
            await MessageBoxAsync("Export complete", $"Exported {entries.Count} record(s) to:\n{destinationPath}\n\nOriginal source files are plaintext under their original names. Analysis/review packages are encrypted. The signed manifest contains file hashes, not document content; secure the destination folder and passphrase.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or CryptographicException or ArgumentException or System.Text.Json.JsonException)
        {
            if (!string.IsNullOrEmpty(stagingPath) && Directory.Exists(stagingPath))
            {
                try { Directory.Delete(stagingPath, recursive: true); }
                catch (IOException) { }
            }
            _runtimeLog.Add("Custodian permanent-record export failed.");
            await MessageBoxAsync("Export failed", ex.Message);
        }
        finally
        {
            if (manifestBytes is not null) CryptographicOperations.ZeroMemory(manifestBytes);
            foreach (var entry in entries)
            {
                CryptographicOperations.ZeroMemory(entry.Bytes);
                CryptographicOperations.ZeroMemory(entry.OriginalBytes);
            }
            credentials[0] = credentials[1] = credentials[2] = string.Empty;
        }
    }

    private async void OnImportRecordsFolderClick(object? sender, RoutedEventArgs e)
    {
        if (!RequireSession()) return;
        if (_currentAccount?.Role != VaultRole.Custodian)
        {
            await MessageBoxAsync("Custodian access required", "Only a Custodian can import historical records.");
            return;
        }

        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Select SecRev encrypted records folder",
            AllowMultiple = false
        });
        if (folders.Count == 0) return;
        var credentials = await PromptTransferCredentialsAsync(
            "Import encrypted historical records",
            "Select an exported SecRev folder. The archive passphrase decrypts packages in memory for validation; records are then saved under this vault's encryption. Re-enter Custodian password to sign the import receipt.");
        if (credentials is null) return;

        try
        {
            VaultAccessPolicy.DemandCustodian(_currentAccount);
            var folderPath = folders[0].Path.LocalPath;
            var allRelativePaths = VaultRecordTransfer.EnumerateRegularFilesWithoutLinks(folderPath);
            var packagePaths = allRelativePaths
                .Where(path => path.EndsWith(".secrev-record.json", StringComparison.Ordinal))
                .Select(path => VaultRecordTransfer.ResolveSafePathWithinRoot(folderPath, path))
                .ToArray();
            if (packagePaths.Length == 0)
                throw new InvalidDataException("No .secrev-record.json packages were found in the selected folder.");
            if (packagePaths.Length > 100)
                throw new InvalidDataException("Import is limited to 100 records per batch.");
            var manifestPath = VaultRecordTransfer.ResolveSafePathWithinRoot(folderPath, "manifest.json");
            if (!File.Exists(manifestPath))
                throw new InvalidDataException("The signed manifest.json file is missing.");
            if (new FileInfo(manifestPath).Length is <= 0 or > 5 * 1024 * 1024)
                throw new InvalidDataException("Transfer manifest exceeds the 5 MiB limit.");
            var manifestBytes = await File.ReadAllBytesAsync(manifestPath);
            var packages = new List<(string Name, byte[] Bytes)>();
            var importedRecords = new List<VaultDocument>();
            var transferFiles = new List<(string Name, byte[] Bytes)>();
            try
            {
                var recordsInManifest = System.Text.Json.JsonSerializer.Deserialize<VaultTransferManifest>(manifestBytes)
                    ?? throw new InvalidDataException("Transfer manifest is malformed.");
                long totalTransferBytes = manifestBytes.Length;
                foreach (var path in packagePaths)
                {
                    var relative = Path.GetRelativePath(folderPath, path).Replace(Path.DirectorySeparatorChar, '/');
                    var safePath = VaultRecordTransfer.ResolveSafePathWithinRoot(folderPath, relative);
                    var info = new FileInfo(safePath);
                    if (info.Length <= 0 || info.Length > VaultRecordTransfer.MaxPackageBytes)
                        throw new InvalidDataException($"Record package '{Path.GetFileName(path)}' exceeds the supported size limit.");
                    totalTransferBytes = checked(totalTransferBytes + info.Length);
                    if (totalTransferBytes > 500L * 1024 * 1024)
                        throw new InvalidDataException("Bulk import exceeds the 500 MiB aggregate memory limit.");
                    var bytes = await File.ReadAllBytesAsync(safePath);
                    packages.Add((relative, bytes));
                    transferFiles.Add((relative, bytes));
                }
                foreach (var recordEntry in recordsInManifest.Records)
                {
                    var sourcePath = VaultRecordTransfer.ResolveSafePathWithinRoot(folderPath, recordEntry.SourceFileName);
                    var relative = Path.GetRelativePath(folderPath, sourcePath).Replace(Path.DirectorySeparatorChar, '/');
                    if (!File.Exists(sourcePath)) throw new InvalidDataException($"Original source file '{recordEntry.OriginalFileName}' is missing.");
                    var sourceInfo = new FileInfo(sourcePath);
                    if (sourceInfo.Length <= 0 || sourceInfo.Length > VaultRecordTransfer.MaxPackageBytes)
                        throw new InvalidDataException($"Original file '{recordEntry.OriginalFileName}' exceeds the supported size limit.");
                    totalTransferBytes = checked(totalTransferBytes + sourceInfo.Length);
                    if (totalTransferBytes > 500L * 1024 * 1024)
                        throw new InvalidDataException("Bulk import exceeds the 500 MiB aggregate memory limit.");
                    transferFiles.Add((relative, await File.ReadAllBytesAsync(sourcePath)));
                }

                var expectedPaths = new HashSet<string>(transferFiles.Select(file => file.Name), StringComparer.Ordinal) { "manifest.json" };
                var actualPaths = allRelativePaths.ToHashSet(StringComparer.Ordinal);
                if (!actualPaths.SetEquals(expectedPaths))
                    throw new InvalidDataException("Transfer folder contains extra or unlisted files; remove them and retry.");

                var manifest = VaultRecordTransfer.ParseAndVerifyManifest(manifestBytes, transferFiles);
                if (!string.Equals(manifest.Receipt.Operation, "Export", StringComparison.Ordinal))
                    throw new InvalidDataException("The manifest is not an export receipt.");
                if (manifest.Records is null || manifest.Records.Count != packages.Count)
                    throw new InvalidDataException("Manifest record count does not match the package set.");
                foreach (var package in packages)
                {
                    var packageHeader = System.Text.Json.JsonSerializer.Deserialize<VaultRecordPackage>(package.Bytes)
                        ?? throw new InvalidDataException($"Record package '{package.Name}' is malformed.");
                    if (!string.Equals(packageHeader.ExportedByCustodianAccountId, manifest.Receipt.CustodianAccountId, StringComparison.Ordinal) ||
                        !string.Equals(packageHeader.ExportedByCustodianName, manifest.Receipt.CustodianName, StringComparison.Ordinal))
                        throw new CryptographicException("Package export attribution does not match the signed manifest receipt.");
                    var record = VaultRecordTransfer.ImportPermanentRecord(package.Bytes, credentials[0]);
                    var manifestRecord = manifest.Records.Single(entry => entry.PackageFileName == package.Name);
                    if (!string.Equals(record.Id, manifestRecord.RecordId, StringComparison.Ordinal) ||
                        !string.Equals(record.Name, manifestRecord.OriginalFileName, StringComparison.Ordinal))
                        throw new CryptographicException("Record ID or original filename does not match the signed transfer manifest.");
                    var sourceEntry = transferFiles.Single(file => file.Name == manifestRecord.SourceFileName);
                    var sourceHash = Convert.ToHexString(SHA256.HashData(sourceEntry.Bytes));
                    if (!string.Equals(sourceHash, record.ContentSha256, StringComparison.OrdinalIgnoreCase))
                        throw new CryptographicException($"Original file '{manifestRecord.OriginalFileName}' does not match its encrypted analysis record.");
                    importedRecords.Add(record);
                }

                var duplicateIds = importedRecords.Select(record => record.Id).Distinct(StringComparer.Ordinal).Count() != importedRecords.Count;
                if (duplicateIds || importedRecords.Any(record => _vault.Documents.Any(existing => existing.Id == record.Id)))
                    throw new InvalidDataException("The batch contains repeated record IDs or records already present in this vault.");
                if (!await ConfirmAsync("Import permanent records", $"Import {importedRecords.Count} Custodian-signed permanent record(s) from '{Path.GetFileName(folderPath)}'? Original source and review payloads stay encrypted in the destination vault."))
                    return;

                _vault.ImportPermanentRecords(_currentAccount!, importedRecords, manifest.Receipt.ManifestSha256, credentials[2]);
                RefreshDocuments();
                _runtimeLog.Add($"Custodian imported {importedRecords.Count} encrypted historical record bundle(s); transfer manifest verified and import receipt signed.");
                await MessageBoxAsync("Import complete", $"Imported {importedRecords.Count} permanent record(s). Their source/review payloads are encrypted under this vault; decrypted content was only used in memory for integrity validation.");
                CryptographicOperations.ZeroMemory(manifestBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(manifestBytes);
                foreach (var package in packages) CryptographicOperations.ZeroMemory(package.Bytes);
                foreach (var file in transferFiles) CryptographicOperations.ZeroMemory(file.Bytes);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or CryptographicException or ArgumentException or System.Text.Json.JsonException)
        {
            _runtimeLog.Add("Custodian historical record import failed.");
            await MessageBoxAsync("Import failed", ex.Message);
        }
        finally
        {
            credentials[0] = credentials[1] = credentials[2] = string.Empty;
        }
    }

    private async Task<string[]?> PromptTransferCredentialsAsync(string title, string message)
    {
        var completion = new TaskCompletionSource<string[]?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var archivePassword = new TextBox { PasswordChar = '●', PlaceholderText = "Archive passphrase (12+ characters)" };
        var archivePasswordConfirm = new TextBox { PasswordChar = '●', PlaceholderText = "Confirm archive passphrase" };
        var custodianPassword = new TextBox { PasswordChar = '●', PlaceholderText = "Custodian account password" };
        var status = new TextBlock { TextWrapping = Avalonia.Media.TextWrapping.Wrap };
        var dialog = new Window
        {
            Title = title,
            Width = 520,
            SizeToContent = Avalonia.Controls.SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false
        };
        var cancel = new Button { Content = "Cancel", Classes = { "secondary" } };
        var proceed = new Button { Content = "Continue", Classes = { "action" } };
        proceed.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(archivePassword.Text) || archivePassword.Text.Length < 12 ||
                !string.Equals(archivePassword.Text, archivePasswordConfirm.Text, StringComparison.Ordinal))
            {
                status.Text = "Archive passphrases must match and contain at least 12 characters.";
                return;
            }
            if (string.IsNullOrEmpty(custodianPassword.Text))
            {
                status.Text = "Re-enter the Custodian password to authorize and sign this transfer.";
                return;
            }
            completion.TrySetResult(new[] { archivePassword.Text!, archivePasswordConfirm.Text!, custodianPassword.Text! });
            archivePassword.Text = archivePasswordConfirm.Text = custodianPassword.Text = string.Empty;
            dialog.Close();
        };
        dialog.Content = new StackPanel
        {
            Margin = new Avalonia.Thickness(20),
            Spacing = 12,
            Children =
            {
                new TextBlock { Text = message, TextWrapping = Avalonia.Media.TextWrapping.Wrap },
                archivePassword,
                archivePasswordConfirm,
                custodianPassword,
                status,
                new StackPanel { Orientation = Avalonia.Layout.Orientation.Horizontal, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right, Spacing = 8, Children = { cancel, proceed } }
            }
        };
        dialog.Closed += (_, _) => completion.TrySetResult(null);
        AttachRuntimeProtections(dialog);
        await dialog.ShowDialog(this);
        var result = await completion.Task;
        archivePassword.Text = archivePasswordConfirm.Text = custodianPassword.Text = string.Empty;
        return result;
    }

    private async void OnManageAccountsClick(object? sender, RoutedEventArgs e)
    {
        if (!RequireSession()) return;
        try 
        { 
            VaultAccessPolicy.DemandCustodian(_currentAccount); 
        }
        catch (UnauthorizedAccessException)
        {
            await MessageBoxAsync("Custodian access required", "Only a signed-in Custodian can manage local accounts.");
            return;
        }

        var accountsPanel = new StackPanel { Spacing = 8 };
        var status = new TextBlock { TextWrapping = Avalonia.Media.TextWrapping.Wrap };
        var nameBox = new TextBox { PlaceholderText = "Account name" };
        var passwordBox = new TextBox { PlaceholderText = "Initial password (12+ characters)", PasswordChar = '●' };
        var rolePicker = new ComboBox { SelectedIndex = 0, ItemsSource = new[] { "Analyst", "Custodian" } };
        void RefreshAccounts()
        {
            accountsPanel.Children.Clear();
            foreach (var managedAccount in _vault.Accounts.ToArray())
            {
                var row = new StackPanel { Orientation = Avalonia.Layout.Orientation.Horizontal, Spacing = 8 };
                row.Children.Add(new TextBlock
                {
                    Text = $"{managedAccount.Name} · {managedAccount.Role} · {(managedAccount.IsEnabled ? "Active" : "Disabled")}",
                    VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center,
                    Width = 390
                    });
                var toggle = new Button
                {
                    Content = managedAccount.IsEnabled ? "Disable" : "Enable",
                    Classes = { "secondary" }
                };
                toggle.Click += async (_, _) =>
                {
                    try
                    {
                        VaultAccessPolicy.DemandCustodian(_currentAccount);
                        if (managedAccount.Id == _currentAccount?.Id && managedAccount.IsEnabled)
                        {
                            status.Text = "Sign out before disabling the account currently in use.";
                            return;
                        }
                        _vault.SetAccountEnabled(_currentAccount!, managedAccount.Id, !managedAccount.IsEnabled);
                        _vault.Save();
                        _runtimeLog.Add("A local account was enabled or disabled by a Custodian.");
                        status.Text = "Account status saved in the encrypted vault.";
                        RefreshAccounts();
                    }
                    catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or IOException)
                    {
                        status.Text = ex.Message;
                    }
                    await Task.CompletedTask;
                };
                row.Children.Add(toggle);
                accountsPanel.Children.Add(row);
            }
        }

        var createButton = new Button { Content = "Create account", Classes = { "action" }, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Left };
        createButton.Click += (_, _) =>
        {
            try
            {
                VaultAccessPolicy.DemandCustodian(_currentAccount);
                var role = rolePicker.SelectedIndex == 1 ? VaultRole.Custodian : VaultRole.Analyst;
                _vault.CreateAccount(_currentAccount!, nameBox.Text ?? string.Empty, passwordBox.Text ?? string.Empty, role);
                passwordBox.Text = string.Empty;
                nameBox.Text = string.Empty;
                status.Text = "Account created. Its password verifier is stored inside the encrypted vault.";
                _runtimeLog.Add("A local account was created by a Custodian.");
                RefreshAccounts();
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or UnauthorizedAccessException or IOException)
            {
                passwordBox.Text = string.Empty;
                status.Text = ex.Message;
            }
        };

        RefreshAccounts();
        var manager = new Window
        {
            Title = "Local account manager",
            Width = 560,
            Height = 620,
            MinHeight = 480,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = new ScrollViewer
            {
                Content = new StackPanel
                {
                    Margin = new Avalonia.Thickness(20),
                    Spacing = 12,
                    Children =
                    {
                        new TextBlock { Text = "Accounts", FontSize = 18, FontWeight = Avalonia.Media.FontWeight.Bold },
                        accountsPanel,
                        new TextBlock { Text = "Create account", FontSize = 16, FontWeight = Avalonia.Media.FontWeight.SemiBold, Margin = new Avalonia.Thickness(0, 8, 0, 0) },
                        nameBox, passwordBox, rolePicker, createButton, status
                    }
                }
            }
        };
        AttachRuntimeProtections(manager);
        await manager.ShowDialog(this);
    }

    private async void OnManageRecordClick(object? sender, RoutedEventArgs e)
    {
        if (!TryGetSelectedAccessible(out var document)) return;
        if (_currentAccount?.Role != VaultRole.Custodian && !_sessionQueueIds.Contains(document.Id))
        {
            await MessageBoxAsync("Queue record first", "Analysts must add a persistent record to the current Session Work Queue before editing its metadata.");
            return;
        }
        var nameBox = new TextBox { Text = document.Name };
        var priorityPicker = new ComboBox
        {
            SelectedIndex = document.RequiredPriority,
            ItemsSource = new[] { "P0 · General", "P1 · Analyst", "P2 · Custodian" },
            IsVisible = _currentAccount?.Role == VaultRole.Custodian
        };
        var status = new TextBlock { TextWrapping = Avalonia.Media.TextWrapping.Wrap };
        var recordDialog = new Window
        {
            Title = "Manage record metadata",
            Width = 480,
            SizeToContent = Avalonia.Controls.SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false
        };
        var saveButton = new Button { Content = "Save metadata", Classes = { "action" }, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Left };
        saveButton.Click += (_, _) =>
        {
            try
            {
                _vault.DemandDocumentAccess(_currentAccount!, document);
                _vault.RenameDocument(_currentAccount!, document.Id, nameBox.Text ?? string.Empty);
                if (_currentAccount?.Role == VaultRole.Custodian)
                    _vault.SetDocumentPriority(_currentAccount, document.Id, priorityPicker.SelectedIndex);
                _vault.Save();
                _runtimeLog.Add("Record metadata was updated by an authenticated account.");
                RefreshDocuments();
                DocumentsList.SelectedItem = document;
                recordDialog.Close();
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or UnauthorizedAccessException or IOException)
            {
                status.Text = ex.Message;
            }
        };
        var actions = new StackPanel { Orientation = Avalonia.Layout.Orientation.Horizontal, Spacing = 8 };
        actions.Children.Add(saveButton);
        if (_currentAccount?.Role == VaultRole.Custodian)
        {
            var deleteButton = new Button { Content = "Delete record", Classes = { "secondary" } };
            deleteButton.Click += async (_, _) =>
            {
                if (!await ConfirmAsync("Delete record", "Permanently remove this record from the current encrypted vault? This does not guarantee secure erasure from filesystem history or backups.")) return;
                try
                {
                    VaultAccessPolicy.DemandCustodian(_currentAccount);
                    _vault.DeleteDocument(_currentAccount!, document.Id);
                    _runtimeLog.Add("A vault record was deleted by a Custodian.");
                    RefreshDocuments();
                    DocumentsList.SelectedItem = null;
                    UpdateSelection();
                    recordDialog.Close();
                }
                catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or IOException)
                {
                    status.Text = ex.Message;
                }
            };
            actions.Children.Add(deleteButton);
        }
        recordDialog.Content = new StackPanel
        {
            Margin = new Avalonia.Thickness(20),
            Spacing = 12,
            Children =
            {
                new TextBlock { Text = "Record name", FontWeight = Avalonia.Media.FontWeight.SemiBold },
                nameBox,
                new TextBlock { Text = "Required priority (Custodian only)", FontWeight = Avalonia.Media.FontWeight.SemiBold, IsVisible = priorityPicker.IsVisible },
                priorityPicker,
                actions,
                status
            }
        };
        AttachRuntimeProtections(recordDialog);
        await recordDialog.ShowDialog(this);
    }

    private async Task<bool> ConfirmAsync(string title, string message)
    {
        var dialog = new Window
        {
            Title = title,
            Width = 440,
            SizeToContent = Avalonia.Controls.SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false
        };
        var buttons = new StackPanel { Orientation = Avalonia.Layout.Orientation.Horizontal, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right, Spacing = 8 };
        var cancel = new Button { Content = "Cancel", Classes = { "secondary" } };
        var confirm = new Button { Content = "Confirm", Classes = { "action" } };
        cancel.Click += (_, _) => dialog.Close(false);
        confirm.Click += (_, _) => dialog.Close(true);
        buttons.Children.Add(cancel);
        buttons.Children.Add(confirm);
        dialog.Content = new StackPanel
        {
            Margin = new Avalonia.Thickness(20),
            Spacing = 16,
            Children = { new TextBlock { Text = message, TextWrapping = Avalonia.Media.TextWrapping.Wrap }, buttons }
        };
        AttachRuntimeProtections(dialog);
        return await dialog.ShowDialog<bool>(this);
    }

    private async Task<bool> PromptAnalystTimeManagementAsync()
    {
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var dialog = new Window
        {
            Title = "Five-minute review check-in",
            Width = 520,
            SizeToContent = Avalonia.Controls.SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false
        };
        var continueButton = new Button { Content = "No, continue working", Classes = { "secondary" } };
        var nextButton = new Button { Content = "Yes, Begin new record", Classes = { "action" } };
        continueButton.Click += (_, _) =>
        {
            completion.TrySetResult(false);
            dialog.Close();
        };
        nextButton.Click += (_, _) =>
        {
            completion.TrySetResult(true);
            dialog.Close();
        };
        dialog.Content = new StackPanel
        {
            Margin = new Avalonia.Thickness(20),
            Spacing = 16,
            Children =
            {
                new TextBlock
                {
                    Text = "You have been working on this record for 5 mins, would you like to save record for later and move on to next record?",
                    TextWrapping = Avalonia.Media.TextWrapping.Wrap
                },
                new StackPanel
                {
                    Orientation = Avalonia.Layout.Orientation.Horizontal,
                    HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right,
                    Spacing = 8,
                    Children = { continueButton, nextButton }
                }
            }
        };
        dialog.Closed += (_, _) => completion.TrySetResult(false);
        AttachRuntimeProtections(dialog);
        await dialog.ShowDialog(this);
        return await completion.Task;
    }

    private async Task CheckAnalystTimeManagementPromptAsync()
    {
        if (_analystTimePromptOpen || SelectedDocument is not { } document)
            return;

        var timerIsRunning = _reviewTimers.TryGetValue(document.Id, out var timer);
        var elapsed = timerIsRunning
            ? timer!.Stopwatch.Elapsed
            : TimeSpan.Zero;
        var alreadyPrompted = _analystTimePromptedIds.Contains(document.Id);
        if (!AnalystTimeManagementPolicy.ShouldPrompt(_currentAccount?.Role, document.WorkflowStatus,
                _sessionQueueIds.Contains(document.Id), timerIsRunning, elapsed, alreadyPrompted) ||
            !_analystTimePromptedIds.Add(document.Id))
            return;

        _analystTimePromptOpen = true;
        try
        {
            _runtimeLog.Add("Analyst five-minute record time-management prompt displayed.");
            if (await PromptAnalystTimeManagementAsync())
                await SaveAnalystRecordForLaterAndBeginNextAsync(document);
            else
                _runtimeLog.Add("Analyst chose to continue reviewing the current record.");
        }
        finally
        {
            _analystTimePromptOpen = false;
        }
    }

    private async Task SaveAnalystRecordForLaterAndBeginNextAsync(VaultDocument document)
    {
        if (_currentAccount?.Role != VaultRole.Analyst || SelectedDocument?.Id != document.Id ||
            !_sessionQueueIds.Contains(document.Id) || document.WorkflowStatus != "InReview")
            return;

        document.Draft.MatchQuery = MatchQueryBox.Text?.Trim() ?? string.Empty;
        document.Draft.ImagesVerified = ImagesVerifiedCheck.IsChecked == true;
        if (int.TryParse(AccuracyBox.Text?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var accuracy) && accuracy is >= 0 and <= 100)
            document.Draft.AccuracyPercent = accuracy;
        document.Draft.ReviewNotes = ReviewNotesBox.Text?.Trim() ?? string.Empty;
        if (document.IsPdf)
        {
            document.Draft.PdfBrandNameVerified = PdfBrandNameCheck.IsChecked == true;
            document.Draft.PdfAlcoholVolumeVerified = PdfAlcoholVolumeCheck.IsChecked == true;
            document.Draft.PdfGovernmentWarningVerified = PdfGovernmentWarningCheck.IsChecked == true;
            document.Draft.PdfVisibleVerified = PdfVisibleCheck.IsChecked == true;
            document.PdfBrandNameVerified = document.Draft.PdfBrandNameVerified;
            document.PdfAlcoholVolumeVerified = document.Draft.PdfAlcoholVolumeVerified;
            document.PdfGovernmentWarningVerified = document.Draft.PdfGovernmentWarningVerified;
            document.PdfVisibleVerified = document.Draft.PdfVisibleVerified;
            document.Draft.PdfVisualInspectionConfirmed = ConfirmVisualInspectionCheck.IsChecked == true;
            document.PdfVisualInspectionConfirmed = document.Draft.PdfVisualInspectionConfirmed;
        }

        try
        {
            DocumentWorkflow.EncryptWorkingDraft(document, document.Draft);
            document.IsSavedForLater = true;
            StopTimerAndSave(document);
            _vault.Save();
            _sessionQueueIds.Remove(document.Id);
            _selectedDocument = null;
            DocumentsList.SelectedItem = null;
            RefreshDocuments();

            var nextRecord = _vault.Documents.FirstOrDefault(record => _sessionQueueIds.Contains(record.Id) &&
                record.WorkflowStatus is "InReview" or "ReturnedForReview");
            if (nextRecord is not null)
            {
                _selectedDocument = nextRecord;
                DocumentsList.SelectedItem = nextRecord;
                UpdateSelection();
                NavigateTo("Inspect");
            }
            else
            {
                UpdateSelection();
                NavigateTo("Workspace");
                _runtimeLog.Add("Analyst began a new document task after saving the current encrypted working draft.");
                OnAddDocumentClick(this, new RoutedEventArgs());
                return;
            }

            _runtimeLog.Add("Analyst saved the current working draft in per-record authenticated encryption and began the next queued record.");
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or CryptographicException or System.Text.Json.JsonException)
        {
            await MessageBoxAsync("Could not save review for later", ex.Message);
        }
    }

    private void OnLogoutClick(object? sender, RoutedEventArgs e)
    {
        LockSession("manual sign-out", inactivityTimeout: false);
    }

    private void LockSession(string reason, bool inactivityTimeout)
    {
        try
        {
            StopTimerAndSave();
            if (_vault.IsUnlocked)
            {
                _vault.SetLastLogout(reason);
            }
            _sessionQueueIds.Clear();
            _analystTimePromptedIds.Clear();
            _selectedDocument = null;
            _vault.Lock();
            _authenticated = false;
            _currentAccount = null;
            _sessionIdentity = string.Empty;
            _roleLevel = 1;
            DocumentsList.SelectedItem = null;
            DocumentsList.ItemsSource = new ObservableCollection<VaultDocument>();
            VaultRecordsList.SelectedItem = null;
            VaultRecordsList.ItemsSource = new ObservableCollection<VaultDocument>();
            VaultRecordsList.IsVisible = false;
            DocumentsList.IsEnabled = false;
            AccountSessionPanel.IsVisible = false;
            BootstrapTokenBox.IsVisible = false;
            BootstrapTokenBox.Text = AccountNameBox.Text = AccountPasswordBox.Text = PassphraseBox.Text = string.Empty;
            BootstrapPasswordConfirmBox.Text = CustodianPasswordBox.Text = CustodianDecisionNoteBox.Text = string.Empty;
            AccuracyBox.Text = ReviewNotesBox.Text = MatchQueryBox.Text = string.Empty;
            PassphraseBox.IsEnabled = true;
            UnlockButton.IsEnabled = true;
            ManageAccountsButton.IsVisible = false;
            ExportPermanentRecordsButton.IsVisible = false;
            ImportRecordsFolderButton.IsVisible = false;
            ManageRecordButton.IsEnabled = false;
            AddToQueueButton.IsEnabled = false;
            RemoveFromQueueButton.IsEnabled = false;
            SavePdfForLaterButton.IsVisible = false;
            EncryptReviewButton.IsEnabled = false;
            ConfirmVisualInspectionCheck.IsChecked = false;
            ConfirmVisualInspectionCheck.IsVisible = false;
            PdfBrandNameCheck.IsChecked = PdfAlcoholVolumeCheck.IsChecked = false;
            PdfGovernmentWarningCheck.IsChecked = PdfVisibleCheck.IsChecked = false;
            ImportDocumentButtonState(false);
            SessionStatus.Text = inactivityTimeout ? "Locked · 600-second inactivity timeout" : "Locked · sign in to switch user";
            DocumentCount.Text = "No documents loaded";
            SelectedDocumentTitle.Text = "No document selected";
            PolicyStatus.Text = "Authenticate to open access";
            RecordKeyStatus.Text = "Record key: —";
            IdentityStampStatus.Text = "Identity stamp: pending";
            TextDataBox.Text = AnalysisDataBox.Text = string.Empty;
            ScanResult.Text = "Scan: pending";
            AnalysisStatus.Text = "Analysis not run";
            TimerStatus.Text = "Timer stopped";
            TimerDisplay.Text = "00:00:00";
            CompletionSummary.Text = "Select a record to view its workflow status.";
            ImagesVerifiedCheck.IsChecked = false;
            ClearPdfImagePreviews(string.Empty);
            _runtimeLog.Entries.Clear();
            UpdatePdfExtractionButtonState();
            RefreshStageButtons();
            _runtimeLog.Add(inactivityTimeout
                ? "Session locked after 600 seconds of inactivity; decrypted UI was cleared."
                : "Signed-out account session cleared and vault key locked.");
            NavigateTo("Unlock");
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            _ = MessageBoxAsync("Could not lock vault", ex.Message);
        }
    }

    private async void OnRestartClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            StopTimerAndSave();
            if (_vault.IsUnlocked)
            {
                _vault.SetLastLogout("application restart");
            }
            _sessionQueueIds.Clear();
            var executable = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(executable)) throw new InvalidOperationException("Could not resolve the current process executable.");
            var startInfo = new ProcessStartInfo(executable) { UseShellExecute = false };
            foreach (var argument in Environment.GetCommandLineArgs().Skip(1)) startInfo.ArgumentList.Add(argument);
            Process.Start(startInfo);
            if (Avalonia.Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime lifetime)
            {
                _runtimeLog.Add("Application restart requested; vault saved.");
                lifetime.Shutdown();
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or System.ComponentModel.Win32Exception)
        {
            await MessageBoxAsync("Restart failed", ex.Message);
        }
    }

    private async void OnProceedToNextRecordClick(object? sender, RoutedEventArgs e)
    {
        if (!RequireSession() || SelectedDocument is not { } completed) return;
        if (_currentAccount?.Role == VaultRole.Analyst &&
            (completed.WorkflowStage < 3 || completed.WorkflowStatus != "Submitted" || !DocumentWorkflow.VerifyReviewCompletion(completed)))
        {
            await MessageBoxAsync("Review not finalized", "Complete Stage 2 encryption and Stage 3 finalize/sign before saving this Analyst review and proceeding.");
            return;
        }

        if (!await ConfirmAsync("Save Analyst review", "Save the signed Analyst review to the encrypted vault and proceed to the next record? The record remains pending Custodian Stage 4 review; this does not mark it permanent."))
            return;
        try
        {
            StopTimerAndSave(completed);
            _vault.Save();
            _sessionQueueIds.Remove(completed.Id);
            _selectedDocument = null;
            DocumentsList.SelectedItem = null;
            RefreshDocuments();
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            await MessageBoxAsync("Could not save record", ex.Message);
            return;
        }
        var nextRecord = _vault.Documents.FirstOrDefault(record => _sessionQueueIds.Contains(record.Id) &&
            record.WorkflowStatus is "InReview" or "ReturnedForReview");
        if (nextRecord is not null)
        {
            ClearAnalystReviewInputs();
            _reviewInputDocumentId = null;
            _selectedDocument = nextRecord;
            DocumentsList.SelectedItem = nextRecord;
            UpdateSelection();
            NavigateTo("Inspect");
            return;
        }

        UpdateSelection();
        NavigateTo("Workspace");
        OnAddDocumentClick(sender, e);
    }

    private bool TryGetReadableDocument(out VaultDocument document, out string text)
    {
        text = string.Empty;
        if (!TryGetSelectedAccessible(out document)) return false;
        try
        {
            text = DocumentWorkflow.ReadSourceText(document);
            return true;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or InvalidDataException or DecoderFallbackException)
        {
            _runtimeLog.Add("Source integrity check failed; document text was not displayed.");
            _ = MessageBoxAsync("Document integrity failure", "The source text could not be authenticated or decoded.");
            return false;
        }
    }

    private bool TryGetSelectedAccessible(out VaultDocument document, bool allowPendingDuplicateInspection = false)
    {
        document = SelectedDocument ?? null!;
        if (!RequireSession() || document is null)
        {
            _ = MessageBoxAsync("Select a record", "Authenticate and select a document first.");
            return false;
        }
        var duplicatePending = document.DuplicateResolution == "PendingCustodianReview" ||
                               document.WorkflowStatus == "DuplicatePendingCustodianReview";
        if (document.WorkflowStatus == "DuplicateConfirmed" ||
            (duplicatePending && !allowPendingDuplicateInspection && !_sessionQueueIds.Contains(document.Id)))
        {
            _ = MessageBoxAsync("Duplicate review only", document.WorkflowStatus == "DuplicateConfirmed"
                ? "A confirmed duplicate's source is not available for further inspection. The retained record is not deleted."
                : "This duplicate candidate is available for inspection. Add it to the Session Work Queue to analyze and submit before Custodian resolution.");
            return false;
        }
        try
        {
            _vault.DemandDocumentAccess(_currentAccount!, document);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            PolicyStatus.Text = "Access denied by the authenticated account's local workflow role.";
            _runtimeLog.Add("Access denied by local account role or record priority.");
            _ = MessageBoxAsync("Access denied", "The authenticated account does not meet the selected record's required priority.");
            return false;
        }
        catch (DllNotFoundException)
        {
            _ = MessageBoxAsync("Native core unavailable", "Build the application to compile the C++ policy core.");
            return false;
        }
    }

    private bool RequireSession()
    {
        if (_authenticated && _vault.IsUnlocked && _currentAccount is not null)
        {
            try
            {
                VaultAccessPolicy.DemandAnalyst(_currentAccount);
                MarkActivity();
                return true;
            }
            catch (UnauthorizedAccessException) { }
        }
        _ = MessageBoxAsync("Authentication required", "Authenticate and unlock the local vault first.");
        return false;
    }

    private void RenderDocument(VaultDocument document)
    {
        if (document.IsPdf)
        {
            if (document.WorkflowStage >= 2)
            {
                LoadReviewDraft(document);
            }
            else
            {
                if (!string.IsNullOrEmpty(document.PdfImageExtractionJson))
                {
                    try
                    {
                        var saved = System.Text.Json.JsonSerializer.Deserialize<LocalPdfReviewResult>(document.PdfImageExtractionJson, ExtractionJsonOptions);
                        if (saved is not null)
                        {
                            document.Draft.Images = saved.Images;
                            document.Draft.ImageExtractionCompleted = string.Equals(saved.ScanResult, "No threats found", StringComparison.Ordinal);
                            document.Draft.PdfMalwareScanResult = saved.ScanResult;
                            document.Draft.PdfMalwareScanProvider = saved.ScanProvider;
                            document.Draft.PdfImageStreamUndecodedCount = saved.UndecodedCount;
                            document.Draft.PdfExtractedTextAndForms = saved.TextAndForms;
                            document.Draft.PdfSelectableTextAndForms = string.IsNullOrEmpty(document.PdfSelectableTextAndForms)
                                ? saved.SelectableTextAndForms : document.PdfSelectableTextAndForms;
                            document.Draft.PdfEmbeddedImageOcrText = string.IsNullOrEmpty(document.PdfEmbeddedImageOcrText)
                                ? saved.EmbeddedImageOcrText : document.PdfEmbeddedImageOcrText;
                            document.Draft.PdfTextVerified = saved.PdfTextVerified;
                            document.PdfExtractedTextVerified = saved.PdfTextVerified;
                            document.PdfImageStreamCount = saved.ImageStreamCount;
                            document.Draft.MatchQuery = document.PdfMatchQuery;
                            document.Draft.MatchCount = document.PdfMatchCount;
                            document.Draft.WordCount = document.WordCount;
                            document.Draft.EmailCandidates = document.EmailCandidates;
                            document.Draft.NumberGroups = document.NumberGroups;
                        }
                    }
                    catch (System.Text.Json.JsonException)
                    {
                        document.Draft.ImageExtractionCompleted = false;
                        document.Draft.PdfMalwareScanResult = "Invalid stored extraction result";
                        document.Draft.Images.Clear();
                    }
                }
                // Stage 1 PDF records still have per-record review inputs. Load them
                // so a new PDF task cannot inherit the previous record's text fields.
                LoadReviewDraft(document);
            }
            MatchQueryBox.Text = document.Draft.MatchQuery;
            AnalysisStatus.Text = document.Draft.MatchQuery.Length > 0
                ? $"{document.Draft.WordCount:N0} words · {document.Draft.MatchCount:N0} match(es)"
                : "Analysis not run";
            var indicatorCount = CountPdfIndicators(document.PdfStaticScanReport);
            TextDataBox.Text = document.Draft.ImageExtractionCompleted
                ? AppendOcrReference(
                    string.IsNullOrEmpty(document.Draft.PdfSelectableTextAndForms) ? document.Draft.PdfExtractedTextAndForms : document.Draft.PdfSelectableTextAndForms,
                    document.Draft.PdfEmbeddedImageOcrText)
                : "PDF text/forms are unavailable until the optional local ClamAV clean-scan extraction completes. The static report below is not extracted text or antivirus.\n\n" + document.PdfStaticScanReport;
            PdfOcrDataBox.Text = document.Draft.PdfEmbeddedImageOcrText;
            if (document.Draft.ImageExtractionCompleted)
            {
                ScanResult.Text = $"Local malware scan: {document.Draft.PdfMalwareScanResult} · {document.Draft.PdfMalwareScanProvider}";
                RenderPdfImagePreviews(document.Draft);
            }
            else if (string.IsNullOrEmpty(document.Draft.PdfMalwareScanResult))
            {
                ClearPdfImagePreviews(document.SourceMaterialDestroyed
                    ? "Source PDF removed after restart. Re-import it to extract image streams."
                    : "No PDF images loaded. Run the local scan and extraction first.");
            }
            else
            {
                ScanResult.Text = $"Local malware scan: {document.Draft.PdfMalwareScanResult} · {document.Draft.PdfMalwareScanProvider}";
                ClearPdfImagePreviews("PDF parsing was blocked because the local scanner did not report clean.");
            }
            AnalysisReportText.Text = document.Draft.ImageExtractionCompleted
                ? $"Local PDF extraction report\nMalware gate: {document.Draft.PdfMalwareScanResult} ({document.Draft.PdfMalwareScanProvider})\nPages: {document.Draft.PdfSelectableTextAndForms.Split("===== PAGE ", StringSplitOptions.None).Length - 1}\nImage streams found: {document.PdfImageStreamCount}\nImages not decoded: {document.Draft.PdfImageStreamUndecodedCount}"
                : "PDF text, form, and image extraction results will appear here after the local ClamAV clean result.";
            if (!string.IsNullOrWhiteSpace(document.Draft.PdfComparisonReport))
                AnalysisReportText.Text += $"\n\n{document.Draft.PdfComparisonReport}";
            if (string.IsNullOrEmpty(document.Draft.PdfMalwareScanResult))
                ScanResult.Text = $"Static PDF markers: {indicatorCount} · NOT ANTIVIRUS";
            AnalysisStatus.Text = document.Draft.MatchQuery.Length > 0
                ? $"{document.Draft.WordCount:N0} words · {document.Draft.MatchCount:N0} match(es) across selectable text, forms & embedded-image OCR"
                : "Analysis not run";
            SyncReviewScreenContent(document);
            return;
        }
        var text = DocumentWorkflow.ReadSourceText(document);
        var preview = FormatDisplay(text, "Document preview");
        if (string.IsNullOrEmpty(TextDataBox.Text)) TextDataBox.Text = preview;
        if (document.WorkflowStage >= 2) LoadReviewDraft(document);
        RefreshReviewData(document);
    }

    private static int CountPdfIndicators(string report)
    {
        const string marker = "Configured risk-marker categories present: ";
        var start = report.IndexOf(marker, StringComparison.Ordinal);
        if (start < 0) return 0;
        start += marker.Length;
        var end = report.IndexOfAny(new[] { '\r', '\n' }, start);
        var value = end < 0 ? report[start..] : report[start..end];
        return int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var count) ? count : 0;
    }

    private void LoadReviewDraft(VaultDocument document)
    {
        if (!string.IsNullOrEmpty(document.EncryptedWorkingDraft))
        {
            document.Draft = DocumentWorkflow.ReadWorkingDraft(document);
        }
            if (!string.IsNullOrEmpty(document.EncryptedWorkingDraft))
            {
                document.Draft = DocumentWorkflow.ReadWorkingDraft(document);
            }
            else if (document.WorkflowStage >= 2)
        {
            document.Draft = DocumentWorkflow.ReadReview(document);
        }
        else if (document.IsPdf)
        {
            document.Draft.MatchQuery = document.PdfMatchQuery;
            document.Draft.MatchCount = document.PdfMatchCount;
            document.Draft.WordCount = document.WordCount;
            document.Draft.EmailCandidates = document.EmailCandidates;
            document.Draft.NumberGroups = document.NumberGroups;
            document.Draft.PdfBrandNameVerified = document.PdfBrandNameVerified;
            document.Draft.PdfAlcoholVolumeVerified = document.PdfAlcoholVolumeVerified;
            document.Draft.PdfGovernmentWarningVerified = document.PdfGovernmentWarningVerified;
            document.Draft.PdfVisibleVerified = document.PdfVisibleVerified;
        }
        if (document.IsPdf)
        {
            if (string.IsNullOrEmpty(document.Draft.PdfSelectableTextAndForms))
                document.Draft.PdfSelectableTextAndForms = document.PdfSelectableTextAndForms;
            if (string.IsNullOrEmpty(document.Draft.PdfEmbeddedImageOcrText))
                document.Draft.PdfEmbeddedImageOcrText = document.PdfEmbeddedImageOcrText;
            if (string.IsNullOrEmpty(document.Draft.PdfComparisonReport))
                document.Draft.PdfComparisonReport = document.PdfComparisonReport;
        }
        ImagesVerifiedCheck.IsChecked = document.Draft.ImagesVerified;
        AccuracyBox.Text = document.Draft.AccuracyPercent > 0 ? document.Draft.AccuracyPercent.ToString(CultureInfo.InvariantCulture) : string.Empty;
        ReviewNotesBox.Text = document.Draft.ReviewNotes;
        MatchQueryBox.Text = document.Draft.MatchQuery;
        ScanResult.Text = document.Draft.ScanCompleted
            ? $"Heuristic scan: {document.Draft.ScanFindingCount} indicator(s) · {document.Draft.ScanFindings}"
            : "Scan: pending";
        AnalysisStatus.Text = document.Draft.MatchQuery.Length > 0
            ? $"{document.Draft.WordCount:N0} words · {document.Draft.MatchCount:N0} match(es)"
            : "Analysis not run";
        AnalysisDataBox.Text = document.Draft.ImageExtractionCompleted ? FormatImageData(document.Draft.Images) : "Image extraction has not been run.";
        UpdatePdfVisualChecklistState(document, loadValues: true);
        RefreshVerificationStatus();
        RefreshReviewData(document);
    }

    private void RefreshReviewData(VaultDocument document)
    {
        if (document.WorkflowStage >= 2)
        {
            try { document.Draft = DocumentWorkflow.ReadReview(document); }
            catch (Exception ex) when (ex is CryptographicException or FormatException or InvalidDataException or System.Text.Json.JsonException)
            {
                AnalysisDataBox.Text = "Encrypted review data failed integrity validation.";
                return;
            }
        }
        AnalysisDataBox.Text = BuildAnalysisText(document.Draft);
    }

    private static string BuildAnalysisText(ReviewDraft draft) =>
        $"Analysis summary\nWords: {draft.WordCount:N0}\nEmail candidates: {draft.EmailCandidates:N0}\nNumber groups: {draft.NumberGroups:N0}\nMatch term: {draft.MatchQuery}\nMatches: {draft.MatchCount:N0}\n\nDefensive scan\n{(draft.ScanCompleted ? draft.ScanFindings : "Not run")}\n\nImages extracted: {(draft.ImageExtractionCompleted ? draft.Images.Count.ToString(CultureInfo.InvariantCulture) : "Not run")}\nText verified: {draft.TextVerified}\nImage data verified: {draft.ImagesVerified}\nPDF visual confirmations — BRAND NAME: {draft.PdfBrandNameVerified}; ALC./VOL mL: {draft.PdfAlcoholVolumeVerified}; GOVERNMENT WARNING: {draft.PdfGovernmentWarningVerified}; VISIBLE: {draft.PdfVisibleVerified}\nAccuracy estimate: {draft.AccuracyPercent}%\n\nReview notes\n{draft.ReviewNotes}" +
        (string.IsNullOrWhiteSpace(draft.PdfComparisonReport) ? string.Empty : $"\n\n{draft.PdfComparisonReport}");

    private static string FormatImageData(System.Collections.Generic.IReadOnlyList<ExtractedImage> images)
    {
        if (images.Count == 0) return "No supported, signature-verified embedded image data was found.";
        var output = new StringBuilder();
        for (var i = 0; i < images.Count; i++)
        {
            var image = images[i];
            var sourceLabel = image.ExtractionSource == "RenderedPageFallback" ? "rendered page fallback" : "embedded image";
            output.AppendLine($"Image {i + 1} · {sourceLabel} · {image.MimeType} · {image.ByteLength:N0} bytes" +
                              (image.PageNumber > 0 ? $" · page {image.PageNumber} · {image.Width}×{image.Height}" : ""));
            output.AppendLine($"SHA-256: {image.Sha256}");
            if (!string.IsNullOrWhiteSpace(image.ComparisonNotes))
            {
                output.AppendLine("Blank-form comparison:");
                output.AppendLine(image.ComparisonNotes);
            }
            output.Append("Base64 data (preview): ");
            output.AppendLine(image.Base64Data.Length <= 4096 ? image.Base64Data : image.Base64Data[..4096] + "… [truncated in UI]");
            output.AppendLine();
        }
        return output.ToString();
    }

    private void RenderPdfImagePreviews(ReviewDraft draft)
    {
        ClearPdfImagePreviews(draft.Images.Count == 0
            ? draft.PdfImageStreamUndecodedCount > 0
                ? "A clean scan completed, but image streams were unsupported or exceeded extraction limits."
                : "A clean scan completed. No embedded image streams were found in this PDF."
            : string.Empty);
        if (!draft.ImageExtractionCompleted ||
            !string.Equals(draft.PdfMalwareScanResult, "No threats found", StringComparison.Ordinal) ||
            !string.Equals(draft.PdfMalwareScanProvider, "ClamAV", StringComparison.Ordinal))
        {
            return;
        }

        long totalPixels = 0;
        foreach (var item in draft.Images)
        {
            if (!string.Equals(item.MimeType, "image/png", StringComparison.Ordinal) || item.ByteLength is <= 0 or > 2 * 1024 * 1024 ||
                item.Width is <= 0 or > 4096 || item.Height is <= 0 or > 4096)
            {
                continue;
            }

            byte[] imageBytes;
            try { imageBytes = Convert.FromBase64String(item.Base64Data); }
            catch (FormatException) { continue; }
            try
            {
                if (imageBytes.Length != item.ByteLength || imageBytes.Length < 24 ||
                    !imageBytes.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }) ||
                    BinaryPrimitives.ReadUInt32BigEndian(imageBytes.AsSpan(16, 4)) != item.Width ||
                    BinaryPrimitives.ReadUInt32BigEndian(imageBytes.AsSpan(20, 4)) != item.Height ||
                    !string.Equals(Convert.ToHexString(SHA256.HashData(imageBytes)), item.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                using var imageStream = new MemoryStream(imageBytes, writable: false);
                var bitmap = new Bitmap(imageStream);
                var pixels = (long)bitmap.PixelSize.Width * bitmap.PixelSize.Height;
                if (bitmap.PixelSize.Width is <= 0 or > 4096 || bitmap.PixelSize.Height is <= 0 or > 4096 ||
                    pixels > 4_000_000 || totalPixels + pixels > 12_000_000)
                {
                    bitmap.Dispose();
                    continue;
                }

                totalPixels += pixels;
                _pdfImageBitmaps.Add(bitmap);
                _pdfImagePreviews.Add((item, bitmap));
                ExtractedPdfImagesPanel.Children.Add(CreatePdfImagePreviewCard(item, bitmap, 240, 250));
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidDataException or NotSupportedException or IOException)
            {
                // Skip an image if the framework decoder rejects the bounded PNG output.
            }
            finally
            {
                CryptographicOperations.ZeroMemory(imageBytes);
            }
        }

        if (_pdfImageBitmaps.Count == 0 && draft.Images.Count > 0)
            ExtractedPdfImagesPanel.Children.Add(new TextBlock { Text = "The scan was clean, but no supported bounded image streams could be displayed." });
        RefreshReviewImagesPanel(draft);
    }

    private Border CreatePdfImagePreviewCard(ExtractedImage item, Bitmap bitmap, double width, double maxHeight)
    {
        var preview = new Avalonia.Controls.Image
        {
            Source = bitmap,
            Width = width,
            MaxHeight = maxHeight,
            Stretch = Avalonia.Media.Stretch.Uniform,
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center
        };
        var zoomButton = new Button { Content = "Zoom image", Classes = { "secondary" }, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Left };
        zoomButton.Click += async (_, _) => await OpenPdfImageZoomAsync(bitmap, $"PDF image · page {item.PageNumber}");
        return new Border
        {
            Background = Avalonia.Media.Brushes.White,
            BorderBrush = Avalonia.Media.Brushes.LightGray,
            BorderThickness = new Avalonia.Thickness(1),
            CornerRadius = new Avalonia.CornerRadius(7),
            Padding = new Avalonia.Thickness(8),
            Child = new StackPanel
            {
                Spacing = 7,
                Children =
                {
                    preview,
                    new TextBlock { Text = $"{(item.ExtractionSource == "RenderedPageFallback" ? "Rendered page fallback" : "Embedded image")} · page {item.PageNumber} · {item.Width}×{item.Height}", FontWeight = Avalonia.Media.FontWeight.SemiBold, TextWrapping = Avalonia.Media.TextWrapping.Wrap },
                    new TextBlock { Text = string.IsNullOrEmpty(item.Sha256) ? "Rendered preview; not the original image stream." : $"SHA-256 {item.Sha256}", FontSize = 9, TextWrapping = Avalonia.Media.TextWrapping.Wrap },
                    zoomButton
                }
            }
        };
    }

    private async Task OpenPdfImageZoomAsync(Bitmap bitmap, string title)
    {
        var zoom = new Slider { Minimum = 0.5, Maximum = 4, Value = 1, TickFrequency = 0.25, IsSnapToTickEnabled = false };
        var zoomLabel = new TextBlock { Text = "100%", VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center };
        var image = new Avalonia.Controls.Image
        {
            Source = bitmap,
            Width = bitmap.PixelSize.Width,
            Height = bitmap.PixelSize.Height,
            Stretch = Avalonia.Media.Stretch.Uniform,
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center,
            VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center
        };
        zoom.PropertyChanged += (_, args) =>
        {
            if (args.Property != Slider.ValueProperty) return;
            image.Width = Math.Clamp(bitmap.PixelSize.Width * zoom.Value, 1, 16_384);
            image.Height = Math.Clamp(bitmap.PixelSize.Height * zoom.Value, 1, 16_384);
            zoomLabel.Text = $"{zoom.Value:P0}";
        };
        var dialog = new Window
        {
            Title = title,
            Width = 1000,
            Height = 760,
            MinWidth = 600,
            MinHeight = 480,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = new DockPanel
            {
                Margin = new Avalonia.Thickness(12),
                Children =
                {
                    new StackPanel
                    {
                        Orientation = Avalonia.Layout.Orientation.Horizontal,
                        Spacing = 12,
                        Children = { new TextBlock { Text = "Zoom", VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center }, zoom, zoomLabel }
                    },
                    new ScrollViewer { Content = image, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto, VerticalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto }
                }
            }
        };
        DockPanel.SetDock(dialog.Content is DockPanel panel ? panel.Children[0] : null!, Dock.Top);
        AttachRuntimeProtections(dialog);
        await dialog.ShowDialog(this);
    }

    private void ClearPdfImagePreviews(string message)
    {
        foreach (var bitmap in _pdfImageBitmaps) bitmap.Dispose();
        _pdfImageBitmaps.Clear();
        _pdfImagePreviews.Clear();
        ExtractedPdfImagesPanel.Children.Clear();
        ReviewImagesPanel.Children.Clear();
        if (!string.IsNullOrWhiteSpace(message))
            ExtractedPdfImagesPanel.Children.Add(new TextBlock { Text = message, TextWrapping = Avalonia.Media.TextWrapping.Wrap });
    }

    private static string FormatDisplay(string text, string header)
    {
        if (text.Length <= MaxDisplayCharacters) return text;
        return text[..MaxDisplayCharacters] + $"\n\n[{header} truncated in view after {MaxDisplayCharacters:N0} characters; encrypted record is unchanged.]";
    }

    private void RefreshDocuments()
    {
        var selectedId = _selectedDocument?.Id;
        var queueRecords = _vault.Documents.Where(item => _sessionQueueIds.Contains(item.Id)).ToArray();
        var custodian = _authenticated && _currentAccount?.Role == VaultRole.Custodian;
        foreach (var record in _vault.Documents)
        {
            record.CanSelectForBulkDelete = custodian;
            if (!custodian) record.IsSelectedForBulkDelete = false;
        }
        var persistentRecords = _currentAccount?.Role == VaultRole.Custodian
            ? _vault.Documents.ToArray()
            : _currentAccount?.Role == VaultRole.Analyst
                ? _vault.Documents.Where(item => item.IsSavedForLater || item.DuplicateResolution == "PendingCustodianReview" ||
                                                  item.WorkflowStatus == "DuplicatePendingCustodianReview").ToArray()
                : Array.Empty<VaultDocument>();
        _syncingSelection = true;
        DocumentsList.ItemsSource = new ObservableCollection<VaultDocument>(queueRecords);
        VaultRecordsList.ItemsSource = new ObservableCollection<VaultDocument>(persistentRecords);
        VaultRecordsHeader.Text = _currentAccount?.Role == VaultRole.Analyst
            ? "Saved drafts and pending duplicate candidates · add to queue to resume"
            : "Persistent Records Vault · remains across sessions";
        if (selectedId is not null)
        {
            DocumentsList.SelectedItem = queueRecords.FirstOrDefault(item => item.Id == selectedId);
            if (DocumentsList.SelectedItem is null && _authenticated)
                VaultRecordsList.SelectedItem = _vault.Documents.FirstOrDefault(item => item.Id == selectedId);
        }
        _selectedDocument = DocumentsList.SelectedItem as VaultDocument ?? VaultRecordsList.SelectedItem as VaultDocument;
        _syncingSelection = false;
        VaultRecordsList.IsVisible = _authenticated && persistentRecords.Length > 0;
        BulkDeleteRecordsButton.IsVisible = custodian;
        BulkDeleteRecordsButton.IsEnabled = custodian && _vault.Documents.Any(record => record.IsSelectedForBulkDelete);
        DocumentCount.Text = $"{queueRecords.Length} in Session Work Queue · {_vault.Documents.Count} persistent vault record(s)";
        RefreshStageButtons();
    }

    private void RefreshStageButtons()
    {
        var document = SelectedDocument;
        UpdatePdfVisualChecklistState(document, loadValues: false);
        var accessible = _authenticated && document is not null && NativeCore.CanAccess(_roleLevel, document.RequiredPriority);
        var analyst = _currentAccount?.Role == VaultRole.Analyst;
        var custodian = _currentAccount?.Role == VaultRole.Custodian;
        var canSavePdfForLater = analyst && document is { IsPdf: true, WorkflowStage: 1, WorkflowStatus: "InReview" } &&
                     _sessionQueueIds.Contains(document.Id) && document.Draft.ImageExtractionCompleted &&
                     !IsStageTwoReady(document);
        SavePdfForLaterButton.IsVisible = canSavePdfForLater;
        SavePdfForLaterButton.IsEnabled = canSavePdfForLater;
        var canProceedToReview = analyst && document is { IsPdf: true, WorkflowStage: 1, WorkflowStatus: "InReview" } &&
                     _sessionQueueIds.Contains(document.Id) && document.Draft.ImageExtractionCompleted &&
                     IsPdfVisualChecklistComplete(document.Draft);
        ProceedToReviewButton.IsVisible = canProceedToReview;
        ProceedToReviewButton.IsEnabled = canProceedToReview;
        ProceedToReviewButton.Opacity = canProceedToReview ? 1.0 : 0.55;
        var custodianCanEnterStageFour = custodian && document is { WorkflowStatus: "Submitted", WorkflowStage: >= 3 } &&
                                         _sessionQueueIds.Contains(document.Id) &&
                                         document.DuplicateResolution != "PendingCustodianReview" &&
                                         DocumentWorkflow.VerifyReviewCompletion(document) &&
                                         (!document.IsPdf || (document.Draft.ImageExtractionCompleted &&
                                             IsPdfVisualChecklistComplete(document.Draft) &&
                                             document.Draft.PdfVisualInspectionConfirmed));
        ProceedToCustodianReviewButton.IsVisible = custodian;
        ProceedToCustodianReviewButton.IsEnabled = accessible && custodianCanEnterStageFour;
        AnalystVisualAttestationStatus.IsVisible = custodian && document?.IsPdf == true;
        if (custodian && document is not null)
        {
            var analystSignatureValid = DocumentWorkflow.VerifyReviewCompletion(document);
            AnalystVisualAttestationStatus.Text = analystSignatureValid
                ? $"Analyst Stage 3 attestations: signature valid · PDF checklist {(IsPdfVisualChecklistComplete(document.Draft) ? "complete" : "incomplete")} · visual inspection {(document.Draft.PdfVisualInspectionConfirmed ? "confirmed" : "not confirmed")}."
                : "Analyst Stage 3 signature is invalid or missing.";
        }
        ManageRecordButton.IsEnabled = accessible && (custodian || (document is not null && _sessionQueueIds.Contains(document.Id)));
        ManageAccountsButton.IsVisible = _authenticated && _currentAccount?.Role == VaultRole.Custodian;
        ExportPermanentRecordsButton.IsVisible = _authenticated && _currentAccount?.Role == VaultRole.Custodian;
        ExportPermanentRecordsButton.IsEnabled = _vault.Documents.Any(record => record.IsPermanentlyStored);
        ImportRecordsFolderButton.IsVisible = _authenticated && _currentAccount?.Role == VaultRole.Custodian;
        var queueable = document is not null && WorkflowEligibility.CanAddToQueue(_currentAccount, document);
        AddToQueueButton.IsEnabled = accessible && queueable &&
                                     document is not null && !_sessionQueueIds.Contains(document.Id);
        AddToQueueButton.IsVisible = analyst || custodian;
        var custodianCanReviewSubmission = document is not null &&
                           WorkflowEligibility.CanCustodianReviewSubmission(_currentAccount, document, isAccessible: accessible);
        CustodianReviewButton.IsVisible = custodian;
        CustodianReviewButton.IsEnabled = accessible && custodianCanReviewSubmission;
        var stageTwoWorkflowReady = document is not null && _sessionQueueIds.Contains(document.Id) &&
                                    document.WorkflowStatus == "InReview" &&
                                    (document.WorkflowStage == 1 || document.WorkflowStage >= 3);
        var extractionIsReady = document is not null && (!document.IsPdf ||
                               (string.Equals(document.Draft.PdfMalwareScanResult, "No threats found", StringComparison.Ordinal) &&
                                string.Equals(document.Draft.PdfMalwareScanProvider, "ClamAV", StringComparison.Ordinal) &&
                                document.Draft.ImageExtractionCompleted));
        var reviewConfirmationIsReady = document is not null && (!document.IsPdf ||
                                      (IsPdfVisualChecklistComplete(document.Draft) &&
                                       document.Draft.PdfVisualInspectionConfirmed));
        EncryptReviewButton.IsEnabled = accessible && analyst && stageTwoWorkflowReady && extractionIsReady &&
                                       reviewConfirmationIsReady && IsStageTwoReady(document!);
        EncryptReviewButton.IsVisible = analyst;
        if (document is { IsPdf: true, WorkflowStage: 1 } && analyst)
        {
            EncryptReviewStatus.Text = BuildMissingStageTwoRequirements(document);
        }
        else
        {
            EncryptReviewStatus.Text = "Confirm visual inspection. The encrypt action also requires completed review checks, match, accuracy, and notes from Inspect.";
        }
        StageThreeButton.IsVisible = analyst;
        StageThreeButton.IsEnabled = accessible && analyst && document is { WorkflowStatus: "InReview", WorkflowStage: 2 } &&
                         _sessionQueueIds.Contains(document.Id) && IsStageTwoReady(document) &&
                         (!document.IsPdf || (string.Equals(document.Draft.PdfMalwareScanResult, "No threats found", StringComparison.Ordinal) &&
                          string.Equals(document.Draft.PdfMalwareScanProvider, "ClamAV", StringComparison.Ordinal) && document.Draft.ImageExtractionCompleted));
        var pendingCustodianDecision = document is not null && accessible &&
            WorkflowEligibility.CanCustodianDecide(_currentAccount, document, _sessionQueueIds.Contains(document.Id));
        CustodianApproveButton.IsEnabled = pendingCustodianDecision;
        CustodianRejectButton.IsEnabled = pendingCustodianDecision;
        CustodianReturnButton.IsEnabled = pendingCustodianDecision;
        CustodianDecisionNoteBox.IsEnabled = pendingCustodianDecision;
        CustodianPasswordBox.IsEnabled = pendingCustodianDecision;
        CustodianDecisionPanel.IsVisible = _authenticated && custodian;
        ConfirmVisualInspectionCheck.IsVisible = analyst && document?.IsPdf == true;
        CustodianVisualInspectionCheck.IsVisible = custodian && document?.IsPdf == true;
        _settingCustodianVisualInspection = true;
        CustodianVisualInspectionCheck.IsChecked = document?.CustodianVisualInspectionConfirmed == true;
        _settingCustodianVisualInspection = false;
        ProceedToCustodianDecisionButton.IsVisible = custodian;
        ProceedToCustodianDecisionButton.IsEnabled = document is not null &&
            WorkflowEligibility.IsCustodianDecisionReady(_currentAccount, document, _sessionQueueIds.Contains(document.Id));
        DuplicateReviewPanel.IsVisible = _authenticated && custodian && document is { WorkflowStatus: "Submitted", WorkflowStage: >= 3 } &&
                 document.DuplicateResolution == "PendingCustodianReview" &&
                         DocumentWorkflow.VerifyReviewCompletion(document);
        ConfirmDuplicateButton.IsEnabled = DuplicateReviewPanel.IsVisible;
        MarkNotDuplicateButton.IsEnabled = DuplicateReviewPanel.IsVisible;
        RemoveFromQueueButton.IsEnabled = document is not null && _sessionQueueIds.Contains(document.Id);
        if (document is not null)
        {
            DocumentCount.Text = $"{_sessionQueueIds.Count} in Session Work Queue · {_vault.Documents.Count} persistent vault record(s) · selected: {document.WorkflowStatus}";
        }
        UpdateCompletionSummary(document);
        var pdfChecklistMissing = document?.IsPdf == true && !IsPdfVisualChecklistComplete(document.Draft);
        if (pdfChecklistMissing && document!.Draft.ImageExtractionCompleted && _sessionQueueIds.Contains(document.Id))
            VerificationStatus.Text = "Required PDF checks incomplete — use Save For Later or complete all checks";
    }

    private void UpdateCompletionSummary(VaultDocument? document)
    {
        if (document is null)
        {
            CompletionSummary.Text = "Select a record to view its workflow status.";
            CompleteInputText.Text = CompleteOcrText.Text = CompleteAnalysisText.Text = string.Empty;
            CompleteImagesPanel.Children.Clear();
            return;
        }

        var reviewSignature = string.IsNullOrEmpty(document.ReviewCompletionSignature)
            ? "not submitted"
            : DocumentWorkflow.VerifyReviewCompletion(document) ? "verifies" : "INVALID";
        var decisionSignature = string.IsNullOrEmpty(document.CustodianDecisionSignature)
            ? "not decided"
            : DocumentWorkflow.VerifyCustodianDecision(document) ? "verifies" : "INVALID";
        var duplicateResolutionSignature = string.IsNullOrEmpty(document.DuplicateResolutionSignature)
            ? "not resolved"
            : DocumentWorkflow.VerifyDuplicateResolution(document) ? "verifies" : "INVALID";
        var stageThreeSignature = document.WorkflowStage >= 3
            ? DocumentWorkflow.VerifyReviewCompletion(document) ? "verifies" : "INVALID"
            : "not signed";
        CompletionSummary.Text = $"Record: {document.Name}\nWorkflow status: {document.WorkflowStatus}\nPermanent vault record: {(document.IsPermanentlyStored ? "Yes · Custodian signed" : "No · pending Custodian resolution/signature")}\nWorkflow stage: {document.WorkflowStage} of 4\nRecord key: {(string.IsNullOrEmpty(document.RecordKeyId) ? "Not created" : document.RecordKeyId)}\nStage 3 Analyst completion signature: {stageThreeSignature} · {document.ReviewAnalystName} · {FormatStampDate(document.ReviewCompletedAtUtc)}\nStage 4 Custodian decision signature: {decisionSignature} · {document.CustodianDecision} · {FormatStampDate(document.CustodianDecisionUtc)}\nDuplicate resolution signature: {duplicateResolutionSignature} · {document.DuplicateResolution} · {FormatStampDate(document.DuplicateResolvedAtUtc)}\nDuplicate reference: {(string.IsNullOrEmpty(document.DuplicateOfRecordId) ? "none" : document.DuplicateOfRecordId)}\nReview started (UTC): {(string.IsNullOrEmpty(document.ReviewStartedAtUtc) ? "not started" : document.ReviewStartedAtUtc)}\nElapsed review time: {TimeSpan.FromSeconds(Math.Max(0, document.ReviewElapsedSeconds)):g}";
        CompleteInputText.Text = document.IsPdf
            ? (string.IsNullOrEmpty(document.PdfSelectableTextAndForms) ? document.Draft.PdfExtractedTextAndForms : document.PdfSelectableTextAndForms)
            : TextDataBox.Text;
        CompleteOcrText.Text = document.PdfEmbeddedImageOcrText;
        CompleteAnalysisText.Text = BuildAnalysisText(document.Draft) +
            (string.IsNullOrWhiteSpace(document.PdfComparisonReport) ? string.Empty : $"\n\n{document.PdfComparisonReport}");
        CompleteImagesPanel.Children.Clear();
        foreach (var preview in _pdfImagePreviews)
            CompleteImagesPanel.Children.Add(CreatePdfImagePreviewCard(preview.Item, preview.Bitmap, 150, 150));
    }

    private void ImportDocumentButtonState(bool enabled)
    {
        // Locate the named import button through the generated visual tree without exposing vault state in XAML bindings.
        if (this.FindControl<Button>("ImportDocumentButton") is { } importButton) importButton.IsEnabled = enabled;
    }

    private void UpdateVerificationStatus()
    {
        var isPdf = SelectedDocument is VaultDocument { IsPdf: true };
        var checklistComplete = !isPdf || ArePdfVisualChecklistChecksComplete(
            PdfBrandNameCheck.IsChecked == true,
            PdfAlcoholVolumeCheck.IsChecked == true,
            PdfGovernmentWarningCheck.IsChecked == true,
            PdfVisibleCheck.IsChecked == true);
        VerificationStatus.Text = ImagesVerifiedCheck.IsChecked == true && checklistComplete
            ? "Image and visual checks marked; accuracy and notes still required"
            : isPdf && !checklistComplete
                ? "Complete all PDF image/form checks"
                : "Verification pending";
        RefreshStageButtons();
    }

    private void OnPdfVisualChecklistChanged(object? sender, RoutedEventArgs e)
    {
        if (_loadingPdfVisualChecklist || SelectedDocument is not { IsPdf: true } document ||
            !_sessionQueueIds.Contains(document.Id)) return;
        document.Draft.PdfBrandNameVerified = PdfBrandNameCheck.IsChecked == true;
        document.Draft.PdfAlcoholVolumeVerified = PdfAlcoholVolumeCheck.IsChecked == true;
        document.Draft.PdfGovernmentWarningVerified = PdfGovernmentWarningCheck.IsChecked == true;
        document.Draft.PdfVisibleVerified = PdfVisibleCheck.IsChecked == true;
        document.PdfBrandNameVerified = document.Draft.PdfBrandNameVerified;
        document.PdfAlcoholVolumeVerified = document.Draft.PdfAlcoholVolumeVerified;
        document.PdfGovernmentWarningVerified = document.Draft.PdfGovernmentWarningVerified;
        document.PdfVisibleVerified = document.Draft.PdfVisibleVerified;
        if (_vault.IsUnlocked) _vault.Save();
        UpdateVerificationStatus();
    }

    private void UpdatePdfVisualChecklistState(VaultDocument? document, bool loadValues)
    {
        if (document is not null && SelectedDocument?.Id != document.Id) return;
        var isPdf = document?.IsPdf == true;
        PdfVisualChecklistPanel.IsVisible = isPdf;
        ConfirmVisualInspectionCheck.IsVisible = isPdf;
        if (loadValues)
        {
            _loadingPdfVisualChecklist = true;
            var brandName = isPdf && (document!.WorkflowStage >= 2 ? document.Draft.PdfBrandNameVerified : document.PdfBrandNameVerified);
            var alcoholVolume = isPdf && (document!.WorkflowStage >= 2 ? document.Draft.PdfAlcoholVolumeVerified : document.PdfAlcoholVolumeVerified);
            var governmentWarning = isPdf && (document!.WorkflowStage >= 2 ? document.Draft.PdfGovernmentWarningVerified : document.PdfGovernmentWarningVerified);
            var visible = isPdf && (document!.WorkflowStage >= 2 ? document.Draft.PdfVisibleVerified : document.PdfVisibleVerified);
            PdfBrandNameCheck.IsChecked = brandName;
            PdfAlcoholVolumeCheck.IsChecked = alcoholVolume;
            PdfGovernmentWarningCheck.IsChecked = governmentWarning;
            PdfVisibleCheck.IsChecked = visible;
            _settingVisualInspectionConfirmation = true;
            ConfirmVisualInspectionCheck.IsChecked = isPdf && (document!.WorkflowStage >= 2
                ? document.Draft.PdfVisualInspectionConfirmed
                : document.PdfVisualInspectionConfirmed);
            _settingVisualInspectionConfirmation = false;
            if (isPdf)
            {
                document!.Draft.PdfBrandNameVerified = brandName;
                document.Draft.PdfAlcoholVolumeVerified = alcoholVolume;
                document.Draft.PdfGovernmentWarningVerified = governmentWarning;
                document.Draft.PdfVisibleVerified = visible;
                if (document.WorkflowStage < 2)
                    document.Draft.PdfVisualInspectionConfirmed = document.PdfVisualInspectionConfirmed;
            }
            _loadingPdfVisualChecklist = false;
        }

        var mayEdit = isPdf && _authenticated && _currentAccount?.Role == VaultRole.Analyst &&
                      _sessionQueueIds.Contains(document!.Id) && document.Draft.ImageExtractionCompleted &&
                      document.WorkflowStatus == "InReview" && (document.WorkflowStage == 1 || document.WorkflowStage >= 3);
        PdfBrandNameCheck.IsEnabled = mayEdit;
        PdfAlcoholVolumeCheck.IsEnabled = mayEdit;
        PdfGovernmentWarningCheck.IsEnabled = mayEdit;
        PdfVisibleCheck.IsEnabled = mayEdit;
    }

    private static bool ArePdfVisualChecklistChecksComplete(bool brandName, bool alcoholVolume, bool governmentWarning, bool visible) =>
        brandName && alcoholVolume && governmentWarning && visible;

    private static bool IsPdfVisualChecklistComplete(ReviewDraft draft) => ArePdfVisualChecklistChecksComplete(
        draft.PdfBrandNameVerified,
        draft.PdfAlcoholVolumeVerified,
        draft.PdfGovernmentWarningVerified,
        draft.PdfVisibleVerified);

    private static void ResetPdfVisualChecklist(ReviewDraft draft)
    {
        draft.PdfBrandNameVerified = false;
        draft.PdfAlcoholVolumeVerified = false;
        draft.PdfGovernmentWarningVerified = false;
        draft.PdfVisibleVerified = false;
        draft.PdfVisualInspectionConfirmed = false;
    }

    private static void ResetPdfVisualChecklist(VaultDocument document, ReviewDraft draft)
    {
        ResetPdfVisualChecklist(draft);
        document.PdfBrandNameVerified = false;
        document.PdfAlcoholVolumeVerified = false;
        document.PdfGovernmentWarningVerified = false;
        document.PdfVisibleVerified = false;
        document.PdfVisualInspectionConfirmed = false;
    }

    private void RefreshVerificationStatus() => UpdateVerificationStatus();

    private bool IsStageTwoReady(VaultDocument document)
    {
                var extractionReady = document.IsPdf
                        ? string.Equals(document.Draft.PdfMalwareScanResult, "No threats found", StringComparison.Ordinal) &&
                            string.Equals(document.Draft.PdfMalwareScanProvider, "ClamAV", StringComparison.Ordinal) &&
                            document.Draft.ImageExtractionCompleted &&
                                    !string.IsNullOrWhiteSpace(document.Draft.PdfExtractedTextAndForms) &&
                                    !string.IsNullOrWhiteSpace(document.Draft.MatchQuery)
                        : document.Draft.ScanCompleted && document.Draft.ImageExtractionCompleted &&
                            !string.IsNullOrWhiteSpace(document.Draft.MatchQuery);
            return extractionReady && ImagesVerifiedCheck.IsChecked == true &&
                    (!document.IsPdf || (IsPdfVisualChecklistComplete(document.Draft) &&
                                          (document.Draft.PdfVisualInspectionConfirmed || ConfirmVisualInspectionCheck.IsChecked == true))) &&
               int.TryParse(AccuracyBox.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var score) && score is >= 0 and <= 100 &&
               (ReviewNotesBox.Text?.Trim().Length ?? 0) >= 5;
    }

    private List<string> GetMissingStageTwoRequirements(VaultDocument document, bool includeReviewFields)
    {
        var missing = new List<string>();
        if (_currentAccount?.Role != VaultRole.Analyst)
            missing.Add("Sign in with an Analyst account.");
        if (!_sessionQueueIds.Contains(document.Id))
            missing.Add("Add the selected record to the current Session Work Queue.");
        if (document.WorkflowStatus != "InReview" || (document.WorkflowStage != 1 && document.WorkflowStage < 3))
            missing.Add("Select an active review draft (Stage 1 or a returned review).");

        if (document.IsPdf)
        {
            if (!string.Equals(document.Draft.PdfMalwareScanResult, "No threats found", StringComparison.Ordinal) ||
                !string.Equals(document.Draft.PdfMalwareScanProvider, "ClamAV", StringComparison.Ordinal))
                missing.Add("Complete the local ClamAV scan and obtain the required clean result.");
            if (!document.Draft.ImageExtractionCompleted || string.IsNullOrWhiteSpace(document.Draft.PdfExtractedTextAndForms))
                missing.Add("Extract PDF selectable text, form fields, and supported embedded images.");
            if (string.IsNullOrWhiteSpace(document.Draft.MatchQuery))
                missing.Add("Enter a match term and run Analyze and match.");
            if (!IsPdfVisualChecklistComplete(document.Draft))
            {
                if (!document.Draft.PdfBrandNameVerified) missing.Add("Check BRAND NAME in Inspect.");
                if (!document.Draft.PdfAlcoholVolumeVerified) missing.Add("Check ALC./VOL mL in Inspect.");
                if (!document.Draft.PdfGovernmentWarningVerified) missing.Add("Check GOVERNMENT WARNING in Inspect.");
                if (!document.Draft.PdfVisibleVerified) missing.Add("Check VISIBLE in Inspect.");
            }
            if (includeReviewFields && !document.Draft.PdfVisualInspectionConfirmed && ConfirmVisualInspectionCheck.IsChecked != true)
                missing.Add("Check Confirm visual inspection in Step 4 (Review).");
        }
        else
        {
            if (!document.Draft.ScanCompleted) missing.Add("Run the defensive text scan.");
            if (!document.Draft.ImageExtractionCompleted) missing.Add("Run image extraction, including confirming the no-image case.");
            if (string.IsNullOrWhiteSpace(document.Draft.MatchQuery)) missing.Add("Enter a match term and run Analyze and match.");
        }

        if (includeReviewFields)
        {
            if (ImagesVerifiedCheck.IsChecked != true) missing.Add("Check Images reviewed.");
            if (!int.TryParse(AccuracyBox.Text?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var score) || score is < 0 or > 100)
                missing.Add("Enter an accuracy value as a whole number from 0 to 100.");
            if ((ReviewNotesBox.Text?.Trim().Length ?? 0) < 5)
                missing.Add("Enter review notes of at least 5 characters.");
        }
        return missing;
    }

    private string BuildMissingStageTwoRequirements(VaultDocument document)
    {
        var missing = GetMissingStageTwoRequirements(document, includeReviewFields: true);
        return missing.Count == 0
            ? "All review requirements are complete. Confirm review and encrypt is ready."
            : "Still required:\n• " + string.Join("\n• ", missing);
    }

    private void StopTimerAndSave(VaultDocument? document = null)
    {
        var timers = document is null
            ? _reviewTimers.Values.ToArray()
            : _reviewTimers.TryGetValue(document.Id, out var selectedTimer) ? new[] { selectedTimer } : Array.Empty<ReviewTimerState>();
        if (timers.Length == 0) return;
        foreach (var timer in timers)
        {
            timer.Stopwatch.Stop();
            timer.Document.ReviewElapsedSeconds = timer.BaseElapsedSeconds + timer.Stopwatch.Elapsed.TotalSeconds;
            timer.Document.ReviewTimerActive = false;
            _reviewTimers.Remove(timer.Document.Id);
        }
        if (_vault.IsUnlocked) _vault.Save();
        TimerStatus.Text = "Timer stopped automatically; elapsed time saved";
        _runtimeLog.Add("Review timer stopped; elapsed seconds saved with the record.");
        UpdateTimerDisplay();
    }

    private void SyncReviewTimer(VaultDocument document)
    {
        if (_reviewTimers.ContainsKey(document.Id))
            return;

        if (_currentAccount?.Role != VaultRole.Analyst)
        {
            TimerStatus.Text = "Timer runs only while an Analyst is actively reviewing a record";
            UpdateTimerDisplay();
            return;
        }

        if (document.WorkflowStatus != "InReview")
        {
            TimerStatus.Text = $"Review timer stopped · {document.WorkflowStatus}";
            UpdateTimerDisplay();
            return;
        }

        _reviewTimers[document.Id] = new ReviewTimerState(document, Stopwatch.StartNew(), Math.Max(0, document.ReviewElapsedSeconds));
        if (string.IsNullOrEmpty(document.ReviewStartedAtUtc))
            document.ReviewStartedAtUtc = DateTimeOffset.UtcNow.ToString("O");
        document.ReviewTimerActive = true;
        TimerStatus.Text = "Review timer running automatically for the selected Analyst draft";
        _runtimeLog.Add("Review timer started automatically for an active Analyst draft.");
        _vault.Save();
        UpdateTimerDisplay();
    }

    private void PersistRunningTimer()
    {
        if (_reviewTimers.Count == 0 || !_vault.IsUnlocked) return;
        foreach (var timer in _reviewTimers.Values)
        {
            timer.Document.ReviewElapsedSeconds = timer.BaseElapsedSeconds + timer.Stopwatch.Elapsed.TotalSeconds;
            timer.Document.ReviewTimerActive = true;
        }
        _vault.Save();
    }

    private void MarkActivity() => _lastActivityTimestamp = Stopwatch.GetTimestamp();

    private void UpdateTimerDisplay()
    {
        var document = SelectedDocument;
        var total = document is not null && _reviewTimers.TryGetValue(document.Id, out var timer)
            ? timer.BaseElapsedSeconds + timer.Stopwatch.Elapsed.TotalSeconds
            : document?.ReviewElapsedSeconds ?? 0;
        var elapsed = TimeSpan.FromSeconds(Math.Max(0, total));
        TimerDisplay.Text = $"{(int)elapsed.TotalHours:00}:{elapsed.Minutes:00}:{elapsed.Seconds:00}";
    }

    private static string FormatStampDate(string value) =>
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var timestamp)
            ? timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.CurrentCulture)
            : "timestamp unavailable";

    private async Task MessageBoxAsync(string title, string message)
    {
        var closeButton = new Button
        {
            Content = "Close",
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right,
            Padding = new Avalonia.Thickness(18, 8)
        };
        var dialog = new Window
        {
            Title = title,
            Width = 440,
            SizeToContent = Avalonia.Controls.SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false,
            Content = new StackPanel
            {
                Margin = new Avalonia.Thickness(20),
                Spacing = 16,
                Children =
                {
                    new TextBlock { Text = message, TextWrapping = Avalonia.Media.TextWrapping.Wrap },
                    closeButton
                }
            }
        };
        closeButton.Click += (_, _) => dialog.Close();
        AttachRuntimeProtections(dialog);
        await dialog.ShowDialog(this);
    }

    private async Task<string?> PromptAccountPasswordAsync(string title, string message)
    {
        var completion = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var passwordBox = new TextBox { PasswordChar = '●', PlaceholderText = "Account password" };
        var status = new TextBlock { TextWrapping = Avalonia.Media.TextWrapping.Wrap };
        var dialog = new Window
        {
            Title = title,
            Width = 460,
            SizeToContent = Avalonia.Controls.SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false
        };
        var cancel = new Button { Content = "Cancel", Classes = { "secondary" } };
        var confirm = new Button { Content = "Authenticate and sign", Classes = { "action" } };
        cancel.Click += (_, _) =>
        {
            passwordBox.Text = string.Empty;
            completion.TrySetResult(null);
            dialog.Close();
        };
        confirm.Click += (_, _) =>
        {
            if (string.IsNullOrEmpty(passwordBox.Text))
            {
                status.Text = "Enter your account password to continue.";
                return;
            }
            var password = passwordBox.Text;
            passwordBox.Text = string.Empty;
            completion.TrySetResult(password);
            dialog.Close();
        };
        dialog.Content = new StackPanel
        {
            Margin = new Avalonia.Thickness(20),
            Spacing = 12,
            Children =
            {
                new TextBlock { Text = message, TextWrapping = Avalonia.Media.TextWrapping.Wrap },
                passwordBox,
                status,
                new StackPanel
                {
                    Orientation = Avalonia.Layout.Orientation.Horizontal,
                    HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right,
                    Spacing = 8,
                    Children = { cancel, confirm }
                }
            }
        };
        dialog.Closed += (_, _) =>
        {
            passwordBox.Text = string.Empty;
            completion.TrySetResult(null);
        };
        AttachRuntimeProtections(dialog);
        await dialog.ShowDialog(this);
        return await completion.Task;
    }

    protected override void OnClosed(EventArgs e)
    {
        try
        {
            StopTimerAndSave();
            _sessionQueueIds.Clear();
            _vault.Dispose();
        }
        catch (IOException)
        {
            _runtimeLog.Add("Could not save elapsed timer before closing.");
        }
        finally
        {
            _uiTimer.Stop();
            _localPdfParser.Dispose();
            if (_localPdfServicesProcess is { HasExited: false } localServices)
            {
                try { localServices.Kill(entireProcessTree: true); }
                catch (InvalidOperationException) { }
            }
            StopLocalPdfContainers();
            _localPdfServicesProcess?.Dispose();
            ClearPdfImagePreviews(string.Empty);
        }
        base.OnClosed(e);
    }

    private sealed record ReviewTimerState(VaultDocument Document, Stopwatch Stopwatch, double BaseElapsedSeconds);
}
