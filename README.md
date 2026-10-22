# SecRev — Local Document Review Prototype

SecRev is an experimental Avalonia/.NET 10 desktop application with a native C++ analysis library. It supports local Analyst/Custodian review of UTF-8 text documents and PDFs. It is a prototype—not a production security product, malware sandbox, audit system, or compliance implementation. Nothing here establishes FIPS validation or FedRAMP authorization.

## At a glance

- **Desktop:** Avalonia/.NET 10, local encrypted vault, local account roles, transient session work queue.
- **Native library:** C ABI/P/Invoke for role-priority checks, simple text statistics, fixed-string scanning, and exact substring matching.
- **PDF services:** macOS uses local ClamAV/Tesseract dependencies; Windows and Linux use the restricted local Docker Compose parser/ClamAV stack. See [PDF processing](#pdf-processing).
- **Azure:** separate reference scaffold under `Azure/PdfPipeline/`; it is not called by the desktop and has not been deployed.

## Build and run

Requirements for the desktop: .NET 10 SDK and Apple Clang/Xcode command-line tools on macOS.

### GitHub Codespaces and browser use

The checked-in project is an Avalonia **desktop** application targeting `net10.0` with `OutputType` `WinExe`; it is not a precompiled Codespaces application, browser-hosted UI, or WebAssembly build. `dotnet build` may compile the project in a suitably provisioned Codespace, but a Codespaces browser tab does not by itself provide the native desktop window/display required to interact with it. The current native C++ bridge is compiled as a platform-specific shared library and called through P/Invoke; it is not compiled to WebAssembly. Running the desktop from a headless Codespace would require a separately configured remote desktop/virtual display, while browser-tab use requires a separately designed and validated web/WASM frontend and compatible native-function bridge. PDF services and their platform dependencies also require separate setup. Do not assume the current desktop package will run seamlessly in Codespaces or a browser.

#### Turnkey Codespaces desktop preview

This repository includes a Linux devcontainer under `.devcontainer/` for building and previewing the **existing desktop app** in a Codespaces browser tab. Create a Codespace from the repository's default branch; the container uses .NET 10, installs Clang/C++ tools and Avalonia/X11 runtime libraries, restores/builds/tests SecRev, then starts Xvfb, Fluxbox, x11vnc and noVNC. Open the automatically forwarded **private** port 6080 to view the desktop; the landing page connects to the virtual display, where SecRev starts automatically. Closing/exiting the **last** noVNC browser client disconnects its VNC session; x11vnc's disconnect callback then stops SecRev only, leaving Xvfb, x11vnc and noVNC running so port 6080 keeps working. The callback skips the stop if another client is still connected (for example, a browser tab refresh), and x11vnc relaunches SecRev automatically whenever a browser connects and it is not running. A transient viewer/network disconnect also ends the SecRev session until the next connection. Use `bash .devcontainer/stop-codespace.sh` for full manual shutdown; restarting the Codespace starts the desktop again.

This is remote-desktop streaming of the Linux desktop app, **not** Avalonia WebAssembly or a native browser UI. The noVNC web port must remain Codespaces-private; the VNC server listens only on container loopback and has no VNC password. Do not make the forwarded port public or use this preview with production/regulated documents, credentials, or real vault data. A Codespace is a hosted development environment; its storage, forwarded display, identity, and network are not the local prototype's security boundary.

The setup validates the .NET desktop build/tests and native Linux compilation. It does not automatically provide the PDF malware/parser stack: PDF scanning may require Docker-in-Docker support and service setup not included in this desktop preview. Windows/macOS builds and screen-capture behavior must still be validated on their respective platforms. See `.devcontainer/devcontainer.json` and the scripts in `.devcontainer/` for implementation details.

**Online sandbox configuration acknowledged:** `.devcontainer/devcontainer.json` provisions the .NET 10 Linux Codespace, C++ toolchain, Avalonia/X11 runtime libraries, private forwarded port 6080, and automated restore/build/test/start commands. `.devcontainer/install-dependencies.sh` installs native and virtual-display dependencies; `.devcontainer/start-codespace.sh` launches Xvfb, Fluxbox, loopback-only VNC, noVNC, and SecRev; `.devcontainer/stop-codespace.sh` supports manual shutdown and the automatic last-browser-client disconnect callback. These files prepare a development/test sandbox only. They do not make SecRev a browser/WASM app or make the Codespace appropriate for sensitive production records. Configuration syntax has been checked locally, but Codespaces provisioning, GUI interaction, and browser-close shutdown still require an end-to-end test in GitHub Codespaces.

#### DigitalOcean Droplet deployment (one container, persistent vault)

`deploy/digitalocean/deploy.sh` creates one Droplet (`s-1vcpu-2gb`) running a single container built from `Dockerfile.desktop`, plus a **1 GiB** block-storage volume (DigitalOcean's minimum size). The container holds the full desktop UI (streamed to the browser via noVNC), ClamAV, Tesseract and the PDF parser, so every feature runs inside it. Only the encrypted vault directory (`/data/.config/SecRev`, i.e. `vault.enc`) lives on the volume; it is mounted at `/mnt/secrev_data/vault` on the host, formatted only if blank, and survives container rebuilds and Droplet restarts. ClamAV signatures (several hundred MB) are intentionally kept off the volume and re-downloaded on each start.

```sh
doctl auth init
[VNC_PASSWORD='at-least-12-chars'] DOMAIN=secrev.example.com ADMIN_CIDR=203.0.113.4/32 deploy/digitalocean/deploy.sh
```

- `VNC_PASSWORD` is **optional**. If set (12+ characters from `A-Z a-z 0-9 . _ @ % + = -`), noVNC prompts for it; if unset, no viewer password is required, so with a public `DOMAIN` anyone with the URL can use the desktop.
- With `DOMAIN`, the Droplet installs Caddy (a host service, not a second container) for automatic HTTPS and opens ports 80/443; point the domain's A record at the printed IP. Without `DOMAIN`, nothing is exposed publicly: set `ADMIN_CIDR` to allow SSH and use `ssh -L 8080:127.0.0.1:8080 root@<ip>`, then open `http://localhost:8080`.
- First boot clones the repository (it must be publicly cloneable, or set `REPO_URL`) and builds the image, which takes roughly 10-15 minutes. PDF scans fail closed for another minute or two after each start until ClamAV signatures download. Override `REGION`, `SIZE`, `NAME`, or `BRANCH` through environment variables; do not go below 4 GB RAM because clamd alone uses about 1.3 GB.
- The container publishes on `127.0.0.1` only, runs as a non-root user with all capabilities dropped, and the Droplet firewall allows only the ports above.

Still a demo-grade deployment: the first-Custodian bootstrap token is prefilled in the UI and printed in `docker logs secrev` on each start, so setting `VNC_PASSWORD` is strongly recommended; there are no backups of the volume (take DigitalOcean snapshots if needed); and the container is not an approved enterprise scanning or isolation boundary. Do not use real or regulated documents without a separate review.

#### Optional Render browser-streamed desktop and PDF services

Render cannot run Docker-in-Docker, so `Dockerfile.desktop` bundles ClamAV, Tesseract and the PDF parser inside the image. `scripts/render-desktop.sh` downloads ClamAV signatures on every container start, then runs clamd and the parser on loopback with a per-start random token and passes the endpoint/token to the app (`SECREV_PDF_SERVICES_MANAGED=1`). The compose launcher is not used there. PDF scans fail closed until signatures are loaded, so the first scan after a start can report that services are still starting. clamd uses roughly 1.3 GB of RAM; choose an instance with at least 2 GB. This remains a demo-only arrangement, not an approved enterprise scanning attestation.

#### Public static showcase

The `docs/` folder contains a public, static showcase with fixed synthetic examples and downloadable synthetic text samples only. Anything in the published folder is publicly accessible. It has no upload form, free-text input, account, vault, or processing API; it is not the desktop application or a hosted document-review service. The page does not open or process its downloadable samples. GitHub Pages can publish this static page from the repository, but it cannot run the .NET/native backend. To publish, enable **Settings → Pages → Build and deployment → Source: GitHub Actions**. The workflow at `.github/workflows/pages.yml` deploys `docs/` after changes are pushed to `main` (or when manually run). GitHub provides the public Pages URL after the first successful deployment; availability is subject to GitHub Pages service availability.

```sh
dotnet build SecRev.csproj
dotnet run --project SecRev.csproj
dotnet test Tests/SecRev.Tests/SecRev.Tests.csproj
clang++ -std=c++17 -O2 native/secrev_native.cpp native/native_core_tests.cpp -o /tmp/secrev-native-tests && /tmp/secrev-native-tests
```

The desktop build and native C++ tests are separate checks. They do not constitute end-to-end PDF, security, or cryptographic validation.

### PDF service prerequisites

PDF scanning and extraction use a local parser plus ClamAV. The app starts the service launcher automatically on the first PDF scan. These are the host prerequisites for that workflow:

| Host OS | Prerequisites |
|---|---|
| macOS | .NET 10 SDK, Apple Clang/Xcode command-line tools, Homebrew ClamAV, Tesseract with English (`eng`) data, `openssl`, and `python3`. |
| Windows | Docker Desktop with its Linux container engine enabled, Docker Compose v2, and Windows PowerShell. Start Docker Desktop before scanning. |
| Linux | Docker Engine, the Docker Compose v2 plugin, Bash, and permission for the current user to access the Docker daemon. Start Docker before scanning. |

On Windows and Linux, the Compose configuration runs Linux containers and currently requests the `linux/amd64` parser image. Non-amd64 hosts need Docker support/emulation for that architecture. The first scan requires network access to pull/build the parser image and download ClamAV signatures; subsequent starts reuse the image and persistent signature volume. Ensure `127.0.0.1:5080` is available. No host ClamAV or Tesseract installation is required on Windows/Linux.

Prepare/update macOS scanner signatures before scanning:

```sh
brew install clamav tesseract
bash Azure/PdfPipeline/PdfSandbox/run-local-no-docker.sh --update-signatures-only
```

On Windows and Linux, the app uses the Compose launchers [run-local-container-windows.ps1](Azure/PdfPipeline/PdfSandbox/run-local-container-windows.ps1) and [run-local-container-linux.sh](Azure/PdfPipeline/PdfSandbox/run-local-container-linux.sh). The compose file binds the parser only to loopback (`127.0.0.1:5080`), applies resource/process limits, and keeps ClamAV internal to the Compose network. The app supplies a random per-session token; it does not require manual endpoint/token entry. On app close, the launcher stops its Compose services while retaining the ClamAV signature volume. Docker daemon access is highly privileged; use a trusted local Docker installation and user account.

These prerequisites cover the PDF services, not the whole desktop build. The main project has native C++ build targets for macOS (Apple Clang), Linux (Clang), and Windows (MSVC `cl.exe`). Windows desktop builds also require the MSVC C++ Build Tools. Linux native-core build configuration is present but has not been validated on a Linux host; the repository's documented and validated development target remains macOS.

On macOS, the app continues to use the local ClamAV/Tesseract launcher described above. Automatic service discovery depends on repository scripts and the compose file, so a desktop binary published without those companion assets is not a turnkey PDF-processing distribution. Local PDF processing runs in the logged-in user's OS context; the Docker configuration is a prototype isolation layer, not a hardened or independently assessed sandbox. A ClamAV clean verdict is a gate, not proof that a file is safe.

## First run and accounts

1. Unlock or create the local vault with a passphrase of at least 12 characters.
2. On first setup, provision the initial Custodian with the externally supplied one-time token (`SECREV_BOOTSTRAP_TOKEN`) and set account credentials.
3. Sign in with a named local Analyst or Custodian account. The vault passphrase is still required for every session.
4. Analysts import supported files; each import is encrypted and persisted before processing. Custodians manage accounts, review submissions, make Stage 4 decisions, delete records, and transfer permanent records.

In the Codespaces preview only, `.devcontainer/start-codespace.sh` generates a fresh `SECREV_BOOTSTRAP_TOKEN` (stored with mode 600 in the runtime directory, so a rebuild creates a new one) and sets `SECREV_PREFILL_BOOTSTRAP_TOKEN=1`, which makes the app prefill the token field during first-Custodian setup. This demo convenience removes the out-of-band nature of the token; do not use it outside the disposable preview.

The Render browser-streamed demo (`Dockerfile.desktop`, `scripts/render-desktop.sh`) does the same: every container start, restart or redeploy generates a **new** `SECREV_BOOTSTRAP_TOKEN` (unless you set one in Render), prefills it into the first-Custodian form, and also prints it once to the Render service logs. The app shows a "Demo notice" under the token field saying so. The free tier has no persistent disk, so the vault is also reset on each restart; the token and vault are therefore disposable. The stream is public by default, so anyone with the URL can use the prefilled form to become the first Custodian. Setting a `VNC_PASSWORD` environment variable in Render is **optional**; if unset, no viewer password is required. Do not use this demo with real data.

Local account permissions/signatures are workflow controls, not an independent identity authority or security boundary. The bootstrap token is not recoverable after setup.

## Analyst workflow

| Step | Action | Requirements / outcome |
|---|---|---|
| 1 · Unlock | Unlock vault and authenticate | The session queue starts empty. |
| 2 · Workspace | Import a PDF or UTF-8 `.txt`, `.md`, `.csv`, `.json` | Text files are capped at 5 MB; PDFs at 25 MiB. Source bytes are SHA-256 hashed and encrypted at Stage 1. **Scan PDF after import** is an opt-in checkbox here. |
| 3 · Inspect | Scan/extract, compare, analyze, review | PDF extraction requires the exact local ClamAV clean verdict. The input/form, OCR, image-preview and analysis panes are separate. Choose **Compare with blank form** to select a baseline PDF. |
| 4 · Review | Compare OCR and embedded-image previews; confirm visual inspection | This screen has two panes: Tesseract OCR and image previews. **Confirm visual inspection** is required for PDFs. **Confirm review and Encrypt · Stage 2** also requires the checks and fields completed in Inspect. |
| 5 · Protect | **Finalize and Sign · Stage 3** | Re-enter the Analyst password. The signed submission is saved encrypted and awaits Custodian action. |
| 6 · Complete | Review the saved submission; **Save record and proceed to next record** | Removes only the record ID from the session queue. The record remains in the vault and is not permanent until Custodian Stage 4. |

### Step 3 review requirements

Complete the following in Inspect before Stage 2:

- A successful ClamAV-gated PDF extraction, if the record is a PDF.
- A nonempty match term and **Analyze and match**.
- **Images reviewed**. There is no separate extracted-text/forms checkbox; the text/form output still requires human review.
- For PDFs, check **BRAND NAME**, **ALC./VOL mL**, **GOVERNMENT WARNING**, and **VISIBLE** after checking the image/OCR evidence.
- A whole-number accuracy estimate from 0–100 and notes of at least five characters.
- In Step 4, **Confirm visual inspection** after comparing OCR with image previews.

The Stage 2 warning lists specific outstanding requirements. **Save For Later · start next import** preserves the encrypted record and current progress, removes it only from the session queue, and opens the next import picker. Requeue a saved draft from the Analyst vault list to resume it. This action does not encrypt the review at Stage 2, sign it, or mark it permanent.

## PDF processing and comparison

### Import and extraction

PDF import performs basic header/EOF and raw-token checks, then encrypts the source. Those static checks are not antivirus or a full PDF validation. On scan, ClamAV must return its exact clean result before parsing. PdfPig extracts bounded selectable text and read-only AcroForm values; supported embedded images are decoded to bounded PNG previews. Tesseract OCR runs on supported embedded images only (up to five images per PDF). It does not OCR full-page renders or rendered-page fallback previews. Output is machine-generated and must be reviewed; scan/OCR results do not establish document safety or extraction accuracy.

### Blank-form comparison

The sample directory contains `TTB-BLANK-FORM-f510031.pdf` and `TTB-FORM-unlocked.pdf`. Import the filled form, click **Compare with blank form**, then select the blank PDF. Both PDFs must pass local ClamAV before extraction. The comparison reports nonempty changed AcroForm values and selectable-text/OCR differences against the blank baseline. OCR-to-form matching is literal/token comparison, not layout understanding or semantic classification. Flattened/unsupported forms may expose no AcroForm values; OCR may miss or misread text. The report is a review aid, not an automatic decision.

The PDF exact-term match searches the filled document's selectable text, form names/values and embedded-image OCR. It is case-insensitive exact substring matching (1–256 characters), not fuzzy or semantic matching. The selected blank baseline is not itself the query corpus. OCR appears in its dedicated pane and as a labeled reference appended to the selectable/form pane. Image previews provide a zoom slider.

## Persistent records, duplicates, and custody

The **Session Work Queue** is in-memory and resets on login, logout, timeout, and restart. The **Persistent Records Vault** stores encrypted pending and finalized records across sessions. Duplicate detection compares SHA-256 of original bytes; candidates are retained and linked for Custodian resolution. It does not detect semantic duplicates.

Persisted record stages are: **Stage 1** source encryption, **Stage 2** review encryption, **Stage 3** Analyst submission signature, and **Stage 4** Custodian decision signature. The Custodian Review and Custodian Decision are separate UI workflow steps, not persisted Stages 4 and 5. Custodians can select a record directly in the Persistent Records Vault, inspect it read-only, add a valid Stage 3 submission to the Session Work Queue, or use **Review selected submission** to queue it and open Inspect. The Custodian review transition uses the existing valid Stage 3 signature and Analyst PDF attestations; it does not ask the Custodian to repeat the Analyst's extraction/checklist work. In Review, the Custodian can inspect OCR and image previews, see the Analyst attestation status, and separately confirm visual inspection for a PDF before proceeding to the decision screen. That Custodian confirmation is stored and included in the Stage 4 decision signature. The decision screen provides note/password fields and **Approve**, **Reject**, or **Return for further review** actions. Approved and rejected records are permanent after a valid Stage 4 signature; returned records remain at persisted Stage 4 with `ReturnedForReview` status, are not permanent, and can be requeued by an Analyst. Duplicate candidates use the separate duplicate-resolution flow before an approve/reject decision.

The queue and vault record headers include a status dot and text legend: **yellow** means an Analyst-created record is not yet Custodian-approved/rejected (the tooltip distinguishes active submissions awaiting Custodian review from records returned to the Analyst), **green** means Custodian approved, and **red** means Custodian rejected. The status label is also available as a tooltip; color is not the only status indicator. Analyst Stage 3 submission alone does not make a record permanent. No immutable version history is maintained.

Review timers use an in-process monotonic stopwatch and local UTC metadata. The 600-second idle lock and five-attempt/900-second lockouts are local friction controls; a person controlling the app, device, files, or clock can alter/bypass them. Runtime events are in-memory, bounded, and not audit-grade.

For Analysts, when an active queued record reaches five accumulated minutes on its review timer, the app displays a one-time-per-record-per-session time-management prompt: **“You have been working on this record for 5 mins, would you like to save record for later and move on to next record?”** **No, continue working** dismisses the prompt without stopping the timer or blocking the workflow; it will not prompt again for that record until a new login session. **Yes, Begin new record** saves the current in-progress review draft with per-record AES-GCM encryption, marks the record saved for later, removes it from the session queue, and opens the next queued Analyst draft or the import picker. The draft is restored when the record is requeued; formal Stage 2 encryption replaces and clears this interim draft ciphertext. The prompt is an efficiency reminder, not a deadline or an automatic decision; it does not run for Custodians.

The `Tests/SecRev.Tests` project covers Analyst Stage 3 submission/signature verification, Custodian approve/reject/return signatures, PDF attestation gating, queue eligibility, vault save/reload permanence/export eligibility, and encrypted working-draft persistence/time-prompt policy. Run it with `dotnet test Tests/SecRev.Tests/SecRev.Tests.csproj`. These are workflow regression tests; they do not replace end-to-end UI, platform, parser, or security testing.

## Application-layer security policy and enforcement

This section states the policy implemented by the desktop application itself. Enforcement is in the local process and encrypted-vault code; it is not backed by a remote identity provider, trusted execution environment, managed key service, or server-side authorization boundary.

| Policy | Application implementation | Boundary / limitation |
|---|---|---|
| **Unlock before vault access** | Vault unlock requires a passphrase of at least 12 characters. The vault payload is encrypted with AES-256-GCM; the key is derived using PBKDF2-HMAC-SHA-256 with a random salt and 600,000 iterations. The vault key is cleared and in-memory document/account collections reset on lock/dispose. | Local files and process memory are controlled by the host user/admin. Memory clearing is best effort and cannot guarantee erasure of all copies. |
| **Authenticate named, enabled accounts** | Initial Custodian provisioning requires an externally supplied bootstrap token of at least 32 decoded random bytes. Account passwords are at least 12 characters and stored as salted PBKDF2-HMAC-SHA-256 verifiers (600,000 iterations); comparisons use fixed-time equality. Five failed account attempts trigger a 900-second local lockout. | The bootstrap environment variable and vault are local. Lockout state, application code, and the system clock can be changed by someone controlling the device. |
| **Enforce roles and record priority for app operations** | Vault service methods re-check that the account still exists, is enabled, and has the stored role. Analyst operations and Custodian-only operations are separated; document access also checks required priority through the native C ABI. Custodian decisions require password re-entry, and Stage 3/4 workflow signatures are verified before completion/transfer operations. | Roles and signatures are local workflow controls, not an external identity authority or tamper-resistant authorization boundary. A device owner can modify the app or vault. |
| **Encrypt imported source and review data** | Imported source bytes are SHA-256 identified and encrypted at Stage 1 with a per-record random key and AES-256-GCM. Stage 2 review data uses a key derived with HKDF-SHA-256 and is separately encrypted with AES-256-GCM. Temporary byte buffers are zeroed where implemented. | Cryptographic algorithms are implementation choices, not a FIPS validation claim. Data may exist in UI strings, framework buffers, process memory, backups, or plaintext exports. No secure deletion is promised. |
| **Bound and gate untrusted document processing** | Text imports are limited to 5 MB and PDFs to 25 MiB. PDF static inspection checks header/EOF and raw marker strings but is explicitly heuristic. PDF parsing/extraction is gated on the configured local ClamAV exact clean verdict; parser/OCR outputs are bounded and require human review. | Static checks are not antivirus. Local ClamAV is demo-only, not an approved enterprise attestation. Parser/native dependencies are not a hardened disposable sandbox, and clean results do not prove safety. |
| **End inactive sessions and minimize logs** | The app locks after 600 seconds without observed pointer/key activity, clears session queues and sensitive UI values, and locks the vault. Runtime logging is bounded/in-memory and designed to omit document text and clipboard contents. | Local inactivity/lockout controls can be bypassed; active UI and process memory can expose plaintext. Logs are not an immutable or audit-grade record. |
| **Reduce in-app clipboard and capture exposure** | SecRev blocks selected clipboard shortcuts/context-menu requests inside its `TextBox` controls. On Windows it requests capture affinity per window and reports the result. | These are best-effort UI/OS controls; coverage varies, other platforms have no native capture flag implemented, and they cannot stop a device owner or external camera. Details are in [Runtime application safeguards (RASP)](#runtime-application-safeguards-rasp). |

The implementation is intended to reduce accidental disclosure and enforce workflow rules during normal app use. It does not protect against a compromised OS, malicious administrator, process injection, memory inspection, application replacement, or a user who can alter local files. Do not treat client-side policy checks as a substitute for independently enforced service-side controls when a trusted security boundary is required.

## Runtime application safeguards (RASP)

SecRev includes **app-level, best-effort** clipboard and screen-capture interventions plus an optional release obfuscation step. These features are intended to reduce accidental disclosure and raise casual inspection effort; they do not make a client running on a user-controlled device a trusted security boundary.

### Clipboard policy

- Common copy/cut/paste shortcuts originating in a SecRev Avalonia `TextBox` are handled by the app, including Ctrl/Command+C/X/V, Ctrl+Insert, Shift+Insert, and Shift+Delete. Context-menu requests originating in a `TextBox` are suppressed. The policy is attached to the main window and custom dialogs, including password-entry dialogs.
- The UI reports blocked clipboard action categories and a count. Runtime logging is throttled and records only the action category; SecRev never reads, stores, or logs clipboard contents.
- Scope is limited to keyboard and context-menu routed input recognized by the app. Clipboard operations through accessibility, input methods, automation, drag/drop, platform-native menus, or other paths may not be blocked. This is **not** global monitoring: SecRev installs no OS-wide clipboard listener or keyboard hook and does not observe other applications.

### Screen-capture policy

- On Windows, when each Avalonia window opens, SecRev requests the native `WDA_EXCLUDEFROMCAPTURE` display affinity. If that request fails, it attempts `WDA_MONITOR`. The in-app status reports the request result or failure; statuses are also written to the bounded in-memory runtime log without document content.
- On macOS and Linux, SecRev currently reports OS-level capture protection as unavailable; it does not apply an equivalent native capture flag.
- Windows display affinity is an OS request, not a guarantee. Results depend on Windows version and capture path. It cannot prevent external cameras, another device, unsupported capture tools, or bypass by a device owner/administrator.

### Release-only code obfuscation

- The optional Obfuscar pipeline performs **selective private-symbol renaming** on the explicitly marked `NativeCore` and `VaultAccessPolicy` types. It is the only implemented reverse-engineering friction for app-level code; it does not obfuscate the full application.
- It preserves public APIs, skips generated/special-name members, and disables string hiding to avoid its runtime lookup cost. Avalonia/XAML code, persisted models, JSON contracts, and the RASP code are intentionally excluded to reduce reflection, serialization, and UI compatibility risk. Publish output omits PDBs; the original symbols and Obfuscar mapping remain in the ignored `artifacts/obfuscation/` directory and must be protected as private build artifacts.
- To produce a release, restore the pinned local tool with `dotnet tool restore`, then use [publish-obfuscated.sh](scripts/publish-obfuscated.sh) on a matching macOS/Linux host or [publish-obfuscated.ps1](scripts/publish-obfuscated.ps1) with a matching Windows/MSVC developer environment. Supply a supported RID matching the host OS and architecture; native-core cross-compilation is not configured. Test the produced package on its target OS before distribution. The current workspace has validated the macOS x64 obfuscated publish; Windows and Linux obfuscated packages have not yet been validated.
- Obfuscation is **not encryption or anti-tamper**. It does not conceal runtime behavior, reliably protect embedded strings or secrets, or prevent dnSpy, Ghidra, debugging, process modification, or replacement of the client. The project does not implement control-flow flattening, block splitting, junk-code injection, method encryption, virtualization, anti-debugging, release-signature enforcement, or platform security attestation. Those mechanisms are not claimed as implemented.

No in-process RASP feature can reliably prevent a device owner or administrator from inspecting or changing the client. Release signing, verified updates, and OS/device-management enforcement remain separate deployment responsibilities. Treat clipboard blocking, screen-capture flags, and symbol obfuscation as defense-in-depth friction; validate each supported OS and input/capture path before relying on it.

## Custodian record transfer

Custodians can bulk-export permanent records and import SecRev bundles. Each export bundle includes a signed manifest, an encrypted `record.secrev-record.json` package, and the original file in plaintext under its original filename. **Protect the destination as sensitive plaintext data**, using access-controlled encrypted storage. Package passphrases and signatures do not create an external identity trust anchor; local signatures are tamper-evident only relative to bundled keys/code. Import validates the bundle and record signatures/hashes, rejects unsafe/unlisted files and symlinks, and stores accepted records under the destination vault encryption. The local transfer feature is not a managed external vault or remote sync service.

### Custodian export to Azure NoSQL-compatible archive

After a Custodian creates the existing signed permanent-record export bundle, the separate converter can validate and reorganize it for a later Azure Cosmos DB for NoSQL import:

| Host | Command |
|---|---|
| macOS/Linux | `bash scripts/export-nosql-records.sh <custodian-bundle-directory> <new-output-directory> <tenant-guid>` |
| Windows PowerShell | `./scripts/export-nosql-records.ps1 -CustodianBundle <custodian-bundle-directory> -NewOutputDirectory <new-output-directory> -TenantId <tenant-guid>` |

The converter prompts interactively for the Custodian export archive passphrase; it is not accepted as a command-line argument. It consumes only the normal Custodian-created bundle (not the live vault), verifies the signed manifest and its hashes/path list, decrypts each package in memory for validation, and accepts only records whose Analyst Stage 3 signature and Custodian **Approved** or **Rejected** Stage 4 decision verify and are marked permanent. Pending, returned, incomplete, duplicate-only, or invalidly signed records are rejected; the pre-existing Custodian export UI likewise filters to permanent records. The conversion is all-or-nothing and refuses to overwrite an existing output directory.

The output is an **upload-preparation archive**, not a database connection or deployment: it contains per-tenant metadata JSON under `records/<tenant-guid>/<record-id>.json`, the original encrypted `.secrev-record.json` packages under `payloads/<tenant-guid>/`, and `nosql-export-manifest.json`. Metadata preserves record ID, tenant/partition key (`PartitionKey`, matching the current Bicep `/PartitionKey` path), approved/rejected decision and status, Analyst and Custodian identifiers/names/timestamps, Stage 3/Stage 4 signatures and public keys, content digest, export receipt provenance/signature, and encrypted-package path/hash/size. The encrypted package is copied byte-for-byte; plaintext source files, decrypted record JSON, OCR text, image bytes, review notes, and archive passphrase are not written into the NoSQL archive. The converter verifies the plaintext original against the permanent record hash before discarding its in-memory buffer.

Protect the **metadata archive too**: names, identifiers, decision history, timestamps, and document digests can be sensitive. Store the output in access-controlled encrypted storage. Upload the encrypted payloads to a private Azure Blob container and replace the relative `EncryptedPackagePath` values with the resulting URI as part of a separately reviewed ingestion process. The current utility does not connect to Azure, create Cosmos records, upload blobs, or establish tenant authorization, encryption-at-rest, backup, or network-in-transit guarantees. The Azure scaffold is disconnected and undeployed; validate its schema, access controls, key handling, and transport before importing this archive into any production database.

## Future Azure assistant and scan-provider integration (not enabled)

The desktop has **no active Azure API client, cloud-agent connection, Entra token acquisition, token storage, or remote document workflow**. The Azure Upload API and extraction worker described above are a disconnected reference scaffold. A new `Services/FutureCloudIntegrationContracts.cs` file defines dormant boundaries for a future approved threat-scanning provider and an advisory cloud document assistant; these interfaces have no concrete network implementation and are not registered or called by the desktop.

The intended future flow is:

1. Obtain a short-lived Entra access token through an approved interactive/device or brokered sign-in flow. Never embed a client secret or long-lived API token in the desktop, source, settings, command line, or exported record. The API must validate issuer, audience, tenant, user and role server-side and authorize every record request independently of the local desktop role.
2. Send an untrusted PDF only to an approved malware scanning service first. Continue to fail closed: unavailable, unknown, mismatched-digest, or non-clean results must block parsing and AI submission. Record the scanner/provider, verdict, timestamp and exact source digest as provenance.
3. After an explicit per-operation user consent and a valid clean scan for the same content digest, an assistant may receive only the minimum required bounded extracted text/OCR. That content is sensitive. Enforce tenant isolation, TLS, service-side authorization, prompt-injection-aware handling, retention/deletion limits, redacted operational logs, and documented regional/data-processing controls. Do not expose source PDFs, vault keys, credentials or unrelated records to the assistant by default.
4. Treat all model output as **untrusted suggestions** with model/version and evidence references. The assistant must have no tool permission to alter records, set workflow status, sign, approve/reject, make a Custodian decision, or bypass human review. Analysts/Custodians remain responsible for verifying output and signing through the existing local workflow.

The future integration contracts intentionally represent a scanner verdict plus content digest and an advisory request/result, but they do not implement token acquisition, transport, consent UI, Azure endpoints, or data retention. The assistant eligibility helper is policy scaffolding only; it is not proof that an Azure service is configured or that a scan attestation is trustworthy. Any production adapter requires independent security review and integration tests before it is wired into the UI.

**Metasploit is not an antivirus or document malware-scanning service.** It is a penetration-testing/exploitation framework, so SecRev will not call a Metasploit API to scan uploaded PDFs or automate exploitation. Use a vetted malware scanning service such as the existing demo ClamAV gate or an approved Defender for Storage integration for that purpose. Do not process untrusted documents with exploit modules as a substitute for malware scanning or isolated parsing.

These are architecture preparations only. No cloud AI agent, Azure token API integration, Azure upload path from the desktop, or Metasploit integration is installed or enabled.

## Security and functionality assessment

This is a source-based prototype assessment, not an independent security audit or dynamic penetration test. The current desktop and PDF parser .NET projects build; native C++ tests pass. No end-to-end test of PDF samples, password recovery, malicious inputs, or the complete signed workflow was run for this assessment.

### 

| Area | Assessment |
|---|---|
| Core import, encrypted persistence, queue | Stage 1 encryption, local persistence, queue separation, duplicate hash links and resume flows exist. No recovery, secure erasure, multi-user concurrency or immutable versions. |
| Analyst/Custodian workflow |  Staged UI, local role checks, signatures, review requirements and Custodian decisions exist. Local keys/code are not independently trusted; UI/service gating is not tamper-resistant. |
| PDF extraction and review | ClamAV-gated PdfPig/form and embedded-image OCR/preview paths, comparison and bounded outputs exist. Native process isolation is weak; OCR/form comparison is heuristic and no full-page OCR occurs. |
| Authentication and key management | Per-account PBKDF2 verifiers, vault encryption and lockout friction exist. One shared local vault passphrase, local mutable state, self-managed keys, no OS key store/HSM, recovery or external identity. |
| Testing and operational readiness | Build checks and native unit tests exist. No comprehensive .NET test suite, end-to-end parser tests, fuzzing, independent review, release signing/notarization or recovery operations. |
| Azure reference pipeline | Separate code/infrastructure scaffold exists, but it is undeployed and disconnected from desktop; no live integration/security validation. |
| **Overall prototype completeness** | Useful functional demonstration; not suitable as a production document-security or compliance system. |

### 

The security assessment reflects intended sensitive-document use and current local trust boundary; it is not a vulnerability certification. The highest risks are: PDFs are processed by native/parser libraries in the user's process/service context rather than a hardened disposable sandbox; desktop authorization, signing keys and vault files are locally controlled; exported originals are plaintext; local ClamAV is demo-only and not an enterprise attestation; process memory may contain plaintext; and there is no independent audit trail, trusted identity/timestamp, secure deletion, recovery, backup validation, or external key custody. Do not use with regulated/high-impact documents without redesign and independent assessment.

## Unused, placeholder, and disconnected code

A source-reference review found these items; “unused” means no active call/read path was found in the workspace, not that removing the field is safe for old vault data:

- `LocalPdfParserClient.ScanAndExtractImagesAsync()` is an older alternative extraction client path; current desktop PDF review calls `ScanAndExtractReviewAsync()`. The parser still has a corresponding route, but the desktop does not use this method.
- `VaultDocument.ImportedAtUtc` and `PdfLooksEncrypted` are written/defaulted but have no meaningful read/display path. They may be retained for serialized-vault compatibility.
- `VaultDocument.IdentitySigningPrivateKey` is assigned by an identity-stamp path but is not read by current verification/workflow code; the active Stage 3/4 signatures use separate fields. This is unnecessary secret material to review before any data migration/removal.
- `AnalysisDataBox` is hidden in XAML and retained as a code-behind compatibility buffer; the visible analysis UI is `AnalysisReportText`.
- Azure `UploadApi`, `Worker`, `PdfSandbox`, and Bicep are a separate scaffold. They are buildable reference code but not called by the desktop and are not deployed. The parser's Azure/internal endpoints are therefore dormant in this desktop product.
- Source-PDF page preview is explicitly not implemented in the desktop. The Azure parser's PDFium page-one preview is a different, undeployed service path.

Do not remove persisted properties solely because current code does not read them: vault compatibility/migration may depend on their serialized shape.

## Project status and boundaries

The desktop is local/offline and does not connect to Azure. Azure scaffold builds do not prove Azure permissions, connectivity, Defender event compatibility, deployment security, or compliance. No FIPS validation, FedRAMP authorization, zero-knowledge proof, Azure Managed HSM integration, or external identity service is implemented. Cryptographic algorithm names are not certifications. Windows code paths are present but this workspace's validated development target is macOS; there is no iOS target.
