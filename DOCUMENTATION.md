# SecRev Application and Human-in-the-Loop Documentation

**Status:** Source-based documentation for the local prototype, reviewed 2026-10-21. This is not a security audit, deployment attestation, or compliance statement.

## 1. Human-in-the-loop (HITL) model

SecRev is designed as a human-operated review workflow. Automated checks and extraction provide bounded evidence or workflow gating; they do not make substantive document, safety, or Custodian decisions.

### Analyst responsibilities

1. **Unlock and authenticate.** The Analyst unlocks the local vault and signs in with an enabled local account.
2. **Import and choose whether to scan immediately.** The Analyst selects a supported UTF-8 text file or PDF. PDF auto-scan after import is optional; the Analyst can scan later.
3. **Inspect automated evidence.** The Analyst reviews static PDF indicators, ClamAV results, selectable text/forms, supported embedded-image OCR, image previews, and any blank-form comparison. Static checks, ClamAV verdicts, OCR, and comparisons are not a safety or accuracy determination.
4. **Analyze and attest.** The Analyst enters an exact-match query, runs analysis, reviews the content and images, records accuracy and notes, marks the required review checkboxes, and—when applicable—confirms PDF-specific fields and visual inspection.
5. **Protect and submit.** The Analyst confirms Stage 2 review encryption, re-authenticates, and signs the Stage 3 submission. Stage 3 submission does not make a record permanent.
6. **Manage time and work queue.** After five accumulated minutes on an active queued record, the Analyst sees a one-time-per-record-per-session efficiency reminder. They can continue or save the in-progress draft under record-level authenticated encryption and move to the next queued record or import another. The reminder does not auto-submit, reject, or discard work.
7. **Complete the task.** The Analyst reviews the summary and saves/proceeds. Saved-for-later and returned records can be requeued; they remain non-permanent until a valid Custodian decision.

### Custodian responsibilities

1. **Select and inspect an Analyst submission.** The Custodian selects a record from the Persistent Records Vault, queues a valid Stage 3 submission, and opens its review view. The UI displays the Analyst's existing signed submission and PDF attestations.
2. **Perform a separate visual confirmation for PDFs.** Analyst attestations are retained as evidence; they do not substitute for the Custodian's own required visual-inspection confirmation before reaching the decision view.
3. **Make and sign the Stage 4 decision.** The Custodian records a decision note, re-enters their account password, then chooses **Approve**, **Reject**, or **Return for further review**. The decision is signed and bound to the Analyst submission. Approved/rejected records become permanent; returned records remain non-permanent and return to Analyst review.
4. **Resolve duplicates separately.** Duplicate candidates require a Custodian duplicate-resolution action before the ordinary approve/reject workflow.
5. **Transfer only finalized records.** Permanent record export requires Custodian authorization. The export includes a signed manifest, encrypted record packages, and plaintext originals; the destination must be protected as sensitive data. The optional NoSQL converter accepts signed export bundles and only validated permanent Approved/Rejected records.

### Other human decisions and interventions

- **User handles errors and dependency failures.** Invalid input, unavailable scanners/parsers, failed signatures, incomplete attestations, and unsupported extraction are surfaced as status or error dialogs. A failed or non-clean PDF scan must not be treated as successful extraction.
- **User may cancel import, comparison, export, or transfer dialogs.** These actions do not silently create a final decision.
- **RASP is advisory/containment-oriented.** Selected clipboard shortcuts/context-menu requests are blocked inside app TextBoxes; Windows capture affinity is requested best-effort. The user can observe statuses, but these controls do not provide a trustworthy remote audit record.
- **No cloud AI agent currently participates.** The future assistant contracts are dormant. If later connected, model output must remain advisory and require human review; the agent must not sign, approve, reject, modify workflow status, or bypass the Analyst/Custodian gates.

## 2. Automation and authority boundaries

| Function | Automation provides | Human retains authority |
|---|---|---|
| File intake | Size/header checks, SHA-256 digest, source encryption | Select file; decide whether/when to process |
| PDF inspection | Heuristic byte markers | Interpret results; no marker report proves safety |
| Malware scan | Local ClamAV verdict gate in the prototype | Decide next steps; unavailable/unknown/non-clean means parsing is blocked |
| Extraction/OCR | Bounded text, form values, image output and OCR | Compare output with source previews; judge accuracy and relevance |
| Text analysis | Counts and exact substring matches | Select term and interpret findings |
| Stage 2 requirements | Checks required fields/attestations before encryption | Review content and provide attestations/notes |
| Stage 3/4 signatures | Hashes and signatures bind submitted payload/decision | Analyst signs their submission; Custodian makes and signs the disposition |
| Future AI assistant | Proposed evidence-linked suggestions only | Human validates every suggestion; existing signatures remain authoritative |

**No autonomous final decision exists.** A machine-generated clean result, match, OCR result, risk marker, or future assistant suggestion is not equivalent to human review or Custodian approval.

## 3. Application-level security model (HIDL)

For this document, **HIDL** means the application's human-in-the-loop decision model: the division between automated evidence, required human review, and final human authority. It is a workflow design description, not a named certification or a claim of independent assurance.

### Roles and transitions

- **Analyst:** imports, inspects, analyzes, records attestations, encrypts the review, and signs Stage 3.
- **Custodian:** manages privileged local functions, reviews valid Stage 3 submissions, resolves duplicates, and signs Stage 4 outcomes.
- **Stages:** Stage 1 encrypts source; Stage 2 encrypts review; Stage 3 signs Analyst submission; Stage 4 signs the Custodian decision. “Custodian Review” and “Custodian Decision” are UI steps, not separate persisted stage numbers.
- **Permanent status:** only a valid, signed Approved/Rejected Stage 4 decision or confirmed duplicate qualifies as permanent. Returned records are not permanent.
- **Local authority limitation:** both accounts, keys, vault data, and app code reside within a user-controlled client environment. Role checks and signatures are local workflow controls, not independent identity or tamper-resistant authorization.

### Data and security assumptions

- New source files are encrypted before persistence; formal review payloads and five-minute working drafts use per-record authenticated encryption. The complete local JSON vault is encrypted with AES-GCM using a passphrase-derived key.
- The local PDF parser is expected to be loopback-bound and token-protected, with configured resource limits. The macOS local process path is not a hardened sandbox; Windows/Linux container use is prototype isolation, not a validated boundary.
- OCR and extracted text are sensitive document content. They are not harmless metadata and must not be sent to cloud services without explicit policy, consent, authorization, data-minimization, retention, and regional-processing decisions.
- The application does not promise secure erasure, trusted timestamps, external identity, immutable audit logging, backup/recovery, protection against a device administrator, or FIPS/FedRAMP compliance.

## 4. SDLC approach and tools

### Current observed development/validation approach

The repository reflects an **iterative prototype SDLC**, not a documented formal lifecycle standard. The available practices evidenced in the workspace are:

1. **Requirements and risk boundaries:** README and workspace guidance document intended workflows, threat boundaries, unsupported claims, and known limitations.
2. **Implementation:** a .NET 10 / Avalonia 12.1.4 desktop, C# services/models, C++17 native C ABI, local PDF parser, and disconnected Azure reference projects.
3. **Verification:** desktop builds with `dotnet build SecRev.csproj`; .NET workflow/security tests run with `dotnet test Tests/SecRev.Tests/SecRev.Tests.csproj`; native-core checks are a standalone C++ test executable. These tests cover selected workflow policy and cryptographic-signature regressions, not full UI/platform behavior.
4. **Release preparation:** optional release-only Obfuscar symbol renaming is available for selected private helpers. Release signing, notarization, provenance/SBOM enforcement, and production deployment approval are not established by the current code.
5. **Operational review:** platform-specific PDF launchers and README prerequisites exist, but all OS workflows have not been end-to-end validated in this workspace.

### Tools and technologies in this workspace

- **Desktop/UI:** .NET 10, C#, Avalonia 12.1.4, XAML, Visual Studio Code.
- **Native core:** C++17, C ABI/P/Invoke, Apple Clang on macOS; MSVC `cl.exe` for Windows; Linux build target is present but platform validation is outstanding.
- **Local PDF flow:** PdfPig, PDFium, Tesseract OCR, ClamAV; macOS shell launcher and Windows/Linux Docker Compose launchers.
- **Tests:** xUnit, Microsoft.NET.Test.Sdk, native C++ assertions.
- **Future cloud reference:** ASP.NET Core, Entra JWT validation, Azure Blob Storage, Defender for Storage event flow, Service Bus, Azure Document Intelligence, Cosmos DB for NoSQL, Azure AI Search, Managed Identity, and Bicep. These Azure components are reference scaffold only and are not connected/deployed as the desktop backend.
- **Optional code hardening:** pinned Obfuscar tool for selective private-symbol renaming in release pipeline. It is not anti-tamper and does not stop reverse engineering.

### Assumptions and non-claims

- This is a local-first demonstration with a single encrypted vault, not a multi-user synchronized record system.
- Custodian and Analyst decisions are made by people. No AI or automated scanner makes authoritative approval/rejection decisions.
- A clean local antivirus response is a gate for the demonstrated parser flow, not proof that a document is safe.
- Azure service names in code/configuration do not imply provisioned resources, secure deployment, production connectivity, or compliance.
- The source-based project assessment and tests do not replace independent security review, threat modeling, fuzzing, platform-specific UI testing, accessibility review, operational readiness, or a production release process.

## 5. Implementation references

- [Analyst/Custodian workflow and stages](README.md#analyst-workflow)
- [Application-layer security policy](README.md#application-layer-security-policy-and-enforcement)
- [Runtime safeguards](README.md#runtime-application-safeguards-rasp)
- [Azure NoSQL conversion](README.md#custodian-export-to-azure-nosql-compatible-archive)
- [Workflow and security tests](Tests/SecRev.Tests/WorkflowSecurityTests.cs)
- [Future cloud integration contracts](Services/FutureCloudIntegrationContracts.cs)
