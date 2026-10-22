# SecRev workspace guidance

- The user interface is Avalonia with C#; the native analysis/policy core is C++ and is exposed through a C ABI/P/Invoke.
- Keep native functions deterministic and validate inputs at the ABI boundary.
- Keep document content out of runtime logs.
- Treat PDFs and imported files as untrusted; do not render/execute them without an isolated, resource-limited parser/renderer and an approved malware scanning service. The desktop prototype's optional local ClamAV container integration is demo-only, fails closed before PdfPig image extraction, and is not an approved enterprise scanning attestation.
- Preserve authenticated encryption and do not describe this experimental starter as production-ready.
- Do not claim FIPS validation or FedRAMP compliance without the exact validated module, configuration, Azure boundary, and authorization evidence.
- Stage 3's local ECDSA key is a demo only; Azure Managed HSM integration is not implemented.
- Zero-knowledge proof functionality is not implemented; do not imply otherwise.
- Build and validate on macOS with `dotnet build .`.
