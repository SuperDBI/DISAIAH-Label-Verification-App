using System.Collections.Generic;

namespace SecRev.Models;

internal sealed class VaultTransferManifest
{
    public int Version { get; set; } = 1;
    public VaultTransferReceipt Receipt { get; set; } = new();
    public List<VaultTransferManifestEntry> Records { get; set; } = new();
}

internal sealed class VaultTransferManifestEntry
{
    public string PackageFileName { get; set; } = string.Empty;
    public string PackageSha256 { get; set; } = string.Empty;
    public string SourceFileName { get; set; } = string.Empty;
    public string SourceFileSha256 { get; set; } = string.Empty;
    public string RecordId { get; set; } = string.Empty;
    public string OriginalFileName { get; set; } = string.Empty;
}
