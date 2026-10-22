using System;

namespace SecRev.Models;

internal enum VaultRole
{
    Analyst = 1,
    Custodian = 2
}

internal sealed class VaultAccount
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = string.Empty;
    public VaultRole Role { get; set; } = VaultRole.Analyst;
    public bool IsEnabled { get; set; } = true;
    public string PasswordSalt { get; set; } = string.Empty;
    public string PasswordVerifier { get; set; } = string.Empty;
    public int PasswordIterations { get; set; }
}
