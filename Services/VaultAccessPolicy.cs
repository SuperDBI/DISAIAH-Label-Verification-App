using System;
using System.Reflection;
using SecRev.Models;

namespace SecRev.Services;

[Obfuscation(Exclude = false, ApplyToMembers = true)]
internal static class VaultAccessPolicy
{
    public static void DemandAnalyst(VaultAccount? account)
    {
        if (account is null || !account.IsEnabled || account.Role is not (VaultRole.Analyst or VaultRole.Custodian))
            throw new UnauthorizedAccessException("An active account session is required.");
    }

    public static void DemandCustodian(VaultAccount? account)
    {
        DemandAnalyst(account);
        if (account!.Role != VaultRole.Custodian)
            throw new UnauthorizedAccessException("Custodian access is required for this action.");
    }

    public static void DemandDocumentAccess(VaultAccount? account, VaultDocument document)
    {
        DemandAnalyst(account);
        var rolePriority = account!.Role == VaultRole.Custodian ? 2 : 1;
        if (!NativeCore.CanAccess(rolePriority, document.RequiredPriority))
            throw new UnauthorizedAccessException("The account does not meet this record's required priority.");
    }
}
