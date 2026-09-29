using System.Security.Principal;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows;

/// <summary>
/// This process: the account it runs as and whether it is elevated, from its access token.
/// </summary>
public static class CurrentProcess
{
    /// <summary>Reads the account this process runs as.</summary>
    /// <returns>
    /// The account: its name as Windows resolves it (DOMAIN\user, or NT AUTHORITY\SYSTEM), whether the
    /// token holds the Administrators group enabled, and whether it is LocalSystem.
    /// </returns>
    public static ProcessAccount ReadAccount()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return new ProcessAccount(identity.Name, principal.IsInRole(WindowsBuiltInRole.Administrator), identity.IsSystem);
    }
}
