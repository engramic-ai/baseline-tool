namespace Engramic.Baseline.Platform;

/// <summary>
/// The account this process runs as, from its access token.
/// </summary>
/// <param name="Name">The account name, such as CONTOSO\alex or NT AUTHORITY\SYSTEM.</param>
/// <param name="IsAdministrator">
/// Whether the token holds the Administrators group enabled: an elevated administrator, or SYSTEM. An
/// administrator's filtered token under User Account Control does not.
/// </param>
/// <param name="IsLocalSystem">Whether the account is LocalSystem (S-1-5-18).</param>
public sealed record ProcessAccount(string Name, bool IsAdministrator, bool IsLocalSystem)
{
    /// <summary>Gets whether the process can do what needs elevation: an elevated administrator or SYSTEM.</summary>
    public bool IsElevated => IsAdministrator || IsLocalSystem;
}
