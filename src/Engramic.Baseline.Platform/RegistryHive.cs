namespace Engramic.Baseline.Platform;

/// <summary>
/// A registry hive the registry primitive can read. Hives are added as the checks that need them are ported.
/// </summary>
public enum RegistryHive
{
    /// <summary>HKEY_LOCAL_MACHINE: the device's own settings.</summary>
    LocalMachine,

    /// <summary>
    /// HKEY_USERS: the hives Windows has loaded, one for each account signed in or otherwise in use, each named by
    /// its security identifier, with the account's classes hive beside it as <c>&lt;sid&gt;_Classes</c>.
    /// </summary>
    Users,
}
