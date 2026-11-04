namespace Engramic.Baseline.Platform;

/// <summary>
/// A registry hive the registry primitive can read. Hives are added as the checks that need them are ported.
/// </summary>
public enum RegistryHive
{
    /// <summary>HKEY_LOCAL_MACHINE: the device's own settings.</summary>
    LocalMachine,

    /// <summary>
    /// HKEY_USERS: the hives of the accounts whose profiles are loaded, each under its security identifier,
    /// such as the signed-in person's per-user installs and Store packages.
    /// </summary>
    Users,
}
