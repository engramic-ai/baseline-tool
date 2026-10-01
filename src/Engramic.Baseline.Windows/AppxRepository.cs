using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows;

/// <summary>
/// Where Windows keeps its records of Store packages in the registry, and who the users are: what the two Appx
/// sources share.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>The device's package repository, <see cref="MachineRepositoryKey"/>: one key for each package on the device
/// (staged, or registered for anyone), named by its full name, with its folder in the value <c>Path</c>. Resource
/// packages and bundles have keys too. A package removed from the device loses its key.</item>
/// <item>Each user's package repository, <see cref="UserRepositoryKey"/> in the user's classes hive
/// (<c>HKEY_USERS\&lt;sid&gt;_Classes</c>, loaded while the user is signed in): one key for each main and framework
/// package registered for the user. Keys of packages since updated or removed are not always deleted, so a key
/// here alone does not mean the package is installed.</item>
/// <item>The profiles, <see cref="ProfileListKey"/>: one key for each account that has a profile on the device,
/// signed in or not.</item>
/// </list>
/// None of these is documented as an interface; docs/DOTNET.md (spike 8) records what was compared with Windows'
/// own answer, and on which builds.
/// </remarks>
internal static class AppxRepository
{
    /// <summary>The device's package repository, below HKEY_LOCAL_MACHINE.</summary>
    public const string MachineRepositoryKey = @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages";

    /// <summary>A user's package repository, below their classes hive.</summary>
    public const string UserRepositoryKey = @"Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

    /// <summary>The profiles on the device, below HKEY_LOCAL_MACHINE.</summary>
    public const string ProfileListKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    /// <summary>The suffix of the name a user's classes hive is loaded under, beside their own hive.</summary>
    public const string ClassesSuffix = "_Classes";

    /// <summary>
    /// The users of the device: every account with a profile, and every account whose hive is loaded, in the order
    /// of their security identifiers.
    /// </summary>
    public static IReadOnlyList<AppxUser> ReadUsers(IRegistry registry)
    {
        var loaded = registry.GetSubKeyNames(RegistryHive.Users, RegistryView.Registry64, string.Empty) ?? [];
        var profiles = registry.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, ProfileListKey) ?? [];
        var hives = new HashSet<string>(loaded, StringComparer.OrdinalIgnoreCase);
        var users = new SortedDictionary<string, Sid>(StringComparer.Ordinal);
        foreach (var name in loaded.Concat(profiles))
        {
            if (Sid.TryParse(name, out var sid))
            {
                users.TryAdd(sid.Value, sid);
            }
        }

        return [.. users.Values.Select(sid => new AppxUser(sid, hives.Contains(sid.Value), hives.Contains(sid.Value + ClassesSuffix)))];
    }

    /// <summary>The full names of every package on the device, from its package repository.</summary>
    /// <exception cref="IOException">The device's package repository does not exist.</exception>
    public static IReadOnlyList<string> ReadMachinePackageNames(IRegistry registry)
    {
        return registry.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, MachineRepositoryKey)
            ?? throw new IOException($@"The device's package repository, HKEY_LOCAL_MACHINE\{MachineRepositoryKey}, does not exist.");
    }

    /// <summary>The folder the device's package repository gives for a package; empty when it gives none.</summary>
    public static string ReadInstallLocation(IRegistry registry, string fullName)
    {
        return registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, MachineRepositoryKey + @"\" + fullName, "Path")?.Text ?? string.Empty;
    }

    /// <summary>Why a user's hive was not read, when it was not loaded.</summary>
    public static string NotLoadedDetail(AppxUser user)
    {
        return user.HiveLoaded
            ? "The user's classes hive (UsrClass.dat) is not loaded, so their package repository cannot be read."
            : "The user's registry hive is not loaded, as when they are not signed in, so their package repository cannot be read.";
    }
}

/// <summary>A user of the device, and which of their hives are loaded.</summary>
/// <param name="Sid">The user's security identifier.</param>
/// <param name="HiveLoaded">Whether their own hive (NTUSER.DAT) is loaded under HKEY_USERS.</param>
/// <param name="ClassesLoaded">Whether their classes hive (UsrClass.dat) is loaded under HKEY_USERS.</param>
internal sealed record AppxUser(Sid Sid, bool HiveLoaded, bool ClassesLoaded);
