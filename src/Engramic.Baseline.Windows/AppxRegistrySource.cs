using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows;

/// <summary>
/// The Store packages registered for each user, from the package repositories Windows keeps in the registry: it
/// takes a package as installed for a user when their own repository and the device's both list it, which the
/// remarks qualify.
/// </summary>
/// <remarks>
/// <para>
/// Reads only the registry, through the registry primitive, so it is AOT-clean and needs no WinRT. A user's
/// repository is in their classes hive, which is loaded only while they are signed in (or something runs as them):
/// as SYSTEM or an elevated administrator it reads every user whose classes hive is loaded, and lists every other
/// account with a profile as <see cref="AppxReadOutcome.NotLoaded"/>, since their packages are not known; so is a
/// user whose classes hive is unloaded while this runs. Without elevation it reads the current user and is usually
/// denied the others. The service accounts never have a classes hive, so they are
/// <see cref="AppxReadOutcome.Unsupported"/>, and a package registered for one of them alone is never seen.
/// </para>
/// <para>
/// A user's repository keeps keys of packages since updated or removed. Such a key is passed over, and counted in
/// the detail, only once the device's repository no longer lists that package, which is when no one on the device
/// keeps that version: while another user still has the version this user updated from or removed, the key passes,
/// and this user is reported with it. The device's repository lists every package on the device, including those
/// staged for users who do not have them, so it is never read on its own.
/// </para>
/// </remarks>
public sealed class AppxRegistrySource : IAppxPackageSource
{
    private const string ServiceAccountDetail = "A service account has no classes hive (UsrClass.dat), so it has no package repository this source can read.";
    private const string UnloadedDetail = "The user's classes hive (UsrClass.dat) was unloaded while their packages were being read, as when they sign out, so their packages are not known.";

    private readonly IRegistry _registry;

    /// <summary>Initializes a new instance of the <see cref="AppxRegistrySource"/> class.</summary>
    /// <param name="registry">The registry primitive.</param>
    public AppxRegistrySource(IRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);
        _registry = registry;
    }

    /// <inheritdoc/>
    public IReadOnlyList<AppxUserPackages> ReadInstalled()
    {
        var machine = new HashSet<string>(AppxRepository.ReadMachinePackageNames(_registry), AppxPackage.FullNameComparer);
        var locations = new Dictionary<string, string>(AppxPackage.FullNameComparer);
        var results = new List<AppxUserPackages>();
        foreach (var user in AppxRepository.ReadUsers(_registry))
        {
            results.Add(
                AppxRepository.IsServiceAccount(user.Sid) ? new AppxUserPackages(user.Sid, AppxReadOutcome.Unsupported, [], ServiceAccountDetail)
                : user.ClassesLoaded ? ReadUser(user.Sid, machine, locations)
                : new AppxUserPackages(user.Sid, AppxReadOutcome.NotLoaded, [], AppxRepository.NotLoadedDetail(user)));
        }

        return results;
    }

    private AppxUserPackages ReadUser(Sid user, HashSet<string> machine, Dictionary<string, string> locations)
    {
        var classes = user.Value + AppxRepository.ClassesSuffix;
        IReadOnlyList<string>? names;
        try
        {
            names = _registry.GetSubKeyNames(RegistryHive.Users, RegistryView.Registry64, classes + @"\" + AppxRepository.UserRepositoryKey);
            if (names is null && _registry.GetSubKeyNames(RegistryHive.Users, RegistryView.Registry64, classes) is null)
            {
                // HKEY_USERS listed the classes hive a moment ago, and it has gone: the user signed out while this ran.
                return new AppxUserPackages(user, AppxReadOutcome.NotLoaded, [], UnloadedDetail);
            }
        }
        catch (UnauthorizedAccessException e)
        {
            return new AppxUserPackages(user, AppxReadOutcome.Denied, [], e.Message);
        }
        catch (IOException e)
        {
            return new AppxUserPackages(user, AppxReadOutcome.Failed, [], e.Message);
        }

        if (names is null)
        {
            // The classes hive is loaded and has no repository: an account that has never had a package.
            return new AppxUserPackages(user, AppxReadOutcome.Read, [], string.Empty);
        }

        var packages = new List<AppxPackage>();
        var notOnDevice = 0;
        var notNames = 0;
        foreach (var name in names)
        {
            if (!machine.Contains(name))
            {
                notOnDevice++;
            }
            else if (!AppxPackage.TryParse(name, out var package))
            {
                notNames++;
            }
            else
            {
                if (!locations.TryGetValue(name, out var location))
                {
                    location = AppxRepository.ReadInstallLocation(_registry, name);
                    locations[name] = location;
                }

                packages.Add(package with { InstallLocation = location });
            }
        }

        var notes = new List<string>();
        if (notOnDevice > 0)
        {
            notes.Add($"Passed over {notOnDevice} keys of the user's package repository that the device's repository does not list: packages since updated or removed, which no one on the device keeps.");
        }

        if (notNames > 0)
        {
            notes.Add($"Passed over {notNames} keys that are not package full names.");
        }

        return new AppxUserPackages(user, AppxReadOutcome.Read, [.. packages.OrderBy(p => p.FullName, AppxPackage.FullNameComparer)], string.Join(' ', notes));
    }
}
