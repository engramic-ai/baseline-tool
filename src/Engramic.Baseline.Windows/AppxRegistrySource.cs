using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows;

/// <summary>
/// The Store packages registered for each user, from the package repositories Windows keeps in the registry: a
/// package is installed for a user when their own repository and the device's both list it.
/// </summary>
/// <remarks>
/// <para>
/// Reads only the registry, through the registry primitive, so it is AOT-clean and needs no WinRT. A user's
/// repository is in their classes hive, which is loaded only while they are signed in (or something runs as them):
/// as SYSTEM or an elevated administrator it reads every user whose classes hive is loaded, and lists every other
/// account with a profile as <see cref="AppxReadOutcome.NotLoaded"/>, since their packages are not known. Without
/// elevation it reads the current user and is usually denied the others.
/// </para>
/// <para>
/// A user's repository keeps keys of packages since updated or removed, which the device's repository no longer
/// lists; those are passed over and counted in the detail. The device's repository lists every package on the
/// device, including those staged for users who do not have them, so it is never read on its own.
/// </para>
/// </remarks>
public sealed class AppxRegistrySource : IAppxPackageSource
{
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
            results.Add(user.ClassesLoaded
                ? ReadUser(user.Sid, machine, locations)
                : new AppxUserPackages(user.Sid, AppxReadOutcome.NotLoaded, [], AppxRepository.NotLoadedDetail(user)));
        }

        return results;
    }

    private AppxUserPackages ReadUser(Sid user, HashSet<string> machine, Dictionary<string, string> locations)
    {
        IReadOnlyList<string>? names;
        try
        {
            names = _registry.GetSubKeyNames(RegistryHive.Users, RegistryView.Registry64, user.Value + AppxRepository.ClassesSuffix + @"\" + AppxRepository.UserRepositoryKey);
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
            // A classes hive with no repository: an account that has never had a package, such as a service's.
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
            notes.Add($"Passed over {notOnDevice} keys of the user's package repository that the device's repository does not list: packages since updated or removed.");
        }

        if (notNames > 0)
        {
            notes.Add($"Passed over {notNames} keys that are not package full names.");
        }

        return new AppxUserPackages(user, AppxReadOutcome.Read, [.. packages.OrderBy(p => p.FullName, AppxPackage.FullNameComparer)], string.Join(' ', notes));
    }
}
