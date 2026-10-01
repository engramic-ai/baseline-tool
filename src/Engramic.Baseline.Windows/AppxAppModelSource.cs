using System.Runtime.InteropServices;
using System.Security.Principal;
using Engramic.Baseline.Platform;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.Storage.Packaging.Appx;

namespace Engramic.Baseline.Windows;

/// <summary>
/// The Store packages registered for each user, as Windows' package runtime answers for them (appmodel.h): each
/// package on the device is looked up for each user with <c>OpenPackageInfoByFullNameForUser</c>.
/// </summary>
/// <remarks>
/// <para>
/// The packages to ask about are those the device's package repository lists (<see cref="AppxRegistrySource"/>
/// explains it), and the users every account with a profile or a loaded hive. The function is flat Win32, so this
/// is AOT-clean and needs no WinRT; resource packages and bundles are left out, by the properties Windows gives for
/// each package. It needs no elevation to answer for another account.
/// </para>
/// <para>
/// Spike 8 (docs/DOTNET.md) compared it with Get-AppxPackage, and found that Windows answers
/// "registered" for the system packages registered for every user even for an account that does not exist, so a
/// user it cannot otherwise see looks like one with only those; and it also finds a few system packages that
/// Get-AppxPackage does not list (last-known-good copies). It asks once for each package and user.
/// </para>
/// </remarks>
public sealed class AppxAppModelSource : IAppxPackageSource
{
    private readonly IRegistry _registry;
    private readonly IPackageRegistrations _registrations;

    /// <summary>Initializes a new instance of the <see cref="AppxAppModelSource"/> class.</summary>
    /// <param name="registry">The registry primitive, to list the packages on the device and the users.</param>
    public AppxAppModelSource(IRegistry registry)
        : this(registry, new PackageRegistrations())
    {
    }

    internal AppxAppModelSource(IRegistry registry, IPackageRegistrations registrations)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(registrations);
        _registry = registry;
        _registrations = registrations;
    }

    /// <inheritdoc/>
    public IReadOnlyList<AppxUserPackages> ReadInstalled()
    {
        var candidates = new List<AppxPackage>();
        foreach (var name in AppxRepository.ReadMachinePackageNames(_registry))
        {
            if (AppxPackage.TryParse(name, out var package))
            {
                candidates.Add(package);
            }
        }

        candidates.Sort((a, b) => AppxPackage.FullNameComparer.Compare(a.FullName, b.FullName));
        return [.. AppxRepository.ReadUsers(_registry).Select(user => ReadUser(user, candidates))];
    }

    private AppxUserPackages ReadUser(AppxUser user, List<AppxPackage> candidates)
    {
        var packages = new List<AppxPackage>();
        foreach (var candidate in candidates)
        {
            var answer = _registrations.Find(user.Sid, candidate.FullName);
            switch (answer.Error)
            {
                case PackageRegistration.NotFound:
                    continue;
                case PackageRegistration.AccessDenied:
                    return new AppxUserPackages(user.Sid, AppxReadOutcome.Denied, [], $"Windows denied this account the user's packages (looking up {candidate.FullName}).");
                case not PackageRegistration.Success:
                    return new AppxUserPackages(user.Sid, AppxReadOutcome.Failed, [], $"Looking up {candidate.FullName} for the user failed with Windows error {answer.Error}.");
            }

            if ((answer.Properties & (PackageRegistration.ResourceProperty | PackageRegistration.BundleProperty)) == 0)
            {
                packages.Add(candidate with { InstallLocation = answer.Path });
            }
        }

        var detail = user.HiveLoaded
            ? string.Empty
            : "The user's registry hive is not loaded. Windows still answered, but it answers the packages registered for every user even for an account that does not exist.";
        return new AppxUserPackages(user.Sid, AppxReadOutcome.Read, packages, detail);
    }
}

/// <summary>Looks up whether a package is registered for a user: the native call, or a fake in tests.</summary>
internal interface IPackageRegistrations
{
    /// <summary>Looks up one package for one user.</summary>
    PackageRegistration Find(Sid user, string fullName);
}

/// <summary>What Windows answered for one package and user.</summary>
/// <param name="Error">The Win32 error: 0 when the package is registered for the user.</param>
/// <param name="Properties">The package's PACKAGE_PROPERTY_* flags, when it is registered.</param>
/// <param name="Path">The folder the package is installed in, when it is registered.</param>
internal readonly record struct PackageRegistration(uint Error, uint Properties, string Path)
{
    public const uint Success = 0;
    public const uint AccessDenied = 5;
    public const uint NotFound = 1168;
    public const uint ResourceProperty = 0x2;
    public const uint BundleProperty = 0x4;

    public static PackageRegistration Registered(uint properties, string path) => new(Success, properties, path);

    public static PackageRegistration Failed(uint error) => new(error, 0, string.Empty);
}

/// <summary>
/// The native lookup: <c>OpenPackageInfoByFullNameForUser</c>, then <c>GetPackageInfo</c> for the package itself, whose
/// PACKAGE_PROPERTY_* flags say whether it is a framework (0x1), resource (0x2), bundle (0x4) or optional (0x8) package.
/// </summary>
internal sealed unsafe class PackageRegistrations : IPackageRegistrations
{
    private readonly Dictionary<string, byte[]> _sids = new(StringComparer.Ordinal);

    public PackageRegistration Find(Sid user, string fullName)
    {
        if (!_sids.TryGetValue(user.Value, out var sid))
        {
            var identifier = new SecurityIdentifier(user.Value);
            sid = new byte[identifier.BinaryLength];
            identifier.GetBinaryForm(sid, 0);
            _sids[user.Value] = sid;
        }

        fixed (byte* sidBytes = sid)
        fixed (char* name = fullName)
        {
            _PACKAGE_INFO_REFERENCE* reference;
            var opened = PInvoke.OpenPackageInfoByFullNameForUser(new PSID(sidBytes), new PCWSTR(name), 0, &reference);
            if (opened != WIN32_ERROR.ERROR_SUCCESS)
            {
                return PackageRegistration.Failed((uint)opened);
            }

            try
            {
                return ReadHead(reference, fullName);
            }
            finally
            {
                PInvoke.ClosePackageInfo(reference);
            }
        }
    }

    private static PackageRegistration ReadHead(_PACKAGE_INFO_REFERENCE* reference, string fullName)
    {
        // No filter: the package itself, first, then what it depends on, when it is a main or framework package;
        // nothing at all when it is a resource package.
        const uint Flags = PInvoke.PACKAGE_INFORMATION_FULL;
        uint length = 0;
        uint count = 0;
        var sized = PInvoke.GetPackageInfo(reference, Flags, &length, null, &count);
        if (sized == WIN32_ERROR.ERROR_SUCCESS && count == 0)
        {
            return PackageRegistration.Registered(PackageRegistration.ResourceProperty, string.Empty);
        }

        if (sized != WIN32_ERROR.ERROR_INSUFFICIENT_BUFFER)
        {
            return PackageRegistration.Failed(sized == WIN32_ERROR.ERROR_SUCCESS ? (uint)WIN32_ERROR.ERROR_INVALID_DATA : (uint)sized);
        }

        var buffer = new byte[length];
        fixed (byte* bytes = buffer)
        {
            var read = PInvoke.GetPackageInfo(reference, Flags, &length, bytes, &count);
            if (read != WIN32_ERROR.ERROR_SUCCESS)
            {
                return PackageRegistration.Failed((uint)read);
            }

            var head = (PackageInfoHead*)bytes;
            if (count < 1 || head->PackageFullName is null || !AppxPackage.FullNameComparer.Equals(new string(head->PackageFullName), fullName))
            {
                return PackageRegistration.Failed((uint)WIN32_ERROR.ERROR_INVALID_DATA);
            }

            return PackageRegistration.Registered(head->Flags, head->Path is null ? string.Empty : new string(head->Path));
        }
    }

    /// <summary>
    /// The first fields of appmodel.h's PACKAGE_INFO, which come before anything its packing changes, so they lie
    /// where the natural layout puts them on x86, x64 and Arm64 alike. Only the first entry is read, so the size of
    /// the whole structure, which differs, is never needed.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct PackageInfoHead
    {
        public uint Reserved;
        public uint Flags;
        public char* Path;
        public char* PackageFullName;
    }
}
