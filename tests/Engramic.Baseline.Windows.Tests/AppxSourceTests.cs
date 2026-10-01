using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// The two Appx sources on a registry in memory, laid out as Windows lays out its package repositories, and, for
/// the package runtime, a fake of what it answers.
/// </summary>
public sealed class AppxSourceTests
{
    private const string Alex = "S-1-5-21-1004336348-1177238915-682003330-1001";
    private const string Sam = "S-1-5-21-1004336348-1177238915-682003330-1002";
    private const string Signedout = "S-1-5-21-1004336348-1177238915-682003330-1003";
    private const string Claude = "Claude_2.16120.0.0_x64__pzs8sxrjxfjjc";
    private const string OldClaude = "Claude_2.15000.0.0_x64__pzs8sxrjxfjjc";
    private const string ChatGpt = "OpenAI.ChatGPT-Desktop_1.2025.112.0_x64__2p2nqsd0c76g0";
    private const string ClaudeBundle = "Claude_2.16120.0.0_neutral_~_pzs8sxrjxfjjc";
    private const string Office = "Microsoft.MicrosoftOfficeHub_18.2308.1034.0_x64__8wekyb3d8bbwe";
    private const string Paint = "Microsoft.Paint_11.2605.81.0_x64__8wekyb3d8bbwe";
    private const string PaintScale = "Microsoft.Paint_11.2605.81.0_neutral_split.scale-125_8wekyb3d8bbwe";

    [Fact]
    public void Registry_a_package_is_installed_for_a_user_when_their_repository_and_the_device_s_both_list_it()
    {
        var registry = Device()
            .WithUser(Alex, Claude, OldClaude, Paint)
            .WithUser(Sam, ChatGpt);

        var users = new AppxRegistrySource(registry).ReadInstalled();

        var alex = Assert.Single(users, u => u.User.Value == Alex);
        Assert.Equal(AppxReadOutcome.Read, alex.Outcome);
        Assert.Equal([Claude, Paint], alex.Packages.Select(p => p.FullName));
        Assert.Contains("Passed over 1 keys", alex.Detail, StringComparison.Ordinal);
        Assert.Equal(@"C:\Program Files\WindowsApps\" + Claude, alex.Packages[0].InstallLocation);
        var sam = Assert.Single(users, u => u.User.Value == Sam);
        Assert.Equal([ChatGpt], sam.Packages.Select(p => p.FullName));
        Assert.Equal(string.Empty, sam.Detail);
    }

    [Fact]
    public void Registry_a_package_staged_on_the_device_but_not_registered_for_the_user_is_not_theirs()
    {
        // As the Office hub is on a new device: provisioned for everyone, and removed by this user.
        var registry = Device().WithUser(Alex, Claude);

        var alex = Assert.Single(new AppxRegistrySource(registry).ReadInstalled(), u => u.User.Value == Alex);

        Assert.DoesNotContain(alex.Packages, p => p.Name == "Microsoft.MicrosoftOfficeHub");
    }

    [Fact]
    public void Registry_lists_a_user_whose_hive_is_not_loaded_as_not_known()
    {
        var registry = Device().WithUser(Alex, Claude).CreateKey(RegistryHive.LocalMachine, AppxRepository.ProfileListKey + @"\" + Signedout);

        var users = new AppxRegistrySource(registry).ReadInstalled();

        var signedOut = Assert.Single(users, u => u.User.Value == Signedout);
        Assert.Equal(AppxReadOutcome.NotLoaded, signedOut.Outcome);
        Assert.Empty(signedOut.Packages);
        Assert.Contains("not signed in", signedOut.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Registry_says_when_only_the_classes_hive_is_missing()
    {
        // SYSTEM's own hive is always loaded, without a classes hive beside it.
        var registry = Device().CreateKey(RegistryHive.Users, @"S-1-5-18\Software");

        var system = Assert.Single(new AppxRegistrySource(registry).ReadInstalled());

        Assert.Equal(AppxReadOutcome.NotLoaded, system.Outcome);
        Assert.Contains("classes hive", system.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Registry_reports_a_user_it_may_not_read_and_reads_the_others()
    {
        var registry = Device().WithUser(Alex, Claude).WithUser(Sam, ChatGpt)
            .Deny(RegistryHive.Users, Sam + AppxRepository.ClassesSuffix + @"\" + AppxRepository.UserRepositoryKey);

        var users = new AppxRegistrySource(registry).ReadInstalled();

        Assert.Equal(AppxReadOutcome.Read, users.Single(u => u.User.Value == Alex).Outcome);
        var sam = users.Single(u => u.User.Value == Sam);
        Assert.Equal(AppxReadOutcome.Denied, sam.Outcome);
        Assert.Empty(sam.Packages);
    }

    [Fact]
    public void Registry_a_user_with_no_repository_has_no_packages()
    {
        var registry = Device().CreateKey(RegistryHive.Users, @"S-1-5-19\Software").CreateKey(RegistryHive.Users, @"S-1-5-19_Classes\Local Settings");

        var service = Assert.Single(new AppxRegistrySource(registry).ReadInstalled());

        Assert.Equal(AppxReadOutcome.Read, service.Outcome);
        Assert.Empty(service.Packages);
    }

    [Fact]
    public void Registry_passes_over_keys_that_are_not_full_names()
    {
        var registry = Device(extra: "Not a package").WithUser(Alex, Claude, "Not a package");

        var alex = Assert.Single(new AppxRegistrySource(registry).ReadInstalled());

        Assert.Equal([Claude], alex.Packages.Select(p => p.FullName));
        Assert.Contains("not package full names", alex.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Both_sources_fail_when_the_device_has_no_package_repository()
    {
        var registry = new FakeRegistry().WithUser(Alex, Claude);

        Assert.Throws<IOException>(() => new AppxRegistrySource(registry).ReadInstalled());
        Assert.Throws<IOException>(() => new AppxAppModelSource(registry, new FakeRegistrations()).ReadInstalled());
    }

    [Fact]
    public void Users_are_every_profile_and_every_loaded_hive_in_order_without_repeats()
    {
        var registry = Device().WithUser(Sam, ChatGpt).WithUser(Alex, Claude)
            .CreateKey(RegistryHive.Users, @".DEFAULT\Software")
            .CreateKey(RegistryHive.LocalMachine, AppxRepository.ProfileListKey + @"\" + Alex)
            .CreateKey(RegistryHive.LocalMachine, AppxRepository.ProfileListKey + @"\" + Signedout)
            .CreateKey(RegistryHive.LocalMachine, AppxRepository.ProfileListKey + @"\Not a SID");

        var users = AppxRepository.ReadUsers(registry);

        Assert.Equal([Alex, Sam, Signedout], users.Select(u => u.Sid.Value));
        Assert.Equal([true, true, false], users.Select(u => u.ClassesLoaded));
    }

    [Fact]
    public void AppModel_asks_about_every_package_on_the_device_for_every_user_and_keeps_main_and_framework_packages()
    {
        var registry = Device().WithUser(Alex, Claude).CreateKey(RegistryHive.LocalMachine, AppxRepository.ProfileListKey + @"\" + Signedout);
        var registrations = new FakeRegistrations()
            .Register(Alex, Claude, 0, @"C:\Program Files\WindowsApps\" + Claude)
            .Register(Alex, ClaudeBundle, PackageRegistration.BundleProperty, @"C:\Program Files\WindowsApps\" + ClaudeBundle)
            .Register(Alex, PaintScale, PackageRegistration.ResourceProperty, @"C:\Program Files\WindowsApps\" + PaintScale)
            .Register(Signedout, ChatGpt, 0, @"C:\Program Files\WindowsApps\" + ChatGpt);

        var users = new AppxAppModelSource(registry, registrations).ReadInstalled();

        var alex = users.Single(u => u.User.Value == Alex);
        Assert.Equal(AppxReadOutcome.Read, alex.Outcome);
        Assert.Equal([Claude], alex.Packages.Select(p => p.FullName));
        Assert.Equal(@"C:\Program Files\WindowsApps\" + Claude, alex.Packages[0].InstallLocation);
        var signedOut = users.Single(u => u.User.Value == Signedout);
        Assert.Equal(AppxReadOutcome.Read, signedOut.Outcome);
        Assert.Equal([ChatGpt], signedOut.Packages.Select(p => p.FullName));
        Assert.Contains("not loaded", signedOut.Detail, StringComparison.Ordinal);
        Assert.Equal(2 * MachinePackages.Length, registrations.Asked);
    }

    [Fact]
    public void AppModel_reports_a_user_Windows_denies_or_fails_for()
    {
        var registry = Device().WithUser(Alex, Claude).WithUser(Sam, ChatGpt);
        var registrations = new FakeRegistrations().Fail(Alex, PackageRegistration.AccessDenied).Fail(Sam, 87);

        var users = new AppxAppModelSource(registry, registrations).ReadInstalled();

        Assert.Equal(AppxReadOutcome.Denied, users.Single(u => u.User.Value == Alex).Outcome);
        var sam = users.Single(u => u.User.Value == Sam);
        Assert.Equal(AppxReadOutcome.Failed, sam.Outcome);
        Assert.Contains("error 87", sam.Detail, StringComparison.Ordinal);
    }

    private static readonly string[] MachinePackages = [Claude, ChatGpt, ClaudeBundle, Office, Paint, PaintScale];

    /// <summary>A device whose package repository lists these packages, each with its folder.</summary>
    private static FakeRegistry Device(string? extra = null)
    {
        var registry = new FakeRegistry();
        foreach (var name in MachinePackages.Append(extra).OfType<string>())
        {
            registry.Set(RegistryHive.LocalMachine, AppxRepository.MachineRepositoryKey + @"\" + name, "Path", RegistryValue.FromText(@"C:\Program Files\WindowsApps\" + name));
        }

        return registry;
    }

    /// <summary>What the package runtime answers, by user and full name; anything not registered is not found.</summary>
    private sealed class FakeRegistrations : IPackageRegistrations
    {
        private readonly Dictionary<(string User, string Name), PackageRegistration> _registered = [];
        private readonly Dictionary<string, uint> _failures = [];

        public int Asked { get; private set; }

        public FakeRegistrations Register(string user, string fullName, uint properties, string path)
        {
            _registered[(user, fullName)] = PackageRegistration.Registered(properties, path);
            return this;
        }

        public FakeRegistrations Fail(string user, uint error)
        {
            _failures[user] = error;
            return this;
        }

        public PackageRegistration Find(Sid user, string fullName)
        {
            Asked++;
            if (_failures.TryGetValue(user.Value, out var error))
            {
                return PackageRegistration.Failed(error);
            }

            return _registered.TryGetValue((user.Value, fullName), out var found) ? found : PackageRegistration.Failed(PackageRegistration.NotFound);
        }
    }
}

/// <summary>Lays out a user's hives in a fake registry as Windows loads them.</summary>
internal static class AppxFakeRegistryExtensions
{
    /// <summary>Loads a user's hive and classes hive, with these keys in their package repository.</summary>
    public static FakeRegistry WithUser(this FakeRegistry registry, string sid, params string[] packages)
    {
        registry.CreateKey(RegistryHive.Users, sid + @"\Software");
        registry.CreateKey(RegistryHive.Users, sid + AppxRepository.ClassesSuffix + @"\" + AppxRepository.UserRepositoryKey);
        foreach (var name in packages)
        {
            registry.Set(RegistryHive.Users, sid + AppxRepository.ClassesSuffix + @"\" + AppxRepository.UserRepositoryKey + @"\" + name, "PackageID", RegistryValue.FromText(name));
        }

        return registry;
    }
}
