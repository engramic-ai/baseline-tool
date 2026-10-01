using System.Diagnostics;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// The two Appx sources, on this device, against Windows' own package manager (Get-AppxPackage, WinRT's
/// PackageManager, in a separate Windows PowerShell): for the account running the tests, for every user as an
/// elevated administrator, and for every user as SYSTEM, the account the scheduled audit runs as.
/// </summary>
/// <remarks>
/// Each writes the whole comparison to the test output and to standard output, which the SYSTEM job's log carries,
/// and fails on any difference of the registry source, the one the product is to use, for a user it says it read: a
/// user it could not read because their hive is not loaded is reported, not failed, since not knowing is what it says.
/// Only the reviewed differences seen on CI's runner are let off (<see cref="AppxKnownDifferences"/>), and they are
/// still reported. So that a comparison of nobody cannot pass, each also fails unless Get-AppxPackage named someone
/// and the registry source read every user whose classes hive is loaded, or for the account running the tests, that
/// account. The package runtime's own answers are compared and reported the same way, without failing the test.
/// <para>
/// They run alone, never beside other tests: asking the deployment service about every user's packages can set
/// Windows' own components sending requests, and the SYSTEM tests of the service client count every request that
/// reaches the machine's WinHTTP proxy while they have it set.
/// </para>
/// </remarks>
[Collection(nameof(AppxOracleTests))]
public sealed class AppxOracleTests
{
    private const string NeedsSystem = "Compares every user's packages as SYSTEM, as CI runs it on its runner; skipped otherwise.";
    private const string Registry = "registry";
    private const string AppModel = "appmodel";
    private const string NeedsElevatedAdministrator = "Compares every user's packages as an elevated administrator, as CI's runner is; skipped otherwise.";

    [Fact]
    public void Both_sources_match_Get_AppxPackage_for_the_account_running_the_tests()
    {
        Assert.SkipWhen(Elevation.IsSystem, "As SYSTEM, the comparison of every user covers this.");
        var oracle = AppxOracle.ForCurrentUser(Elevation.CurrentUser);
        var sources = ReadBoth();

        var comparison = AppxComparison.Compare(oracle, sources, Explain, Elevation.CurrentUser);

        Report(comparison);
        Assert.True(sources[0].Users.Any(u => u.User == Elevation.CurrentUser && u.Outcome == AppxReadOutcome.Read), "The registry source did not read the account running the tests:\n" + comparison.Report);
        Assert.True(comparison.DifferencesOf(Registry).Count == 0, comparison.Report);
        Assert.True(comparison.DifferencesOf(AppModel).All(d => d.Contains(" listed ", StringComparison.Ordinal)), "The package runtime missed or could not read packages:\n" + comparison.Report);
    }

    [Fact]
    public void Both_sources_match_Get_AppxPackage_AllUsers_for_every_user_they_read_as_an_elevated_administrator()
    {
        Assert.SkipUnless(Elevation.IsElevated && !Elevation.IsSystem, NeedsElevatedAdministrator);

        CompareEveryUser();
    }

    [Fact(Explicit = true)]
    [Trait("Context", "System")]
    public void Both_sources_match_Get_AppxPackage_AllUsers_for_every_user_they_read_as_SYSTEM()
    {
        Assert.SkipUnless(Elevation.IsSystem, NeedsSystem);

        CompareEveryUser();
    }

    private static void CompareEveryUser()
    {
        var oracle = AppxOracle.ForAllUsers();
        var sources = ReadBoth();

        var comparison = AppxComparison.Compare(oracle, sources, Explain);

        Report(comparison);
        Assert.True(oracle.Installed.Count > 0, $"{oracle.Command} named no user with packages installed, so nothing was compared:\n" + comparison.Report);
        var unread = UsersWithClassesLoaded()
            .Where(sid => !sources[0].Users.Any(u => u.User == sid && u.Outcome == AppxReadOutcome.Read))
            .ToList();
        Assert.True(unread.Count == 0, $"The registry source did not read every user whose classes hive is loaded: not {string.Join(", ", unread)}.\n" + comparison.Report);
        Assert.True(comparison.DifferencesOf(Registry).Count == 0, comparison.Report);
    }

    /// <summary>The users whose classes hive HKEY_USERS lists, read apart from the sources.</summary>
    private static List<Sid> UsersWithClassesLoaded()
    {
        var hives = new WindowsRegistry().GetSubKeyNames(RegistryHive.Users, RegistryView.Registry64, string.Empty) ?? [];
        var users = new List<Sid>();
        foreach (var hive in hives.Where(h => h.EndsWith(AppxRepository.ClassesSuffix, StringComparison.OrdinalIgnoreCase)))
        {
            if (Sid.TryParse(hive[..^AppxRepository.ClassesSuffix.Length], out var sid))
            {
                users.Add(sid);
            }
        }

        return users;
    }

    private static List<(string Name, IReadOnlyList<AppxUserPackages> Users, TimeSpan Took)> ReadBoth()
    {
        var registry = new WindowsRegistry();
        return [Read(Registry, new AppxRegistrySource(registry)), Read(AppModel, new AppxAppModelSource(registry))];
    }

    private static (string Name, IReadOnlyList<AppxUserPackages> Users, TimeSpan Took) Read(string name, IAppxPackageSource source)
    {
        var stopwatch = Stopwatch.StartNew();
        var users = source.ReadInstalled();
        return (name, users, stopwatch.Elapsed);
    }

    /// <summary>
    /// Where each source would have found a package: in the deployment service's lists, the device's package
    /// repository and the user's, and what the package runtime answers when asked about it directly; and whether the
    /// miss is a known difference, which only the user's repository decides (<see cref="AppxKnownDifferences"/>).
    /// </summary>
    private static (string Text, string? Excuse) Explain(string sid, string fullName)
    {
        var registry = new WindowsRegistry();
        string Listed(RegistryHive hive, string key)
        {
            try
            {
                var names = registry.GetSubKeyNames(hive, RegistryView.Registry64, key);
                return names is null ? "no such key" : names.Contains(fullName, StringComparer.OrdinalIgnoreCase) ? "listed" : "not listed";
            }
            catch (Exception e) when (e is UnauthorizedAccessException or IOException)
            {
                return e.GetType().Name;
            }
        }

        // The deployment service's own lists: work it still has to do for each user, such as a registration waiting for
        // them to sign in, and the packages provisioned for every new user.
        const string AllUserStore = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore";
        var pending = Listed(RegistryHive.LocalMachine, AllUserStore + @"\" + sid);
        var provisioned = Listed(RegistryHive.LocalMachine, AllUserStore + @"\Applications");
        var machine = Listed(RegistryHive.LocalMachine, AppxRepository.MachineRepositoryKey);
        var user = Listed(RegistryHive.Users, sid + AppxRepository.ClassesSuffix + @"\" + AppxRepository.UserRepositoryKey);
        // The package runtime's answer is reported, not used: it is not shown to be independent of the user's repository.
        var answer = new PackageRegistrations().Find(Sid.Parse(sid), fullName);
        var folder = AppxRepository.ReadInstallLocation(registry, fullName);
        return ($"AppxAllUserStore\\<user>: {pending}; AppxAllUserStore\\Applications: {provisioned}; device repository: {machine}; user's repository: {user}; package runtime asked directly: error {answer.Error}, properties 0x{answer.Properties:X}, folder {(answer.Path.Length > 0 ? answer.Path : "none")}; device repository's folder: {(folder.Length > 0 ? folder : "none")}", AppxKnownDifferences.Excuse(fullName, userRepositoryLacksIt: user is "not listed" or "no such key"));
    }

    private static void Report(AppxComparison comparison)
    {
        TestContext.Current.TestOutputHelper?.WriteLine(comparison.Report);
        Console.WriteLine(comparison.Report);
    }
}

/// <summary>Runs <see cref="AppxOracleTests"/> on their own, after the tests that run in parallel.</summary>
[CollectionDefinition(nameof(AppxOracleTests), DisableParallelization = true)]
public sealed class AppxOracleCollection
{
}
