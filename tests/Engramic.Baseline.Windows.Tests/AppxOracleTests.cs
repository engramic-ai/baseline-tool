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
/// The package runtime's answers are compared and reported the same way, without failing the test: docs/DOTNET.md
/// (spike 8) records what they showed.
/// </remarks>
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

        var comparison = AppxComparison.Compare(oracle, ReadBoth(), Elevation.CurrentUser);

        Report(comparison);
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

        var comparison = AppxComparison.Compare(oracle, ReadBoth());

        Report(comparison);
        Assert.True(comparison.DifferencesOf(Registry).Count == 0, comparison.Report);
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

    private static void Report(AppxComparison comparison)
    {
        TestContext.Current.TestOutputHelper?.WriteLine(comparison.Report);
        Console.WriteLine(comparison.Report);
    }
}
