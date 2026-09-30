using System.Security.AccessControl;
using System.Security.Principal;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// SecureStore with the product's rules, on folders made as the installer makes them: owned by
/// Administrators and locked from birth. Only an elevated administrator can make those, so these tests
/// skip without elevation; CI runs them.
/// </summary>
public sealed class SecureStoreElevatedTests : IDisposable
{
    private readonly TempTree _tree = new();

    public void Dispose() => _tree.Dispose();

    [Fact]
    public void Opens_the_data_folder_the_installer_makes_and_writes_files_owned_by_Administrators()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        var programData = _tree.Folder("ProgramData", Descriptors.ProgramDataLike);
        var dataFolder = _tree.Folder(@"ProgramData\EngramicBaseline", Descriptors.InstallerLocked);
        using var store = SecureStore.Open(new SecureStoreOptions { ProgramDataPath = programData, Registry = DataFolderFixture.Sealed() });

        store.WriteFile("status.json", "old"u8);
        store.WriteFile("status.json", "{}"u8);

        var status = Path.Combine(dataFolder, "status.json");
        var security = new FileInfo(status).GetAccessControl();
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList();
        Assert.Equal("{}", File.ReadAllText(status));
        Assert.Equal("S-1-5-32-544", security.GetOwner(typeof(SecurityIdentifier))!.Value);
        Assert.Equal(["S-1-5-18", "S-1-5-32-544"], rules.Select(r => r.IdentityReference.Value).Order(StringComparer.Ordinal));
        Assert.All(rules, r => Assert.True(r.IsInherited && r.AccessControlType == AccessControlType.Allow && r.FileSystemRights == FileSystemRights.FullControl));
        Assert.Null(DataFolderTrust.Machine.FindSecurityProblem(status, new ItemSecurity(Sid.Administrators, [.. rules.Select(r => new AccessEntry(AccessEntryType.Allow, Sid.Parse(r.IdentityReference.Value), (uint)r.FileSystemRights))])));
    }

    [Fact]
    public void Refuses_a_data_folder_owned_by_the_administrator_s_own_account()
    {
        Assert.SkipUnless(Elevation.IsElevated && !Elevation.IsSystem, Elevation.NeedsElevation);
        var programData = _tree.Folder("ProgramData", Descriptors.ProgramDataLike);
        var dataFolder = _tree.Folder(@"ProgramData\EngramicBaseline", $"O:{Elevation.CurrentUser}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");

        var e = Assert.Throws<SecureStoreException>(() => SecureStore.Open(new SecureStoreOptions { ProgramDataPath = programData, Registry = DataFolderFixture.Sealed() }));

        Assert.Equal($"{dataFolder} is owned by {Elevation.CurrentUser}, not SYSTEM, Administrators or TrustedInstaller.", e.Message);
    }

    [Fact]
    public void Refuses_a_ProgramData_folder_owned_by_the_administrator_s_own_account()
    {
        Assert.SkipUnless(Elevation.IsElevated && !Elevation.IsSystem, Elevation.NeedsElevation);
        var programData = _tree.Folder("ProgramData", $"O:{Elevation.CurrentUser}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        _tree.Folder(@"ProgramData\EngramicBaseline", Descriptors.InstallerLocked);

        var e = Assert.Throws<SecureStoreException>(() => SecureStore.Open(new SecureStoreOptions { ProgramDataPath = programData, Registry = DataFolderFixture.Sealed() }));

        Assert.Equal($"{programData} is owned by {Elevation.CurrentUser}, not SYSTEM, Administrators or TrustedInstaller.", e.Message);
    }

    [Fact]
    public void Refuses_the_locked_data_folder_of_an_install_that_did_not_seal_it()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        var programData = _tree.Folder("ProgramData", Descriptors.ProgramDataLike);
        _tree.Folder(@"ProgramData\EngramicBaseline", Descriptors.InstallerLocked);

        var e = Assert.Throws<SecureStoreException>(() => SecureStore.Open(new SecureStoreOptions { ProgramDataPath = programData, Registry = new Testing.FakeRegistry() }));

        Assert.Contains("its DataRootSealed marker is missing", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_symbolic_link_to_a_file_outside_is_refused_with_the_product_s_rules()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        var programData = _tree.Folder("ProgramData", Descriptors.ProgramDataLike);
        var dataFolder = _tree.Folder(@"ProgramData\EngramicBaseline", Descriptors.InstallerLocked);
        var outside = _tree.File("outside.json", "outside");
        Assert.SkipUnless(Links.TryCreateFileSymbolicLink(Path.Combine(dataFolder, "status.json"), outside), "This account may not make a symbolic link.");
        using var store = SecureStore.Open(new SecureStoreOptions { ProgramDataPath = programData, Registry = DataFolderFixture.Sealed() });

        Assert.Throws<SecureStoreException>(() => store.WriteFile("status.json", "{}"u8));

        Assert.Equal("outside", File.ReadAllText(outside));
    }
}
