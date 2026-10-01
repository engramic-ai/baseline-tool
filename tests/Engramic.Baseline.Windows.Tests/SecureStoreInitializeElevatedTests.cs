using System.Diagnostics;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;
using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// SecureStore making the data folder with the product's rules, as the install and SYSTEM do: folders born
/// owned by Administrators with SYSTEM and Administrators alone in their access lists. Only an elevated
/// administrator or SYSTEM can name Administrators as an owner, so these skip without elevation; CI runs them
/// elevated, and the Security job runs them as SYSTEM too.
/// </summary>
[Trait("Suite", "Security")]
public sealed class SecureStoreInitializeElevatedTests : IDisposable
{
    private static readonly string[] KeptFolders = ["cache", "config", "logs", "reports", "scratch", "undo"];

    private readonly TempTree _tree = new();
    private readonly FakeEventLog _events = new();

    public void Dispose() => _tree.Dispose();

    [Fact]
    public void Makes_every_folder_owned_by_Administrators_with_SYSTEM_and_Administrators_alone()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        var programData = _tree.Folder("ProgramData", Descriptors.RealProgramData);
        var dataFolder = Path.Combine(programData, SecureStore.DataFolderName);

        using var store = SecureStore.Initialize(Options(programData));
        store.WriteFile("status.json", "{}"u8);
        store.WriteFile(DataFolder.Config, "network.json", "{}"u8);
        using var scratch = store.CreateScratchFolder();

        Assert.Equal(KeptFolders.Append("status.json").Order(StringComparer.Ordinal), DataFolderFixture.Names(dataFolder));
        foreach (var folder in KeptFolders.Select(f => Path.Combine(dataFolder, f)).Prepend(dataFolder).Append(scratch.Path))
        {
            var usersRead = Path.GetFileName(folder) == "config";
            Assert.Equal("S-1-5-32-544", Acls.Owner(folder));
            Assert.True(Acls.IsProtected(folder), $"{folder} inherits from its parent.");
            Assert.Equal(Entries(usersRead ? Descriptors.InstallerLockedUsersRead : Descriptors.InstallerLocked), Acls.Entries(folder).Order(StringComparer.Ordinal));
        }

        Assert.Equal("S-1-5-32-544", Acls.Owner(Path.Combine(dataFolder, "status.json")));
        Assert.Equal("S-1-5-32-544", Acls.Owner(Path.Combine(dataFolder, "config", "network.json")));
        Assert.Empty(store.Notices);
    }

    [Fact]
    public void Moves_aside_a_data_folder_owned_by_the_administrator_s_own_account_even_when_sealed()
    {
        Assert.SkipUnless(Elevation.IsElevated && !Elevation.IsSystem, Elevation.NeedsElevation);
        var programData = _tree.Folder("ProgramData", Descriptors.RealProgramData);
        _tree.Folder(@"ProgramData\EngramicBaseline", $"O:{Elevation.CurrentUser}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");

        using var store = SecureStore.Initialize(Options(programData));

        Assert.Contains($"is owned by {Elevation.CurrentUser}, not SYSTEM, Administrators or TrustedInstaller", Assert.Single(store.Notices), StringComparison.Ordinal);
        Assert.Equal("S-1-5-32-544", Acls.Owner(Path.Combine(programData, SecureStore.DataFolderName)));
    }

    [Fact]
    public void Moves_aside_a_folder_that_denies_SYSTEM_and_Administrators_everything_by_the_rights_of_its_parent()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        var programData = _tree.Folder("ProgramData", Descriptors.RealProgramData);
        _tree.Folder(@"ProgramData\EngramicBaseline", $"O:{Elevation.CurrentUser}D:P(D;;FA;;;SY)(D;;FA;;;BA)");
        string[] quarantines = [];
        try
        {
            using var store = SecureStore.Initialize(Options(programData));

            quarantines = [.. DataFolderFixture.Names(programData).Where(DataFolderLayout.IsAsideName).Select(n => Path.Combine(programData, n))];
            Assert.Single(quarantines);
            Assert.Contains("cannot be read by this account (access is denied)", Assert.Single(store.Notices), StringComparison.Ordinal);
        }
        finally
        {
            foreach (var quarantine in quarantines)
            {
                Acls.Reset(quarantine, TempTree.TreeAccess);
            }
        }
    }

    [Fact]
    public void Deletes_symbolic_links_at_the_data_folder_and_a_kept_folder_as_links()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);
        var programData = _tree.Folder("ProgramData", Descriptors.RealProgramData);
        var elsewhere = _tree.Folder("Elsewhere");
        var kept = _tree.File(@"Elsewhere\kept.txt", "kept");
        Assert.SkipUnless(Links.TryCreateFolderSymbolicLink(Path.Combine(programData, SecureStore.DataFolderName), elsewhere), "This account may not make a symbolic link.");

        using (var store = SecureStore.Initialize(Options(programData)))
        {
            Assert.StartsWith($@"{programData}\EngramicBaseline was a link", Assert.Single(store.Notices), StringComparison.Ordinal);
        }

        var logs = Path.Combine(programData, SecureStore.DataFolderName, "logs");
        Directory.Delete(logs);
        Assert.True(Links.TryCreateFolderSymbolicLink(logs, elsewhere));
        using (var store = SecureStore.Initialize(Options(programData)))
        {
            Assert.StartsWith($@"{logs} was a link", Assert.Single(store.Notices), StringComparison.Ordinal);
        }

        Assert.Equal("kept", File.ReadAllText(kept));
        Assert.Equal(["kept.txt"], DataFolderFixture.Names(elsewhere));
    }

    [Fact]
    public void Refuses_to_read_a_file_owned_by_the_administrator_s_own_account()
    {
        Assert.SkipUnless(Elevation.IsElevated && !Elevation.IsSystem, Elevation.NeedsElevation);
        var programData = _tree.Folder("ProgramData", Descriptors.RealProgramData);
        using var store = SecureStore.Initialize(Options(programData));
        var file = Path.Combine(programData, SecureStore.DataFolderName, "config", "network.json");

        // Owned by the administrator's own account whatever the policy on the default owner says.
        var security = new System.Security.AccessControl.FileSecurity();
        security.SetSecurityDescriptorSddlForm($"O:{Elevation.CurrentUser}");
        using (var created = new FileInfo(file).Create(FileMode.CreateNew, System.Security.AccessControl.FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, security))
        {
            created.Write("{}"u8);
        }

        var e = Assert.Throws<SecureStoreException>(() => store.ReadFile(DataFolder.Config, "network.json", 1024));

        Assert.Equal($"{file} is owned by {Elevation.CurrentUser}, not SYSTEM, Administrators or TrustedInstaller.", e.Message);
    }

    [Fact]
    public void Writes_notices_to_the_Application_log_as_event_1003()
    {
        Assert.SkipUnless(Elevation.IsElevated, Elevation.NeedsElevation);

        // A source of the tests' own, never the product's: Windows takes a source no install registered.
        var log = new WindowsEventLog("EngramicBaselineTests");
        var marker = Guid.NewGuid().ToString("n");

        Assert.True(log.Write(DataFolderLayout.NoticeEventId, EventLogLevel.Warning, "Engramic Baseline - data folder: a test notice " + marker));

        var query = "*[System[Provider[@Name='EngramicBaselineTests'] and (EventID=1003)]]";
        using var wevtutil = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "wevtutil.exe"), ["qe", "Application", "/q:" + query, "/rd:true", "/c:20", "/f:xml"])
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        })!;
        var output = wevtutil.StandardOutput.ReadToEnd();
        wevtutil.WaitForExit();
        Assert.Contains(marker, output, StringComparison.Ordinal);
    }

    private static string[] Entries(string sddl)
    {
        var security = new System.Security.AccessControl.DirectorySecurity();
        security.SetSecurityDescriptorSddlForm(sddl);
        return [.. security
            .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(System.Security.Principal.SecurityIdentifier))
            .Cast<System.Security.AccessControl.FileSystemAccessRule>()
            .Select(r => $"{r.AccessControlType} {r.IdentityReference.Value} 0x{(int)r.FileSystemRights:X} {r.InheritanceFlags}")
            .Order(StringComparer.Ordinal)];
    }

    private SecureStoreOptions Options(string programData)
    {
        return new SecureStoreOptions { ProgramDataPath = programData, Registry = DataFolderFixture.Sealed(), EventLog = _events };
    }
}
