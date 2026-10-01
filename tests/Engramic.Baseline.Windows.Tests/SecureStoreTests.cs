using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing.Windows;
using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// SecureStore on real folders under the temp folder: what it accepts, what it refuses, and what an
/// attacker's link, hard link or swap does to a write. None of these needs elevation.
/// </summary>
[Trait("Suite", "Security")]
public sealed class SecureStoreTests : IDisposable
{
    private readonly DataFolderFixture _fixture = new();

    public void Dispose() => _fixture.Dispose();

    [Fact]
    public void Opens_a_sealed_trusted_data_folder_and_writes_a_file_in_it()
    {
        using var store = _fixture.Open();

        store.WriteFile("status.json", "\uFEFF{}"u8);

        Assert.Equal(_fixture.DataFolder, store.RootPath, ignoreCase: true);
        Assert.Equal("\uFEFF{}"u8.ToArray(), File.ReadAllBytes(_fixture.StatusJson));
        Assert.Equal(["status.json"], _fixture.Entries);
    }

    [Fact]
    public void Replaces_a_file_whole_and_leaves_no_temporary_file()
    {
        using var store = _fixture.Open();
        store.WriteFile("status.json", Encoding.UTF8.GetBytes(new string('o', 100_000)));

        store.WriteFile("status.json", "new"u8);

        Assert.Equal("new", File.ReadAllText(_fixture.StatusJson));
        Assert.Equal(1u, Links.LinkCount(_fixture.StatusJson));
        Assert.Equal(["status.json"], _fixture.Entries);
    }

    [Fact]
    public void Writes_a_new_file_under_a_random_name_beside_the_target_then_renames_it()
    {
        string[]? during = null;
        using var store = _fixture.Open(new SecureStoreHooks { BeforeRename = (_, _) => during = _fixture.Entries });

        store.WriteFile("status.json", "{}"u8);
        store.WriteFile("status.json", "{}"u8);

        Assert.Equal(2, during!.Length);
        Assert.Equal("status.json", during[0]);
        Assert.Matches("^status\\.json\\.[0-9a-f]{32}\\.tmp$", during[1]);
        Assert.Equal(["status.json"], _fixture.Entries);
    }

    [Fact]
    public void Writes_an_empty_file()
    {
        using var store = _fixture.Open();

        store.WriteFile("last-error.json", []);

        Assert.Empty(File.ReadAllBytes(Path.Combine(_fixture.DataFolder, "last-error.json")));
    }

    [Fact]
    public void A_new_file_takes_the_data_folder_s_access_list()
    {
        using var store = _fixture.Open();

        store.WriteFile("status.json", "{}"u8);

        var security = new FileInfo(_fixture.StatusJson).GetAccessControl();
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList();
        Assert.False(security.AreAccessRulesProtected);
        Assert.All(rules, r => Assert.True(r.IsInherited));
        Assert.Equal(
            Elevation.FullControl.Select(a => a.Value).Order(StringComparer.Ordinal),
            rules.Select(r => r.IdentityReference.Value).Distinct().Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Holds_the_data_folder_and_ProgramData_so_neither_can_be_renamed_while_open()
    {
        using (_fixture.Open())
        {
            // ERROR_SHARING_VIOLATION: the data folder is held without FILE_SHARE_DELETE. ERROR_ACCESS_DENIED:
            // ProgramData is held for its attributes and permissions alone, which sharing checks ignore, but
            // Windows refuses to rename a folder while anything in it, here the data folder, is open.
            Assert.Equal(32, NtFiles.MoveByPath(_fixture.DataFolder, _fixture.DataFolder + "-moved"));
            Assert.Equal(5, NtFiles.MoveByPath(_fixture.ProgramData, _fixture.ProgramData + "-moved"));
        }

        Directory.Move(_fixture.DataFolder, _fixture.DataFolder + "-moved");
        Directory.Move(_fixture.DataFolder + "-moved", _fixture.DataFolder);
    }

    [Fact]
    public void Opens_and_sets_up_the_data_folder_while_another_process_holds_ProgramData_open_without_sharing_it()
    {
        // This account may write to the fixture's ProgramData, as standard users may to the real one, so Windows
        // honours its refusal to share: an open that would list the folder is refused while it is held.
        using var holder = Native.OpenWithShare(_fixture.ProgramData, NtFiles.ListDirectory | NtFiles.Synchronize, NtFiles.ShareNone);
        Assert.Equal(32, Native.TryOpen(_fixture.ProgramData, NtFiles.ListDirectory | NtFiles.Synchronize, NtFiles.ShareReadWrite));

        using (var store = _fixture.Open())
        {
            store.WriteFile("status.json", "{}"u8);
            Assert.Equal("{}"u8.ToArray(), store.ReadFile(DataFolder.Root, "status.json", 100));
        }

        using (var store = _fixture.Initialize())
        {
            Assert.Empty(store.Notices);
        }

        Assert.Equal(["cache", "config", "logs", "reports", "scratch", "status.json", "undo"], _fixture.Entries);
    }

    [Fact]
    public void Refuses_to_write_once_disposed()
    {
        var store = _fixture.Open();
        store.Dispose();
        store.Dispose();

        Assert.Throws<ObjectDisposedException>(() => store.WriteFile("status.json", "{}"u8));
    }

    [Fact]
    public void Refuses_a_ProgramData_folder_that_is_missing()
    {
        var missing = _fixture.Tree.PathOf("Missing");

        var e = Assert.Throws<SecureStoreException>(() => SecureStore.Open(_fixture.Options with { ProgramDataPath = missing }, DataFolderFixture.Rules, null));

        Assert.Equal($"The ProgramData folder {missing} does not exist. The fleet install creates the data folder locked; this tool does not create it.", e.Message);
    }

    [Theory]
    [InlineData(@"ProgramData")]
    [InlineData(@"C:")]
    [InlineData(@"C:\")]
    [InlineData(@"C:ProgramData")]
    [InlineData(@"C:\ProgramData\")]
    [InlineData(@"C:\ProgramData\.\x")]
    [InlineData(@"C:\ProgramData\..\ProgramData")]
    [InlineData(@"C:\ProgramData.")]
    [InlineData(@"C:\ProgramData ")]
    [InlineData(@"C:\Program*Data")]
    [InlineData(@"C:\ProgramData:stream")]
    [InlineData(@"C:/ProgramData")]
    [InlineData(@"\\server\share\ProgramData")]
    [InlineData(@"\\?\C:\ProgramData")]
    [InlineData(@"\\.\C:\ProgramData")]
    [InlineData(@"\??\C:\ProgramData")]
    [InlineData("")]
    public void Refuses_a_ProgramData_path_that_is_not_a_plain_full_local_path(string path)
    {
        var e = Assert.Throws<SecureStoreException>(() => SecureStore.Open(_fixture.Options with { ProgramDataPath = path }, DataFolderFixture.Rules, null));

        Assert.Equal($"{path} is not a full path on a drive with a letter, so it is not used as the ProgramData folder.", e.Message);
    }

    [Fact]
    public void Refuses_a_ProgramData_folder_that_is_a_junction()
    {
        var link = _fixture.Tree.PathOf("LinkedProgramData");
        Links.CreateJunction(link, _fixture.ProgramData);

        var e = Assert.Throws<SecureStoreException>(() => SecureStore.Open(_fixture.Options with { ProgramDataPath = link }, DataFolderFixture.Rules, null));

        Assert.Equal($"{link} is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.", e.Message);
    }

    [Fact]
    public void Refuses_a_ProgramData_folder_reached_through_a_junction_on_the_way()
    {
        var real = _fixture.Tree.Folder("Real");
        _fixture.Tree.Folder(@"Real\ProgramData");
        _fixture.Tree.Folder(@"Real\ProgramData\EngramicBaseline");
        var link = _fixture.Tree.PathOf("Linked");
        Links.CreateJunction(link, real);
        var through = Path.Combine(link, "ProgramData");

        var e = Assert.Throws<SecureStoreException>(() => SecureStore.Open(_fixture.Options with { ProgramDataPath = through }, DataFolderFixture.Rules, null));

        Assert.Equal($"{through} leads to {Path.Combine(real, "ProgramData")}, so a folder on the way is a link or was replaced.", e.Message);
    }

    [Fact]
    public void Refuses_a_ProgramData_folder_whose_owner_is_not_trusted()
    {
        // Only TrustedInstaller trusted: the folders these tests make are owned by the account running them.
        var e = Assert.Throws<SecureStoreException>(() => _fixture.Open(trust: new DataFolderTrust([Sid.TrustedInstaller])));

        Assert.StartsWith($"{_fixture.ProgramData} is owned by S-1-5-", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Refuses_a_data_folder_that_is_missing()
    {
        using var fixture = new DataFolderFixture(withDataFolder: false);

        var e = Assert.Throws<SecureStoreException>(() => fixture.Open());

        Assert.Equal($"The data folder {fixture.DataFolder} does not exist. The fleet install creates the data folder locked; this tool does not create it.", e.Message);
    }

    [Fact]
    public void Refuses_a_data_folder_that_is_a_junction_and_leaves_where_it_leads_alone()
    {
        using var fixture = new DataFolderFixture(withDataFolder: false);
        var elsewhere = fixture.Tree.Folder("Elsewhere");
        Links.CreateJunction(fixture.DataFolder, elsewhere);

        var e = Assert.Throws<SecureStoreException>(() => fixture.Open());

        Assert.Equal($"{fixture.DataFolder} is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.", e.Message);
        Assert.Empty(Directory.GetFileSystemEntries(elsewhere));
    }

    [Fact]
    public void Refuses_a_file_in_place_of_the_data_folder()
    {
        using var fixture = new DataFolderFixture(withDataFolder: false);
        File.WriteAllText(fixture.DataFolder, "not a folder");

        var e = Assert.Throws<SecureStoreException>(() => fixture.Open());

        Assert.Equal($"{fixture.DataFolder} is a file, not a folder.", e.Message);
    }

    [Fact]
    public void Refuses_a_data_folder_that_was_never_sealed()
    {
        _fixture.Registry = new Testing.FakeRegistry();

        var e = Assert.Throws<SecureStoreException>(() => _fixture.Open());

        Assert.Contains("its DataRootSealed marker is missing", e.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("empty text")]
    [InlineData("a number")]
    [InlineData("expandable text")]
    public void Refuses_a_seal_that_is_not_text(string kind)
    {
        _fixture.Registry = DataFolderFixture.Sealed(kind switch
        {
            "empty text" => RegistryValue.FromText(string.Empty),
            "a number" => RegistryValue.FromDWord(1),
            _ => RegistryValue.FromExpandText("0.3.2"),
        });

        Assert.Throws<SecureStoreException>(() => _fixture.Open());
    }

    [Fact]
    public void Reads_the_seal_from_the_64_bit_view_of_the_key_it_is_given()
    {
        var registry = new Testing.FakeRegistry().Set(RegistryHive.LocalMachine, @"SOFTWARE\Tests\Seal", "Sealed", RegistryValue.FromText("1.0.0"));
        _fixture.Registry = registry;

        using var store = SecureStore.Open(_fixture.Options with { SealKeyPath = @"SOFTWARE\Tests\Seal", SealValueName = "Sealed" }, DataFolderFixture.Rules, null);

        Assert.Equal((RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Tests\Seal", "Sealed"), Assert.Single(registry.Reads));
    }

    [Fact]
    public void Refuses_a_data_folder_when_the_seal_cannot_be_read()
    {
        _fixture.Registry = new Testing.FakeRegistry().Deny(RegistryHive.LocalMachine, SecureStoreOptions.MachineSealKeyPath);

        var e = Assert.Throws<SecureStoreException>(() => _fixture.Open());

        Assert.StartsWith(@"The seal of the data folder, HKEY_LOCAL_MACHINE\SOFTWARE\EngramicBaseline.DataRoot\DataRootSealed, could not be read", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Refuses_a_data_folder_standard_users_can_add_files_to()
    {
        using var fixture = new DataFolderFixture(dataFolderAccess: TempTree.TreeAccess + "(A;OICI;0x2;;;BU)");

        var e = Assert.Throws<SecureStoreException>(() => fixture.Open());

        Assert.Equal($"{fixture.DataFolder} can be changed by S-1-5-32-545, not only administrators.", e.Message);
    }

    [Fact]
    public void Refuses_a_data_folder_with_an_inherit_only_entry_that_would_let_users_change_new_files()
    {
        using var fixture = new DataFolderFixture(dataFolderAccess: TempTree.TreeAccess + "(A;OICIIO;FA;;;AU)");

        var e = Assert.Throws<SecureStoreException>(() => fixture.Open());

        Assert.Equal($"{fixture.DataFolder} can be changed by S-1-5-11, not only administrators.", e.Message);
    }

    [Fact]
    public void Keeps_a_data_folder_that_users_may_only_read()
    {
        using var fixture = new DataFolderFixture(dataFolderAccess: TempTree.TreeAccess + "(A;OICI;0x1200a9;;;BU)");

        using var store = fixture.Open();

        store.WriteFile("status.json", "{}"u8);
    }

    [Fact]
    public void Refuses_a_data_folder_that_denies_SYSTEM_anything()
    {
        using var fixture = new DataFolderFixture(dataFolderAccess: "D:P(D;;WD;;;SY)" + TempTree.TreeAccess[4..]);

        var e = Assert.Throws<SecureStoreException>(() => fixture.Open());

        Assert.Equal($"{fixture.DataFolder} denies S-1-5-18 some rights, so the tool may be unable to replace it.", e.Message);
    }

    [Fact]
    public void Refuses_a_junction_in_place_of_the_file_and_writes_nothing_through_it()
    {
        var elsewhere = _fixture.Tree.Folder("Elsewhere");
        Links.CreateJunction(_fixture.StatusJson, elsewhere);
        using var store = _fixture.Open();

        var e = Assert.Throws<SecureStoreException>(() => store.WriteFile("status.json", "{}"u8));

        Assert.Equal($"{_fixture.StatusJson} is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.", e.Message);
        Assert.Empty(Directory.GetFileSystemEntries(elsewhere));
        Assert.Equal(["status.json"], _fixture.Entries);
    }

    [Fact]
    public void Refuses_a_folder_in_place_of_the_file()
    {
        Directory.CreateDirectory(_fixture.StatusJson);
        using var store = _fixture.Open();

        var e = Assert.Throws<SecureStoreException>(() => store.WriteFile("status.json", "{}"u8));

        Assert.Equal($"{_fixture.StatusJson} is a folder, not a file.", e.Message);
        Assert.Equal(["status.json"], _fixture.Entries);
    }

    [Fact]
    public void Refuses_a_file_with_a_second_name_and_changes_neither_name()
    {
        File.WriteAllText(_fixture.StatusJson, "old");
        var outside = _fixture.Tree.PathOf("outside.json");
        Links.CreateHardLink(outside, _fixture.StatusJson);
        using var store = _fixture.Open();

        var e = Assert.Throws<SecureStoreException>(() => store.WriteFile("status.json", "{}"u8));

        Assert.Equal($"{_fixture.StatusJson} has 2 names (hard links), not one, so it may also be a file somewhere else.", e.Message);
        Assert.Equal("old", File.ReadAllText(outside));
        Assert.Equal("old", File.ReadAllText(_fixture.StatusJson));
        Assert.Equal(["status.json"], _fixture.Entries);
    }

    [Fact]
    public void Refuses_a_file_that_is_another_kind_of_reparse_point()
    {
        File.WriteAllText(_fixture.StatusJson, "old");
        Links.MakeThirdPartyReparsePoint(_fixture.StatusJson);
        using var store = _fixture.Open();

        var e = Assert.Throws<SecureStoreException>(() => store.WriteFile("status.json", "{}"u8));

        Assert.Equal($"{_fixture.StatusJson} is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.", e.Message);
        Assert.Equal(["status.json"], _fixture.Entries);
    }

    [Fact]
    public void Refuses_a_symbolic_link_in_place_of_the_file_and_writes_nothing_through_it()
    {
        var outside = _fixture.Tree.File("outside.json", "outside");
        Assert.SkipUnless(Links.TryCreateFileSymbolicLink(_fixture.StatusJson, outside), "Making a symbolic link needs elevation or developer mode.");
        using var store = _fixture.Open();

        var e = Assert.Throws<SecureStoreException>(() => store.WriteFile("status.json", "{}"u8));

        Assert.StartsWith($"{_fixture.StatusJson} is a junction, symbolic link", e.Message, StringComparison.Ordinal);
        Assert.Equal("outside", File.ReadAllText(outside));
    }

    [Fact]
    public void Refuses_a_read_only_file()
    {
        File.WriteAllText(_fixture.StatusJson, "old");
        File.SetAttributes(_fixture.StatusJson, FileAttributes.ReadOnly);
        using var store = _fixture.Open();

        var e = Assert.Throws<SecureStoreException>(() => store.WriteFile("status.json", "{}"u8));

        Assert.Equal($"{_fixture.StatusJson} is read-only, so it cannot be replaced.", e.Message);
        Assert.Equal("old", File.ReadAllText(_fixture.StatusJson));
    }

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData(".status.json")]
    [InlineData("status.json.")]
    [InlineData(@"..\status.json")]
    [InlineData(@"reports\status.json")]
    [InlineData("reports/status.json")]
    [InlineData(@"C:\status.json")]
    [InlineData("status.json:stream")]
    [InlineData("status .json")]
    [InlineData("status*.json")]
    [InlineData("NUL")]
    [InlineData("nul.json")]
    [InlineData("CON")]
    [InlineData("com1.json")]
    [InlineData("LPT9")]
    [InlineData("st\u00e4tus.json")]
    public void Refuses_a_name_that_is_not_a_plain_file_name(string name)
    {
        using var store = _fixture.Open();

        Assert.Throws<ArgumentException>(() => store.WriteFile(name, "{}"u8));
        Assert.Empty(_fixture.Entries);
    }

    [Theory]
    [InlineData("status.json")]
    [InlineData("last-error.json")]
    [InlineData("user_status.v2.json")]
    [InlineData("COM10.json")]
    [InlineData("console.log")]
    public void Accepts_a_plain_file_name(string name)
    {
        using var store = _fixture.Open();

        store.WriteFile(name, "{}"u8);

        Assert.Equal([name], _fixture.Entries);
    }

    [Fact]
    public void Does_not_follow_a_junction_planted_at_the_name_of_the_new_file()
    {
        var elsewhere = _fixture.Tree.Folder("Elsewhere");
        Links.CreateJunction(Path.Combine(_fixture.DataFolder, "planted.tmp"), elsewhere);
        using var store = _fixture.Open(new SecureStoreHooks { TemporaryName = _ => "planted.tmp" });

        var e = Assert.Throws<SecureStoreException>(() => store.WriteFile("status.json", "{}"u8));

        Assert.StartsWith($@"Could not write {_fixture.StatusJson}: Could not create {_fixture.DataFolder}\planted.tmp", e.Message, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFileSystemEntries(elsewhere));
        Assert.Equal(["planted.tmp"], _fixture.Entries);
    }

    [Fact]
    public void Does_not_open_a_file_planted_at_the_name_of_the_new_file()
    {
        var planted = _fixture.Tree.File(@"ProgramData\EngramicBaseline\planted.tmp", "planted");
        using var store = _fixture.Open(new SecureStoreHooks { TemporaryName = _ => "planted.tmp" });

        Assert.Throws<SecureStoreException>(() => store.WriteFile("status.json", "{}"u8));

        Assert.Equal("planted", File.ReadAllText(planted));
        Assert.Equal(["planted.tmp"], _fixture.Entries);
    }

    [Fact]
    public void A_junction_swapped_in_after_the_check_is_not_written_through()
    {
        File.WriteAllText(_fixture.StatusJson, "old");
        var elsewhere = _fixture.Tree.Folder("Elsewhere");
        var clock = new FakeTimeProvider();
        _fixture.Time = clock;
        using var store = _fixture.Open(new SecureStoreHooks
        {
            BeforeRename = (target, attempt) =>
            {
                if (attempt == 1)
                {
                    File.Delete(target);
                    Links.CreateJunction(target, elsewhere);
                }
            },
        });

        var e = Assert.Throws<SecureStoreException>(() => AdvanceUntilDone(clock, () => store.WriteFile("status.json", "{}"u8)));

        Assert.StartsWith($"Could not write {_fixture.StatusJson}: Could not replace {_fixture.StatusJson}", e.Message, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFileSystemEntries(elsewhere));
        Assert.Equal(["status.json"], _fixture.Entries);
    }

    [Fact]
    public void A_hard_link_swapped_in_after_the_check_is_replaced_as_a_name_not_written_through()
    {
        File.WriteAllText(_fixture.StatusJson, "old");
        var outside = _fixture.Tree.File("outside.json", "outside");
        using var store = _fixture.Open(new SecureStoreHooks
        {
            BeforeRename = (target, attempt) =>
            {
                File.Delete(target);
                Links.CreateHardLink(target, outside);
            },
        });

        store.WriteFile("status.json", "new"u8);

        Assert.Equal("new", File.ReadAllText(_fixture.StatusJson));
        Assert.Equal("outside", File.ReadAllText(outside));
        Assert.Equal(1u, Links.LinkCount(outside));
        Assert.Equal(1u, Links.LinkCount(_fixture.StatusJson));
    }

    [Fact]
    public void Another_kind_of_reparse_point_swapped_in_after_the_check_is_replaced_as_a_name()
    {
        // What a standard user can make on a file without a privilege: the rename replaces it as it would a
        // symbolic link, which needs one (the next test).
        File.WriteAllText(_fixture.StatusJson, "old");
        using var store = _fixture.Open(new SecureStoreHooks
        {
            BeforeRename = (target, attempt) =>
            {
                File.Delete(target);
                File.WriteAllText(target, "planted");
                Links.MakeThirdPartyReparsePoint(target);
            },
        });

        store.WriteFile("status.json", "new"u8);

        Assert.Equal("new", File.ReadAllText(_fixture.StatusJson));
        Assert.False(File.GetAttributes(_fixture.StatusJson).HasFlag(FileAttributes.ReparsePoint));
        Assert.Equal(["status.json"], _fixture.Entries);
    }

    [Fact]
    public void A_symbolic_link_swapped_in_after_the_check_is_replaced_as_a_name_not_followed()
    {
        File.WriteAllText(_fixture.StatusJson, "old");
        var outside = _fixture.Tree.File("outside.json", "outside");
        var probe = _fixture.Tree.PathOf("probe.json");
        Assert.SkipUnless(Links.TryCreateFileSymbolicLink(probe, outside), "Making a symbolic link needs elevation or developer mode.");
        using var store = _fixture.Open(new SecureStoreHooks
        {
            BeforeRename = (target, attempt) =>
            {
                File.Delete(target);
                File.CreateSymbolicLink(target, outside);
            },
        });

        store.WriteFile("status.json", "new"u8);

        Assert.Equal("new", File.ReadAllText(_fixture.StatusJson));
        Assert.False(File.GetAttributes(_fixture.StatusJson).HasFlag(FileAttributes.ReparsePoint));
        Assert.Equal("outside", File.ReadAllText(outside));
    }

    [Fact]
    public void Replaces_a_file_a_reader_holds_open_once_the_reader_closes_it()
    {
        File.WriteAllText(_fixture.StatusJson, "old");
        var clock = new FakeTimeProvider();
        _fixture.Time = clock;
        FileStream? reader = null;
        var attempts = 0;
        using var store = _fixture.Open(new SecureStoreHooks
        {
            BeforeRename = (target, attempt) =>
            {
                attempts = attempt;
                if (attempt == 1)
                {
                    reader = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read);
                }
                else
                {
                    reader?.Dispose();
                }
            },
        });

        AdvanceUntilDone(clock, () => store.WriteFile("status.json", "new"u8));

        Assert.Equal("new", File.ReadAllText(_fixture.StatusJson));
        Assert.True(attempts >= 2, $"Renamed at attempt {attempts}.");
        Assert.Equal(["status.json"], _fixture.Entries);
    }

    [Fact]
    public void Gives_up_on_a_file_held_open_after_six_attempts_over_three_seconds_and_removes_its_new_file()
    {
        File.WriteAllText(_fixture.StatusJson, "old");
        var clock = new FakeTimeProvider();
        _fixture.Time = clock;
        var start = clock.GetUtcNow();
        var attempts = 0;
        using var reader = new FileStream(_fixture.StatusJson, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var store = _fixture.Open(new SecureStoreHooks { BeforeRename = (_, attempt) => attempts = attempt });

        var e = Assert.Throws<SecureStoreException>(() => AdvanceUntilDone(clock, () => store.WriteFile("status.json", "new"u8)));

        Assert.Equal(6, attempts);
        Assert.True(clock.GetUtcNow() - start >= TimeSpan.FromMilliseconds(3100), $"Waited {clock.GetUtcNow() - start}.");
        Assert.Contains("(it may be open in another process)", e.Message, StringComparison.Ordinal);
        Assert.Equal(["status.json"], _fixture.Entries);
        reader.Dispose();
        Assert.Equal("old", File.ReadAllText(_fixture.StatusJson));
    }

    /// <summary>Runs a write on a thread of its own, moving a fake clock on until it finishes, so its waits take no real time.</summary>
    private static void AdvanceUntilDone(FakeTimeProvider clock, Action write)
    {
        var done = Task.Factory.StartNew(write, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        while (!done.IsCompleted)
        {
            clock.Advance(TimeSpan.FromMilliseconds(50));
            Thread.Sleep(1);
        }

        done.GetAwaiter().GetResult();
    }
}
