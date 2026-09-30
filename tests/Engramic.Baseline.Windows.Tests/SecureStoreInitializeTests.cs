using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;
using Engramic.Baseline.Testing.Windows;
using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// SecureStore making the data folder and the folders kept in it, on real folders under the temp folder:
/// what it keeps, what it moves aside and where to, what it deletes as a link, and what it will not do while
/// something holds an untrusted item open. None of these needs elevation: the account running the tests
/// stands in for the trusted accounts, and for the standard user whose items are refused.
/// </summary>
[Trait("Suite", "Security")]
public sealed class SecureStoreInitializeTests : IDisposable
{
    private const string Aside = @"^EngramicBaseline\.untrusted-[0-9a-f]{32}$";

    private static readonly string[] KeptFolders = ["cache", "config", "logs", "reports", "scratch", "undo"];

    private readonly DataFolderFixture _fixture = new(withDataFolder: false);

    public void Dispose() => _fixture.Dispose();

    private static string[] Locked => [.. Elevation.FullControl.Select(a => $"Allow {a} 0x1F01FF ContainerInherit, ObjectInherit")];

    [Fact]
    public void Makes_the_data_folder_and_each_folder_kept_in_it_locked_from_birth()
    {
        using var store = _fixture.Initialize();

        Assert.Equal(_fixture.DataFolder, store.RootPath, ignoreCase: true);
        Assert.Equal(KeptFolders, _fixture.Entries);
        foreach (var folder in KeptFolders.Select(f => Path.Combine(_fixture.DataFolder, f)).Prepend(_fixture.DataFolder))
        {
            Assert.True(Acls.IsProtected(folder), $"{folder} inherits from its parent.");
            Assert.Equal(Elevation.DefaultOwner.Value, Acls.Owner(folder));
            Assert.Equal(
                (Path.GetFileName(folder) == "config" ? [.. Locked, "Allow S-1-5-32-545 0x1200A9 ContainerInherit, ObjectInherit"] : Locked).Order(StringComparer.Ordinal),
                Acls.Entries(folder).Order(StringComparer.Ordinal));
        }

        Assert.Empty(store.Notices);
        Assert.Empty(_fixture.Events.Entries);
        Assert.Equal([SecureStore.DataFolderName], _fixture.ProgramDataEntries);
    }

    [Fact]
    public void Makes_no_packs_folder_and_leaves_one_an_older_install_made()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline");
        var packs = _fixture.Tree.Folder(@"ProgramData\EngramicBaseline\packs");
        _fixture.Tree.File(@"ProgramData\EngramicBaseline\packs\pack.json", "{}");

        using (_fixture.Initialize())
        {
        }

        Assert.Equal([.. KeptFolders.Append("packs").Order(StringComparer.Ordinal)], _fixture.Entries);
        Assert.Equal("{}", File.ReadAllText(Path.Combine(packs, "pack.json")));
    }

    [Fact]
    public void Keeps_a_sealed_trusted_data_folder_with_what_is_in_it()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline");
        var status = _fixture.Tree.File(@"ProgramData\EngramicBaseline\status.json", "{}");
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline\reports");
        var report = _fixture.Tree.File(@"ProgramData\EngramicBaseline\reports\report.html", "report");

        using var store = _fixture.Initialize();

        Assert.Equal("{}", File.ReadAllText(status));
        Assert.Equal("report", File.ReadAllText(report));
        Assert.Equal([.. KeptFolders.Append("status.json").Order(StringComparer.Ordinal)], _fixture.Entries);
        Assert.Empty(_fixture.Quarantines);
        Assert.Empty(store.Notices);
    }

    [Fact]
    public void Moves_a_data_folder_that_was_never_sealed_aside_and_makes_a_fresh_one()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline");
        _fixture.Tree.File(@"ProgramData\EngramicBaseline\status.json", "old");
        _fixture.Registry = new FakeRegistry();

        using var store = _fixture.Initialize();

        var quarantine = Assert.Single(_fixture.Quarantines);
        Assert.Matches(Aside, Path.GetFileName(quarantine));
        Assert.Equal("old", File.ReadAllText(Path.Combine(quarantine, "status.json")));
        Assert.Equal(KeptFolders, _fixture.Entries);
        var notice = $"Moved an untrusted {_fixture.DataFolder} aside to {quarantine} ({_fixture.DataFolder} was not created locked by an install of this tool (its DataRootSealed marker is missing), so a standard user may once have been able to change it, and a handle they opened then would keep that access) and made a fresh, locked one in its place. Nothing in it is used again; check it, then delete it.";
        Assert.Equal([notice], store.Notices);
        Assert.Equal([(1003, EventLogLevel.Warning, "Engramic Baseline - data folder: " + notice)], _fixture.Events.Entries);
    }

    [Fact]
    public void Moves_aside_a_sealed_data_folder_that_standard_users_can_change()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline", TempTree.TreeAccess + "(A;OICI;0x2;;;BU)");

        using var store = _fixture.Initialize();

        var quarantine = Assert.Single(_fixture.Quarantines);
        Assert.Contains($"({_fixture.DataFolder} can be changed by S-1-5-32-545, not only administrators)", Assert.Single(store.Notices), StringComparison.Ordinal);
        Assert.Contains(Acls.Entries(quarantine), e => e.StartsWith("Allow S-1-5-32-545 0x2 ", StringComparison.Ordinal));
        Assert.Equal(Locked.Order(StringComparer.Ordinal), Acls.Entries(_fixture.DataFolder).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Moves_aside_a_data_folder_that_denies_SYSTEM_a_right()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline", "D:P(D;;WD;;;SY)" + TempTree.TreeAccess[4..]);

        using var store = _fixture.Initialize();

        Assert.Single(_fixture.Quarantines);
        Assert.Contains($"({_fixture.DataFolder} denies S-1-5-18 some rights, so the tool may be unable to replace it)", Assert.Single(store.Notices), StringComparison.Ordinal);
    }

    [Fact]
    public void Moves_aside_a_data_folder_that_denies_this_account_everything_its_parent_does_not_grant()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline", $"D:P(D;;0x1301ff;;;{Elevation.CurrentUser})");
        try
        {
            using var store = _fixture.Initialize();

            Assert.Contains($"({_fixture.DataFolder} cannot be read by this account (access is denied), so who may change it cannot be judged)", Assert.Single(store.Notices), StringComparison.Ordinal);
            Assert.Equal(Locked.Order(StringComparer.Ordinal), Acls.Entries(_fixture.DataFolder).Order(StringComparer.Ordinal));
        }
        finally
        {
            foreach (var quarantine in _fixture.Quarantines)
            {
                Acls.Reset(quarantine, TempTree.TreeAccess);
            }
        }
    }

    [Fact]
    public void Deletes_a_junction_in_place_of_the_data_folder_as_a_link_and_leaves_where_it_leads_alone()
    {
        var elsewhere = _fixture.Tree.Folder("Elsewhere");
        _fixture.Tree.File(@"Elsewhere\kept.txt", "kept");
        Links.CreateJunction(_fixture.DataFolder, elsewhere);

        using var store = _fixture.Initialize();

        Assert.Equal(["kept.txt"], DataFolderFixture.Names(elsewhere));
        Assert.False(File.GetAttributes(_fixture.DataFolder).HasFlag(FileAttributes.ReparsePoint));
        Assert.Equal(KeptFolders, _fixture.Entries);
        Assert.Empty(_fixture.Quarantines);
        var notice = $"{_fixture.DataFolder} was a link (a junction, symbolic link or other reparse point), not a folder. A standard user may have made it to redirect the tool's data, so the link was removed; what it leads to was left alone.";
        Assert.Equal([notice], store.Notices);
        Assert.Equal([(1003, EventLogLevel.Warning, "Engramic Baseline - data folder: " + notice)], _fixture.Events.Entries);
    }

    [Fact]
    public void Deletes_a_reparse_point_of_another_kind_in_place_of_the_data_folder_as_itself()
    {
        _fixture.Tree.File(@"ProgramData\EngramicBaseline", "tagged");
        Links.MakeThirdPartyReparsePoint(_fixture.DataFolder);

        using var store = _fixture.Initialize();

        Assert.True(Directory.Exists(_fixture.DataFolder));
        Assert.StartsWith($"{_fixture.DataFolder} was a link", Assert.Single(store.Notices), StringComparison.Ordinal);
    }

    [Fact]
    public void Moves_aside_a_file_in_place_of_the_data_folder()
    {
        _fixture.Tree.File(@"ProgramData\EngramicBaseline", "not a folder");

        using var store = _fixture.Initialize();

        var quarantine = Assert.Single(_fixture.Quarantines);
        Assert.Equal("not a folder", File.ReadAllText(quarantine));
        Assert.Contains($"({_fixture.DataFolder} is a file, not a folder)", Assert.Single(store.Notices), StringComparison.Ordinal);
        Assert.Equal(KeptFolders, _fixture.Entries);
    }

    [Fact]
    public void Moves_aside_a_data_folder_stored_online_only()
    {
        var folder = _fixture.Tree.Folder(@"ProgramData\EngramicBaseline");
        File.SetAttributes(folder, FileAttributes.Directory | FileAttributes.Offline);

        using var store = _fixture.Initialize();

        Assert.Contains("is stored online only", Assert.Single(store.Notices), StringComparison.Ordinal);
        Assert.False(File.GetAttributes(_fixture.DataFolder).HasFlag(FileAttributes.Offline));
    }

    [Theory]
    [InlineData("reports")]
    [InlineData("config")]
    [InlineData("undo")]
    [InlineData("scratch")]
    public void Moves_an_untrusted_kept_folder_out_of_the_data_folder_and_makes_a_fresh_one(string name)
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline");
        _fixture.Tree.Folder($@"ProgramData\EngramicBaseline\{name}", TempTree.TreeAccess + "(A;OICI;0x2;;;BU)");
        _fixture.Tree.File($@"ProgramData\EngramicBaseline\{name}\planted.json", "planted");

        using var store = _fixture.Initialize();

        var quarantine = Assert.Single(_fixture.Quarantines);
        Assert.Matches($@"^EngramicBaseline\.untrusted-[0-9a-f]{{32}}-{name}$", Path.GetFileName(quarantine));
        Assert.Equal(_fixture.ProgramData, Path.GetDirectoryName(quarantine));
        Assert.Equal("planted", File.ReadAllText(Path.Combine(quarantine, "planted.json")));
        Assert.Empty(DataFolderFixture.Names(Path.Combine(_fixture.DataFolder, name)));
        Assert.DoesNotContain(Acls.Entries(Path.Combine(_fixture.DataFolder, name)), e => e.Contains("S-1-5-32-545 0x2 ", StringComparison.Ordinal));
        Assert.Contains($"aside to {quarantine} ({_fixture.DataFolder}\\{name} can be changed by S-1-5-32-545", Assert.Single(store.Notices), StringComparison.Ordinal);
    }

    [Fact]
    public void Deletes_a_junction_in_place_of_a_kept_folder_as_a_link()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline");
        var elsewhere = _fixture.Tree.Folder("Elsewhere");
        Links.CreateJunction(Path.Combine(_fixture.DataFolder, "logs"), elsewhere);

        using var store = _fixture.Initialize();
        store.WriteFile(DataFolder.Logs, "audit.log", "logged"u8);

        Assert.Empty(DataFolderFixture.Names(elsewhere));
        Assert.Equal("logged", File.ReadAllText(Path.Combine(_fixture.DataFolder, "logs", "audit.log")));
        Assert.StartsWith($@"{_fixture.DataFolder}\logs was a link", Assert.Single(store.Notices), StringComparison.Ordinal);
    }

    [Fact]
    public void Moves_aside_a_file_in_place_of_a_kept_folder()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline");
        _fixture.Tree.File(@"ProgramData\EngramicBaseline\cache", "a file");

        using var store = _fixture.Initialize();

        var quarantine = Assert.Single(_fixture.Quarantines);
        Assert.EndsWith("-cache", quarantine, StringComparison.Ordinal);
        Assert.Equal("a file", File.ReadAllText(quarantine));
        Assert.True(Directory.Exists(Path.Combine(_fixture.DataFolder, "cache")));
    }

    [Fact]
    public void Judges_what_appears_at_the_name_after_it_was_found_missing_and_before_the_folder_is_made()
    {
        var elsewhere = _fixture.Tree.Folder("Elsewhere");
        var planted = false;
        var hooks = new SecureStoreHooks
        {
            BeforeCreate = path =>
            {
                if (!planted && path == _fixture.DataFolder)
                {
                    planted = true;
                    Links.CreateJunction(path, elsewhere);
                }
            },
        };

        using var store = _fixture.Initialize(hooks);

        Assert.True(planted);
        Assert.Empty(DataFolderFixture.Names(elsewhere));
        Assert.False(File.GetAttributes(_fixture.DataFolder).HasFlag(FileAttributes.ReparsePoint));
        Assert.StartsWith($"{_fixture.DataFolder} was a link", Assert.Single(store.Notices), StringComparison.Ordinal);
    }

    [Fact]
    public void Never_moves_an_item_over_a_quarantine_name_already_taken()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline");
        _fixture.Registry = new FakeRegistry();
        var taken = "0123456789abcdef0123456789abcdef";
        var fresh = "fedcba9876543210fedcba9876543210";
        var planted = _fixture.Tree.Folder($@"ProgramData\EngramicBaseline.untrusted-{taken}");
        _fixture.Tree.File($@"ProgramData\EngramicBaseline.untrusted-{taken}\mine.txt", "mine");
        var ids = new Queue<string>([taken, fresh]);

        using var store = _fixture.Initialize(new SecureStoreHooks { NewId = ids.Dequeue });

        Assert.Equal("mine", File.ReadAllText(Path.Combine(planted, "mine.txt")));
        Assert.Equal(["mine.txt"], DataFolderFixture.Names(planted));
        Assert.True(Directory.Exists(Path.Combine(_fixture.ProgramData, $"EngramicBaseline.untrusted-{fresh}")));
    }

    [Fact]
    public void Makes_nothing_in_place_of_an_untrusted_folder_it_cannot_move_while_something_in_it_is_open()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline");
        var held = _fixture.Tree.File(@"ProgramData\EngramicBaseline\held.txt", "held");
        _fixture.Registry = new FakeRegistry();
        var clock = new FakeTimeProvider();
        _fixture.Time = clock;
        var attempts = 0;

        using (new FileStream(held, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            var e = Assert.Throws<SecureStoreException>(() => Waits.AdvanceUntilDone(clock, () => _fixture.Initialize(new SecureStoreHooks { BeforeMoveAside = (_, attempt) => attempts = attempt }).Dispose()));

            Assert.StartsWith($"The untrusted {_fixture.DataFolder} could not be moved aside to {_fixture.ProgramData}\\EngramicBaseline.untrusted-", e.Message, StringComparison.Ordinal);
            Assert.Contains("so nothing was made in its place. Another process may have it, or something in it, open: Access is denied", e.Message, StringComparison.Ordinal);
        }

        Assert.Equal(6, attempts);
        Assert.Equal(["held.txt"], _fixture.Entries);
        Assert.Empty(_fixture.Quarantines);
        Assert.Empty(_fixture.Events.Entries);
    }

    [Fact]
    public void Makes_nothing_in_place_of_an_untrusted_folder_it_cannot_move_while_ProgramData_is_held_without_sharing()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline");
        _fixture.Registry = new FakeRegistry();
        var clock = new FakeTimeProvider();
        _fixture.Time = clock;
        var attempts = 0;

        // A rename opens the folder it renames into, to add the name, so it waits on whoever holds that folder
        // open without sharing it: here this account, which may write to the fixture's ProgramData as standard
        // users may to the real one.
        using (Native.OpenWithShare(_fixture.ProgramData, NtFiles.ListDirectory | NtFiles.Synchronize, NtFiles.ShareNone))
        {
            var e = Assert.Throws<SecureStoreException>(() => Waits.AdvanceUntilDone(clock, () => _fixture.Initialize(new SecureStoreHooks { BeforeMoveAside = (_, attempt) => attempts = attempt }).Dispose()));

            Assert.StartsWith($"The untrusted {_fixture.DataFolder} could not be moved aside to {_fixture.ProgramData}\\EngramicBaseline.untrusted-", e.Message, StringComparison.Ordinal);
            Assert.Contains($"so nothing was made in its place. Another process may hold {_fixture.ProgramData} open without sharing it: ", e.Message, StringComparison.Ordinal);
            Assert.EndsWith("(Win32 error 32).", e.Message, StringComparison.Ordinal);
        }

        Assert.Equal(6, attempts);
        Assert.Empty(_fixture.Entries);
        Assert.Empty(_fixture.Quarantines);
        Assert.Empty(_fixture.Events.Entries);

        using var store = _fixture.Initialize();
        Assert.Single(_fixture.Quarantines);
        Assert.Equal(KeptFolders, _fixture.Entries);
    }

    [Fact]
    public void Moves_an_untrusted_folder_aside_once_what_held_it_lets_go()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline");
        var held = _fixture.Tree.File(@"ProgramData\EngramicBaseline\held.txt", "held");
        _fixture.Registry = new FakeRegistry();
        var clock = new FakeTimeProvider();
        _fixture.Time = clock;
        var reader = new FileStream(held, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var hooks = new SecureStoreHooks
        {
            BeforeMoveAside = (_, attempt) =>
            {
                if (attempt == 3)
                {
                    reader.Dispose();
                }
            },
        };

        SecureStore? store = null;
        Waits.AdvanceUntilDone(clock, () => store = _fixture.Initialize(hooks));
        using (store)
        {
            Assert.Single(_fixture.Quarantines);
            Assert.Equal(KeptFolders, _fixture.Entries);
        }
    }

    [Fact]
    public void Moves_nothing_when_the_seal_cannot_be_read()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline");
        _fixture.Registry = new FakeRegistry().Deny(RegistryHive.LocalMachine, SecureStoreOptions.MachineSealKeyPath);

        var e = Assert.Throws<SecureStoreException>(() => _fixture.Initialize());

        Assert.StartsWith(@"The seal of the data folder, HKEY_LOCAL_MACHINE\SOFTWARE\EngramicBaseline.DataRoot\DataRootSealed, could not be read", e.Message, StringComparison.Ordinal);
        Assert.Equal([SecureStore.DataFolderName], _fixture.ProgramDataEntries);
        Assert.Empty(_fixture.Entries);
    }

    [Fact]
    public void Refuses_a_ProgramData_folder_that_is_a_junction_and_makes_nothing_where_it_leads()
    {
        var link = _fixture.Tree.PathOf("LinkedProgramData");
        Links.CreateJunction(link, _fixture.ProgramData);

        var e = Assert.Throws<SecureStoreException>(() => SecureStore.Initialize(_fixture.Options with { ProgramDataPath = link }, DataFolderFixture.Rules, null));

        Assert.Equal($"{link} is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.", e.Message);
        Assert.Empty(_fixture.ProgramDataEntries);
    }

    [Fact]
    public void Refuses_a_ProgramData_folder_that_is_missing()
    {
        var missing = _fixture.Tree.PathOf("Missing");

        var e = Assert.Throws<SecureStoreException>(() => SecureStore.Initialize(_fixture.Options with { ProgramDataPath = missing }, DataFolderFixture.Rules, null));

        Assert.StartsWith($"The ProgramData folder {missing} does not exist.", e.Message, StringComparison.Ordinal);
        Assert.False(Directory.Exists(missing));
    }

    [Fact]
    public void Holds_the_data_folder_and_every_kept_folder_so_none_can_be_renamed_while_open()
    {
        using (_fixture.Initialize())
        {
            foreach (var folder in KeptFolders.Select(f => Path.Combine(_fixture.DataFolder, f)).Prepend(_fixture.DataFolder))
            {
                Assert.Equal(32, NtFiles.MoveByPath(folder, folder + "-moved"));
            }
        }

        Assert.Equal(0, NtFiles.MoveByPath(_fixture.DataFolder, _fixture.DataFolder + "-moved"));
    }

    [Fact]
    public void Says_so_when_the_event_log_refuses_a_notice()
    {
        _fixture.Tree.File(@"ProgramData\EngramicBaseline", "not a folder");
        _fixture.Events.Refuses = true;

        using var store = _fixture.Initialize();

        Assert.Equal(2, store.Notices.Count);
        Assert.Equal("The notice above could not be written to the Application event log as event 1003.", store.Notices[1]);
    }

    [Fact]
    public void A_second_run_keeps_what_the_first_made()
    {
        using (var first = _fixture.Initialize())
        {
            first.WriteFile("status.json", "{}"u8);
            first.WriteFile(DataFolder.Config, "network.json", "{}"u8);
        }

        using var second = _fixture.Initialize();

        Assert.Empty(second.Notices);
        Assert.Equal("{}"u8.ToArray(), second.ReadFile(DataFolder.Config, "network.json", 100));
        Assert.Empty(_fixture.Quarantines);
    }
}
