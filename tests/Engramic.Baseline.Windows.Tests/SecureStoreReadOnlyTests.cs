using System.Reflection;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;
using Engramic.Baseline.Testing.Windows;
using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// SecureStore's read-only way in, on real folders under the temp folder: it judges the data folder and the
/// folders kept in it as SecureStore does and refuses what fails, but never creates, moves, deletes or writes
/// anything, and records no event. Each test shows the fixture's ProgramData folder name for name and byte for
/// byte as it was, and that no step that would change something was reached. With the tests' rules, which trust
/// the account running them, so none needs elevation; ConfigTrustGateElevatedTests use the product's.
/// </summary>
[Trait("Suite", "Security")]
public sealed class SecureStoreReadOnlyTests : IDisposable
{
    private const string Name = "os-lifecycle.json";

    private readonly DataFolderFixture _fixture = new();
    private readonly List<string> _tripped = [];

    public void Dispose() => _fixture.Dispose();

    private string Config => Path.Combine(_fixture.DataFolder, "config");

    private string Override => Path.Combine(Config, Name);

    /// <summary>Gets hooks at every step that would change something, each of which records that it was reached.</summary>
    private SecureStoreHooks Tripwires => new()
    {
        BeforeCreate = path => _tripped.Add("create " + path),
        BeforeMoveAside = (path, _) => _tripped.Add("move aside " + path),
        BeforeRename = (path, _) => _tripped.Add("replace " + path),
        BeforeOpenInTree = path => _tripped.Add("delete " + path),
        TemporaryName = name =>
        {
            _tripped.Add("write " + name);
            return name + ".tmp";
        },
        NewId = () =>
        {
            _tripped.Add("name something new");
            return new string('0', 32);
        },
    };

    [Fact]
    public void Gives_no_store_for_a_data_folder_that_does_not_exist_and_makes_none()
    {
        using var fixture = new DataFolderFixture(withDataFolder: false);
        var before = fixture.Snapshot;

        var store = fixture.OpenReadOnly(Tripwires);

        Assert.Null(store);
        Assert.Empty(fixture.ProgramDataEntries);
        AssertUnchanged(fixture, before);
    }

    [Fact]
    public void Refuses_a_ProgramData_folder_that_is_missing()
    {
        var missing = _fixture.Tree.PathOf("Missing");

        var e = Assert.Throws<SecureStoreException>(() => SecureStore.OpenReadOnly(_fixture.Options with { ProgramDataPath = missing }, DataFolderFixture.Rules, Tripwires));

        Assert.Equal($"The ProgramData folder {missing} does not exist. The fleet install creates the data folder locked; this tool does not create it.", e.Message);
        Assert.False(Directory.Exists(missing));
        Assert.Empty(_tripped);
    }

    [Fact]
    public void Refuses_a_data_folder_that_was_never_sealed_and_changes_nothing()
    {
        PlantOverride();
        _fixture.Registry = new FakeRegistry();
        var before = _fixture.Snapshot;

        var e = Assert.Throws<SecureStoreException>(() => _fixture.OpenReadOnly(Tripwires));

        Assert.Contains("its DataRootSealed marker is missing", e.Message, StringComparison.Ordinal);
        AssertUnchanged(_fixture, before);
    }

    [Fact]
    public void Refuses_a_data_folder_standard_users_can_change_rather_than_moving_it_aside()
    {
        using var fixture = new DataFolderFixture(dataFolderAccess: TempTree.TreeAccess + "(A;OICI;FA;;;BU)");
        fixture.Tree.Folder(@"ProgramData\EngramicBaseline\config");
        fixture.Tree.File(@"ProgramData\EngramicBaseline\config\" + Name, "{}");
        var before = fixture.Snapshot;

        var e = Assert.Throws<SecureStoreException>(() => fixture.OpenReadOnly(Tripwires));

        Assert.Equal($"{fixture.DataFolder} can be changed by S-1-5-32-545, not only administrators.", e.Message);
        Assert.Empty(fixture.Quarantines);
        AssertUnchanged(fixture, before);
    }

    [Fact]
    public void Refuses_a_junction_in_place_of_the_data_folder_and_leaves_it_and_where_it_leads_alone()
    {
        using var fixture = new DataFolderFixture(withDataFolder: false);
        var elsewhere = fixture.Tree.Folder("Elsewhere");
        fixture.Tree.Folder(@"Elsewhere\config");
        fixture.Tree.File(@"Elsewhere\config\" + Name, "{}");
        Links.CreateJunction(fixture.DataFolder, elsewhere);
        var before = fixture.Snapshot;
        var beforeElsewhere = TreeSnapshot.Of(elsewhere);

        var e = Assert.Throws<SecureStoreException>(() => fixture.OpenReadOnly(Tripwires));

        Assert.Equal($"{fixture.DataFolder} is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.", e.Message);
        Assert.True(File.GetAttributes(fixture.DataFolder).HasFlag(FileAttributes.ReparsePoint));
        Assert.Equal(beforeElsewhere, TreeSnapshot.Of(elsewhere));
        AssertUnchanged(fixture, before);
    }

    [Fact]
    public void Reads_a_trusted_override_and_changes_nothing()
    {
        PlantOverride("""{ "lastReviewed": "2026-01-01" }""");
        var before = _fixture.Snapshot;

        using (var store = _fixture.OpenReadOnly(Tripwires))
        {
            Assert.NotNull(store);
            Assert.Equal(_fixture.DataFolder, store.RootPath, ignoreCase: true);
            Assert.Equal("""{ "lastReviewed": "2026-01-01" }"""u8.ToArray(), store.ReadFile(DataFolder.Config, Name, 1024));

            // Read again from the folder it now holds.
            Assert.Equal("""{ "lastReviewed": "2026-01-01" }"""u8.ToArray(), store.ReadFile(DataFolder.Config, Name, 1024));
        }

        AssertUnchanged(_fixture, before);
    }

    [Fact]
    public void Reads_a_file_in_the_data_folder_itself()
    {
        _fixture.Tree.File(@"ProgramData\EngramicBaseline\status.json", "{}");

        using var store = _fixture.OpenReadOnly(Tripwires);

        Assert.Equal("{}"u8.ToArray(), store!.ReadFile(DataFolder.Root, "status.json", 1024));
        Assert.Null(store.ReadFile(DataFolder.Root, "last-error.json", 1024));
        Assert.Empty(_tripped);
    }

    [Fact]
    public void Reads_nothing_from_a_config_folder_that_does_not_exist_and_makes_none()
    {
        var before = _fixture.Snapshot;

        using (var store = _fixture.OpenReadOnly(Tripwires))
        {
            Assert.Null(store!.ReadFile(DataFolder.Config, Name, 1024));
            Assert.Null(store.ReadFile(DataFolder.Cache, "catalog.json", 1024));
        }

        Assert.Empty(_fixture.Entries);
        AssertUnchanged(_fixture, before);
    }

    [Fact]
    public void Refuses_a_config_folder_standard_users_can_change_rather_than_moving_it_aside()
    {
        // SecureStore.Open would move this folder aside, with event 1003 (SecureStoreReadTests).
        PlantOverride();
        Acls.Reset(Config, TempTree.TreeAccess + "(A;OICI;FA;;;BU)");
        var before = _fixture.Snapshot;

        using (var store = _fixture.OpenReadOnly(Tripwires))
        {
            var e = Assert.Throws<SecureStoreException>(() => store!.ReadFile(DataFolder.Config, Name, 1024));

            Assert.Equal($"{Config} can be changed by S-1-5-32-545, not only administrators.", e.Message);
            Assert.False(e.IsUnavailable);
            Assert.True(e.IsFolderRefused);

            // Judged again, and refused again, each time: a refused folder is not held.
            Assert.Throws<SecureStoreException>(() => store!.ReadFile(DataFolder.Config, Name, 1024));
        }

        Assert.Empty(_fixture.Quarantines);
        AssertUnchanged(_fixture, before);
    }

    [Fact]
    public void Refuses_a_junction_in_place_of_the_config_folder_and_reads_nothing_through_it()
    {
        var elsewhere = _fixture.Tree.Folder("Elsewhere");
        _fixture.Tree.File(@"Elsewhere\" + Name, "{}");
        Links.CreateJunction(Config, elsewhere);
        var before = _fixture.Snapshot;

        using (var store = _fixture.OpenReadOnly(Tripwires))
        {
            var e = Assert.Throws<SecureStoreException>(() => store!.ReadFile(DataFolder.Config, Name, 1024));

            Assert.Equal($"{Config} is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.", e.Message);
            Assert.False(e.IsUnavailable);
            Assert.True(e.IsFolderRefused);
        }

        Assert.True(File.GetAttributes(Config).HasFlag(FileAttributes.ReparsePoint));
        AssertUnchanged(_fixture, before);
    }

    [Fact]
    public void Refuses_a_file_in_place_of_the_config_folder()
    {
        _fixture.Tree.File(@"ProgramData\EngramicBaseline\config", "not a folder");
        var before = _fixture.Snapshot;

        using (var store = _fixture.OpenReadOnly(Tripwires))
        {
            var e = Assert.Throws<SecureStoreException>(() => store!.ReadFile(DataFolder.Config, Name, 1024));

            Assert.Equal($"{Config} is a file, not a folder.", e.Message);
            Assert.True(e.IsFolderRefused);
        }

        AssertUnchanged(_fixture, before);
    }

    [Fact]
    public void Refuses_a_config_folder_it_may_not_open_to_judge()
    {
        PlantOverride();
        Acls.Reset(Config, $"D:P(D;;FA;;;{Elevation.CurrentUser})");
        try
        {
            var before = _fixture.Snapshot;

            using (var store = _fixture.OpenReadOnly(Tripwires))
            {
                var e = Assert.Throws<SecureStoreException>(() => store!.ReadFile(DataFolder.Config, Name, 1024));

                Assert.Equal($"{Config} cannot be read by this account (access is denied), so who may change it cannot be judged.", e.Message);
                Assert.False(e.IsUnavailable);
                Assert.True(e.IsFolderRefused);
            }

            AssertUnchanged(_fixture, before);
        }
        finally
        {
            Acls.Reset(Config, TempTree.TreeAccess);
        }
    }

    [Fact]
    public void Refuses_an_override_with_a_second_name_and_changes_neither()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline\config");
        var outside = _fixture.Tree.File("outside.json", "outside");
        Links.CreateHardLink(Override, outside);
        var before = _fixture.Snapshot;

        using (var store = _fixture.OpenReadOnly(Tripwires))
        {
            var e = Assert.Throws<SecureStoreException>(() => store!.ReadFile(DataFolder.Config, Name, 1024));

            Assert.Equal($"{Override} has 2 names (hard links), not one, so it may also be a file somewhere else.", e.Message);
            Assert.False(e.IsFolderRefused);
        }

        Assert.Equal(2u, Links.LinkCount(outside));
        AssertUnchanged(_fixture, before);
    }

    [Theory]
    [MemberData(nameof(Holders.Ways), MemberType = typeof(Holders))]
    public void Says_an_override_someone_holds_up_could_not_be_read_rather_than_judging_it_or_waiting_for_them(string way)
    {
        // As this account, which may write to the fixture's folders, so Windows honours each refusal to share. The
        // store judges the config folder at its first read, so holding the folder stops that too.
        PlantOverride();
        var clock = new FakeTimeProvider();
        _fixture.Time = clock;
        var before = _fixture.Snapshot;
        using var store = _fixture.OpenReadOnly(Tripwires);

        using (var holder = Holders.Hold(way, Override, Config))
        {
            var e = Assert.Throws<SecureStoreException>(() => Waits.AdvanceUntilDone(clock, () => store!.ReadFile(DataFolder.Config, Name, 10)));

            Assert.True(e.IsUnavailable, e.Message);
            Assert.False(e.IsFolderRefused);
            Assert.StartsWith("Could not read ", e.Message, StringComparison.Ordinal);
            if (holder is Oplock oplock)
            {
                Assert.True(oplock.BreakRequested);
            }
        }

        Assert.Equal("{}"u8.ToArray(), store!.ReadFile(DataFolder.Config, Name, 10));
        AssertUnchanged(_fixture, before);
    }

    [Fact]
    public void Holds_the_data_folder_and_a_folder_it_read_from_so_neither_can_be_renamed_while_open()
    {
        PlantOverride();

        using (var store = _fixture.OpenReadOnly())
        {
            _ = store!.ReadFile(DataFolder.Config, Name, 1024);

            Assert.Equal(32, NtFiles.MoveByPath(_fixture.DataFolder, _fixture.DataFolder + "-moved"));
            Assert.Equal(32, NtFiles.MoveByPath(Config, Config + "-moved"));
        }

        Directory.Move(Config, Config + "-moved");
        Directory.Move(Config + "-moved", Config);
    }

    [Fact]
    public void Refuses_to_read_once_disposed()
    {
        var store = _fixture.OpenReadOnly()!;
        store.Dispose();
        store.Dispose();

        Assert.Throws<ObjectDisposedException>(() => store.ReadFile(DataFolder.Config, Name, 1024));
    }

    [Theory]
    [InlineData(@"..\status.json", 1)]
    [InlineData(@"config\os-lifecycle.json", 1)]
    [InlineData("", 1)]
    [InlineData("os-lifecycle.json", 0)]
    [InlineData("os-lifecycle.json", SecureStore.MaxReadLength + 1)]
    public void Refuses_a_name_that_is_not_plain_or_a_limit_out_of_range(string name, int maxLength)
    {
        using var store = _fixture.OpenReadOnly();

        Assert.ThrowsAny<ArgumentException>(() => store!.ReadFile(DataFolder.Config, name, maxLength));
    }

    [Fact]
    public void The_read_only_store_has_no_way_to_write()
    {
        var type = typeof(ReadOnlySecureStore);

        // Not a SecureStore, so no cast reaches a writer; made only by OpenReadOnly.
        Assert.False(typeof(ISecureStore).IsAssignableFrom(type));
        Assert.True(type.IsSealed);
        Assert.Empty(type.GetConstructors());
        Assert.Equal([typeof(IDataFolderReader), typeof(IDisposable)], type.GetInterfaces().OrderBy(i => i.Name, StringComparer.Ordinal));
        Assert.Equal(
            ["Dispose", "ReadFile", "RootPath", "get_RootPath"],
            type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly).Select(m => m.Name).Order(StringComparer.Ordinal));
        Assert.Equal(type, typeof(SecureStore).GetMethod(nameof(SecureStore.OpenReadOnly), [typeof(SecureStoreOptions)])!.ReturnType);
    }

    /// <summary>Plants an override in a config folder that the tests' rules trust.</summary>
    private void PlantOverride(string text = "{}")
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline\config");
        _fixture.Tree.File(@"ProgramData\EngramicBaseline\config\" + Name, text);
    }

    /// <summary>Nothing in ProgramData changed, no step that would change something was reached, and no event was written.</summary>
    private void AssertUnchanged(DataFolderFixture fixture, string[] before)
    {
        Assert.Equal(before, fixture.Snapshot);
        Assert.Empty(_tripped);
        Assert.Empty(fixture.Events.Entries);
    }
}
