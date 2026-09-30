using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing.Windows;
using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// Reading files in the data folder through their handles: only an ordinary file with one name that no one
/// else can change, never beyond the length the caller allows, and never through a link. None needs elevation.
/// </summary>
[Trait("Suite", "Security")]
public sealed class SecureStoreReadTests : IDisposable
{
    private readonly DataFolderFixture _fixture = new();

    public void Dispose() => _fixture.Dispose();

    private static readonly string FileAccessList = $"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{Elevation.CurrentUser})";

    private string Config => Path.Combine(_fixture.DataFolder, "config");

    [Theory]
    [InlineData(DataFolder.Root)]
    [InlineData(DataFolder.Logs)]
    [InlineData(DataFolder.Reports)]
    [InlineData(DataFolder.Config)]
    [InlineData(DataFolder.Cache)]
    [InlineData(DataFolder.Undo)]
    public void Reads_back_what_it_wrote_in_each_folder(DataFolder folder)
    {
        using var store = _fixture.Initialize();

        store.WriteFile(folder, "file.json", "{\"a\":1}"u8);

        Assert.Equal("{\"a\":1}"u8.ToArray(), store.ReadFile(folder, "file.json", 1024));
    }

    [Fact]
    public void Reads_an_empty_file_as_no_bytes_and_a_missing_one_as_nothing()
    {
        using var store = _fixture.Initialize();
        store.WriteFile(DataFolder.Config, "empty.json", []);

        Assert.Empty(store.ReadFile(DataFolder.Config, "empty.json", 1)!);
        Assert.Null(store.ReadFile(DataFolder.Config, "missing.json", 1));
    }

    [Fact]
    public void Reads_a_file_exactly_as_long_as_the_limit_and_refuses_one_a_byte_longer()
    {
        using var store = _fixture.Initialize();
        store.WriteFile(DataFolder.Cache, "exact.json", new byte[100]);
        store.WriteFile(DataFolder.Cache, "longer.json", new byte[101]);

        Assert.Equal(100, store.ReadFile(DataFolder.Cache, "exact.json", 100)!.Length);
        var e = Assert.Throws<SecureStoreException>(() => store.ReadFile(DataFolder.Cache, "longer.json", 100));
        Assert.Equal($@"{_fixture.DataFolder}\cache\longer.json is 101 bytes long, more than the 100 bytes the tool reads from it.", e.Message);
    }

    [Fact]
    public void Refuses_a_file_with_a_second_name_and_reads_neither()
    {
        using var store = _fixture.Initialize();
        var planted = _fixture.Tree.File("outside.json", "outside");
        Links.CreateHardLink(Path.Combine(Config, "network.json"), planted);

        var e = Assert.Throws<SecureStoreException>(() => store.ReadFile(DataFolder.Config, "network.json", 1024));

        Assert.Equal($@"{Config}\network.json has 2 names (hard links), not one, so it may also be a file somewhere else.", e.Message);
    }

    [Fact]
    public void Refuses_a_junction_in_place_of_a_file_and_reads_nothing_through_it()
    {
        using var store = _fixture.Initialize();
        var elsewhere = _fixture.Tree.Folder("Elsewhere");
        Links.CreateJunction(Path.Combine(Config, "network.json"), elsewhere);

        var e = Assert.Throws<SecureStoreException>(() => store.ReadFile(DataFolder.Config, "network.json", 1024));

        Assert.Equal($@"{Config}\network.json is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.", e.Message);
    }

    [Fact]
    public void Refuses_a_reparse_point_of_another_kind_such_as_a_cloud_placeholder()
    {
        using var store = _fixture.Initialize();
        var file = _fixture.Tree.File(@"ProgramData\EngramicBaseline\config\network.json", "{}");
        Links.MakeThirdPartyReparsePoint(file);

        var e = Assert.Throws<SecureStoreException>(() => store.ReadFile(DataFolder.Config, "network.json", 1024));

        Assert.EndsWith("is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Refuses_a_file_stored_online_only()
    {
        using var store = _fixture.Initialize();
        var file = _fixture.Tree.File(@"ProgramData\EngramicBaseline\config\network.json", "{}");
        File.SetAttributes(file, FileAttributes.Offline);

        var e = Assert.Throws<SecureStoreException>(() => store.ReadFile(DataFolder.Config, "network.json", 1024));

        Assert.Equal($@"{Config}\network.json is stored online only, so opening it would fetch it from elsewhere.", e.Message);
    }

    [Fact]
    public void Refuses_a_folder_in_place_of_a_file()
    {
        using var store = _fixture.Initialize();
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline\config\network.json");

        var e = Assert.Throws<SecureStoreException>(() => store.ReadFile(DataFolder.Config, "network.json", 1024));

        Assert.Equal($@"{Config}\network.json is a folder, not a file.", e.Message);
    }

    [Fact]
    public void Refuses_a_file_standard_users_can_change()
    {
        using var store = _fixture.Initialize();
        var file = _fixture.Tree.File(@"ProgramData\EngramicBaseline\config\network.json", "{}");
        Acls.Reset(file, FileAccessList + "(A;;0x2;;;BU)");

        var e = Assert.Throws<SecureStoreException>(() => store.ReadFile(DataFolder.Config, "network.json", 1024));

        Assert.Equal($@"{Config}\network.json can be changed by S-1-5-32-545, not only administrators.", e.Message);
    }

    [Fact]
    public void Refuses_a_file_that_denies_SYSTEM_a_right()
    {
        using var store = _fixture.Initialize();
        var file = _fixture.Tree.File(@"ProgramData\EngramicBaseline\config\network.json", "{}");
        Acls.Reset(file, "D:P(D;;WD;;;SY)" + FileAccessList[4..]);

        var e = Assert.Throws<SecureStoreException>(() => store.ReadFile(DataFolder.Config, "network.json", 1024));

        Assert.Equal($@"{Config}\network.json denies S-1-5-18 some rights, so the tool may be unable to replace it.", e.Message);
    }

    [Fact]
    public void Refuses_a_file_it_cannot_open_to_read()
    {
        using var store = _fixture.Initialize();
        var file = _fixture.Tree.File(@"ProgramData\EngramicBaseline\config\network.json", "{}");
        Acls.Reset(file, $"D:P(D;;FR;;;{Elevation.CurrentUser})");
        try
        {
            var e = Assert.Throws<SecureStoreException>(() => store.ReadFile(DataFolder.Config, "network.json", 1024));

            Assert.StartsWith($@"Could not read {Config}\network.json: Could not open {Config}\network.json to read it: Access is denied", e.Message, StringComparison.Ordinal);
        }
        finally
        {
            Acls.Reset(file, FileAccessList);
        }
    }

    [Fact]
    public void Waits_for_a_writer_to_close_a_file_then_reads_it_whole()
    {
        var clock = new FakeTimeProvider();
        _fixture.Time = clock;
        using var store = _fixture.Initialize();
        store.WriteFile(DataFolder.Config, "network.json", "{}"u8);
        var writer = new FileStream(Path.Combine(Config, "network.json"), FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);

        // The read shares the file with no writer, so it waits until the writer closes it, a little later.
        using var closes = clock.CreateTimer(_ => writer.Dispose(), null, TimeSpan.FromMilliseconds(250), Timeout.InfiniteTimeSpan);
        byte[]? read = null;
        Waits.AdvanceUntilDone(clock, () => read = store.ReadFile(DataFolder.Config, "network.json", 10));

        Assert.Equal("{}"u8.ToArray(), read);
    }

    [Fact]
    public void Gives_up_on_a_file_a_writer_keeps_open()
    {
        var clock = new FakeTimeProvider();
        _fixture.Time = clock;
        using var store = _fixture.Initialize();
        store.WriteFile(DataFolder.Config, "network.json", "{}"u8);
        using var writer = new FileStream(Path.Combine(Config, "network.json"), FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);

        var e = Assert.Throws<SecureStoreException>(() => Waits.AdvanceUntilDone(clock, () => store.ReadFile(DataFolder.Config, "network.json", 10)));

        Assert.Contains("The process cannot access the file because it is being used by another process", e.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(SecureStore.MaxReadLength + 1)]
    public void Refuses_a_limit_that_is_not_positive_or_is_too_large(int maxLength)
    {
        using var store = _fixture.Initialize();

        Assert.Throws<ArgumentOutOfRangeException>(() => store.ReadFile(DataFolder.Config, "network.json", maxLength));
    }

    [Theory]
    [InlineData(@"..\status.json")]
    [InlineData(@"config\network.json")]
    [InlineData("network.json:stream")]
    [InlineData("")]
    public void Refuses_a_name_that_is_not_a_plain_file_name(string name)
    {
        using var store = _fixture.Initialize();

        Assert.Throws<ArgumentException>(() => store.ReadFile(DataFolder.Config, name, 1));
    }

    [Fact]
    public void Reads_nothing_from_a_folder_that_does_not_exist_and_makes_none()
    {
        using var store = _fixture.Open();

        Assert.Null(store.ReadFile(DataFolder.Config, "network.json", 1024));
        Assert.Empty(_fixture.Entries);
    }

    [Fact]
    public void Moves_aside_an_untrusted_folder_it_is_asked_to_read_from_reads_nothing_and_says_it_made_nothing_in_its_place()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline\config", TempTree.TreeAccess + "(A;OICI;FA;;;BU)");
        _fixture.Tree.File(@"ProgramData\EngramicBaseline\config\network.json", "{\"proxy\":\"planted\"}");
        using var store = _fixture.Open();

        Assert.Null(store.ReadFile(DataFolder.Config, "network.json", 1024));

        var quarantine = Assert.Single(_fixture.Quarantines);
        Assert.EndsWith("-config", quarantine, StringComparison.Ordinal);
        Assert.Empty(_fixture.Entries);
        var notice = $@"Moved an untrusted {_fixture.DataFolder}\config aside to {quarantine} ({_fixture.DataFolder}\config can be changed by S-1-5-32-545, not only administrators); nothing was made in its place. Nothing in it is used again; check it, then delete it.";
        Assert.Equal([notice], store.Notices);
        Assert.Equal([(1003, EventLogLevel.Warning, "Engramic Baseline - data folder: " + notice)], _fixture.Events.Entries);
    }
}
