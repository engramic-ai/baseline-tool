using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// Scratch folders for a Windows tool's files: made locked from birth under a random name in the data
/// folder's scratch folder, held while in use, and deleted with everything in them, without following a
/// link, when disposed. None needs elevation.
/// </summary>
[Trait("Suite", "Security")]
public sealed class SecureStoreScratchTests : IDisposable
{
    private readonly DataFolderFixture _fixture = new();

    public void Dispose() => _fixture.Dispose();

    private string Scratch => Path.Combine(_fixture.DataFolder, "scratch");

    [Fact]
    public void Makes_a_folder_locked_from_birth_under_a_random_name_in_the_scratch_folder()
    {
        using var store = _fixture.Initialize();

        using var first = store.CreateScratchFolder();
        using var second = store.CreateScratchFolder();

        Assert.Equal(Scratch, Path.GetDirectoryName(first.Path));
        Assert.Matches("^[0-9a-f]{32}$", Path.GetFileName(first.Path));
        Assert.NotEqual(first.Path, second.Path);
        Assert.Equal(first.Path, Links.FinalPath(first.Path));
        Assert.True(Acls.IsProtected(first.Path));
        Assert.Equal(
            Elevation.FullControl.Select(a => a.Value).Order(StringComparer.Ordinal),
            Acls.Entries(first.Path).Select(e => e.Split(' ')[1]).Order(StringComparer.Ordinal));
        Assert.Equal(Path.Combine(first.Path, "secpol.inf"), first.PathOf("secpol.inf"));
    }

    [Fact]
    public void Makes_the_scratch_folder_itself_when_an_opened_data_folder_has_none()
    {
        using var store = _fixture.Open();

        using var scratch = store.CreateScratchFolder();

        Assert.Equal(["scratch"], _fixture.Entries);
        Assert.True(Acls.IsProtected(Scratch));
    }

    [Fact]
    public void Writes_and_reads_files_a_tool_uses_and_deletes_them_all_when_disposed()
    {
        using var store = _fixture.Initialize();
        var scratch = store.CreateScratchFolder();
        scratch.WriteFile("configure.inf", "[Unicode]"u8);

        // What a tool run with the folder might leave: its own output, a folder, a read-only file.
        File.WriteAllText(scratch.PathOf("secpol.inf"), "exported");
        Directory.CreateDirectory(Path.Combine(scratch.Path, "logs"));
        File.WriteAllText(Path.Combine(scratch.Path, "logs", "tool.log"), "log");
        File.WriteAllText(scratch.PathOf("read-only.sdb"), "database");
        File.SetAttributes(scratch.PathOf("read-only.sdb"), FileAttributes.ReadOnly);

        Assert.Equal("exported"u8.ToArray(), scratch.ReadFile("secpol.inf", 1024));
        Assert.Equal("[Unicode]"u8.ToArray(), scratch.ReadFile("configure.inf", 1024));
        var path = scratch.Path;
        scratch.Dispose();

        Assert.False(Directory.Exists(path));
        Assert.Empty(DataFolderFixture.Names(Scratch));
        Assert.Empty(store.Notices);
    }

    [Fact]
    public void Deletes_a_link_a_tool_left_in_it_as_a_link_and_leaves_what_it_leads_to_alone()
    {
        using var store = _fixture.Initialize();
        var elsewhere = _fixture.Tree.Folder("Elsewhere");
        var kept = _fixture.Tree.File(@"Elsewhere\kept.txt", "kept");
        var outside = _fixture.Tree.File("outside.txt", "outside");
        var scratch = store.CreateScratchFolder();
        Links.CreateJunction(Path.Combine(scratch.Path, "junction"), elsewhere);
        Links.CreateHardLink(scratch.PathOf("hard-link.txt"), outside);
        File.SetAttributes(outside, FileAttributes.ReadOnly);

        scratch.Dispose();

        Assert.Equal("kept", File.ReadAllText(kept));
        Assert.Equal("outside", File.ReadAllText(outside));
        Assert.Equal(1u, Links.LinkCount(outside));
        Assert.True(File.GetAttributes(outside).HasFlag(FileAttributes.ReadOnly));
        Assert.Empty(DataFolderFixture.Names(Scratch));
        File.SetAttributes(outside, FileAttributes.Normal);
    }

    [Fact]
    public void Leaves_a_folder_a_tool_made_that_others_can_change_in_place_unlisted_and_says_so()
    {
        using var store = _fixture.Initialize();
        var scratch = store.CreateScratchFolder();
        var open = Path.Combine(scratch.Path, "open");
        _fixture.Tree.Folder(Path.GetRelativePath(_fixture.Tree.Root, open), TempTree.TreeAccess + "(A;OICI;0x2;;;BU)");
        File.WriteAllText(Path.Combine(open, "planted.txt"), "planted");
        var path = scratch.Path;

        scratch.Dispose();

        Assert.Equal("planted", File.ReadAllText(Path.Combine(open, "planted.txt")));
        Assert.Equal([$"{open} can be changed by S-1-5-32-545, not only administrators, so it was left in place, unlisted."], store.Notices);
        Assert.True(Directory.Exists(path));
    }

    [Fact]
    public void Tries_another_name_when_one_is_taken()
    {
        _fixture.Tree.Folder(@"ProgramData\EngramicBaseline\scratch", TempTree.TreeAccess);
        var taken = "0123456789abcdef0123456789abcdef";
        var planted = _fixture.Tree.File($@"ProgramData\EngramicBaseline\scratch\{taken}", "planted");
        var ids = new Queue<string>([taken, "fedcba9876543210fedcba9876543210"]);
        using var store = _fixture.Initialize(new SecureStoreHooks { NewId = ids.Dequeue });

        using var scratch = store.CreateScratchFolder();

        Assert.EndsWith("fedcba9876543210fedcba9876543210", scratch.Path, StringComparison.Ordinal);
        Assert.Equal("planted", File.ReadAllText(planted));
    }

    [Fact]
    public void Holds_the_folder_so_that_it_cannot_be_renamed_while_in_use()
    {
        using var store = _fixture.Initialize();
        using var scratch = store.CreateScratchFolder();

        Assert.Equal(32, NtFiles.MoveByPath(scratch.Path, scratch.Path + "-moved"));
    }

    [Fact]
    public void Refuses_use_once_disposed_and_may_be_disposed_twice()
    {
        using var store = _fixture.Initialize();
        var scratch = store.CreateScratchFolder();
        scratch.Dispose();
        scratch.Dispose();

        Assert.Throws<ObjectDisposedException>(() => scratch.WriteFile("a.txt", "a"u8));
        Assert.Throws<ObjectDisposedException>(() => scratch.ReadFile("a.txt", 1));
    }

    [Fact]
    public void Refuses_a_name_that_is_not_a_plain_file_name()
    {
        using var store = _fixture.Initialize();
        using var scratch = store.CreateScratchFolder();

        Assert.Throws<ArgumentException>(() => scratch.PathOf(@"..\status.json"));
        Assert.Throws<ArgumentException>(() => scratch.WriteFile(@"sub\file.txt", "x"u8));
        Assert.Throws<ArgumentException>(() => scratch.ReadFile("file.txt:stream", 1));
    }

    [Fact]
    public void Reads_only_files_it_may_trust()
    {
        using var store = _fixture.Initialize();
        using var scratch = store.CreateScratchFolder();
        var outside = _fixture.Tree.File("outside.inf", "outside");
        Links.CreateHardLink(scratch.PathOf("secpol.inf"), outside);

        var e = Assert.Throws<SecureStoreException>(() => scratch.ReadFile("secpol.inf", 1024));

        Assert.Equal($@"{scratch.Path}\secpol.inf has 2 names (hard links), not one, so it may also be a file somewhere else.", e.Message);
    }
}
