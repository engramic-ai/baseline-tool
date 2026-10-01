using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing.Windows;
using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// Deleting a tree in the data folder: every folder checked through its handle just before it is listed,
/// every item opened relative to its folder's handle and as itself, links deleted as links, and anything
/// the tool cannot trust left in place, unlisted. None needs elevation.
/// </summary>
[Trait("Suite", "Security")]
public sealed class SecureStoreTreeDeleteTests : IDisposable
{
    private readonly DataFolderFixture _fixture = new();

    public void Dispose() => _fixture.Dispose();

    private string Reports => Path.Combine(_fixture.DataFolder, "reports");

    [Fact]
    public void Deletes_a_folder_and_everything_in_it()
    {
        using var store = _fixture.Initialize();
        var report = Report("PC01-20260930-101500");
        File.WriteAllText(Path.Combine(report, "report.html"), "report");
        Directory.CreateDirectory(Path.Combine(report, "assets", "fonts"));
        File.WriteAllText(Path.Combine(report, "assets", "fonts", "font.ttf"), "font");

        var left = store.DeleteTree(DataFolder.Reports, "PC01-20260930-101500");

        Assert.Empty(left);
        Assert.Empty(DataFolderFixture.Names(Reports));
    }

    [Fact]
    public void Deletes_a_single_file_and_is_content_when_nothing_is_there()
    {
        using var store = _fixture.Initialize();
        store.WriteFile(DataFolder.Reports, "old.json", "{}"u8);

        Assert.Empty(store.DeleteTree(DataFolder.Reports, "old.json"));
        Assert.Empty(store.DeleteTree(DataFolder.Reports, "missing"));
        Assert.Empty(DataFolderFixture.Names(Reports));
    }

    [Fact]
    public void Deletes_a_junction_in_the_tree_as_a_link_and_leaves_what_it_leads_to_alone()
    {
        using var store = _fixture.Initialize();
        var elsewhere = _fixture.Tree.Folder("Elsewhere");
        var kept = _fixture.Tree.File(@"Elsewhere\kept.txt", "kept");
        var report = Report("old");
        Links.CreateJunction(Path.Combine(report, "junction"), elsewhere);

        Assert.Empty(store.DeleteTree(DataFolder.Reports, "old"));

        Assert.Equal("kept", File.ReadAllText(kept));
        Assert.False(Directory.Exists(report));
    }

    [Fact]
    public void Deletes_a_junction_named_for_deletion_as_a_link()
    {
        using var store = _fixture.Initialize();
        var elsewhere = _fixture.Tree.Folder("Elsewhere");
        var kept = _fixture.Tree.File(@"Elsewhere\kept.txt", "kept");
        Links.CreateJunction(Path.Combine(Reports, "old"), elsewhere);

        Assert.Empty(store.DeleteTree(DataFolder.Reports, "old"));

        Assert.Equal("kept", File.ReadAllText(kept));
        Assert.Empty(DataFolderFixture.Names(Reports));
    }

    [Fact]
    public void An_item_swapped_for_a_junction_after_its_folder_was_listed_is_deleted_as_a_link()
    {
        var elsewhere = _fixture.Tree.Folder("Elsewhere");
        var kept = _fixture.Tree.File(@"Elsewhere\kept.txt", "kept");
        var swapped = false;
        using var store = _fixture.Initialize(new SecureStoreHooks
        {
            BeforeOpenInTree = path =>
            {
                if (!swapped && path.EndsWith(@"\old\sub", StringComparison.Ordinal))
                {
                    swapped = true;
                    Directory.Delete(path, recursive: true);
                    Links.CreateJunction(path, elsewhere);
                }
            },
        });
        var report = Report("old");
        Directory.CreateDirectory(Path.Combine(report, "sub"));
        File.WriteAllText(Path.Combine(report, "sub", "file.txt"), "file");

        Assert.Empty(store.DeleteTree(DataFolder.Reports, "old"));

        Assert.True(swapped);
        Assert.Equal(["kept.txt"], DataFolderFixture.Names(elsewhere));
        Assert.Equal("kept", File.ReadAllText(kept));
    }

    [Fact]
    public void Leaves_a_folder_others_can_change_in_place_and_unlisted()
    {
        using var store = _fixture.Initialize();
        var report = Report("old");
        var open = _fixture.Tree.Folder(@"ProgramData\EngramicBaseline\reports\old\open", TempTree.TreeAccess + "(A;OICI;0x2;;;BU)");
        File.WriteAllText(Path.Combine(open, "planted.txt"), "planted");
        File.WriteAllText(Path.Combine(report, "report.html"), "report");

        var left = store.DeleteTree(DataFolder.Reports, "old");

        Assert.Equal([$"{open} can be changed by S-1-5-32-545, not only administrators, so it was left in place, unlisted."], left);
        Assert.Equal(["open"], DataFolderFixture.Names(report));
        Assert.Equal("planted", File.ReadAllText(Path.Combine(open, "planted.txt")));
    }

    [Fact]
    public void Leaves_a_folder_it_cannot_read_in_place()
    {
        using var store = _fixture.Initialize();
        Report("old");
        var closed = _fixture.Tree.Folder(@"ProgramData\EngramicBaseline\reports\old\closed", $"D:P(D;;0x1301ff;;;{Elevation.CurrentUser})");
        try
        {
            var left = store.DeleteTree(DataFolder.Reports, "old");

            Assert.Equal([$"{closed} cannot be read by this account (access is denied), so it was left in place, unlisted."], left);
        }
        finally
        {
            Acls.Reset(closed, TempTree.TreeAccess);
        }
    }

    [Fact]
    public void Leaves_a_quarantine_in_the_tree_for_an_administrator()
    {
        using var store = _fixture.Initialize();
        var report = Report("old");
        var quarantine = Path.Combine(report, "EngramicBaseline.untrusted-0123456789abcdef0123456789abcdef");
        Directory.CreateDirectory(quarantine);
        File.WriteAllText(Path.Combine(quarantine, "kept.txt"), "kept");

        var left = store.DeleteTree(DataFolder.Reports, "old");

        Assert.Equal([$"{quarantine} is an item moved aside, for an administrator to check and delete, so it was left in place, unlisted."], left);
        Assert.Equal("kept", File.ReadAllText(Path.Combine(quarantine, "kept.txt")));
    }

    [Fact]
    public void Deletes_a_tree_whose_paths_are_far_longer_than_Windows_allows_a_path()
    {
        using var store = _fixture.Initialize();
        var name = new string('d', 200);
        var deepest = Report("deep");
        for (var level = 0; level < 40; level++)
        {
            deepest = Path.Combine(deepest, name);
        }

        Directory.CreateDirectory(deepest);
        File.WriteAllText(Path.Combine(deepest, "bottom.txt"), "bottom");
        Assert.True(deepest.Length > 8000);

        Assert.Empty(store.DeleteTree(DataFolder.Reports, "deep"));

        Assert.Empty(DataFolderFixture.Names(Reports));
    }

    [Fact]
    public void Leaves_what_is_deeper_than_sixty_four_folders_in_place()
    {
        using var store = _fixture.Initialize();
        var deepest = Report("deep");
        for (var level = 2; level <= SecureStore.MaxTreeDepth + 1; level++)
        {
            deepest = Path.Combine(deepest, "d");
        }

        Directory.CreateDirectory(deepest);

        var left = store.DeleteTree(DataFolder.Reports, "deep");

        Assert.Equal([$"{deepest} is more than 64 folders deep, so it was left in place, unlisted."], left);
        Assert.True(Directory.Exists(deepest));
    }

    [Fact]
    public void Deletes_a_read_only_file_and_a_read_only_file_with_another_name_leaving_that_name_as_it_was()
    {
        using var store = _fixture.Initialize();
        var report = Report("old");
        var outside = _fixture.Tree.File("outside.txt", "outside");
        File.WriteAllText(Path.Combine(report, "read-only.txt"), "read only");
        File.SetAttributes(Path.Combine(report, "read-only.txt"), FileAttributes.ReadOnly);
        Links.CreateHardLink(Path.Combine(report, "linked.txt"), outside);
        File.SetAttributes(outside, FileAttributes.ReadOnly);

        Assert.Empty(store.DeleteTree(DataFolder.Reports, "old"));

        Assert.True(File.GetAttributes(outside).HasFlag(FileAttributes.ReadOnly));
        Assert.Equal(1u, Links.LinkCount(outside));
        File.SetAttributes(outside, FileAttributes.Normal);
    }

    [Fact]
    public void Without_the_newer_way_to_delete_clears_the_read_only_attribute_only_of_a_file_with_one_name()
    {
        using var store = _fixture.Initialize(new SecureStoreHooks { ClassicDelete = true });
        var report = Report("old");
        var outside = _fixture.Tree.File("outside.txt", "outside");
        File.WriteAllText(Path.Combine(report, "read-only.txt"), "read only");
        File.SetAttributes(Path.Combine(report, "read-only.txt"), FileAttributes.ReadOnly);
        var linked = Path.Combine(report, "linked.txt");
        Links.CreateHardLink(linked, outside);
        File.SetAttributes(outside, FileAttributes.ReadOnly);

        var left = store.DeleteTree(DataFolder.Reports, "old");

        Assert.Equal([$"{linked} was left in place: it is read-only and has other names (hard links), which share that attribute, so it is not changed."], left);
        Assert.Equal(["linked.txt"], DataFolderFixture.Names(report));
        Assert.True(File.GetAttributes(outside).HasFlag(FileAttributes.ReadOnly));
        File.SetAttributes(outside, FileAttributes.Normal);
    }

    [Fact]
    public void Without_the_newer_way_to_delete_a_folder_whose_file_is_still_open_elsewhere_is_left_in_place()
    {
        var clock = new FakeTimeProvider();
        _fixture.Time = clock;
        using var store = _fixture.Initialize(new SecureStoreHooks { ClassicDelete = true });
        var report = Report("old");
        var held = Path.Combine(report, "held.txt");
        File.WriteAllText(held, "held");
        using var holder = new FileStream(held, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

        IReadOnlyList<string>? left = null;
        Waits.AdvanceUntilDone(clock, () => left = store.DeleteTree(DataFolder.Reports, "old"));

        Assert.StartsWith($"{report} was left in place: it could not be deleted: The directory is not empty", Assert.Single(left!), StringComparison.Ordinal);
    }

    [Fact]
    public void With_the_newer_way_to_delete_a_file_still_open_elsewhere_does_not_hold_up_its_folder()
    {
        using var store = _fixture.Initialize();
        var report = Report("old");
        var held = Path.Combine(report, "held.txt");
        File.WriteAllText(held, "held");
        using var holder = new FileStream(held, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

        Assert.Empty(store.DeleteTree(DataFolder.Reports, "old"));
        Assert.False(Directory.Exists(report));
    }

    [Theory]
    [InlineData("reports")]
    [InlineData("CONFIG")]
    [InlineData("scratch")]
    public void Refuses_to_delete_a_folder_the_store_keeps(string name)
    {
        using var store = _fixture.Initialize();

        Assert.Throws<ArgumentException>(() => store.DeleteTree(DataFolder.Root, name));
    }

    [Theory]
    [InlineData(@"old\sub")]
    [InlineData("..")]
    [InlineData(@"..\EngramicBaseline")]
    public void Refuses_a_name_that_is_not_a_plain_file_name(string name)
    {
        using var store = _fixture.Initialize();

        Assert.Throws<ArgumentException>(() => store.DeleteTree(DataFolder.Reports, name));
    }

    private string Report(string name)
    {
        var path = Path.Combine(Reports, name);
        Directory.CreateDirectory(path);
        return path;
    }
}
