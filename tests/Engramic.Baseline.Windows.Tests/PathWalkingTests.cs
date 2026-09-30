using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// What Windows itself does with a name opened relative to a folder's handle, and with a rename through a
/// handle: the facts SecureStore's way of walking paths rests on (docs/DOTNET.md, spike 1). They run on
/// every build the tests run on, so a machine on another build of Windows answers for itself by running
/// this class. None needs elevation.
/// </summary>
[Trait("Suite", "Security")]
public sealed class PathWalkingTests : IDisposable
{
    private readonly TempTree _tree = new();

    public void Dispose() => _tree.Dispose();

    [Fact]
    public void One_name_opened_relative_to_a_folder_as_itself_is_the_link_not_where_it_leads()
    {
        var parent = _tree.Folder("parent");
        var target = _tree.Folder("target");
        Links.CreateJunction(Path.Combine(parent, "junction"), target);
        using var folder = Native.Open(parent, NtFiles.ListDirectory | NtFiles.Synchronize, asLink: true);

        var asItself = NtFiles.Open(folder, "junction", NtFiles.ReadAttributes, NtFiles.ShareAll, NtFiles.OpenIt, NtFiles.OpenReparsePoint, 0, out var link);
        var through = NtFiles.Open(folder, "junction", NtFiles.ReadAttributes, NtFiles.ShareAll, NtFiles.OpenIt, 0, 0, out var followed);

        Assert.Equal(NtFiles.Success, asItself);
        Assert.Equal(Path.Combine(parent, "junction"), Native.FinalPath(link!));
        Assert.Equal(NtFiles.Success, through);
        Assert.Equal(target, Native.FinalPath(followed!));
        link!.Dispose();
        followed!.Dispose();
    }

    [Fact]
    public void A_name_of_two_parts_goes_through_a_junction_on_the_way_which_is_why_the_store_opens_one_name_at_a_time()
    {
        var parent = _tree.Folder("parent");
        var target = _tree.Folder("target");
        var secret = _tree.File(@"target\secret.txt", "secret");
        Links.CreateJunction(Path.Combine(parent, "junction"), target);
        using var folder = Native.Open(parent, NtFiles.ListDirectory | NtFiles.Synchronize, asLink: true);

        var status = NtFiles.Open(folder, @"junction\secret.txt", NtFiles.ReadAttributes, NtFiles.ShareAll, NtFiles.OpenIt, NtFiles.OpenReparsePoint, 0, out var file);

        Assert.Equal(NtFiles.Success, status);
        Assert.Equal(secret, Native.FinalPath(file!));
        file!.Dispose();
    }

    [Fact]
    public void OBJ_DONT_REPARSE_refuses_a_junction_on_the_way_where_Windows_knows_it_and_never_follows_one()
    {
        var parent = _tree.Folder("parent");
        var target = _tree.Folder("target");
        _tree.File(@"target\secret.txt", "secret");
        Links.CreateJunction(Path.Combine(parent, "junction"), target);
        using var folder = Native.Open(parent, NtFiles.ListDirectory | NtFiles.Synchronize, asLink: true);

        var onTheWay = NtFiles.Open(folder, @"junction\secret.txt", NtFiles.ReadAttributes, NtFiles.ShareAll, NtFiles.OpenIt, 0, NtFiles.DontReparse, out var file);
        var plain = NtFiles.Open(folder, "junction", NtFiles.ReadAttributes, NtFiles.ShareAll, NtFiles.OpenIt, NtFiles.OpenReparsePoint, NtFiles.DontReparse, out var link);
        file?.Dispose();
        link?.Dispose();

        // The store does not use the flag: it names one item at a time, as itself, which needs no flag on any
        // build. This records what this build does with it: 0xC000050B where it is known, and 0xC000000D on a
        // build that does not know it.
        TestContext.Current.TestOutputHelper?.WriteLine($"OBJ_DONT_REPARSE on {Environment.OSVersion.Version}: a junction on the way gives 0x{onTheWay:X8}; the junction opened as itself gives 0x{plain:X8}.");
        Assert.Contains(onTheWay, new[] { NtFiles.ReparsePointEncountered, NtFiles.InvalidParameter });
        Assert.Contains(plain, new[] { NtFiles.Success, NtFiles.InvalidParameter });
    }

    [Fact]
    public void Two_dots_in_a_name_do_not_climb_out_of_the_folder_it_is_opened_in()
    {
        var parent = _tree.Folder("parent");
        _tree.Folder("sibling");
        using var folder = Native.Open(parent, NtFiles.ListDirectory | NtFiles.Synchronize, asLink: true);

        var status = NtFiles.Open(folder, @"..\sibling", NtFiles.ReadAttributes, NtFiles.ShareAll, NtFiles.OpenIt, NtFiles.OpenReparsePoint, 0, out var sibling);

        sibling?.Dispose();
        Assert.Equal(NtFiles.ObjectNameInvalid, status);
    }

    [Fact]
    public void Creating_at_a_name_that_is_taken_is_a_collision_even_when_it_is_a_junction()
    {
        var parent = _tree.Folder("parent");
        var target = _tree.Folder("target");
        Links.CreateJunction(Path.Combine(parent, "junction"), target);
        _tree.Folder(@"parent\folder");
        using var folder = Native.Open(parent, NtFiles.ListDirectory | NtFiles.Synchronize, asLink: true);

        var overJunction = NtFiles.Open(folder, "junction", NtFiles.ReadAttributes | NtFiles.Synchronize, NtFiles.ShareAll, NtFiles.CreateIt, NtFiles.DirectoryFile | NtFiles.SynchronousIo | NtFiles.OpenReparsePoint, 0, out var first);
        var overFolder = NtFiles.Open(folder, "folder", NtFiles.ReadAttributes | NtFiles.Synchronize, NtFiles.ShareAll, NtFiles.CreateIt, NtFiles.DirectoryFile | NtFiles.SynchronousIo | NtFiles.OpenReparsePoint, 0, out var second);

        first?.Dispose();
        second?.Dispose();
        Assert.Equal(NtFiles.ObjectNameCollision, overJunction);
        Assert.Equal(NtFiles.ObjectNameCollision, overFolder);
        Assert.Empty(Directory.GetFileSystemEntries(target));
    }

    [Fact]
    public void A_rename_through_the_native_layer_takes_a_folder_s_handle_and_the_Win32_one_refuses_it()
    {
        var parent = _tree.Folder("parent");
        var other = _tree.Folder("other");
        _tree.Folder(@"parent\item");
        using var from = Native.Open(parent, NtFiles.ListDirectory | NtFiles.Synchronize, asLink: true);
        using var to = Native.Open(other, NtFiles.ListDirectory | NtFiles.Synchronize, asLink: true);
        Assert.Equal(NtFiles.Success, NtFiles.Open(from, "item", NtFiles.Delete | NtFiles.ReadAttributes | NtFiles.Synchronize, NtFiles.ShareAll, NtFiles.OpenIt, NtFiles.OpenReparsePoint | NtFiles.SynchronousIo, 0, out var item));
        using (item)
        {
            // ERROR_INVALID_PARAMETER: SetFileInformationByHandle takes no folder's handle for a rename.
            Assert.Equal(87, NtFiles.Win32Rename(item!, to, "moved"));
            Assert.Equal(NtFiles.Success, NtFiles.Rename(item!, to, "moved"));
            Assert.Equal(Path.Combine(other, "moved"), Native.FinalPath(item!));
        }
    }

    [Fact]
    public void A_folder_held_without_FILE_SHARE_DELETE_cannot_be_renamed()
    {
        var held = _tree.Folder("held");

        using (Native.OpenWithShare(held, NtFiles.ListDirectory | NtFiles.Synchronize, NtFiles.ShareReadWrite))
        {
            // ERROR_SHARING_VIOLATION.
            Assert.Equal(32, NtFiles.MoveByPath(held, held + "-moved"));
        }

        Assert.Equal(0, NtFiles.MoveByPath(held, held + "-moved"));
        Assert.Equal(0, NtFiles.MoveByPath(held + "-moved", held));
    }

    [Fact]
    public void A_folder_with_a_file_open_in_it_cannot_be_renamed_which_lets_its_owner_stop_a_move_aside()
    {
        var folder = _tree.Folder("folder");
        var file = _tree.File(@"folder\open.txt", "open");

        using (new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            // ERROR_ACCESS_DENIED, even though the file is shared for deletion.
            Assert.Equal(5, NtFiles.MoveByPath(folder, folder + "-moved"));
        }

        Assert.Equal(0, NtFiles.MoveByPath(folder, folder + "-moved"));
    }

    [Fact]
    public void The_folder_s_own_rights_let_its_owner_move_aside_a_child_that_denies_it_everything()
    {
        var parent = _tree.Folder("parent");
        var hostile = _tree.Folder(@"parent\hostile", $"D:P(D;;0x1301ff;;;{Elevation.CurrentUser})");
        using var folder = Native.Open(parent, NtFiles.ListDirectory | NtFiles.Synchronize, asLink: true);
        try
        {
            var judged = NtFiles.Open(folder, "hostile", NtFiles.ListDirectory | NtFiles.ReadControl | NtFiles.Synchronize, NtFiles.ShareReadWrite, NtFiles.OpenIt, NtFiles.OpenReparsePoint | NtFiles.SynchronousIo, 0, out var denied);
            denied?.Dispose();

            // DELETE comes from the parent's FILE_DELETE_CHILD and FILE_READ_ATTRIBUTES from its
            // FILE_LIST_DIRECTORY, whatever the child's own list says; SYNCHRONIZE comes from nowhere else.
            var removable = NtFiles.Open(folder, "hostile", NtFiles.Delete | NtFiles.ReadAttributes, NtFiles.ShareAll, NtFiles.OpenIt, NtFiles.OpenReparsePoint, 0, out var item);
            using (item)
            {
                Assert.Equal(NtFiles.AccessDenied, judged);
                Assert.Equal(NtFiles.Success, removable);
                Assert.Equal(NtFiles.Success, NtFiles.Rename(item!, folder, "hostile-aside"));
            }

            Assert.True(Directory.Exists(Path.Combine(parent, "hostile-aside")));
            hostile = Path.Combine(parent, "hostile-aside");
        }
        finally
        {
            Acls.Reset(hostile, TempTree.TreeAccess);
        }
    }
}
