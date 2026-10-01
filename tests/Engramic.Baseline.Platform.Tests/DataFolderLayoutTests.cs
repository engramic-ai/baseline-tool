namespace Engramic.Baseline.Platform.Tests;

/// <summary>
/// The layout of the data folder: the folders kept in it, and the names and words the PowerShell tool uses
/// for what it moves aside, so that an administrator finds and reads both tools' quarantines the same way.
/// </summary>
public sealed class DataFolderLayoutTests
{
    private const string Id = "0123456789abcdef0123456789abcdef";

    [Fact]
    public void Keeps_the_installer_s_folders_less_packs_and_adds_undo_and_scratch()
    {
        Assert.Equal(["logs", "reports", "config", "cache", "undo", "scratch"], DataFolderLayout.KeptFolderNames);
    }

    [Theory]
    [InlineData(DataFolder.Logs, "logs")]
    [InlineData(DataFolder.Reports, "reports")]
    [InlineData(DataFolder.Config, "config")]
    [InlineData(DataFolder.Cache, "cache")]
    [InlineData(DataFolder.Undo, "undo")]
    public void Names_each_folder_as_the_installer_does(DataFolder folder, string name)
    {
        Assert.Equal(name, DataFolderLayout.NameOf(folder));
        Assert.Contains(name, DataFolderLayout.KeptFolderNames);
    }

    [Fact]
    public void Gives_no_name_for_the_data_folder_itself_or_a_value_that_is_no_folder()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => DataFolderLayout.NameOf(DataFolder.Root));
        Assert.Throws<ArgumentOutOfRangeException>(() => DataFolderLayout.NameOf((DataFolder)99));
    }

    [Theory]
    [InlineData("config", true)]
    [InlineData("CONFIG", true)]
    [InlineData("reports", false)]
    [InlineData("undo", false)]
    [InlineData("scratch", false)]
    public void Lets_standard_users_read_config_alone(string name, bool usersMayRead)
    {
        Assert.Equal(usersMayRead, DataFolderLayout.UsersMayRead(name));
    }

    [Fact]
    public void Moves_the_data_folder_aside_to_the_name_the_PowerShell_tool_gives()
    {
        // Get-CEDataAsidePath: "$($target.Root).untrusted-$id", with $id = [guid]::NewGuid().ToString('n').
        Assert.Equal("EngramicBaseline.untrusted-" + Id, DataFolderLayout.AsideName("EngramicBaseline", Id));
        Assert.Equal("EngramicBaseline.untrusted-" + Id, DataFolderLayout.AsideName("EngramicBaseline", Id, string.Empty));
    }

    [Theory]
    [InlineData("reports", "-reports")]
    [InlineData(@"reports\PC01-20260930", "-reports-PC01-20260930")]
    [InlineData(@"reports\\PC01/x", "-reports-PC01-x")]
    public void Moves_an_item_in_it_aside_to_a_sibling_named_as_the_PowerShell_tool_names_it(string relative, string suffix)
    {
        // "$($target.Root).untrusted-$id-" + ($target.Relative -replace '[\\/]+', '-')
        Assert.Equal("EngramicBaseline.untrusted-" + Id + suffix, DataFolderLayout.AsideName("EngramicBaseline", Id, relative));
    }

    [Theory]
    [InlineData("")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("0123456789abcdef0123456789abcde")]
    [InlineData("0123456789abcdef0123456789abcdef0")]
    [InlineData("01234567-89ab-cdef-0123-456789abcdef")]
    [InlineData(@"..\x")]
    public void Takes_only_an_identifier_of_32_lower_case_hexadecimal_digits(string id)
    {
        Assert.Throws<ArgumentException>(() => DataFolderLayout.AsideName("EngramicBaseline", id));
    }

    [Theory]
    [InlineData("EngramicBaseline.untrusted-" + Id, true)]
    [InlineData("EngramicBaseline.untrusted-" + Id + "-reports", true)]
    [InlineData("engramicbaseline.UNTRUSTED-x", true)]
    [InlineData("EngramicBaseline", false)]
    [InlineData("untrusted", false)]
    public void Knows_a_quarantine_by_its_name(string name, bool isAside)
    {
        Assert.Equal(isAside, DataFolderLayout.IsAsideName(name));
    }

    [Fact]
    public void Words_a_move_aside_and_its_event_as_the_module_does_when_a_fresh_folder_was_made_in_its_place()
    {
        var notice = DataFolderLayout.MovedAsideNotice(@"C:\ProgramData\EngramicBaseline", @"C:\ProgramData\EngramicBaseline.untrusted-" + Id, @"C:\ProgramData\EngramicBaseline is owned by S-1-5-32-545, not SYSTEM, Administrators or TrustedInstaller.", replaced: true);

        Assert.Equal(
            $@"Moved an untrusted C:\ProgramData\EngramicBaseline aside to C:\ProgramData\EngramicBaseline.untrusted-{Id} (C:\ProgramData\EngramicBaseline is owned by S-1-5-32-545, not SYSTEM, Administrators or TrustedInstaller) and made a fresh, locked one in its place. Nothing in it is used again; check it, then delete it.",
            notice);
        Assert.Equal("Engramic Baseline - data folder: " + notice, DataFolderLayout.EventMessage(notice));
        Assert.Equal(1003, DataFolderLayout.NoticeEventId);
    }

    [Fact]
    public void Says_so_when_a_move_aside_made_nothing_in_its_place()
    {
        var notice = DataFolderLayout.MovedAsideNotice(@"C:\ProgramData\EngramicBaseline\config", $@"C:\ProgramData\EngramicBaseline.untrusted-{Id}-config", @"C:\ProgramData\EngramicBaseline\config can be changed by S-1-5-32-545, not only administrators.", replaced: false);

        Assert.Equal(
            $@"Moved an untrusted C:\ProgramData\EngramicBaseline\config aside to C:\ProgramData\EngramicBaseline.untrusted-{Id}-config (C:\ProgramData\EngramicBaseline\config can be changed by S-1-5-32-545, not only administrators); nothing was made in its place. Nothing in it is used again; check it, then delete it.",
            notice);
    }

    [Fact]
    public void Words_a_link_removed_as_the_installer_does()
    {
        Assert.Equal(
            @"C:\ProgramData\EngramicBaseline\logs was a link (a junction, symbolic link or other reparse point), not a folder. A standard user may have made it to redirect the tool's data, so the link was removed; what it leads to was left alone.",
            DataFolderLayout.LinkRemovedNotice(@"C:\ProgramData\EngramicBaseline\logs"));
    }

    [Fact]
    public void Reads_the_length_of_nothing_as_zero()
    {
        Assert.Equal(0, new FileFacts().Length);
        Assert.Equal(1u, new FileFacts().LinkCount);
    }
}
