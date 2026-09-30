namespace Engramic.Baseline.Platform.Tests;

/// <summary>
/// The trust rules over made-up security descriptors and handle facts, so every decision is covered
/// without touching a disk: owners, each right, deny entries, links, hard links and the seal.
/// </summary>
public sealed class DataFolderTrustTests
{
    private const string DataFolder = @"C:\ProgramData\EngramicBaseline";
    private const string StatusJson = @"C:\ProgramData\EngramicBaseline\status.json";
    private const string Reports = @"C:\ProgramData\EngramicBaseline\reports";
    private const string Override = @"C:\ProgramData\EngramicBaseline\config\network.json";
    private const uint FullControl = 0x001F_01FF;
    private const uint ReadAndExecute = 0x0012_00A9;

    private static readonly Sid User = Sid.Parse("S-1-5-21-1004336348-1177238915-682003330-1001");
    private static readonly Sid Everyone = Sid.Parse("S-1-1-0");
    private static readonly Sid AuthenticatedUsers = Sid.Parse("S-1-5-11");
    private static readonly FileFacts Folder = new() { IsDirectory = true };
    private static readonly FileFacts File = new();

    private readonly DataFolderTrust _trust = DataFolderTrust.Machine;

    [Fact]
    public void The_folder_the_install_makes_is_trusted()
    {
        // O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA), sealed.
        Assert.Null(_trust.FindDataFolderProblem(DataFolder, Folder, Locked(), isSealed: true));
    }

    [Theory]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")]
    public void SYSTEM_Administrators_and_TrustedInstaller_may_own_it(string owner)
    {
        var security = Locked() with { Owner = Sid.Parse(owner) };

        Assert.Null(_trust.FindSecurityProblem(DataFolder, security));
    }

    [Fact]
    public void A_folder_a_user_owns_is_refused()
    {
        var problem = _trust.FindSecurityProblem(DataFolder, Locked() with { Owner = User });

        Assert.Equal($@"{DataFolder} is owned by {User}, not SYSTEM, Administrators or TrustedInstaller.", problem);
    }

    [Fact]
    public void An_owner_that_could_not_be_read_is_refused()
    {
        Assert.Equal($"{DataFolder} has no owner the tool can read.", _trust.FindSecurityProblem(DataFolder, Locked() with { Owner = null }));
    }

    [Theory]
    [InlineData(0x0000_0002u)] // FILE_WRITE_DATA: add a file
    [InlineData(0x0000_0004u)] // FILE_APPEND_DATA: add a folder
    [InlineData(0x0000_0010u)] // FILE_WRITE_EA
    [InlineData(0x0000_0040u)] // FILE_DELETE_CHILD
    [InlineData(0x0000_0100u)] // FILE_WRITE_ATTRIBUTES
    [InlineData(0x0001_0000u)] // DELETE
    [InlineData(0x0004_0000u)] // WRITE_DAC
    [InlineData(0x0008_0000u)] // WRITE_OWNER
    [InlineData(0x4000_0000u)] // GENERIC_WRITE
    [InlineData(0x1000_0000u)] // GENERIC_ALL
    [InlineData(FullControl)]
    public void Every_right_that_changes_an_item_is_refused_to_anyone_else(uint right)
    {
        var problem = _trust.FindSecurityProblem(DataFolder, Locked(Allow(Sid.Users, right)));

        Assert.Equal($"{DataFolder} can be changed by S-1-5-32-545, not only administrators.", problem);
    }

    [Theory]
    [InlineData(ReadAndExecute)]
    [InlineData(0x0000_0001u)] // FILE_LIST_DIRECTORY
    [InlineData(0x0000_0008u)] // FILE_READ_EA
    [InlineData(0x0000_0020u)] // FILE_TRAVERSE
    [InlineData(0x0000_0080u)] // FILE_READ_ATTRIBUTES
    [InlineData(0x0002_0000u)] // READ_CONTROL
    [InlineData(0x0010_0000u)] // SYNCHRONIZE
    [InlineData(0x8000_0000u)] // GENERIC_READ
    [InlineData(0x2000_0000u)] // GENERIC_EXECUTE
    [InlineData(0u)]
    public void Rights_to_read_are_fine_for_anyone(uint right)
    {
        Assert.Null(_trust.FindSecurityProblem(DataFolder, Locked(Allow(Everyone, right), Allow(Sid.Users, right), Allow(AuthenticatedUsers, right))));
    }

    [Fact]
    public void The_trusted_accounts_and_CREATOR_OWNER_may_hold_every_right()
    {
        var security = new ItemSecurity(Sid.LocalSystem,
        [
            Allow(Sid.LocalSystem, uint.MaxValue),
            Allow(Sid.Administrators, uint.MaxValue),
            Allow(Sid.TrustedInstaller, uint.MaxValue),
            Allow(Sid.CreatorOwner, uint.MaxValue),
        ]);

        Assert.Null(_trust.FindSecurityProblem(DataFolder, security));
    }

    [Theory]
    [InlineData("S-1-5-18", 0x001F_01FFu)]
    [InlineData("S-1-5-32-544", 0x0000_0002u)]
    [InlineData("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", 0x0004_0000u)]
    [InlineData("S-1-5-32-544", 0u)]
    public void Any_deny_entry_against_a_trusted_account_is_refused(string trusted, uint right)
    {
        var sid = Sid.Parse(trusted);

        var problem = _trust.FindSecurityProblem(StatusJson, Locked(Deny(sid, right)));

        Assert.Equal($"{StatusJson} denies {sid} some rights, so the tool may be unable to replace it.", problem);
    }

    [Fact]
    public void A_deny_entry_against_anyone_else_is_fine()
    {
        Assert.Null(_trust.FindSecurityProblem(DataFolder, Locked(Deny(Everyone, FullControl), Deny(Sid.Users, 0x2), Deny(null, FullControl))));
    }

    [Fact]
    public void An_entry_of_a_kind_the_tool_does_not_recognise_is_refused()
    {
        var problem = _trust.FindSecurityProblem(DataFolder, Locked(new AccessEntry(AccessEntryType.Other, Sid.Administrators, 0)));

        Assert.Equal($"{DataFolder} has an access entry of a kind the tool does not recognise, so who may change it cannot be judged.", problem);
    }

    [Fact]
    public void An_entry_that_names_no_readable_account_may_grant_only_rights_to_read()
    {
        Assert.Null(_trust.FindSecurityProblem(DataFolder, Locked(Allow(null, ReadAndExecute))));
        Assert.Equal(
            $"{DataFolder} can be changed by an account the tool cannot read, not only administrators.",
            _trust.FindSecurityProblem(DataFolder, Locked(Allow(null, 0x2))));
    }

    [Fact]
    public void An_item_with_no_access_list_is_refused()
    {
        Assert.Equal($"{DataFolder} has no access list, so anyone may change it.", _trust.FindSecurityProblem(DataFolder, new ItemSecurity(Sid.Administrators, null)));
    }

    [Fact]
    public void An_empty_access_list_with_a_trusted_owner_is_trusted()
    {
        Assert.Null(_trust.FindSecurityProblem(DataFolder, new ItemSecurity(Sid.Administrators, [])));
    }

    [Fact]
    public void The_first_problem_is_reported_in_the_PowerShell_tool_s_order()
    {
        var security = new ItemSecurity(User, [Deny(Sid.Administrators, FullControl), Allow(Sid.Users, FullControl)]);

        Assert.StartsWith($"{DataFolder} is owned by", _trust.FindSecurityProblem(DataFolder, security), StringComparison.Ordinal);
        Assert.StartsWith($"{DataFolder} denies", _trust.FindSecurityProblem(DataFolder, security with { Owner = Sid.LocalSystem }), StringComparison.Ordinal);
    }

    [Fact]
    public void A_data_folder_that_is_a_link_is_refused_whatever_its_security()
    {
        var problem = _trust.FindDataFolderProblem(DataFolder, Folder with { IsReparsePoint = true }, Locked(), isSealed: true);

        Assert.Equal($"{DataFolder} is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.", problem);
    }

    [Fact]
    public void A_data_folder_stored_online_only_is_refused()
    {
        var problem = _trust.FindDataFolderProblem(DataFolder, Folder with { IsOnlineOnly = true }, Locked(), isSealed: true);

        Assert.Equal($"{DataFolder} is stored online only, so opening it would fetch it from elsewhere.", problem);
    }

    [Fact]
    public void A_file_in_place_of_the_data_folder_is_refused()
    {
        Assert.Equal($"{DataFolder} is a file, not a folder.", _trust.FindDataFolderProblem(DataFolder, File, Locked(), isSealed: true));
    }

    [Fact]
    public void A_locked_data_folder_that_was_never_sealed_is_refused()
    {
        var problem = _trust.FindDataFolderProblem(DataFolder, Folder, Locked(), isSealed: false);

        Assert.Equal(
            $"{DataFolder} was not created locked by an install of this tool (its DataRootSealed marker is missing), so a standard user may once have been able to change it, and a handle they opened then would keep that access.",
            problem);
    }

    [Fact]
    public void A_missing_seal_is_reported_before_the_security_as_the_installer_does()
    {
        var problem = _trust.FindDataFolderProblem(DataFolder, Folder, Locked() with { Owner = User }, isSealed: false);

        Assert.Contains("DataRootSealed", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void A_sealed_data_folder_is_still_judged_by_its_security()
    {
        var problem = _trust.FindDataFolderProblem(DataFolder, Folder, Locked(Allow(Sid.Users, 0x2)), isSealed: true);

        Assert.Equal($"{DataFolder} can be changed by S-1-5-32-545, not only administrators.", problem);
    }

    [Fact]
    public void The_real_ProgramData_folder_is_trusted_although_users_may_create_folders_in_it()
    {
        Assert.Null(_trust.FindProgramDataProblem(@"C:\ProgramData", Folder, Sid.LocalSystem));
    }

    [Fact]
    public void A_ProgramData_folder_a_user_owns_is_refused()
    {
        Assert.Equal(
            $@"C:\ProgramData is owned by {User}, not SYSTEM, Administrators or TrustedInstaller.",
            _trust.FindProgramDataProblem(@"C:\ProgramData", Folder, User));
        Assert.Equal(@"C:\ProgramData has no owner the tool can read.", _trust.FindProgramDataProblem(@"C:\ProgramData", Folder, null));
    }

    [Fact]
    public void A_ProgramData_folder_that_is_a_link_or_a_file_is_refused()
    {
        Assert.StartsWith(@"C:\ProgramData is a junction", _trust.FindProgramDataProblem(@"C:\ProgramData", Folder with { IsReparsePoint = true }, Sid.LocalSystem), StringComparison.Ordinal);
        Assert.Equal(@"C:\ProgramData is a file, not a folder.", _trust.FindProgramDataProblem(@"C:\ProgramData", File, Sid.LocalSystem));
    }

    [Fact]
    public void An_ordinary_file_may_be_replaced()
    {
        Assert.Null(DataFolderTrust.FindReplaceProblem(StatusJson, File));
    }

    [Fact]
    public void A_link_in_place_of_a_file_is_not_replaced()
    {
        Assert.StartsWith($"{StatusJson} is a junction", DataFolderTrust.FindReplaceProblem(StatusJson, File with { IsReparsePoint = true }), StringComparison.Ordinal);
        Assert.StartsWith($"{StatusJson} is a junction", DataFolderTrust.FindReplaceProblem(StatusJson, Folder with { IsReparsePoint = true }), StringComparison.Ordinal);
        Assert.StartsWith($"{StatusJson} is stored online only", DataFolderTrust.FindReplaceProblem(StatusJson, File with { IsOnlineOnly = true }), StringComparison.Ordinal);
    }

    [Fact]
    public void A_folder_in_place_of_a_file_is_not_replaced()
    {
        Assert.Equal($"{StatusJson} is a folder, not a file.", DataFolderTrust.FindReplaceProblem(StatusJson, Folder));
    }

    [Theory]
    [InlineData(2u)]
    [InlineData(1024u)]
    [InlineData(0u)]
    public void A_file_with_other_names_is_not_replaced(uint links)
    {
        var problem = DataFolderTrust.FindReplaceProblem(StatusJson, File with { LinkCount = links });

        Assert.Equal($"{StatusJson} has {links} names (hard links), not one, so it may also be a file somewhere else.", problem);
    }

    [Fact]
    public void A_read_only_file_is_not_replaced()
    {
        Assert.Equal($"{StatusJson} is read-only, so it cannot be replaced.", DataFolderTrust.FindReplaceProblem(StatusJson, File with { IsReadOnly = true }));
    }

    [Fact]
    public void A_new_file_with_one_name_a_trusted_owner_and_the_folder_s_access_list_passes()
    {
        Assert.Null(_trust.FindNewFileProblem(StatusJson + ".tmp", File, Locked()));
    }

    [Fact]
    public void A_new_file_owned_by_the_user_who_ran_the_tool_is_refused()
    {
        // As an elevated administrator on a client, whose new items default to their own account as owner.
        Assert.StartsWith($"{StatusJson} is owned by {User}", _trust.FindNewFileProblem(StatusJson, File, Locked() with { Owner = User }), StringComparison.Ordinal);
    }

    [Fact]
    public void A_new_file_that_is_not_an_ordinary_file_with_one_name_is_refused()
    {
        Assert.StartsWith($"{StatusJson} has 2 names", _trust.FindNewFileProblem(StatusJson, File with { LinkCount = 2 }, Locked()), StringComparison.Ordinal);
        Assert.StartsWith($"{StatusJson} is a junction", _trust.FindNewFileProblem(StatusJson, File with { IsReparsePoint = true }, Locked()), StringComparison.Ordinal);
        Assert.Equal($"{StatusJson} is a folder, not a file.", _trust.FindNewFileProblem(StatusJson, Folder, Locked()));
    }

    [Fact]
    public void A_kept_folder_that_is_a_trusted_folder_passes()
    {
        Assert.Null(_trust.FindFolderProblem(Reports, Folder, Locked()));
        Assert.Null(_trust.FindFolderProblem(Reports, Folder, Locked(Allow(Sid.Users, ReadAndExecute))));
    }

    [Fact]
    public void A_kept_folder_needs_no_seal_but_is_refused_as_a_link_a_file_or_untrusted()
    {
        Assert.StartsWith($"{Reports} is a junction", _trust.FindFolderProblem(Reports, Folder with { IsReparsePoint = true }, Locked()), StringComparison.Ordinal);
        Assert.StartsWith($"{Reports} is stored online only", _trust.FindFolderProblem(Reports, Folder with { IsOnlineOnly = true }, Locked()), StringComparison.Ordinal);
        Assert.Equal($"{Reports} is a file, not a folder.", _trust.FindFolderProblem(Reports, File, Locked()));
        Assert.Equal($"{Reports} can be changed by S-1-5-32-545, not only administrators.", _trust.FindFolderProblem(Reports, Folder, Locked(Allow(Sid.Users, 0x2))));
        Assert.StartsWith($"{Reports} is owned by {User}", _trust.FindFolderProblem(Reports, Folder, Locked() with { Owner = User }), StringComparison.Ordinal);
    }

    [Fact]
    public void A_file_to_read_passes_when_it_is_ordinary_trusted_and_no_longer_than_the_limit()
    {
        Assert.Null(_trust.FindReadProblem(Override, File with { Length = 100 }, Locked(), maxLength: 100));
        Assert.Null(_trust.FindReadProblem(Override, File, Locked(Allow(Sid.Users, ReadAndExecute)), maxLength: 1));
    }

    [Fact]
    public void A_file_to_read_that_is_longer_than_the_limit_is_refused_not_cut_short()
    {
        Assert.Equal(
            $"{Override} is 101 bytes long, more than the 100 bytes the tool reads from it.",
            _trust.FindReadProblem(Override, File with { Length = 101 }, Locked(), maxLength: 100));
    }

    [Fact]
    public void A_file_to_read_that_a_user_owns_or_can_change_or_is_linked_or_hard_linked_is_refused()
    {
        Assert.StartsWith($"{Override} is owned by {User}", _trust.FindReadProblem(Override, File, Locked() with { Owner = User }, 100), StringComparison.Ordinal);
        Assert.Equal($"{Override} can be changed by S-1-5-32-545, not only administrators.", _trust.FindReadProblem(Override, File, Locked(Allow(Sid.Users, 0x2)), 100));
        Assert.StartsWith($"{Override} is a junction", _trust.FindReadProblem(Override, File with { IsReparsePoint = true }, Locked(), 100), StringComparison.Ordinal);
        Assert.StartsWith($"{Override} has 2 names", _trust.FindReadProblem(Override, File with { LinkCount = 2 }, Locked(), 100), StringComparison.Ordinal);
        Assert.StartsWith($"{Override} is stored online only", _trust.FindReadProblem(Override, File with { IsOnlineOnly = true }, Locked(), 100), StringComparison.Ordinal);
        Assert.Equal($"{Override} is a folder, not a file.", _trust.FindReadProblem(Override, Folder, Locked(), 100));
    }

    [Fact]
    public void A_file_s_problems_come_before_its_security_and_its_length()
    {
        var problem = _trust.FindReadProblem(Override, File with { LinkCount = 2, Length = 1000 }, Locked() with { Owner = User }, 100);

        Assert.StartsWith($"{Override} has 2 names", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void The_machine_rules_trust_SYSTEM_Administrators_and_TrustedInstaller_only()
    {
        Assert.Equal([Sid.LocalSystem, Sid.Administrators, Sid.TrustedInstaller], DataFolderTrust.Machine.Trusted.OrderBy(s => s.Value, StringComparer.Ordinal));
        Assert.False(DataFolderTrust.Machine.IsTrusted(Sid.Users));
        Assert.False(DataFolderTrust.Machine.IsTrusted(Sid.CreatorOwner));
        Assert.False(DataFolderTrust.Machine.IsTrusted(null));
    }

    [Fact]
    public void Rules_for_other_accounts_trust_those_accounts()
    {
        var trust = new DataFolderTrust([Sid.LocalSystem, User]);

        Assert.True(trust.IsTrusted(User));
        Assert.False(trust.IsTrusted(Sid.Administrators));
        Assert.Null(trust.FindSecurityProblem(DataFolder, new ItemSecurity(User, [Allow(User, FullControl)])));
    }

    [Fact]
    public void Rules_need_at_least_one_account_and_no_null()
    {
        Assert.Throws<ArgumentException>(() => new DataFolderTrust([]));
        Assert.Throws<ArgumentException>(() => new DataFolderTrust([Sid.LocalSystem, null!]));
    }

    [Fact]
    public void The_rights_that_change_an_item_are_the_PowerShell_tool_s_mask()
    {
        // 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288 -bor 0x40000000 -bor 0x10000000
        Assert.Equal(0x500D_0156u, DataFolderTrust.WriteRights);
    }

    private static ItemSecurity Locked(params AccessEntry[] more)
    {
        return new ItemSecurity(Sid.Administrators, [Allow(Sid.LocalSystem, FullControl), Allow(Sid.Administrators, FullControl), .. more]);
    }

    private static AccessEntry Allow(Sid? sid, uint mask) => new(AccessEntryType.Allow, sid, mask);

    private static AccessEntry Deny(Sid? sid, uint mask) => new(AccessEntryType.Deny, sid, mask);
}
