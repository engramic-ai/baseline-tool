using System.Security.AccessControl;
using System.Security.Principal;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>What handles tell: security descriptors read into the trust model, final paths and file facts.</summary>
public sealed class FileHandlesTests : IDisposable
{
    private const uint FullControl = 0x001F_01FF;

    private readonly TempTree _tree = new();

    public void Dispose() => _tree.Dispose();

    [Fact]
    public void Reads_the_security_descriptor_the_installer_gives_the_data_folder()
    {
        var security = FileHandles.ToItemSecurity(Bytes("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"));

        Assert.Equal(Sid.Administrators, security.Owner);
        Assert.Equal(
            [new AccessEntry(AccessEntryType.Allow, Sid.LocalSystem, FullControl), new AccessEntry(AccessEntryType.Allow, Sid.Administrators, FullControl)],
            security.Dacl);
    }

    [Fact]
    public void Reads_deny_entries_masks_and_inherit_only_entries_as_stored()
    {
        var security = FileHandles.ToItemSecurity(Bytes("O:SYD:(D;;WD;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GA;;;CO)(A;OICIIO;GW;;;AU)"));

        Assert.Equal(Sid.LocalSystem, security.Owner);
        Assert.Equal(
            [
                new AccessEntry(AccessEntryType.Deny, Sid.Administrators, 0x0004_0000),
                new AccessEntry(AccessEntryType.Allow, Sid.Users, 0x0012_00A9),
                new AccessEntry(AccessEntryType.Allow, Sid.CreatorOwner, 0x1000_0000),
                new AccessEntry(AccessEntryType.Allow, Sid.Parse("S-1-5-11"), 0x4000_0000),
            ],
            security.Dacl);
    }

    [Fact]
    public void Reads_object_and_conditional_entries_by_what_they_do()
    {
        var security = FileHandles.ToItemSecurity(Bytes(
            "O:BAD:(OA;;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)(OD;;WD;bf967aba-0de6-11d0-a285-00aa003049e2;;SY)(XA;;FA;;;WD;(Member_of {SID(BA)}))(XD;;WO;;;BA;(Member_of {SID(BU)}))"));

        Assert.Equal(
            [AccessEntryType.Allow, AccessEntryType.Deny, AccessEntryType.Allow, AccessEntryType.Deny],
            security.Dacl!.Select(e => e.Type));
        Assert.Equal([Sid.Users, Sid.LocalSystem, Sid.Parse("S-1-1-0"), Sid.Administrators], security.Dacl!.Select(e => e.Trustee));
    }

    [Fact]
    public void Reads_any_other_kind_of_entry_as_Other()
    {
        var acl = new RawAcl(GenericAcl.AclRevision, 2);
        acl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.SystemAudit, (int)FullControl, new SecurityIdentifier("S-1-5-32-545"), false, null));
        acl.InsertAce(1, new CustomAce((AceType)0x42, AceFlags.None, [1, 2, 3, 4]));
        var descriptor = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, new SecurityIdentifier("S-1-5-32-544"), null, null, acl);

        var security = FileHandles.ToItemSecurity(Bytes(descriptor));

        Assert.Equal([AccessEntryType.Other, AccessEntryType.Other], security.Dacl!.Select(e => e.Type));
    }

    [Fact]
    public void A_missing_or_null_access_list_is_null_and_an_empty_one_is_empty()
    {
        Assert.Null(FileHandles.ToItemSecurity(Bytes("O:BA")).Dacl);
        Assert.Null(FileHandles.ToItemSecurity(Bytes("O:BAD:NO_ACCESS_CONTROL")).Dacl);
        Assert.Empty(FileHandles.ToItemSecurity(Bytes("O:BAD:P")).Dacl!);
    }

    [Fact]
    public void An_account_the_trust_model_cannot_hold_is_null()
    {
        // S-1-5 has no sub-authority, which Sid does not read.
        var owner = new SecurityIdentifier([1, 0, 0, 0, 0, 0, 0, 5], 0);
        var descriptor = new RawSecurityDescriptor(ControlFlags.None, owner, null, null, null);

        Assert.Null(FileHandles.ToItemSecurity(Bytes(descriptor)).Owner);
    }

    [Fact]
    public void Refuses_bytes_that_are_not_a_self_relative_security_descriptor()
    {
        var absolute = Bytes("O:BAD:P(A;;FA;;;SY)");
        absolute[3] &= 0x7F;

        Assert.Throws<IOException>(() => FileHandles.ToItemSecurity(absolute));
        Assert.Throws<IOException>(() => FileHandles.ToItemSecurity([1, 0, 0, 0x80]));
        Assert.Throws<IOException>(() => FileHandles.ToItemSecurity([1, 0, 4, 0x80, 0xFF, 0xFF, 0xFF, 0x7F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    }

    [Theory]
    [InlineData(@"\\?\C:\ProgramData", @"C:\ProgramData")]
    [InlineData(@"\\?\d:\Data\EngramicBaseline", @"d:\Data\EngramicBaseline")]
    [InlineData(@"\\?\UNC\server\share\ProgramData", null)]
    [InlineData(@"\\?\Volume{5f4c2a53-0000-0000-0000-100000000000}\ProgramData", null)]
    [InlineData(@"C:\ProgramData", null)]
    [InlineData(@"\\?\C:", null)]
    public void Reads_a_final_path_as_the_local_path_it_names(string finalPath, string? expected)
    {
        Assert.Equal(expected, FileHandles.ToLocalPath(finalPath));
    }

    [Theory]
    [InlineData(@"C:\ProgramData", true)]
    [InlineData(@"c:\Users\John Smith\AppData\Local\Temp\baseline-test-1\ProgramData", true)]
    [InlineData(@"C:\ProgramData\EngramicBaseline.DataRoot", true)]
    [InlineData(@"C:\ProgramData\", false)]
    [InlineData(@"C:\Program\\Data", false)]
    [InlineData(@"C:\ProgramData\..", false)]
    [InlineData(@"C:\a\b|c", false)]
    [InlineData("C:\\a\tb", false)]
    [InlineData(null, false)]
    public void Tells_a_plain_full_local_path(string? path, bool plain)
    {
        Assert.Equal(plain, FileHandles.IsPlainLocalPath(path));
    }

    [Fact]
    public void Reads_the_facts_of_a_file_a_folder_and_a_junction_through_their_handles()
    {
        var file = _tree.File("file.txt", "text");
        var folder = _tree.Folder("folder");
        var junction = _tree.PathOf("junction");
        Links.CreateJunction(junction, folder);
        Links.CreateHardLink(_tree.PathOf("second-name.txt"), file);

        Assert.Equal(new FileFacts { LinkCount = 2 }, Facts(file));
        Assert.Equal(new FileFacts { IsDirectory = true }, Facts(folder));
        Assert.Equal(new FileFacts { IsDirectory = true, IsReparsePoint = true }, Facts(junction));
    }

    [Fact]
    public void Reads_a_read_only_file_and_another_kind_of_reparse_point()
    {
        var readOnly = _tree.File("read-only.txt");
        File.SetAttributes(readOnly, FileAttributes.ReadOnly);
        var tagged = _tree.File("tagged.txt", "text");
        Links.MakeThirdPartyReparsePoint(tagged);

        Assert.True(Facts(readOnly).IsReadOnly);
        Assert.Equal(new FileFacts { IsReparsePoint = true }, Facts(tagged));
    }

    [Fact]
    public void Reads_where_a_handle_leads_and_the_owner_and_access_list_of_its_item()
    {
        var folder = _tree.Folder("folder");
        var junction = _tree.PathOf("junction");
        Links.CreateJunction(junction, folder);

        using (var throughLink = Native.Open(junction, Native.FileReadAttributes, asLink: false))
        {
            Assert.Equal(folder, FileHandles.ReadFinalPath(throughLink));
        }

        using var handle = Native.Open(folder, Native.FileReadAttributes | 0x0002_0000, asLink: true);
        var security = FileHandles.ReadSecurity(handle);
        var ownerOnly = FileHandles.ReadSecurity(handle, ownerOnly: true);

        Assert.Equal(folder, FileHandles.ReadFinalPath(handle));
        Assert.Equal(Elevation.IsElevated ? security.Owner : Elevation.CurrentUser, security.Owner);
        Assert.Equal([Sid.LocalSystem, Sid.Administrators, Elevation.CurrentUser], security.Dacl!.Select(e => e.Trustee));
        Assert.All(security.Dacl!, e => Assert.Equal((AccessEntryType.Allow, FullControl), (e.Type, e.Mask)));
        Assert.Equal(security.Owner, ownerOnly.Owner);
        Assert.Null(ownerOnly.Dacl);
    }

    [Fact]
    public void Describes_a_Win32_error_in_Windows_words()
    {
        var e = FileHandles.Failure("Could not open X", 5);

        Assert.Equal("Could not open X: Access is denied (Win32 error 5).", e.Message);
    }

    private static FileFacts Facts(string path)
    {
        using var handle = Native.Open(path, Native.FileReadAttributes, asLink: true);
        return FileHandles.ReadFacts(handle);
    }

    private static byte[] Bytes(string sddl) => Bytes(new RawSecurityDescriptor(sddl));

    private static byte[] Bytes(RawSecurityDescriptor descriptor)
    {
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }
}
