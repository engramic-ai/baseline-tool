using System.Globalization;
using System.Security.AccessControl;
using System.Text;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows;

/// <summary>
/// Whom SecureStore trusts, and the security descriptors it gives what it creates: for the product
/// (<see cref="Machine"/>), or for a test that is not elevated and so cannot name Administrators as an
/// owner.
/// </summary>
/// <param name="Trust">The trust rules every item is judged by.</param>
/// <param name="Owner">
/// The owner of each folder and file created: Administrators for the product, which SYSTEM and an elevated
/// administrator may name. Null takes the process's default owner, for a test that is not elevated.
/// </param>
/// <param name="FullControl">
/// The accounts a new folder's access list grants full control, and nothing else: SYSTEM and Administrators
/// for the product. The list is protected from inheritance, so nothing of the parent's reaches it.
/// </param>
internal sealed record SecureStoreRules(DataFolderTrust Trust, Sid? Owner, IReadOnlyList<Sid> FullControl)
{
    /// <summary>
    /// Gets the product's: the machine trust rules, and folders born owned by Administrators with SYSTEM and
    /// Administrators in full control, as the installer's New-CEDataDirectorySecurity makes them.
    /// </summary>
    public static SecureStoreRules Machine { get; } = new(DataFolderTrust.Machine, Sid.Administrators, [Sid.LocalSystem, Sid.Administrators]);

    /// <summary>
    /// The security descriptor of a new folder, in SDDL: the owner, and a protected access list granting each
    /// of <see cref="FullControl"/> full control, inherited by what is made in it; with Users' read and execute
    /// too for a folder standard users may read (config).
    /// </summary>
    /// <param name="usersMayRead">Whether standard users may read it.</param>
    /// <returns>Such as O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA), with the accounts written as identifiers.</returns>
    public string FolderSddl(bool usersMayRead)
    {
        var sddl = new StringBuilder();
        if (Owner is not null)
        {
            sddl.Append("O:").Append(Owner.Value);
        }

        sddl.Append("D:P");
        foreach (var account in FullControl)
        {
            sddl.Append(CultureInfo.InvariantCulture, $"(A;OICI;FA;;;{account.Value})");
        }

        if (usersMayRead)
        {
            sddl.Append(CultureInfo.InvariantCulture, $"(A;OICI;0x1200a9;;;{Sid.Users.Value})");
        }

        return sddl.ToString();
    }

    /// <summary>The security descriptor of a new folder, in self-relative form (<see cref="FolderSddl"/>).</summary>
    /// <param name="usersMayRead">Whether standard users may read it.</param>
    /// <returns>The bytes.</returns>
    public byte[] FolderDescriptor(bool usersMayRead) => ToBytes(new RawSecurityDescriptor(FolderSddl(usersMayRead)));

    /// <summary>
    /// The security descriptor of a new file: the owner alone, so that the access list comes from the folder.
    /// Null when there is no owner to name.
    /// </summary>
    /// <returns>The bytes, or null.</returns>
    public byte[]? FileDescriptor() => Owner is null ? null : ToBytes(new RawSecurityDescriptor("O:" + Owner.Value));

    private static byte[] ToBytes(RawSecurityDescriptor descriptor)
    {
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }
}
