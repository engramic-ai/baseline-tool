using System.Security.AccessControl;
using System.Security.Principal;

namespace Engramic.Baseline.Testing.Windows;

/// <summary>
/// Reads and sets the owner and access list of a test's own files and folders, by path: what a test checks
/// SecureStore made, or what an administrator or attacker could have done to an item.
/// </summary>
public static class Acls
{
    /// <summary>Gets the owner of a file or folder, as a security identifier.</summary>
    /// <param name="path">The item.</param>
    /// <returns>Such as S-1-5-32-544.</returns>
    public static string Owner(string path) => Security(path).GetOwner(typeof(SecurityIdentifier))!.Value;

    /// <summary>Gets whether the access list of a file or folder is protected from inheritance.</summary>
    /// <param name="path">The item.</param>
    /// <returns>True when nothing is inherited from its parent.</returns>
    public static bool IsProtected(string path) => Security(path).AreAccessRulesProtected;

    /// <summary>
    /// Gets the entries of the access list of a file or folder as text, in order: allow or deny, the account,
    /// the rights in hexadecimal, and whether it is inherited and what it reaches.
    /// </summary>
    /// <param name="path">The item.</param>
    /// <returns>Such as "Allow S-1-5-18 0x1F01FF ContainerInherit, ObjectInherit".</returns>
    public static string[] Entries(string path)
    {
        return [.. Security(path)
            .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Select(r => $"{r.AccessControlType} {r.IdentityReference.Value} 0x{(int)r.FileSystemRights:X} {r.InheritanceFlags}{(r.IsInherited ? " inherited" : string.Empty)}")];
    }

    /// <summary>Replaces the access list of a file or folder, leaving its owner.</summary>
    /// <param name="path">The item.</param>
    /// <param name="dacl">The access list in SDDL, such as D:P(A;OICI;FA;;;SY).</param>
    public static void Reset(string path, string dacl)
    {
        if (Directory.Exists(path))
        {
            var security = new DirectorySecurity();
            security.SetSecurityDescriptorSddlForm(dacl, AccessControlSections.Access);
            new DirectoryInfo(path).SetAccessControl(security);
        }
        else
        {
            var security = new FileSecurity();
            security.SetSecurityDescriptorSddlForm(dacl, AccessControlSections.Access);
            new FileInfo(path).SetAccessControl(security);
        }
    }

    private static FileSystemSecurity Security(string path)
    {
        return Directory.Exists(path)
            ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
            : new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
    }
}
