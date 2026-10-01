using System.Security.AccessControl;

namespace Engramic.Baseline.Testing.Windows;

/// <summary>
/// Everything under a folder, as text that changes when anything in it is created, moved, renamed, deleted,
/// re-owned, given other permissions or written: so a test can show that code which promises to change nothing
/// changed nothing, name for name and byte for byte. Links are listed as themselves, never followed.
/// </summary>
public static class TreeSnapshot
{
    /// <summary>Takes the snapshot.</summary>
    /// <param name="folder">The folder; it is not listed itself.</param>
    /// <returns>
    /// One line per item, in order: its path from the folder, its attributes, its owner and access list in SDDL,
    /// and a file's bytes in hexadecimal; a link's target is not read.
    /// </returns>
    public static string[] Of(string folder)
    {
        var lines = new List<string>();
        Walk(folder, string.Empty, lines);
        return [.. lines];
    }

    private static void Walk(string folder, string relative, List<string> lines)
    {
        string[] entries;
        try
        {
            entries = [.. Directory.GetFileSystemEntries(folder).Order(StringComparer.Ordinal)];
        }
        catch (UnauthorizedAccessException)
        {
            lines.Add($"{relative}\\* cannot be listed");
            return;
        }

        foreach (var path in entries)
        {
            var name = Path.Combine(relative, Path.GetFileName(path));
            var attributes = File.GetAttributes(path);
            var isLink = (attributes & FileAttributes.ReparsePoint) != 0;
            var isFolder = (attributes & FileAttributes.Directory) != 0;
            lines.Add($"{name} | {attributes} | {(isLink ? "link" : Security(path, isFolder))} | {(isLink || isFolder ? "-" : Content(path))}");
            if (isFolder && !isLink)
            {
                Walk(path, name, lines);
            }
        }
    }

    private static string Security(string path, bool isFolder)
    {
        try
        {
            FileSystemSecurity security = isFolder
                ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
                : new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            return security.GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
        }
        catch (UnauthorizedAccessException)
        {
            return "security cannot be read";
        }
    }

    private static string Content(string path)
    {
        try
        {
            return Convert.ToHexString(File.ReadAllBytes(path));
        }
        catch (UnauthorizedAccessException)
        {
            return "cannot be read";
        }
    }
}
