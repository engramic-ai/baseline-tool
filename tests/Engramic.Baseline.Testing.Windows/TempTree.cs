using System.Security.AccessControl;
using System.Text;

namespace Engramic.Baseline.Testing.Windows;

/// <summary>
/// A folder of a test's own under the temp folder, with a unique name, deleted with everything in it by
/// that exact path when the test ends. Links in it are deleted as links, never followed.
/// </summary>
/// <remarks>
/// The folder is born with SYSTEM, Administrators and the account running the tests in full control, and
/// no access inherited from the temp folder, so what a test builds does not depend on the machine. Its
/// path is kept as Windows spells it in full: a temp folder given with short names (such as RUNNER~1 in
/// CI) would not match the final paths SecureStore compares.
/// </remarks>
public sealed class TempTree : IDisposable
{
    /// <summary>The access list of the tree: SYSTEM, Administrators and the account running the tests, inherited.</summary>
    public static readonly string TreeAccess = $"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{Elevation.CurrentUser})";

    private readonly string _created;

    /// <summary>Makes the folder.</summary>
    public TempTree()
    {
        _created = Path.Combine(Path.GetTempPath(), "baseline-test-" + Guid.NewGuid().ToString("n"));
        Create(_created, TreeAccess);
        Root = Links.FinalPath(_created);
    }

    /// <summary>Gets the full path of the folder, with long names.</summary>
    public string Root { get; }

    /// <summary>Gets the full path of something in the tree.</summary>
    /// <param name="relative">Its path from the root.</param>
    /// <returns>The full path.</returns>
    public string PathOf(string relative) => Path.Combine(Root, relative);

    /// <summary>Makes a folder in the tree, optionally with a security descriptor of its own from its birth.</summary>
    /// <param name="relative">Its path from the root; its parent must exist.</param>
    /// <param name="sddl">The security descriptor in SDDL, or null to inherit the tree's access.</param>
    /// <returns>The full path.</returns>
    public string Folder(string relative, string? sddl = null)
    {
        var path = PathOf(relative);
        Create(path, sddl);
        return path;
    }

    /// <summary>Writes a file in the tree.</summary>
    /// <param name="relative">Its path from the root.</param>
    /// <param name="text">What it holds, in UTF-8.</param>
    /// <returns>The full path.</returns>
    public string File(string relative, string text = "")
    {
        var path = PathOf(relative);
        System.IO.File.WriteAllText(path, text);
        return path;
    }

    /// <summary>
    /// Writes a new file in the tree with a security descriptor of its own from its birth, as an installer or
    /// an administrator's deployment makes one: with only an owner, it takes the access list its folder gives.
    /// </summary>
    /// <param name="relative">Its path from the root; nothing may be there yet.</param>
    /// <param name="text">What it holds, in UTF-8.</param>
    /// <param name="sddl">The security descriptor in SDDL, such as O:BA.</param>
    /// <returns>The full path.</returns>
    public string File(string relative, string text, string sddl)
    {
        var path = PathOf(relative);
        var security = new FileSecurity();
        security.SetSecurityDescriptorSddlForm(sddl);
        using (var stream = new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.Write | FileSystemRights.Read, FileShare.None, 4096, FileOptions.None, security))
        {
            stream.Write(Encoding.UTF8.GetBytes(text));
        }

        return path;
    }

    /// <summary>Deletes the folder and everything in it, by the exact path it was made with.</summary>
    public void Dispose()
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                Remove(_created);
                return;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException && attempt < 20)
            {
                // An antivirus scan or the search indexer may still hold a file that was just written.
                Thread.Sleep(50 * attempt);
            }
        }
    }

    private static void Create(string path, string? sddl)
    {
        if (sddl is null)
        {
            Directory.CreateDirectory(path);
            return;
        }

        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm(sddl);
        new DirectoryInfo(path).Create(security);
    }

    /// <summary>Removes what is at a path: a link as a link, a folder with what is in it, a file even if read-only.</summary>
    private static void Remove(string path)
    {
        FileAttributes attributes;
        try
        {
            attributes = System.IO.File.GetAttributes(path);
        }
        catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException)
        {
            return;
        }

        var isFolder = (attributes & FileAttributes.Directory) != 0;
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            if (isFolder)
            {
                Directory.Delete(path, recursive: false);
            }
            else
            {
                System.IO.File.Delete(path);
            }

            return;
        }

        if (isFolder)
        {
            foreach (var entry in Directory.GetFileSystemEntries(path))
            {
                Remove(entry);
            }

            Directory.Delete(path, recursive: false);
            return;
        }

        if ((attributes & FileAttributes.ReadOnly) != 0)
        {
            System.IO.File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly);
        }

        System.IO.File.Delete(path);
    }
}
