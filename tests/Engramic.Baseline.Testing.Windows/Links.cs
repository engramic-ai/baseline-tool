using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Engramic.Baseline.Testing.Windows;

/// <summary>
/// Makes the links an attacker could plant: junctions and hard links, which a standard user can make,
/// symbolic links, which need a privilege, and a reparse point of another kind on a file.
/// </summary>
public static class Links
{
    private const uint MountPointTag = 0xA000_0003;

    /// <summary>A tag of no Microsoft reparse point, which any user may put on a file they can write.</summary>
    private const uint ThirdPartyTag = 0x0000_1234;

    /// <summary>Makes a junction (a mount point) at <paramref name="link"/> that leads to the folder <paramref name="target"/>.</summary>
    /// <param name="link">Where the junction goes; nothing may be there yet.</param>
    /// <param name="target">The full path of the folder it leads to, which need not exist.</param>
    public static void CreateJunction(string link, string target)
    {
        Directory.CreateDirectory(link);
        var substitute = @"\??\" + target;
        var names = Encoding.Unicode.GetBytes(substitute + "\0" + target + "\0");
        var buffer = new byte[16 + names.Length];
        BitConverter.TryWriteBytes(buffer.AsSpan(0), MountPointTag);
        BitConverter.TryWriteBytes(buffer.AsSpan(4), (ushort)(8 + names.Length));
        BitConverter.TryWriteBytes(buffer.AsSpan(8), (ushort)0);
        BitConverter.TryWriteBytes(buffer.AsSpan(10), (ushort)(substitute.Length * 2));
        BitConverter.TryWriteBytes(buffer.AsSpan(12), (ushort)((substitute.Length + 1) * 2));
        BitConverter.TryWriteBytes(buffer.AsSpan(14), (ushort)(target.Length * 2));
        names.CopyTo(buffer, 16);
        using var folder = Native.Open(link, Native.FileWriteData | Native.FileWriteAttributes, asLink: true);
        Native.SetReparsePoint(folder, buffer);
    }

    /// <summary>Makes another name for an existing file.</summary>
    /// <param name="link">The new name.</param>
    /// <param name="existing">The file.</param>
    public static void CreateHardLink(string link, string existing)
    {
        if (!Native.CreateHardLink(link, existing, IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Could not link {link} to {existing}");
        }
    }

    /// <summary>
    /// Tries to make a symbolic link to a file, which needs the privilege elevated administrators hold, or
    /// developer mode.
    /// </summary>
    /// <param name="link">Where the link goes.</param>
    /// <param name="target">The file it leads to.</param>
    /// <returns>False when this account may not make one.</returns>
    public static bool TryCreateFileSymbolicLink(string link, string target)
    {
        try
        {
            File.CreateSymbolicLink(link, target);
            return true;
        }
        catch (IOException) when (!File.Exists(link))
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Tries to make a symbolic link to a folder, which needs the privilege elevated administrators hold, or
    /// developer mode.
    /// </summary>
    /// <param name="link">Where the link goes.</param>
    /// <param name="target">The folder it leads to.</param>
    /// <returns>False when this account may not make one.</returns>
    public static bool TryCreateFolderSymbolicLink(string link, string target)
    {
        try
        {
            Directory.CreateSymbolicLink(link, target);
            return true;
        }
        catch (IOException) when (!Directory.Exists(link))
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Makes an existing file a reparse point of a kind no filter handles, as a third-party product might:
    /// opened normally it fails, and only opening it as itself works.
    /// </summary>
    /// <param name="file">The file, which this account can write.</param>
    public static void MakeThirdPartyReparsePoint(string file)
    {
        var buffer = new byte[8 + 16 + 4];
        BitConverter.TryWriteBytes(buffer.AsSpan(0), ThirdPartyTag);
        BitConverter.TryWriteBytes(buffer.AsSpan(4), (ushort)4);
        Guid.NewGuid().TryWriteBytes(buffer.AsSpan(8));
        using var handle = Native.Open(file, Native.FileWriteData | Native.FileWriteAttributes, asLink: true);
        Native.SetReparsePoint(handle, buffer);
    }

    /// <summary>Gets how many names a file has.</summary>
    /// <param name="file">The file, followed if it is a link.</param>
    /// <returns>The number of hard links.</returns>
    public static uint LinkCount(string file)
    {
        using var handle = Native.Open(file, Native.FileReadAttributes, asLink: false);
        return Native.LinkCount(handle);
    }

    /// <summary>Gets where a path leads, every link followed, with long names, as SecureStore compares it.</summary>
    /// <param name="path">A file or folder.</param>
    /// <returns>The final path, without the \\?\ prefix.</returns>
    public static string FinalPath(string path)
    {
        using var handle = Native.Open(path, Native.FileReadAttributes, asLink: false);
        return Native.FinalPath(handle);
    }
}
