using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Engramic.Baseline.Testing.Windows;

/// <summary>The Win32 calls the fixtures need to make links and read handles, and to open a handle in a test.</summary>
public static unsafe partial class Native
{
    public const uint FileReadAttributes = 0x0000_0080;
    public const uint FileWriteData = 0x0000_0002;
    public const uint FileWriteAttributes = 0x0000_0100;
    public const uint ShareAll = 0x0000_0007;
    public const uint OpenExisting = 3;
    public const uint BackupSemantics = 0x0200_0000;
    public const uint OpenReparsePoint = 0x0020_0000;
    private const uint FsctlSetReparsePoint = 0x0009_00A4;

    /// <summary>Opens a file or folder with every kind of sharing: as itself when it is a link, or through it.</summary>
    public static SafeFileHandle Open(string path, uint access, bool asLink)
    {
        var handle = CreateFile(path, access, ShareAll, IntPtr.Zero, OpenExisting, BackupSemantics | (asLink ? OpenReparsePoint : 0), IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new Win32Exception(error, $"Could not open {path}");
        }

        return handle;
    }

    public static void SetReparsePoint(SafeFileHandle handle, ReadOnlySpan<byte> buffer)
    {
        fixed (byte* input = buffer)
        {
            uint returned;
            if (!DeviceIoControl(handle, FsctlSetReparsePoint, input, (uint)buffer.Length, null, 0, &returned, null))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not set the reparse point");
            }
        }
    }

    public static string FinalPath(SafeFileHandle handle)
    {
        var buffer = new char[1024];
        fixed (char* start = buffer)
        {
            var length = GetFinalPathNameByHandle(handle, start, (uint)buffer.Length, 0);
            if (length == 0 || length >= buffer.Length)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not read the final path");
            }

            var path = new string(buffer, 0, (int)length);
            return path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;
        }
    }

    public static uint LinkCount(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not read the file's information");
        }

        return information.NumberOfLinks;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateHardLinkW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CreateHardLink(string link, string existing, IntPtr security);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeviceIoControl(SafeFileHandle device, uint code, byte* input, uint inputLength, void* output, uint outputLength, uint* returned, void* overlapped);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true)]
    private static partial uint GetFinalPathNameByHandle(SafeFileHandle file, char* path, uint length, uint flags);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        // FILETIME is two DWORDs, aligned to 4 bytes, not a ulong.
        public uint FileAttributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint LastAccessTimeLow;
        public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow;
        public uint LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}
