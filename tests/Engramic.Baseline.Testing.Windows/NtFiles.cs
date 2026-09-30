using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Engramic.Baseline.Testing.Windows;

/// <summary>
/// Raw calls to the file system's native layer, for the tests that record what Windows itself does with a
/// name opened relative to a folder's handle, and with renames through a handle: the facts SecureStore's
/// way of walking paths rests on (docs/DOTNET.md, spike 1). Every call gives Windows' own status.
/// </summary>
public static unsafe partial class NtFiles
{
    public const uint Success = 0;
    public const uint AccessDenied = 0xC000_0022;
    public const uint InvalidParameter = 0xC000_000D;
    public const uint ObjectNameInvalid = 0xC000_0033;
    public const uint ObjectNameNotFound = 0xC000_0034;
    public const uint ObjectNameCollision = 0xC000_0035;
    public const uint ReparsePointEncountered = 0xC000_050B;

    /// <summary>OBJ_DONT_REPARSE: fail on any reparse point met while the name is parsed.</summary>
    public const uint DontReparse = 0x0000_1000;

    public const uint ListDirectory = 0x0000_0001;
    public const uint ReadAttributes = 0x0000_0080;
    public const uint Delete = 0x0001_0000;
    public const uint ReadControl = 0x0002_0000;
    public const uint Synchronize = 0x0010_0000;

    public const uint ShareAll = 0x0000_0007;
    public const uint ShareReadWrite = 0x0000_0003;

    public const uint OpenIt = 1;
    public const uint CreateIt = 2;

    public const uint DirectoryFile = 0x0000_0001;
    public const uint SynchronousIo = 0x0000_0020;
    public const uint OpenReparsePoint = 0x0020_0000;

    private const uint CaseInsensitive = 0x0000_0040;
    private const int FileRenameInformation = 10;
    private const int FileRenameInfo = 3;

    /// <summary>Opens or creates a name relative to a folder's handle, or an absolute NT path when there is no folder.</summary>
    /// <param name="folder">The folder the name is in, or null for an absolute path such as \??\C:\x.</param>
    /// <param name="name">The name, which may hold more than one part.</param>
    /// <param name="access">The rights to ask for.</param>
    /// <param name="share">What others may do meanwhile.</param>
    /// <param name="disposition"><see cref="OpenIt"/> or <see cref="CreateIt"/>.</param>
    /// <param name="options">Create options, such as <see cref="OpenReparsePoint"/>.</param>
    /// <param name="attributes">Object attributes beside case-insensitivity, such as <see cref="DontReparse"/>.</param>
    /// <param name="handle">The handle, when it was opened.</param>
    /// <returns>The NTSTATUS.</returns>
    public static uint Open(SafeFileHandle? folder, string name, uint access, uint share, uint disposition, uint options, uint attributes, out SafeFileHandle? handle)
    {
        handle = null;
        fixed (char* characters = name)
        {
            var objectName = new UnicodeString { Length = (ushort)(name.Length * 2), MaximumLength = (ushort)(name.Length * 2), Buffer = characters };
            var objectAttributes = new ObjectAttributes
            {
                Length = sizeof(ObjectAttributes),
                RootDirectory = folder?.DangerousGetHandle() ?? IntPtr.Zero,
                ObjectName = &objectName,
                Attributes = CaseInsensitive | attributes,
            };
            IoStatusBlock io;
            IntPtr opened;
            var status = NtCreateFile(&opened, access, &objectAttributes, &io, null, 0x80, share, disposition, options, null, 0);
            GC.KeepAlive(folder);
            if (status == Success)
            {
                handle = new SafeFileHandle(opened, ownsHandle: true);
            }

            return status;
        }
    }

    /// <summary>Renames an open item through its handle, relative to a folder's handle, as the native layer allows.</summary>
    /// <param name="item">The item, opened with DELETE.</param>
    /// <param name="folder">The folder the new name is in.</param>
    /// <param name="name">The new name.</param>
    /// <returns>The NTSTATUS.</returns>
    public static uint Rename(SafeFileHandle item, SafeFileHandle folder, string name)
    {
        var buffer = RenameInformation(folder.DangerousGetHandle(), name);
        fixed (byte* information = buffer)
        {
            IoStatusBlock io;
            var status = NtSetInformationFile(item, &io, information, (uint)buffer.Length, FileRenameInformation);
            GC.KeepAlive(folder);
            return status;
        }
    }

    /// <summary>Tries the same rename through the Win32 call, which reads the name against the current directory.</summary>
    /// <param name="item">The item, opened with DELETE.</param>
    /// <param name="folder">The folder the new name is in.</param>
    /// <param name="name">The new name.</param>
    /// <returns>0 when it renamed, otherwise the Win32 error.</returns>
    public static int Win32Rename(SafeFileHandle item, SafeFileHandle folder, string name)
    {
        var buffer = RenameInformation(folder.DangerousGetHandle(), name);
        fixed (byte* information = buffer)
        {
            var renamed = SetFileInformationByHandle(item, FileRenameInfo, information, (uint)buffer.Length);
            GC.KeepAlive(folder);
            return renamed ? 0 : Marshal.GetLastPInvokeError();
        }
    }

    /// <summary>Renames by path, as any program would.</summary>
    /// <param name="from">The item.</param>
    /// <param name="to">Its new path.</param>
    /// <returns>0 when it renamed, otherwise the Win32 error.</returns>
    public static int MoveByPath(string from, string to) => MoveFileEx(from, to, 0) ? 0 : Marshal.GetLastPInvokeError();

    private static byte[] RenameInformation(IntPtr folder, string name)
    {
        // FILE_RENAME_INFORMATION on 64-bit: the flags, padding, the folder's handle, the name's length in bytes, the name.
        var buffer = new byte[24 + (name.Length * 2)];
        BitConverter.TryWriteBytes(buffer.AsSpan(8), (long)folder);
        BitConverter.TryWriteBytes(buffer.AsSpan(16), name.Length * 2);
        Encoding.Unicode.GetBytes(name).CopyTo(buffer, 20);
        return buffer;
    }

    [LibraryImport("ntdll.dll")]
    private static partial uint NtCreateFile(IntPtr* handle, uint access, ObjectAttributes* attributes, IoStatusBlock* io, long* allocationSize, uint fileAttributes, uint share, uint disposition, uint options, void* ea, uint eaLength);

    [LibraryImport("ntdll.dll")]
    private static partial uint NtSetInformationFile(SafeFileHandle file, IoStatusBlock* io, void* information, uint length, int informationClass);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetFileInformationByHandle(SafeFileHandle file, int informationClass, void* information, uint length);

    [LibraryImport("kernel32.dll", EntryPoint = "MoveFileExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool MoveFileEx(string from, string to, uint flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public char* Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public UnicodeString* ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public IntPtr Information;
    }
}
