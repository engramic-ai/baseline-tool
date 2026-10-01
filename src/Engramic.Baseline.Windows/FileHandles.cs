using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Engramic.Baseline.Platform;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.Security.Authorization;
using Windows.Win32.Storage.FileSystem;

namespace Engramic.Baseline.Windows;

/// <summary>
/// Reads what a handle tells about the file or folder it is open on: its attributes, its names, its
/// final path, its owner and its access list. Nothing is read by path, so what is described is the item
/// the handle is open on, even when that item is a link.
/// </summary>
internal static class FileHandles
{
    /// <summary>
    /// The attributes of a file stored online only: FILE_ATTRIBUTE_OFFLINE, RECALL_ON_OPEN and
    /// RECALL_ON_DATA_ACCESS, the PowerShell tool's 0x441000.
    /// </summary>
    private const uint OnlineOnlyAttributes = 0x0000_1000 | 0x0004_0000 | 0x0040_0000;

    /// <summary>The prefix Windows puts on a final path on a drive with a letter.</summary>
    private const string LocalPrefix = @"\\?\";

    /// <summary>The SE_SELF_RELATIVE bit of a security descriptor's control flags.</summary>
    private const ushort SelfRelative = 0x8000;

    /// <summary>Reads the attributes and the number of names of the item a handle is open on.</summary>
    /// <param name="handle">A handle with FILE_READ_ATTRIBUTES.</param>
    /// <returns>What the handle tells.</returns>
    /// <exception cref="IOException">Windows could not say.</exception>
    public static FileFacts ReadFacts(SafeFileHandle handle)
    {
        var tag = default(FILE_ATTRIBUTE_TAG_INFO);
        if (!PInvoke.GetFileInformationByHandleEx(handle, FILE_INFO_BY_HANDLE_CLASS.FileAttributeTagInfo, MemoryMarshal.AsBytes(new Span<FILE_ATTRIBUTE_TAG_INFO>(ref tag))))
        {
            throw Failure("Could not read the attributes", Marshal.GetLastPInvokeError());
        }

        var standard = default(FILE_STANDARD_INFO);
        if (!PInvoke.GetFileInformationByHandleEx(handle, FILE_INFO_BY_HANDLE_CLASS.FileStandardInfo, MemoryMarshal.AsBytes(new Span<FILE_STANDARD_INFO>(ref standard))))
        {
            throw Failure("Could not read the number of names", Marshal.GetLastPInvokeError());
        }

        var attributes = tag.FileAttributes;
        return new FileFacts
        {
            IsDirectory = (attributes & (uint)FILE_FLAGS_AND_ATTRIBUTES.FILE_ATTRIBUTE_DIRECTORY) != 0,
            IsReparsePoint = (attributes & (uint)FILE_FLAGS_AND_ATTRIBUTES.FILE_ATTRIBUTE_REPARSE_POINT) != 0,
            IsOnlineOnly = (attributes & OnlineOnlyAttributes) != 0,
            LinkCount = standard.NumberOfLinks,
            IsReadOnly = (attributes & (uint)FILE_FLAGS_AND_ATTRIBUTES.FILE_ATTRIBUTE_READONLY) != 0,
            Length = standard.EndOfFile,
        };
    }

    /// <summary>Reads the attributes of the item a handle is open on, as stored.</summary>
    /// <param name="handle">A handle with FILE_READ_ATTRIBUTES.</param>
    /// <returns>The FILE_ATTRIBUTE_* flags.</returns>
    /// <exception cref="IOException">Windows could not say.</exception>
    public static uint ReadAttributes(SafeFileHandle handle)
    {
        var tag = default(FILE_ATTRIBUTE_TAG_INFO);
        if (!PInvoke.GetFileInformationByHandleEx(handle, FILE_INFO_BY_HANDLE_CLASS.FileAttributeTagInfo, MemoryMarshal.AsBytes(new Span<FILE_ATTRIBUTE_TAG_INFO>(ref tag))))
        {
            throw Failure("Could not read the attributes", Marshal.GetLastPInvokeError());
        }

        return tag.FileAttributes;
    }

    /// <summary>
    /// Lists the names in a folder through a handle open on it, never by its path, so what is listed is the
    /// folder the handle holds. The entries . and .. are left out.
    /// </summary>
    /// <param name="folder">A handle on a folder, with FILE_LIST_DIRECTORY, opened for synchronous input and output.</param>
    /// <returns>The names, in the order the file system gives them.</returns>
    /// <exception cref="IOException">Windows could not list it.</exception>
    public static unsafe List<string> ListNames(SafeFileHandle folder)
    {
        const int NoMoreFiles = 18;
        var names = new List<string>();

        // The entries hold 64-bit fields, so the buffer is aligned to 8 bytes, as an array of longs is.
        var buffer = new long[8 * 1024];
        var bytes = MemoryMarshal.AsBytes(buffer.AsSpan());
        var infoClass = FILE_INFO_BY_HANDLE_CLASS.FileFullDirectoryRestartInfo;
        while (PInvoke.GetFileInformationByHandleEx(folder, infoClass, bytes))
        {
            infoClass = FILE_INFO_BY_HANDLE_CLASS.FileFullDirectoryInfo;
            fixed (byte* start = bytes)
            {
                for (var offset = 0; ;)
                {
                    var entry = (FILE_FULL_DIR_INFO*)(start + offset);
                    var name = entry->FileName.AsSpan((int)(entry->FileNameLength / sizeof(char))).ToString();
                    if (name is not ("." or ".."))
                    {
                        names.Add(name);
                    }

                    if (entry->NextEntryOffset == 0)
                    {
                        break;
                    }

                    offset += (int)entry->NextEntryOffset;
                }
            }
        }

        var error = Marshal.GetLastPInvokeError();
        return error == NoMoreFiles ? names : throw Failure("Could not list the folder", error);
    }

    /// <summary>
    /// Reads the final path of the item a handle is open on, as Windows resolves it: every link on the
    /// way followed, every name spelled as on disk.
    /// </summary>
    /// <param name="handle">A handle on a file or folder.</param>
    /// <returns>The path, such as C:\ProgramData, or null when it is not on a drive with a letter.</returns>
    /// <exception cref="IOException">Windows could not say.</exception>
    public static string? ReadFinalPath(SafeFileHandle handle)
    {
        const GETFINALPATHNAMEBYHANDLE_FLAGS Flags = GETFINALPATHNAMEBYHANDLE_FLAGS.FILE_NAME_NORMALIZED | GETFINALPATHNAMEBYHANDLE_FLAGS.VOLUME_NAME_DOS;
        Span<char> buffer = stackalloc char[512];
        var length = PInvoke.GetFinalPathNameByHandle(handle, buffer, Flags);
        if (length >= buffer.Length)
        {
            // Too small: the length is the size needed, with the terminating null.
            buffer = new char[length];
            length = PInvoke.GetFinalPathNameByHandle(handle, buffer, Flags);
        }

        if (length == 0 || length >= buffer.Length)
        {
            throw Failure("Could not read the final path", Marshal.GetLastPInvokeError());
        }

        return ToLocalPath(buffer[..(int)length]);
    }

    /// <summary>Reads the owner and, unless only the owner is wanted, the access list of the item a handle is open on.</summary>
    /// <param name="handle">A handle with READ_CONTROL.</param>
    /// <param name="ownerOnly">True to read the owner alone; the access list is then null.</param>
    /// <returns>The owner and the access list.</returns>
    /// <exception cref="IOException">Windows could not say, or gave a security descriptor that could not be read.</exception>
    public static unsafe ItemSecurity ReadSecurity(SafeFileHandle handle, bool ownerOnly = false)
    {
        var sections = OBJECT_SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION;
        if (!ownerOnly)
        {
            sections |= OBJECT_SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;
        }

        var error = PInvoke.GetSecurityInfo(handle, SE_OBJECT_TYPE.SE_FILE_OBJECT, sections, out _, out _, out _, out _, out var descriptor);
        if (error != WIN32_ERROR.NO_ERROR)
        {
            throw Failure("Could not read the owner and permissions", (int)error);
        }

        try
        {
            var length = PInvoke.GetSecurityDescriptorLength(descriptor);
            return ToItemSecurity(new ReadOnlySpan<byte>(descriptor.Value, checked((int)length)));
        }
        finally
        {
            _ = PInvoke.LocalFree(new HLOCAL(descriptor.Value));
        }
    }

    /// <summary>
    /// Reads the owner and the access list of a security descriptor in self-relative form. Allowed and
    /// denied entries, object and conditional ones included, keep their account and mask; every other
    /// kind of entry is <see cref="AccessEntryType.Other"/>, which no trust decision accepts.
    /// </summary>
    /// <param name="selfRelative">The security descriptor.</param>
    /// <returns>The owner and the access list; the list is null when the descriptor has none.</returns>
    /// <exception cref="IOException">The bytes are not a security descriptor in self-relative form.</exception>
    public static ItemSecurity ToItemSecurity(ReadOnlySpan<byte> selfRelative)
    {
        // The header: revision, a reserved byte, then the control flags.
        if (selfRelative.Length < 20 || (BinaryPrimitives.ReadUInt16LittleEndian(selfRelative[2..]) & SelfRelative) == 0)
        {
            throw new IOException("Windows gave a security descriptor that is not in self-relative form.");
        }

        RawSecurityDescriptor descriptor;
        try
        {
            descriptor = new RawSecurityDescriptor(selfRelative.ToArray(), 0);
        }
        catch (Exception e) when (e is ArgumentException or OverflowException)
        {
            throw new IOException("Windows gave a security descriptor that could not be read: " + e.Message, e);
        }

        var dacl = (descriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) != 0 && descriptor.DiscretionaryAcl is { } acl
            ? acl.Cast<GenericAce>().Select(ToEntry).ToArray()
            : null;
        return new ItemSecurity(ToSid(descriptor.Owner), dacl);
    }

    /// <summary>
    /// Turns a final path into the path it names: \\?\C:\ProgramData becomes C:\ProgramData. A path on a
    /// network share or a volume with no letter is null.
    /// </summary>
    /// <param name="finalPath">A path as GetFinalPathNameByHandleW gives it.</param>
    /// <returns>The path, or null.</returns>
    public static string? ToLocalPath(ReadOnlySpan<char> finalPath)
    {
        if (!finalPath.StartsWith(LocalPrefix, StringComparison.Ordinal))
        {
            return null;
        }

        var path = finalPath[LocalPrefix.Length..];
        return path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\' ? path.ToString() : null;
    }

    /// <summary>
    /// Tells whether a path is a full path on a drive with a letter, spelled plainly: a drive, then names
    /// that are not empty, . or .., hold no character Windows forbids in a name, and do not end in a dot or
    /// a space (which Windows would drop). No \\?\ or \\.\ prefix, no network share, no stream name.
    /// </summary>
    /// <param name="path">The path.</param>
    /// <returns>True when it is.</returns>
    public static bool IsPlainLocalPath(string? path)
    {
        if (path is null || path.Length < 4 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\')
        {
            return false;
        }

        foreach (var name in path[3..].Split('\\'))
        {
            if (name.Length == 0 || name is "." or ".." || name[^1] is '.' or ' ' || name.Any(c => c < ' ' || "\"*/:<>?\\|".Contains(c, StringComparison.Ordinal)))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>An error from a Win32 call, with Windows' own description of it.</summary>
    /// <param name="what">What could not be done.</param>
    /// <param name="error">The Win32 error code.</param>
    /// <returns>The exception to throw.</returns>
    public static IOException Failure(string what, int error)
    {
        return new IOException($"{what}: {Marshal.GetPInvokeErrorMessage(error).TrimEnd('.', ' ', '\r', '\n')} (Win32 error {error}).");
    }

    private static AccessEntry ToEntry(GenericAce ace)
    {
        return ace switch
        {
            CommonAce common => new AccessEntry(TypeOf(common.AceQualifier), ToSid(common.SecurityIdentifier), unchecked((uint)common.AccessMask)),
            ObjectAce entry => new AccessEntry(TypeOf(entry.AceQualifier), ToSid(entry.SecurityIdentifier), unchecked((uint)entry.AccessMask)),
            _ => new AccessEntry(AccessEntryType.Other, null, 0),
        };
    }

    private static AccessEntryType TypeOf(AceQualifier qualifier) => qualifier switch
    {
        AceQualifier.AccessAllowed => AccessEntryType.Allow,
        AceQualifier.AccessDenied => AccessEntryType.Deny,
        _ => AccessEntryType.Other,
    };

    private static Sid? ToSid(SecurityIdentifier? sid) => sid is not null && Sid.TryParse(sid.Value, out var parsed) ? parsed : null;
}
