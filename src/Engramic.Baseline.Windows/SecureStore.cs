using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Engramic.Baseline.Platform;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.Storage.FileSystem;
using Windows.Win32.UI.Shell;

namespace Engramic.Baseline.Windows;

/// <summary>
/// SecureStore: the machine data folder, %ProgramData%\EngramicBaseline, checked through handles and held
/// open while in use. The only code that opens, creates, renames or deletes a file for the product.
/// </summary>
/// <remarks>
/// <para>
/// Opening it checks, without ever following a link: that ProgramData (from the known-folder API, and on
/// the drive Windows is installed on) is a real folder with a trusted owner; and that the data folder in it
/// is a real folder that the install sealed when it made it locked, and is still trusted
/// (<see cref="DataFolderTrust"/>). Anything else is refused with the reason. Nothing is created, repaired
/// or moved aside.
/// </para>
/// <para>
/// Each folder is opened by its path with FILE_FLAG_OPEN_REPARSE_POINT, so a link is opened as itself and
/// seen, then Windows is asked for the final path of the handle, which must be the path that was opened:
/// no component on the way was a link. Both handles are held without FILE_SHARE_DELETE, and with a right
/// the sharing check counts (list), so neither folder can be renamed, replaced or deleted while the store
/// is open, and their paths keep naming the folders that were checked.
/// </para>
/// <para>
/// A file is written by creating a new one under a random name, exclusively (CREATE_NEW, no sharing, and
/// OPEN_REPARSE_POINT so that a link already at the name is a collision, not followed), owned by
/// Administrators and taking the folder's access list; checking it through its handle; writing and
/// flushing it; and renaming it over the target through its handle. The rename replaces the target's name
/// and never writes into or through it; a target that is a link, a folder, read-only or has other names
/// (hard links) is refused first. The rename is given the target's full path, since a relative name would
/// be read against the current directory; the held folders keep that path pointing into the data folder,
/// and the file's final path is checked afterwards. A write that fails deletes its new file by handle.
/// </para>
/// <para>Not safe to use from more than one thread at a time.</para>
/// </remarks>
public sealed class SecureStore : ISecureStore
{
    /// <summary>The name of the data folder in ProgramData.</summary>
    public const string DataFolderName = "EngramicBaseline";

    private const uint FileListDirectory = 0x0000_0001;
    private const uint FileTraverse = 0x0000_0020;
    private const uint FileReadAttributes = 0x0000_0080;
    private const uint Delete = 0x0001_0000;
    private const uint ReadControl = 0x0002_0000;
    private const uint Synchronize = 0x0010_0000;
    private const uint GenericWrite = 0x4000_0000;

    /// <summary>How long to wait before each further attempt to replace a file another process has open.</summary>
    private static readonly TimeSpan[] RenameDelays =
    [
        TimeSpan.FromMilliseconds(100),
        TimeSpan.FromMilliseconds(200),
        TimeSpan.FromMilliseconds(400),
        TimeSpan.FromMilliseconds(800),
        TimeSpan.FromMilliseconds(1600),
    ];

    private readonly SafeFileHandle _programData;
    private readonly SafeFileHandle _root;
    private readonly DataFolderTrust _trust;
    private readonly byte[]? _newFileDescriptor;
    private readonly TimeProvider _time;
    private readonly SecureStoreHooks? _hooks;
    private bool _disposed;

    private SecureStore(SafeFileHandle programData, SafeFileHandle root, string rootPath, DataFolderTrust trust, byte[]? newFileDescriptor, TimeProvider time, SecureStoreHooks? hooks)
    {
        _programData = programData;
        _root = root;
        RootPath = rootPath;
        _trust = trust;
        _newFileDescriptor = newFileDescriptor;
        _time = time;
        _hooks = hooks;
    }

    /// <inheritdoc/>
    public string RootPath { get; }

    /// <summary>Opens the data folder and checks it, holding it and ProgramData open until disposed.</summary>
    /// <param name="options">Where the folder and its seal are, and the clock.</param>
    /// <returns>The store.</returns>
    /// <exception cref="SecureStoreException">
    /// ProgramData or the data folder is missing, cannot be opened, is a link, is not what its path names, is
    /// not sealed or is not trusted; the message says which.
    /// </exception>
    public static SecureStore Open(SecureStoreOptions options) => Open(options, DataFolderTrust.Machine, Sid.Administrators, hooks: null);

    /// <inheritdoc/>
    public void WriteFile(string name, ReadOnlySpan<byte> content)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ThrowIfNotPlainFileName(name);
        var target = RootPath + @"\" + name;
        try
        {
            CheckReplaceable(target);
            var temporary = RootPath + @"\" + TemporaryName(name);
            using var file = CreateExclusive(temporary);
            var written = false;
            try
            {
                ExpectFinalPath(file, temporary);
                Refuse(_trust.FindNewFileProblem(temporary, FileHandles.ReadFacts(file), FileHandles.ReadSecurity(file)));
                RandomAccess.Write(file, content, fileOffset: 0);
                if (!PInvoke.FlushFileBuffers(file))
                {
                    throw FileHandles.Failure($"Could not flush {temporary} to disk", Marshal.GetLastPInvokeError());
                }

                RenameOver(file, target);
                ExpectFinalPath(file, target);
                written = true;
            }
            finally
            {
                if (!written)
                {
                    DeleteByHandle(file);
                }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException && e is not SecureStoreException)
        {
            throw new SecureStoreException($"Could not write {target}: {e.Message}", e);
        }
    }

    /// <summary>Closes the handles on the data folder and ProgramData.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _root.Dispose();
        _programData.Dispose();
    }

    /// <summary>
    /// Opens the data folder with the trust rules, the owner of new files and the hooks a test gives.
    /// </summary>
    /// <param name="options">Where the folder and its seal are, and the clock.</param>
    /// <param name="trust">The trust rules: <see cref="DataFolderTrust.Machine"/> for the product.</param>
    /// <param name="newFileOwner">
    /// The owner new files are created with: Administrators for the product, which SYSTEM and an elevated
    /// administrator may name. Null takes the process's default owner, for a test that is not elevated.
    /// </param>
    /// <param name="hooks">Where a test steps in; null for the product.</param>
    /// <returns>The store.</returns>
    internal static SecureStore Open(SecureStoreOptions options, DataFolderTrust trust, Sid? newFileOwner, SecureStoreHooks? hooks)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(trust);
        var programDataPath = options.ProgramDataPath;
        if (!FileHandles.IsPlainLocalPath(programDataPath))
        {
            throw new SecureStoreException($"{programDataPath} is not a full path on a drive with a letter, so it is not used as the ProgramData folder.");
        }

        SafeFileHandle? programData = null;
        SafeFileHandle? root = null;
        try
        {
            programData = OpenFolder(programDataPath, "The ProgramData folder");
            ExpectFinalPath(programData, programDataPath);
            Refuse(trust.FindProgramDataProblem(programDataPath, FileHandles.ReadFacts(programData), FileHandles.ReadSecurity(programData, ownerOnly: true).Owner));

            var rootPath = programDataPath + @"\" + DataFolderName;
            root = OpenFolder(rootPath, "The data folder");
            var finalRootPath = ExpectFinalPath(root, rootPath);
            Refuse(trust.FindDataFolderProblem(rootPath, FileHandles.ReadFacts(root), FileHandles.ReadSecurity(root), IsSealed(options)));

            var store = new SecureStore(programData, root, finalRootPath, trust, NewFileDescriptor(newFileOwner), options.Time, hooks);
            programData = null;
            root = null;
            return store;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException && e is not SecureStoreException)
        {
            throw new SecureStoreException($"Could not check the data folder in {programDataPath}: {e.Message}", e);
        }
        finally
        {
            root?.Dispose();
            programData?.Dispose();
        }
    }

    /// <summary>
    /// Finds the ProgramData folder with the known-folder API, and checks it is ProgramData on the drive
    /// Windows is installed on (<see cref="CheckProgramData"/>).
    /// </summary>
    /// <returns>The path, such as C:\ProgramData.</returns>
    /// <exception cref="SecureStoreException">Windows gave no path, or another one.</exception>
    internal static unsafe string FindProgramData()
    {
        string knownFolder;
#pragma warning disable RS0030 // SecureStore: asks the known-folder API for ProgramData, whose answer follows %SystemDrive%, then checks it against the Windows drive
        var result = PInvoke.SHGetKnownFolderPath(PInvoke.FOLDERID_ProgramData, KNOWN_FOLDER_FLAG.KF_FLAG_DONT_VERIFY, null, out var path);
#pragma warning restore RS0030
        try
        {
            if (result.Failed)
            {
                throw new SecureStoreException($"Windows did not say where the ProgramData folder is (HRESULT 0x{result.Value:X8}).");
            }

            knownFolder = path.ToString();
        }
        finally
        {
            PInvoke.CoTaskMemFree(path.Value);
        }

        Span<char> buffer = stackalloc char[261];
        var length = PInvoke.GetSystemWindowsDirectory(buffer);
        if (length == 0 || length >= buffer.Length)
        {
            throw new SecureStoreException("Windows did not say which folder it is installed in, so where ProgramData should be is not known.");
        }

        return CheckProgramData(knownFolder, buffer[..(int)length].ToString());
    }

    /// <summary>
    /// Checks the ProgramData folder the known-folder API gave against the folder Windows is installed in,
    /// which comes from the kernel rather than the environment. The API builds ProgramData as
    /// %SystemDrive%\ProgramData from this process's environment, which whoever started the process sets,
    /// so it must be ProgramData on the Windows drive. A ProgramData folder moved elsewhere is not supported.
    /// </summary>
    /// <param name="knownFolder">What the known-folder API gave, such as C:\ProgramData.</param>
    /// <param name="windowsDirectory">The folder Windows is installed in, such as C:\WINDOWS.</param>
    /// <returns>The ProgramData folder, spelled as the API gave it.</returns>
    /// <exception cref="SecureStoreException">They do not agree.</exception>
    internal static string CheckProgramData(string knownFolder, string windowsDirectory)
    {
        ArgumentNullException.ThrowIfNull(knownFolder);
        ArgumentNullException.ThrowIfNull(windowsDirectory);
        if (windowsDirectory.Length < 3 || !char.IsAsciiLetter(windowsDirectory[0]) || windowsDirectory[1] != ':' || windowsDirectory[2] != '\\')
        {
            throw new SecureStoreException($"Windows is installed in {windowsDirectory}, which is not on a drive with a letter, so where ProgramData should be is not known.");
        }

        var expected = string.Concat(windowsDirectory.AsSpan(0, 2), @"\ProgramData");
        return string.Equals(knownFolder, expected, StringComparison.OrdinalIgnoreCase)
            ? knownFolder
            : throw new SecureStoreException(
                $"Windows gives the ProgramData folder as {knownFolder}, not {expected} on the drive Windows is installed on. It builds that path from the SystemDrive environment variable, which whoever started this process can change, so it is not used. A ProgramData folder moved elsewhere is not supported.");
    }

    /// <summary>
    /// Refuses a file name that is not plain: letters, digits, dots, hyphens and underscores only, starting
    /// with a letter or digit, not ending in a dot, and not a device name such as NUL.
    /// </summary>
    /// <param name="name">The name.</param>
    internal static void ThrowIfNotPlainFileName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        var plain = name.Length is > 0 and <= 128
            && char.IsAsciiLetterOrDigit(name[0])
            && name[^1] != '.'
            && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_')
            && !IsDeviceName(name.Split('.')[0]);
        if (!plain)
        {
            throw new ArgumentException($"'{name}' is not a plain file name: use letters, digits, dots, hyphens and underscores, as in status.json.", nameof(name));
        }
    }

    private static bool IsDeviceName(string stem)
    {
        return stem.ToUpperInvariant() switch
        {
            "CON" or "PRN" or "AUX" or "NUL" or "CLOCK$" => true,
            var s when s.Length == 4 && (s.StartsWith("COM", StringComparison.Ordinal) || s.StartsWith("LPT", StringComparison.Ordinal)) && char.IsAsciiDigit(s[3]) => true,
            _ => false,
        };
    }

    /// <summary>
    /// Opens a folder as itself, never through a link at its own name, and so that it cannot be renamed,
    /// replaced or deleted while the handle is held.
    /// </summary>
    private static SafeFileHandle OpenFolder(string path, string what)
    {
#pragma warning disable RS0030 // SecureStore: opens a folder as itself (OPEN_REPARSE_POINT) and without FILE_SHARE_DELETE, so it cannot be renamed or deleted while held
        var folder = PInvoke.CreateFile(
            path,
            FileListDirectory | FileTraverse | FileReadAttributes | ReadControl | Synchronize,
            FILE_SHARE_MODE.FILE_SHARE_READ | FILE_SHARE_MODE.FILE_SHARE_WRITE,
            null,
            FILE_CREATION_DISPOSITION.OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES.FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAGS_AND_ATTRIBUTES.FILE_FLAG_OPEN_REPARSE_POINT,
            null);
#pragma warning restore RS0030
        var error = Marshal.GetLastPInvokeError();
        if (!folder.IsInvalid)
        {
            return folder;
        }

        folder.Dispose();
        throw (WIN32_ERROR)error switch
        {
            WIN32_ERROR.ERROR_FILE_NOT_FOUND or WIN32_ERROR.ERROR_PATH_NOT_FOUND =>
                new SecureStoreException($"{what} {path} does not exist. The fleet install creates the data folder locked; this tool does not create it."),
            WIN32_ERROR.ERROR_ACCESS_DENIED =>
                new SecureStoreException($"{what} {path} cannot be opened by this account (access is denied). The data folder is for SYSTEM and administrators."),
            WIN32_ERROR.ERROR_SHARING_VIOLATION =>
                new SecureStoreException($"{what} {path} is open in another process that may rename or delete it, so it cannot be held."),
            _ => new SecureStoreException(FileHandles.Failure($"Could not open {what.ToLowerInvariant()} {path}", error).Message),
        };
    }

    /// <summary>Checks that a handle's final path is the path it was opened by, and gives Windows' spelling of it.</summary>
    private static string ExpectFinalPath(SafeFileHandle handle, string expected)
    {
        var final = FileHandles.ReadFinalPath(handle);
        return final is not null && string.Equals(final, expected, StringComparison.OrdinalIgnoreCase)
            ? final
            : throw new SecureStoreException($"{expected} leads to {final ?? "a place that is not on a drive with a letter"}, so a folder on the way is a link or was replaced.");
    }

    private static bool IsSealed(SecureStoreOptions options)
    {
        RegistryValue? seal;
        try
        {
            seal = options.Registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, options.SealKeyPath, options.SealValueName);
        }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException)
        {
            throw new SecureStoreException($@"The seal of the data folder, HKEY_LOCAL_MACHINE\{options.SealKeyPath}\{options.SealValueName}, could not be read: {e.Message}", e);
        }

        return seal is { Kind: RegistryValueKind.Text, Text.Length: > 0 };
    }

    /// <summary>
    /// The security descriptor new files are created with: the owner alone, so that the access list comes
    /// from the data folder. Null when there is no owner to name.
    /// </summary>
    private static byte[]? NewFileDescriptor(Sid? owner)
    {
        if (owner is null)
        {
            return null;
        }

        var descriptor = new RawSecurityDescriptor(ControlFlags.None, new SecurityIdentifier(owner.Value), null, null, null);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }

    private static void Refuse(string? problem)
    {
        if (problem is not null)
        {
            throw new SecureStoreException(problem);
        }
    }

    private static bool IsTransient(int error) => (WIN32_ERROR)error is WIN32_ERROR.ERROR_ACCESS_DENIED or WIN32_ERROR.ERROR_SHARING_VIOLATION or WIN32_ERROR.ERROR_LOCK_VIOLATION;

    /// <summary>
    /// Checks what is at the target's name, opened as itself: nothing, or an ordinary file with one name that
    /// may be replaced.
    /// </summary>
    private static void CheckReplaceable(string target)
    {
#pragma warning disable RS0030 // SecureStore: opens what is at the target's name as itself (OPEN_REPARSE_POINT), to read its attributes, never its content
        using var existing = PInvoke.CreateFile(
            target,
            FileReadAttributes | Synchronize,
            FILE_SHARE_MODE.FILE_SHARE_READ | FILE_SHARE_MODE.FILE_SHARE_WRITE | FILE_SHARE_MODE.FILE_SHARE_DELETE,
            null,
            FILE_CREATION_DISPOSITION.OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES.FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAGS_AND_ATTRIBUTES.FILE_FLAG_OPEN_REPARSE_POINT,
            null);
#pragma warning restore RS0030
        var error = Marshal.GetLastPInvokeError();
        if (existing.IsInvalid)
        {
            if ((WIN32_ERROR)error == WIN32_ERROR.ERROR_FILE_NOT_FOUND)
            {
                return;
            }

            throw FileHandles.Failure($"Could not check {target} before replacing it", error);
        }

        ExpectFinalPath(existing, target);
        Refuse(DataFolderTrust.FindReplaceProblem(target, FileHandles.ReadFacts(existing)));
    }

    /// <summary>
    /// The name of a new file: the target's, a random part no one can guess, and .tmp, as the PowerShell tool
    /// names its own (status.json.&lt;id&gt;.tmp).
    /// </summary>
    private string TemporaryName(string name)
    {
        if (_hooks?.TemporaryName is { } chosen)
        {
            var planted = chosen(name);
            ThrowIfNotPlainFileName(planted);
            return planted;
        }

        return $"{name}.{RandomNumberGenerator.GetHexString(32, lowercase: true)}.tmp";
    }

    /// <summary>Creates a new file exclusively, owned as this store names, taking the data folder's access list.</summary>
    private unsafe SafeFileHandle CreateExclusive(string path)
    {
        SafeFileHandle file;
        int error;
        fixed (byte* descriptor = _newFileDescriptor)
        {
            SECURITY_ATTRIBUTES? attributes = descriptor is null
                ? null
                : new SECURITY_ATTRIBUTES { nLength = (uint)sizeof(SECURITY_ATTRIBUTES), lpSecurityDescriptor = descriptor };
#pragma warning disable RS0030 // SecureStore: creates a new file exclusively (CREATE_NEW, no sharing) in the held data folder; OPEN_REPARSE_POINT makes a link at the name a collision, never followed
            file = PInvoke.CreateFile(
                path,
                GenericWrite | Delete | ReadControl | FileReadAttributes | Synchronize,
                FILE_SHARE_MODE.FILE_SHARE_NONE,
                attributes,
                FILE_CREATION_DISPOSITION.CREATE_NEW,
                FILE_FLAGS_AND_ATTRIBUTES.FILE_ATTRIBUTE_NORMAL | FILE_FLAGS_AND_ATTRIBUTES.FILE_FLAG_OPEN_REPARSE_POINT,
                null);
#pragma warning restore RS0030
            error = Marshal.GetLastPInvokeError();
        }

        if (file.IsInvalid)
        {
            file.Dispose();
            throw FileHandles.Failure($"Could not create {path}", error);
        }

        return file;
    }

    /// <summary>
    /// Renames the new file over the target through its handle, replacing the target's name. Tries again a few
    /// times while another process, such as a reader or an antivirus scan, has the target open.
    /// </summary>
    private void RenameOver(SafeFileHandle file, string target)
    {
        var information = RenameInformation(target);
        for (var attempt = 1; ; attempt++)
        {
            _hooks?.BeforeRename?.Invoke(target, attempt);
#pragma warning disable RS0030 // SecureStore: renames its own new file, by its handle, over the target's full path in the held data folder; the target's name is replaced, never written through
            var renamed = PInvoke.SetFileInformationByHandle(file, FILE_INFO_BY_HANDLE_CLASS.FileRenameInfo, information);
#pragma warning restore RS0030
            if (renamed)
            {
                return;
            }

            var error = Marshal.GetLastPInvokeError();
            if (attempt > RenameDelays.Length || !IsTransient(error))
            {
                throw FileHandles.Failure($"Could not replace {target} (it may be open in another process)", error);
            }

            Pause(RenameDelays[attempt - 1]);
        }
    }

    /// <summary>FILE_RENAME_INFO for a full path, replacing what is there.</summary>
    private static unsafe byte[] RenameInformation(string target)
    {
        // Room for the name and a terminating null, which the zeroed buffer holds.
        var buffer = new byte[FILE_RENAME_INFO.SizeOf(target.Length + 1)];
        fixed (byte* start = buffer)
        {
            var information = (FILE_RENAME_INFO*)start;
            information->ReplaceIfExists = new BOOLEAN(true);
            information->RootDirectory = default;
            information->FileNameLength = (uint)(target.Length * sizeof(char));
            target.AsSpan().CopyTo(information->FileName.AsSpan(target.Length));
        }

        return buffer;
    }

    /// <summary>Deletes a file this store created, through its handle, so a failed write leaves nothing behind.</summary>
    private static void DeleteByHandle(SafeFileHandle file)
    {
        var disposition = new FILE_DISPOSITION_INFO { DeleteFile = new BOOLEAN(true) };
#pragma warning disable RS0030 // SecureStore: deletes its own new file through its handle, never by path
        _ = PInvoke.SetFileInformationByHandle(file, FILE_INFO_BY_HANDLE_CLASS.FileDispositionInfo, MemoryMarshal.AsBytes(new ReadOnlySpan<FILE_DISPOSITION_INFO>(in disposition)));
#pragma warning restore RS0030
    }

    private void Pause(TimeSpan delay)
    {
        using var elapsed = new ManualResetEventSlim();
        using var timer = _time.CreateTimer(static state => ((ManualResetEventSlim)state!).Set(), elapsed, delay, Timeout.InfiniteTimeSpan);
        elapsed.Wait();
    }
}
