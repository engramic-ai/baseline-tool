using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Engramic.Baseline.Platform;
using Microsoft.Win32.SafeHandles;
using Windows.Wdk.Foundation;
using Windows.Wdk.Storage.FileSystem;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.Storage.FileSystem;
using Windows.Win32.UI.Shell;
using NtDll = Windows.Wdk.PInvoke;

namespace Engramic.Baseline.Windows;

/// <summary>
/// SecureStore: the machine data folder, %ProgramData%\EngramicBaseline, and the folders the tool keeps in
/// it, checked through handles and held open while in use. The only code that opens, creates, renames or
/// deletes a file or folder for the product.
/// </summary>
/// <remarks>
/// <para>
/// ProgramData (from the known-folder API, and on the drive Windows is installed on) is the one folder
/// opened by its path: as itself, never through a link at its own name, and its final path must be the
/// path that was opened, so no folder on the way is a link. Everything below it is opened one name at a
/// time, relative to the handle of the folder it is in, and as itself: no path is parsed, so no link on the
/// way can be followed, and a link at the name is opened as the link. Folders are held without
/// FILE_SHARE_DELETE, so they cannot be renamed or replaced while held and the paths the store gives keep
/// naming them; each held folder's final path is checked too.
/// </para>
/// <para>
/// <see cref="Open(SecureStoreOptions)"/> checks a data folder the install made: sealed and trusted
/// (<see cref="DataFolderTrust"/>), or refused. <see cref="Initialize(SecureStoreOptions)"/>, for the
/// install and SYSTEM, makes it: a sealed, trusted data folder is kept; anything else there is moved aside,
/// out of the data folder and by its handle (<see cref="DataFolderLayout.AsideName"/>), event 1003 names
/// where it went, and a fresh folder is made locked from birth, its owner and protected access list set in
/// the call that creates it. The folders kept in it (<see cref="DataFolderLayout.KeptFolderNames"/>) are
/// made the same way, and so is one that <see cref="Open(SecureStoreOptions)"/> needs later. A link is
/// deleted as a link. Nothing untrusted is listed, re-owned or repaired: a handle a user opened while they
/// could change an item keeps that access after any later lock.
/// </para>
/// <para>
/// A file is written by creating a new one under a random name, exclusively (a link already at the name is
/// a collision, never followed), owned by Administrators and taking the folder's access list; checking it
/// through its handle; writing and flushing it; and renaming it over the target through its handle. The
/// rename replaces the target's name and never writes into or through it; a target that is a link, a
/// folder, read-only or has other names (hard links) is refused first. A write that fails deletes its new
/// file by handle. A file is read through its handle, and only when the tool may trust it.
/// </para>
/// <para>Not safe to use from more than one thread at a time.</para>
/// </remarks>
public sealed class SecureStore : ISecureStore
{
    /// <summary>The name of the data folder in ProgramData.</summary>
    public const string DataFolderName = "EngramicBaseline";

    /// <summary>The most bytes <see cref="ReadFile"/> reads from one file: 64 MiB.</summary>
    public const int MaxReadLength = 64 * 1024 * 1024;

    /// <summary>How many folders deep a tree delete goes; a folder deeper than this is left in place.</summary>
    internal const int MaxTreeDepth = 64;

    private const uint FileReadData = 0x0000_0001;
    private const uint FileListDirectory = 0x0000_0001;
    private const uint FileReadEa = 0x0000_0008;
    private const uint FileTraverse = 0x0000_0020;
    private const uint FileReadAttributes = 0x0000_0080;
    private const uint FileWriteAttributes = 0x0000_0100;
    private const uint Delete = 0x0001_0000;
    private const uint ReadControl = 0x0002_0000;
    private const uint Synchronize = 0x0010_0000;
    private const uint GenericWrite = 0x4000_0000;

    /// <summary>What a held folder is opened with: to list it, pass through it, and read its attributes and security.</summary>
    private const uint FolderRights = FileListDirectory | FileTraverse | FileReadAttributes | ReadControl | Synchronize;

    /// <summary>What a file is read with.</summary>
    private const uint ReadRights = FileReadData | FileReadEa | FileReadAttributes | ReadControl | Synchronize;

    /// <summary>What a tree delete opens each item with: to judge and list a folder, and to delete anything.</summary>
    private const uint TreeRights = FolderRights | Delete | FileWriteAttributes;

    /// <summary>
    /// The least that moving an item aside or deleting it needs, which the folder it is in grants whatever
    /// its own access list says: DELETE through the folder's FILE_DELETE_CHILD, and FILE_READ_ATTRIBUTES
    /// through its FILE_LIST_DIRECTORY. No SYNCHRONIZE, which only the item's own list can grant, so the
    /// handle is not for synchronous input and output.
    /// </summary>
    private const uint RemoveRights = Delete | FileReadAttributes;

    private const FILE_SHARE_MODE ShareNone = FILE_SHARE_MODE.FILE_SHARE_NONE;
    private const FILE_SHARE_MODE ShareRead = FILE_SHARE_MODE.FILE_SHARE_READ;
    private const FILE_SHARE_MODE ShareReadWrite = FILE_SHARE_MODE.FILE_SHARE_READ | FILE_SHARE_MODE.FILE_SHARE_WRITE;
    private const FILE_SHARE_MODE ShareAll = ShareReadWrite | FILE_SHARE_MODE.FILE_SHARE_DELETE;

    private const NTCREATEFILE_CREATE_OPTIONS Synchronous = NTCREATEFILE_CREATE_OPTIONS.FILE_SYNCHRONOUS_IO_NONALERT;
    private const NTCREATEFILE_CREATE_OPTIONS Asynchronous = 0;

    /// <summary>
    /// Opens without waiting for another process to give up an oplock it holds on the item, which it may never
    /// do: the open that would wait comes back at once, and is tried again like one refused for sharing.
    /// </summary>
    private const NTCREATEFILE_CREATE_OPTIONS NoOplockWait = NTCREATEFILE_CREATE_OPTIONS.FILE_COMPLETE_IF_OPLOCKED;

    /// <summary>STATUS_OPLOCK_BREAK_IN_PROGRESS: the open succeeded without waiting, while another holder's oplock is being broken.</summary>
    private const int OplockBreakInProgress = 0x0000_0108;

    /// <summary>How many times an operation that another process can hold up is tried.</summary>
    private const int Attempts = 6;

    /// <summary>How long to wait before each further attempt: about three seconds in all.</summary>
    private static readonly TimeSpan[] RetryDelays =
    [
        TimeSpan.FromMilliseconds(100),
        TimeSpan.FromMilliseconds(200),
        TimeSpan.FromMilliseconds(400),
        TimeSpan.FromMilliseconds(800),
        TimeSpan.FromMilliseconds(1600),
    ];

    private readonly SafeFileHandle _programData;
    private readonly string _programDataPath;
    private readonly SecureStoreRules _rules;
    private readonly IEventLog _events;
    private readonly TimeProvider _time;
    private readonly SecureStoreHooks? _hooks;
    private readonly Dictionary<string, HeldFolder> _kept = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _notices = [];
    private HeldFolder? _root;
    private bool _disposed;

    private SecureStore(SafeFileHandle programData, string programDataPath, SecureStoreRules rules, SecureStoreOptions options, SecureStoreHooks? hooks)
    {
        _programData = programData;
        _programDataPath = programDataPath;
        _rules = rules;
        _events = options.EventLog;
        _time = options.Time;
        _hooks = hooks;
    }

    /// <inheritdoc/>
    public string RootPath => Root.Path;

    /// <inheritdoc/>
    public IReadOnlyList<string> Notices => _notices.AsReadOnly();

    private HeldFolder Root => _root ?? throw new InvalidOperationException("The data folder is not open.");

    /// <summary>Opens the data folder the install made and checks it, holding it and ProgramData open until disposed.</summary>
    /// <param name="options">Where the folder and its seal are, the event log and the clock.</param>
    /// <returns>The store.</returns>
    /// <exception cref="SecureStoreException">
    /// ProgramData or the data folder is missing, cannot be opened, is a link, is not what its path names, is
    /// not sealed or is not trusted; the message says which. Nothing is created or moved.
    /// </exception>
    public static SecureStore Open(SecureStoreOptions options) => Open(options, SecureStoreRules.Machine, hooks: null);

    /// <summary>
    /// Makes the data folder and each folder kept in it, locked from birth, keeping a sealed, trusted data
    /// folder and each trusted folder in it, and moving anything else aside with event 1003: the install's
    /// and SYSTEM's way in. Holds the folders and ProgramData open until disposed.
    /// </summary>
    /// <param name="options">Where the folder and its seal are, the event log and the clock.</param>
    /// <returns>The store; <see cref="Notices"/> says what was moved aside or removed.</returns>
    /// <remarks>
    /// Run it only as SYSTEM or an elevated administrator, which may name Administrators as the owner, and
    /// with the audit mutex held, as the installer does. A data folder it makes is not sealed: the install
    /// records the seal afterwards, as the installer does, so that <see cref="Open(SecureStoreOptions)"/>
    /// accepts it.
    /// </remarks>
    /// <exception cref="SecureStoreException">
    /// ProgramData cannot be trusted, the seal cannot be read, or a folder cannot be made or an untrusted
    /// item moved aside, such as while another process holds it open; the message says which.
    /// </exception>
    public static SecureStore Initialize(SecureStoreOptions options) => Initialize(options, SecureStoreRules.Machine, hooks: null);

    /// <inheritdoc/>
    public void WriteFile(string name, ReadOnlySpan<byte> content) => WriteFile(DataFolder.Root, name, content);

    /// <inheritdoc/>
    public void WriteFile(DataFolder folder, string name, ReadOnlySpan<byte> content)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ThrowIfNotPlainFileName(name);
        Write(FolderFor(folder, create: true)!, name, content);
    }

    /// <inheritdoc/>
    public byte[]? ReadFile(DataFolder folder, string name, int maxLength)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ThrowIfNotPlainFileName(name);
        ThrowIfNotReadLength(maxLength);
        HeldFolder? held;
        try
        {
            held = FolderFor(folder, create: false);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // The folder could not be opened and checked, or its untrusted namesake moved aside, so nothing in it
            // was judged: what the file holds is not known.
            throw new SecureStoreException($"Could not read {name}: {e.Message}", isUnavailable: true, e);
        }

        return held is null ? null : Read(held, name, maxLength);
    }

    /// <inheritdoc/>
    public IScratchFolder CreateScratchFolder()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var scratch = Kept(DataFolderLayout.ScratchFolderName, create: true)!;
        for (var attempt = 1; attempt <= Attempts; attempt++)
        {
            var name = NewId();
            if (TryCreateFolder(scratch.Handle, name, scratch.PathOf(name), usersMayRead: false, FolderRights | Delete, out var error) is { } created)
            {
                return new ScratchFolder(this, created);
            }

            if ((WIN32_ERROR)error != WIN32_ERROR.ERROR_ALREADY_EXISTS)
            {
                throw new SecureStoreException(FileHandles.Failure($"Could not create a scratch folder in {scratch.Path}", error).Message);
            }
        }

        throw new SecureStoreException($"Could not create a scratch folder in {scratch.Path}: every name tried was taken.");
    }

    /// <inheritdoc/>
    public IReadOnlyList<string> DeleteTree(DataFolder folder, string name)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ThrowIfNotPlainFileName(name);
        if (folder == DataFolder.Root && DataFolderLayout.KeptFolderNames.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"{name} is a folder the store keeps, so it is not deleted.", nameof(name));
        }

        var left = new List<string>();
        if (FolderFor(folder, create: false) is { } held)
        {
            _ = DeleteEntry(held.Handle, name, held.PathOf(name), depth: 1, left);
        }

        return left;
    }

    /// <summary>Closes the handles on the folders the store holds and on ProgramData.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (var folder in _kept.Values)
        {
            folder.Dispose();
        }

        _root?.Dispose();
        _programData.Dispose();
    }

    /// <summary>
    /// Opens the data folder with the rules and the hooks a test gives: checked, never created or moved.
    /// </summary>
    /// <param name="options">Where the folder and its seal are, the event log and the clock.</param>
    /// <param name="rules">The trust rules and the owner of what is created: <see cref="SecureStoreRules.Machine"/> for the product.</param>
    /// <param name="hooks">Where a test steps in; null for the product.</param>
    /// <returns>The store.</returns>
    internal static SecureStore Open(SecureStoreOptions options, SecureStoreRules rules, SecureStoreHooks? hooks) => Start(options, rules, hooks, initialize: false);

    /// <summary>Makes the data folder and the folders kept in it with the rules and the hooks a test gives.</summary>
    /// <param name="options">Where the folder and its seal are, the event log and the clock.</param>
    /// <param name="rules">The trust rules and the owner of what is created: <see cref="SecureStoreRules.Machine"/> for the product.</param>
    /// <param name="hooks">Where a test steps in; null for the product.</param>
    /// <returns>The store.</returns>
    internal static SecureStore Initialize(SecureStoreOptions options, SecureStoreRules rules, SecureStoreHooks? hooks) => Start(options, rules, hooks, initialize: true);

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

    private static void ThrowIfNotReadLength(int maxLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxLength, MaxReadLength);
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

    private static SecureStore Start(SecureStoreOptions options, SecureStoreRules rules, SecureStoreHooks? hooks, bool initialize)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(options.EventLog);
        var programDataPath = options.ProgramDataPath;
        if (!FileHandles.IsPlainLocalPath(programDataPath))
        {
            throw new SecureStoreException($"{programDataPath} is not a full path on a drive with a letter, so it is not used as the ProgramData folder.");
        }

        SecureStore? store = null;
        try
        {
            var programData = OpenByPath(programDataPath, "The ProgramData folder");
            store = new SecureStore(programData, programDataPath, rules, options, hooks);
            ExpectFinalPath(programData, programDataPath);
            Refuse(rules.Trust.FindProgramDataProblem(programDataPath, FileHandles.ReadFacts(programData), FileHandles.ReadSecurity(programData, ownerOnly: true).Owner));
            if (initialize)
            {
                store.EstablishRoot(IsSealed(options));
                foreach (var name in DataFolderLayout.KeptFolderNames)
                {
                    _ = store.Kept(name, create: true);
                }
            }
            else
            {
                store.OpenRoot(options);
            }

            var started = store;
            store = null;
            return started;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException && e is not SecureStoreException)
        {
            throw new SecureStoreException($"Could not {(initialize ? "set up" : "check")} the data folder in {programDataPath}: {e.Message}", e);
        }
        finally
        {
            store?.Dispose();
        }
    }

    /// <summary>
    /// Opens a folder by its path as itself, never through a link at its own name, and so that it cannot be
    /// renamed, replaced or deleted while the handle is held: ProgramData, the one folder opened by path.
    /// </summary>
    private static SafeFileHandle OpenByPath(string path, string what)
    {
#pragma warning disable RS0030 // SecureStore: opens ProgramData by path as itself (OPEN_REPARSE_POINT) and without FILE_SHARE_DELETE, so it cannot be renamed or deleted while held; its final path is checked next
        var folder = PInvoke.CreateFile(
            path,
            FolderRights,
            ShareReadWrite,
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
        throw OpenFailure(what, path, error);
    }

    /// <summary>Why a folder that must exist could not be opened, as a sentence that names it.</summary>
    private static SecureStoreException OpenFailure(string what, string path, int error)
    {
        return (WIN32_ERROR)error switch
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

    /// <summary>Holds a folder that was opened as itself under its path, as Windows spells it.</summary>
    private static HeldFolder Hold(SafeFileHandle handle, string path)
    {
        try
        {
            return new HeldFolder(handle, ExpectFinalPath(handle, path));
        }
        catch
        {
            handle.Dispose();
            throw;
        }
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

    private static void Refuse(string? problem)
    {
        if (problem is not null)
        {
            throw new SecureStoreException(problem);
        }
    }

    private static bool IsTransient(int error) => (WIN32_ERROR)error is WIN32_ERROR.ERROR_ACCESS_DENIED or WIN32_ERROR.ERROR_SHARING_VIOLATION or WIN32_ERROR.ERROR_LOCK_VIOLATION or WIN32_ERROR.ERROR_OPLOCK_BREAK_IN_PROGRESS;

    private static bool IsMissing(int error) => (WIN32_ERROR)error is WIN32_ERROR.ERROR_FILE_NOT_FOUND or WIN32_ERROR.ERROR_PATH_NOT_FOUND;

    private static string Unreadable(string path) => $"{path} cannot be read by this account (access is denied), so who may change it cannot be judged.";

    /// <summary>
    /// Opens or creates the item of one plain name in a folder, relative to the folder's handle and as itself:
    /// no path is parsed, a link at the name is opened as the link, and nothing stored online is recalled.
    /// </summary>
    /// <returns>
    /// 0 when <paramref name="item"/> was opened; otherwise the Win32 error. With <see cref="NoOplockWait"/>, an
    /// open that got in while another process's oplock was still being broken is closed again and gives
    /// ERROR_OPLOCK_BREAK_IN_PROGRESS: reading or waiting on it could wait for that process for as long as it likes.
    /// </returns>
    private static unsafe int OpenRelative(SafeFileHandle folder, string name, uint access, FILE_SHARE_MODE share, NTCREATEFILE_CREATE_DISPOSITION disposition, NTCREATEFILE_CREATE_OPTIONS options, byte[]? descriptor, out SafeFileHandle? item)
    {
        item = null;
        var added = false;
        try
        {
            folder.DangerousAddRef(ref added);
            fixed (char* characters = name)
            fixed (byte* security = descriptor)
            {
                var length = checked((ushort)(name.Length * sizeof(char)));
                var objectName = new UNICODE_STRING { Length = length, MaximumLength = length, Buffer = new PWSTR(characters) };
                var attributes = new OBJECT_ATTRIBUTES
                {
                    Length = (uint)sizeof(OBJECT_ATTRIBUTES),
                    RootDirectory = (HANDLE)folder.DangerousGetHandle(),
                    ObjectName = &objectName,
                    Attributes = OBJECT_ATTRIBUTE_FLAGS.OBJ_CASE_INSENSITIVE,
                    SecurityDescriptor = (SECURITY_DESCRIPTOR*)security,
                };
                // Windows refuses FILE_OPEN_NO_RECALL beside FILE_DIRECTORY_FILE, and a folder has no content to recall.
                var always = NTCREATEFILE_CREATE_OPTIONS.FILE_OPEN_REPARSE_POINT
                    | ((options & NTCREATEFILE_CREATE_OPTIONS.FILE_DIRECTORY_FILE) == 0 ? NTCREATEFILE_CREATE_OPTIONS.FILE_OPEN_NO_RECALL : 0);
#pragma warning disable RS0030 // SecureStore: opens or creates one plain name relative to a held folder's handle, as itself (FILE_OPEN_REPARSE_POINT), so no path is parsed and no link is followed; a new item takes the descriptor given, set in the call that creates it
                var status = NtDll.NtCreateFile(out var handle, (FILE_ACCESS_RIGHTS)access, in attributes, out _, null, FILE_FLAGS_AND_ATTRIBUTES.FILE_ATTRIBUTE_NORMAL, share, disposition, options | always, default);
#pragma warning restore RS0030
                if (status.Value < 0)
                {
                    return (int)PInvoke.RtlNtStatusToDosError(status);
                }

                var opened = new SafeFileHandle(handle, ownsHandle: true);
                if (status.Value == OplockBreakInProgress)
                {
                    opened.Dispose();
                    return (int)WIN32_ERROR.ERROR_OPLOCK_BREAK_IN_PROGRESS;
                }

                item = opened;
                return 0;
            }
        }
        finally
        {
            if (added)
            {
                folder.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Renames an open item through its handle to a plain name in a folder, relative to the folder's handle:
    /// no path is parsed, and a target that is a link is replaced as a name, never written through.
    /// </summary>
    /// <returns>0 when it was renamed; otherwise the Win32 error.</returns>
    private static unsafe int Rename(SafeFileHandle item, SafeFileHandle folder, string name, bool replace)
    {
        // Room for the name and a terminating null, which the zeroed buffer holds.
        var buffer = new byte[FILE_RENAME_INFORMATION.SizeOf(name.Length + 1)];
        var addedItem = false;
        var addedFolder = false;
        try
        {
            item.DangerousAddRef(ref addedItem);
            folder.DangerousAddRef(ref addedFolder);
            fixed (byte* start = buffer)
            {
                var information = (FILE_RENAME_INFORMATION*)start;
                information->ReplaceIfExists = replace;
                information->RootDirectory = (HANDLE)folder.DangerousGetHandle();
                information->FileNameLength = (uint)(name.Length * sizeof(char));
                name.AsSpan().CopyTo(information->FileName.AsSpan(name.Length));
            }

#pragma warning disable RS0030 // SecureStore: renames an item it holds, by its handle, to one plain name relative to a held folder's handle; the target's name is replaced, never written through
            var status = NtDll.NtSetInformationFile((HANDLE)item.DangerousGetHandle(), out _, buffer, FILE_INFORMATION_CLASS.FileRenameInformation);
#pragma warning restore RS0030
            return status.Value < 0 ? (int)PInvoke.RtlNtStatusToDosError(status) : 0;
        }
        finally
        {
            if (addedFolder)
            {
                folder.DangerousRelease();
            }

            if (addedItem)
            {
                item.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Sets information on an open item through its handle: its deletion when it closes, or its attributes.
    /// </summary>
    /// <returns>0 when it was set; otherwise the Win32 error.</returns>
    private static int SetInformation<T>(SafeFileHandle item, FILE_INFORMATION_CLASS informationClass, in T information)
        where T : unmanaged
    {
        var added = false;
        try
        {
            item.DangerousAddRef(ref added);
#pragma warning disable RS0030 // SecureStore: marks an item it holds for deletion, or clears its read-only attribute, through its handle; nothing is named by path
            var status = NtDll.NtSetInformationFile((HANDLE)item.DangerousGetHandle(), out _, MemoryMarshal.AsBytes(new ReadOnlySpan<T>(in information)), informationClass);
#pragma warning restore RS0030
            return status.Value < 0 ? (int)PInvoke.RtlNtStatusToDosError(status) : 0;
        }
        finally
        {
            if (added)
            {
                item.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Marks an item for deletion through its handle, the way this build allows: at once, and whatever its
    /// read-only attribute, where Windows can (version 1709 and later); otherwise when the handle closes,
    /// having cleared the read-only attribute of a file with one name, and never of one with others, since
    /// they share it.
    /// </summary>
    /// <returns>0 when it is marked; otherwise the Win32 error, or -1 for a read-only file with other names.</returns>
    private int MarkForDeletion(SafeFileHandle item, FileFacts facts)
    {
        if (_hooks?.ClassicDelete != true)
        {
            var modern = new FILE_DISPOSITION_INFORMATION_EX
            {
                Flags = FILE_DISPOSITION_INFORMATION_EX_FLAGS.FILE_DISPOSITION_DELETE
                    | FILE_DISPOSITION_INFORMATION_EX_FLAGS.FILE_DISPOSITION_POSIX_SEMANTICS
                    | FILE_DISPOSITION_INFORMATION_EX_FLAGS.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
            };
            var error = SetInformation(item, FILE_INFORMATION_CLASS.FileDispositionInformationEx, in modern);
            if ((WIN32_ERROR)error is not (WIN32_ERROR.ERROR_INVALID_PARAMETER or WIN32_ERROR.ERROR_NOT_SUPPORTED or WIN32_ERROR.ERROR_INVALID_FUNCTION))
            {
                return error;
            }
        }

        if (facts.IsReadOnly)
        {
            if (facts.LinkCount != 1)
            {
                return -1;
            }

            var attributes = FileHandles.ReadAttributes(item) & ~(uint)FILE_FLAGS_AND_ATTRIBUTES.FILE_ATTRIBUTE_READONLY;
            var basic = new FILE_BASIC_INFORMATION { FileAttributes = attributes == 0 ? (uint)FILE_FLAGS_AND_ATTRIBUTES.FILE_ATTRIBUTE_NORMAL : attributes };
            var cleared = SetInformation(item, FILE_INFORMATION_CLASS.FileBasicInformation, in basic);
            if (cleared != 0)
            {
                return cleared;
            }
        }

        var classic = new FILE_DISPOSITION_INFORMATION { DeleteFile = true };
        return SetInformation(item, FILE_INFORMATION_CLASS.FileDispositionInformation, in classic);
    }

    /// <summary>
    /// Opens the item at a name to judge it, as itself: to list, read and hold it when this account may, and
    /// otherwise with the least that removing it needs, which then says it could not be read. Neither open waits
    /// for another process to give up an oplock on the item.
    /// </summary>
    private static int OpenToJudge(SafeFileHandle parent, string name, out SafeFileHandle? item, out bool readable)
    {
        readable = true;
        var error = OpenRelative(parent, name, FolderRights, ShareReadWrite, NTCREATEFILE_CREATE_DISPOSITION.FILE_OPEN, Synchronous | NoOplockWait, null, out item);
        if ((WIN32_ERROR)error != WIN32_ERROR.ERROR_ACCESS_DENIED)
        {
            return error;
        }

        readable = false;
        return OpenRelative(parent, name, RemoveRights, ShareAll, NTCREATEFILE_CREATE_DISPOSITION.FILE_OPEN, Asynchronous | NoOplockWait, null, out item);
    }

    /// <summary>Opens the data folder the install made, checked and held, never created or moved.</summary>
    private void OpenRoot(SecureStoreOptions options)
    {
        var path = _programDataPath + @"\" + DataFolderName;
        var error = OpenRelative(_programData, DataFolderName, FolderRights, ShareReadWrite, NTCREATEFILE_CREATE_DISPOSITION.FILE_OPEN, Synchronous, null, out var root);
        if (root is null)
        {
            throw OpenFailure("The data folder", path, error);
        }

        _root = Hold(root, path);
        Refuse(_rules.Trust.FindDataFolderProblem(path, FileHandles.ReadFacts(root), FileHandles.ReadSecurity(root), IsSealed(options)));
    }

    /// <summary>Makes the data folder, or keeps one that is sealed and trusted.</summary>
    private void EstablishRoot(bool isSealed)
    {
        var path = _programDataPath + @"\" + DataFolderName;
        _root = Establish(_programData, DataFolderName, path, relative: null, (facts, security) => _rules.Trust.FindDataFolderProblem(path, facts, security, isSealed), usersMayRead: false, create: true);
    }

    /// <summary>Gets a folder the store keeps in the data folder, making it when asked and it is missing.</summary>
    private HeldFolder? Kept(string name, bool create)
    {
        if (_kept.TryGetValue(name, out var held))
        {
            return held;
        }

        var path = Root.PathOf(name);
        held = Establish(Root.Handle, name, path, relative: name, (facts, security) => _rules.Trust.FindFolderProblem(path, facts, security), DataFolderLayout.UsersMayRead(name), create);
        if (held is not null)
        {
            _kept.Add(name, held);
        }

        return held;
    }

    private HeldFolder? FolderFor(DataFolder folder, bool create) => folder == DataFolder.Root ? Root : Kept(DataFolderLayout.NameOf(folder), create);

    /// <summary>
    /// Establishes a folder the store keeps at a name in a folder it holds: keeps what is there when it passes
    /// the check, deletes a link as a link, moves anything else aside out of the data folder, and makes the
    /// folder locked from birth when nothing is there and <paramref name="create"/> is set. Something that
    /// appears at the name in the meantime is judged in turn.
    /// </summary>
    /// <returns>The folder, held; null when it is missing and not to be made.</returns>
    private HeldFolder? Establish(SafeFileHandle parent, string name, string path, string? relative, Func<FileFacts, ItemSecurity, string?> judge, bool usersMayRead, bool create)
    {
        var last = "something kept taking its place";
        for (var attempt = 1; attempt <= Attempts; attempt++)
        {
            var error = OpenToJudge(parent, name, out var item, out var readable);
            if (IsMissing(error))
            {
                if (!create)
                {
                    return null;
                }

                if (TryCreateFolder(parent, name, path, usersMayRead, FolderRights, out error) is { } created)
                {
                    return created;
                }

                // Something appeared at the name after it was found missing, or is still being deleted: judge it
                // again, as whatever is there now.
                last = FileHandles.Failure("it could not be created", error).Message;
                continue;
            }

            if (item is null)
            {
                last = FileHandles.Failure("it could not be opened to check it (it may be open in another process)", error).Message;
                if (!IsTransient(error))
                {
                    break;
                }

                Pause(attempt);
                continue;
            }

            string? problem;
            try
            {
                var facts = FileHandles.ReadFacts(item);
                problem = readable ? judge(facts, FileHandles.ReadSecurity(item)) : Unreadable(path);
            }
            catch
            {
                item.Dispose();
                throw;
            }

            if (problem is null)
            {
                return Hold(item, path);
            }

            item.Dispose();
            Remove(parent, name, path, relative, problem);
        }

        throw new SecureStoreException($"Could not make a locked folder at {path}: {last.TrimEnd('.')}.");
    }

    /// <summary>
    /// Creates a folder locked from birth at a name in a folder the store holds, in the call that makes it,
    /// and holds it. Anything already at the name, a link included, is a collision: never opened, never
    /// adopted.
    /// </summary>
    /// <returns>The folder, checked and held; null when the name was taken, with the error.</returns>
    private HeldFolder? TryCreateFolder(SafeFileHandle parent, string name, string path, bool usersMayRead, uint rights, out int error)
    {
        _hooks?.BeforeCreate?.Invoke(path);
        error = OpenRelative(parent, name, rights, ShareReadWrite, NTCREATEFILE_CREATE_DISPOSITION.FILE_CREATE, Synchronous | NTCREATEFILE_CREATE_OPTIONS.FILE_DIRECTORY_FILE, _rules.FolderDescriptor(usersMayRead), out var folder);
        if (folder is null)
        {
            return (WIN32_ERROR)error is WIN32_ERROR.ERROR_ALREADY_EXISTS or WIN32_ERROR.ERROR_ACCESS_DENIED
                ? null
                : throw new SecureStoreException(FileHandles.Failure($"Could not create {path}", error).Message);
        }

        var held = Hold(folder, path);
        try
        {
            Refuse(_rules.Trust.FindFolderProblem(path, FileHandles.ReadFacts(folder), FileHandles.ReadSecurity(folder)));
            return held;
        }
        catch
        {
            held.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Removes an untrusted item from where the store keeps a folder, by its handle, without looking inside
    /// it: a link is deleted as a link, and anything else is renamed aside out of the data folder
    /// (<see cref="DataFolderLayout.AsideName"/>). Either is a notice and event 1003. Tries again while another
    /// process holds it or something in it open, then gives up.
    /// </summary>
    private void Remove(SafeFileHandle parent, string name, string path, string? relative, string reason)
    {
        for (var attempt = 1; ; attempt++)
        {
            _hooks?.BeforeMoveAside?.Invoke(path, attempt);
            var error = OpenRelative(parent, name, RemoveRights, ShareAll, NTCREATEFILE_CREATE_DISPOSITION.FILE_OPEN, Asynchronous, null, out var item);
            if (IsMissing(error))
            {
                return;
            }

            string? aside = null;
            if (item is not null)
            {
                using (item)
                {
                    var facts = FileHandles.ReadFacts(item);
                    if (facts.IsReparsePoint && MarkForDeletion(item, facts) == 0)
                    {
                        Notify(DataFolderLayout.LinkRemovedNotice(path));
                        return;
                    }

                    var asideName = DataFolderLayout.AsideName(DataFolderName, NewId(), relative);
                    aside = _programDataPath + @"\" + asideName;
                    error = Rename(item, _programData, asideName, replace: false);
                    if (error == 0)
                    {
                        Notify(DataFolderLayout.MovedAsideNotice(path, aside, reason));
                        return;
                    }

                    if ((WIN32_ERROR)error == WIN32_ERROR.ERROR_ALREADY_EXISTS && attempt < Attempts)
                    {
                        continue;
                    }
                }
            }

            if (!IsTransient(error) || attempt >= Attempts)
            {
                var what = aside is null ? "opened to move it aside" : $"moved aside to {aside}";
                throw new SecureStoreException(FileHandles.Failure(
                    $"The untrusted {path} could not be {what} ({reason.TrimEnd('.')}), so nothing was made in its place. Another process may have it, or something in it, open",
                    error).Message);
            }

            Pause(attempt);
        }
    }

    /// <summary>Records a notice, and writes it to the event log as event 1003.</summary>
    private void Notify(string notice)
    {
        _notices.Add(notice);
        if (!_events.Write(DataFolderLayout.NoticeEventId, EventLogLevel.Warning, DataFolderLayout.EventMessage(notice)))
        {
            _notices.Add($"The notice above could not be written to the Application event log as event {DataFolderLayout.NoticeEventId}.");
        }
    }

    /// <summary>A new random identifier: 32 lower-case hexadecimal digits, as the module's GUIDs are written.</summary>
    private string NewId() => _hooks?.NewId?.Invoke() ?? RandomNumberGenerator.GetHexString(32, lowercase: true);

    /// <summary>Replaces a file in a held folder atomically: a new file under a random name, renamed over the target.</summary>
    private void Write(HeldFolder folder, string name, ReadOnlySpan<byte> content)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ThrowIfNotPlainFileName(name);
        var target = folder.PathOf(name);
        try
        {
            CheckReplaceable(folder, name, target);
            var temporaryName = TemporaryName(name);
            var temporary = folder.PathOf(temporaryName);
            using var file = CreateExclusive(folder, temporaryName, temporary);
            var written = false;
            try
            {
                ExpectFinalPath(file, temporary);
                Refuse(_rules.Trust.FindNewFileProblem(temporary, FileHandles.ReadFacts(file), FileHandles.ReadSecurity(file)));
                RandomAccess.Write(file, content, fileOffset: 0);
                if (!PInvoke.FlushFileBuffers(file))
                {
                    throw FileHandles.Failure($"Could not flush {temporary} to disk", Marshal.GetLastPInvokeError());
                }

                RenameOver(file, folder, name, target);
                ExpectFinalPath(file, target);
                written = true;
            }
            finally
            {
                if (!written)
                {
                    DeleteOwnFile(file);
                }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException && e is not SecureStoreException)
        {
            throw new SecureStoreException($"Could not write {target}: {e.Message}", e);
        }
    }

    /// <summary>
    /// Checks what is at the target's name, opened as itself: nothing, or an ordinary file with one name that
    /// may be replaced.
    /// </summary>
    private static void CheckReplaceable(HeldFolder folder, string name, string target)
    {
        var error = OpenRelative(folder.Handle, name, FileReadAttributes | Synchronize, ShareAll, NTCREATEFILE_CREATE_DISPOSITION.FILE_OPEN, Synchronous, null, out var existing);
        if (existing is null)
        {
            if (IsMissing(error))
            {
                return;
            }

            throw FileHandles.Failure($"Could not check {target} before replacing it", error);
        }

        using (existing)
        {
            ExpectFinalPath(existing, target);
            Refuse(DataFolderTrust.FindReplaceProblem(target, FileHandles.ReadFacts(existing)));
        }
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

    /// <summary>Creates a new file exclusively in a held folder, owned as the rules say, taking the folder's access list.</summary>
    private SafeFileHandle CreateExclusive(HeldFolder folder, string name, string path)
    {
        var error = OpenRelative(
            folder.Handle,
            name,
            GenericWrite | Delete | ReadControl | FileReadAttributes | Synchronize,
            ShareNone,
            NTCREATEFILE_CREATE_DISPOSITION.FILE_CREATE,
            Synchronous | NTCREATEFILE_CREATE_OPTIONS.FILE_NON_DIRECTORY_FILE,
            _rules.FileDescriptor(),
            out var file);
        return file ?? throw FileHandles.Failure($"Could not create {path}", error);
    }

    /// <summary>
    /// Renames the new file over the target through its handle, replacing the target's name. Tries again a few
    /// times while another process, such as a reader or an antivirus scan, has the target open.
    /// </summary>
    private void RenameOver(SafeFileHandle file, HeldFolder folder, string name, string target)
    {
        for (var attempt = 1; ; attempt++)
        {
            _hooks?.BeforeRename?.Invoke(target, attempt);
            var error = Rename(file, folder.Handle, name, replace: true);
            if (error == 0)
            {
                return;
            }

            if (attempt >= Attempts || !IsTransient(error))
            {
                throw FileHandles.Failure($"Could not replace {target} (it may be open in another process)", error);
            }

            Pause(attempt);
        }
    }

    /// <summary>Deletes a file this store created, through its handle, so a failed write leaves nothing behind.</summary>
    private static void DeleteOwnFile(SafeFileHandle file)
    {
        var disposition = new FILE_DISPOSITION_INFORMATION { DeleteFile = true };
        _ = SetInformation(file, FILE_INFORMATION_CLASS.FileDispositionInformation, in disposition);
    }

    /// <summary>
    /// Reads a whole file in a held folder through its handle, after checking it through that handle: denying
    /// writers while it is read, so it cannot change, and never reading beyond its checked length. A file that
    /// breaks a rule, or that denies this account the right to read it, is refused; one that cannot be opened or
    /// read at the time (held open without sharing, locked in part, an oplock another process does not give up,
    /// or a device error) gives a <see cref="SecureStoreException"/> that says so (<see cref="SecureStoreException.IsUnavailable"/>).
    /// </summary>
    private byte[]? Read(HeldFolder folder, string name, int maxLength)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ThrowIfNotPlainFileName(name);
        ThrowIfNotReadLength(maxLength);
        var path = folder.PathOf(name);
        try
        {
            SafeFileHandle? file;
            for (var attempt = 1; ; attempt++)
            {
                var error = OpenRelative(folder.Handle, name, ReadRights, ShareRead, NTCREATEFILE_CREATE_DISPOSITION.FILE_OPEN, Synchronous | NoOplockWait, null, out file);
                if (file is not null)
                {
                    break;
                }

                if (IsMissing(error))
                {
                    return null;
                }

                if ((WIN32_ERROR)error == WIN32_ERROR.ERROR_ACCESS_DENIED)
                {
                    // Its own access list keeps this account out: a judgement of the file, not something passing.
                    throw new SecureStoreException($"Could not read {path}: {FileHandles.Failure($"Could not open {path} to read it", error).Message}");
                }

                if (attempt >= Attempts || (WIN32_ERROR)error is not (WIN32_ERROR.ERROR_SHARING_VIOLATION or WIN32_ERROR.ERROR_OPLOCK_BREAK_IN_PROGRESS))
                {
                    throw FileHandles.Failure($"Could not open {path} to read it", error);
                }

                Pause(attempt);
            }

            using (file)
            {
                var facts = FileHandles.ReadFacts(file);
                Refuse(_rules.Trust.FindReadProblem(path, facts, FileHandles.ReadSecurity(file), maxLength));
                var content = new byte[facts.Length];
                for (var offset = 0; offset < content.Length;)
                {
                    var read = RandomAccess.Read(file, content.AsSpan(offset), offset);
                    if (read == 0)
                    {
                        throw new IOException($"{path} ended before the length it gave.");
                    }

                    offset += read;
                }

                return content;
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException && e is not SecureStoreException)
        {
            throw new SecureStoreException($"Could not read {path}: {e.Message}", isUnavailable: true, e);
        }
    }

    /// <summary>
    /// Deletes the item at a name in a folder, and everything in it, never following a link. Each folder is
    /// opened relative to its parent's handle, checked through its own handle just before it is listed, and
    /// listed through that handle, so what is listed is what was checked; one that fails is left in place,
    /// unlisted. A link is deleted as a link, and a quarantine is left for an administrator.
    /// </summary>
    /// <returns>True when it is gone.</returns>
    private bool DeleteEntry(SafeFileHandle parent, string name, string path, int depth, List<string> left)
    {
        _hooks?.BeforeOpenInTree?.Invoke(path);
        var readable = true;
        var error = OpenRelative(parent, name, TreeRights, ShareAll, NTCREATEFILE_CREATE_DISPOSITION.FILE_OPEN, Synchronous, null, out var item);
        if ((WIN32_ERROR)error == WIN32_ERROR.ERROR_ACCESS_DENIED)
        {
            readable = false;
            error = OpenRelative(parent, name, RemoveRights, ShareAll, NTCREATEFILE_CREATE_DISPOSITION.FILE_OPEN, Asynchronous, null, out item);
        }

        if (IsMissing(error))
        {
            return true;
        }

        if (item is null)
        {
            left.Add(FileHandles.Failure($"{path} was left in place: it could not be opened", error).Message);
            return false;
        }

        using (item)
        {
            try
            {
                var facts = FileHandles.ReadFacts(item);
                if (facts.IsReparsePoint || !facts.IsDirectory)
                {
                    return DeleteByHandle(item, facts, path, left);
                }

                var problem = depth > 1 && DataFolderLayout.IsAsideName(name)
                    ? $"{path} is an item moved aside, for an administrator to check and delete"
                    : !readable
                        ? $"{path} cannot be read by this account (access is denied)"
                        : _rules.Trust.FindFolderProblem(path, facts, FileHandles.ReadSecurity(item))
                            ?? (depth > MaxTreeDepth ? $"{path} is more than {MaxTreeDepth} folders deep" : null);
                if (problem is not null)
                {
                    left.Add($"{problem.TrimEnd('.')}, so it was left in place, unlisted.");
                    return false;
                }

                var complete = true;
                foreach (var entry in FileHandles.ListNames(item))
                {
                    complete &= DeleteEntry(item, entry, path + @"\" + entry, depth + 1, left);
                }

                return complete && DeleteByHandle(item, facts, path, left);
            }
            catch (IOException e)
            {
                left.Add($"{path} was left in place: {e.Message}");
                return false;
            }
        }
    }

    /// <summary>
    /// Deletes an item the tree delete holds, through its handle: a file, a link as a link, or a folder it has
    /// emptied. Tries again while a deleted item's name lingers because another process still has it open.
    /// </summary>
    private bool DeleteByHandle(SafeFileHandle item, FileFacts facts, string path, List<string> left)
    {
        for (var attempt = 1; ; attempt++)
        {
            var error = MarkForDeletion(item, facts);
            if (error == 0)
            {
                return true;
            }

            if (error == -1)
            {
                left.Add($"{path} was left in place: it is read-only and has other names (hard links), which share that attribute, so it is not changed.");
                return false;
            }

            if (attempt >= Attempts || !(IsTransient(error) || (WIN32_ERROR)error == WIN32_ERROR.ERROR_DIR_NOT_EMPTY))
            {
                left.Add(FileHandles.Failure($"{path} was left in place: it could not be deleted", error).Message);
                return false;
            }

            Pause(attempt);
        }
    }

    /// <summary>Deletes a held scratch folder and everything in it, then the folder itself through its handle.</summary>
    private void DeleteHeld(HeldFolder folder)
    {
        var left = new List<string>();
        try
        {
            var facts = FileHandles.ReadFacts(folder.Handle);
            if (_rules.Trust.FindFolderProblem(folder.Path, facts, FileHandles.ReadSecurity(folder.Handle)) is { } problem)
            {
                left.Add($"{problem.TrimEnd('.')}, so it was left in place, unlisted.");
            }
            else
            {
                var complete = true;
                foreach (var entry in FileHandles.ListNames(folder.Handle))
                {
                    complete &= DeleteEntry(folder.Handle, entry, folder.PathOf(entry), depth: 2, left);
                }

                if (complete)
                {
                    _ = DeleteByHandle(folder.Handle, facts, folder.Path, left);
                }
            }
        }
        catch (IOException e)
        {
            left.Add($"{folder.Path} was left in place: {e.Message}");
        }

        _notices.AddRange(left);
    }

    /// <summary>Waits before another attempt, by the store's clock.</summary>
    /// <param name="attempt">The attempt that failed, from 1.</param>
    private void Pause(int attempt)
    {
        using var elapsed = new ManualResetEventSlim();
        using var timer = _time.CreateTimer(static state => ((ManualResetEventSlim)state!).Set(), elapsed, RetryDelays[Math.Min(attempt, RetryDelays.Length) - 1], Timeout.InfiniteTimeSpan);
        elapsed.Wait();
    }

    /// <summary>A folder the store holds open without FILE_SHARE_DELETE, and its path as Windows spells it.</summary>
    private sealed class HeldFolder(SafeFileHandle handle, string path) : IDisposable
    {
        public SafeFileHandle Handle { get; } = handle;

        public string Path { get; } = path;

        public string PathOf(string name) => Path + @"\" + name;

        public void Dispose() => Handle.Dispose();
    }

    /// <summary>A scratch folder the store made and holds; disposing it deletes it and everything in it.</summary>
    private sealed class ScratchFolder(SecureStore store, HeldFolder folder) : IScratchFolder
    {
        private bool _disposed;

        public string Path => folder.Path;

        public string PathOf(string name)
        {
            ThrowIfNotPlainFileName(name);
            return folder.PathOf(name);
        }

        public void WriteFile(string name, ReadOnlySpan<byte> content)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            store.Write(folder, name, content);
        }

        public byte[]? ReadFile(string name, int maxLength)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return store.Read(folder, name, maxLength);
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            try
            {
                store.DeleteHeld(folder);
            }
            finally
            {
                folder.Dispose();
            }
        }
    }
}
