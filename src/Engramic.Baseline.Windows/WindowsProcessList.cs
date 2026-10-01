using System.Runtime.InteropServices;
using System.Security.Principal;
using Engramic.Baseline.Platform;
using Microsoft.Win32.SafeHandles;
using Windows.Wdk.System.Threading;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.System.Diagnostics.ToolHelp;
using Windows.Win32.System.Threading;
using NtDll = Windows.Wdk.PInvoke;

namespace Engramic.Baseline.Windows;

/// <summary>
/// The process list primitive on Windows: the process table from a snapshot, then each process's image path,
/// command line, session and access token, opened with query-only access.
/// </summary>
/// <remarks>
/// Each process is opened with PROCESS_QUERY_LIMITED_INFORMATION and its token with TOKEN_QUERY, the least
/// either can be opened with, so nothing is read from the process's memory and nothing can be changed. The
/// owner and elevation come from the token, not from WMI, so this stays free of System.Management. The command
/// line comes from NtQueryInformationProcess's ProcessCommandLineInformation (Windows 8.1 and later), which needs
/// no more access than that.
/// </remarks>
public sealed class WindowsProcessList : IProcessList
{
    private const int NoMoreFiles = 18;
    private const int InsufficientBuffer = 122;

    /// <inheritdoc/>
    public unsafe IReadOnlyList<RunningProcess> Read()
    {
        using var snapshot = PInvoke.CreateToolhelp32Snapshot_SafeHandle(CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPPROCESS, 0);
        if (snapshot.IsInvalid)
        {
            throw new IOException($"Could not read the process table (error {Marshal.GetLastPInvokeError()}).");
        }

        var processes = new List<RunningProcess>();
        var entry = new PROCESSENTRY32W { dwSize = (uint)sizeof(PROCESSENTRY32W) };
        var more = PInvoke.Process32FirstW(snapshot, ref entry);
        while (more)
        {
            // Process 0 is the idle process: not a process anything runs in.
            if (entry.th32ProcessID != 0)
            {
                processes.Add(Describe(entry.th32ProcessID, entry.th32ParentProcessID, entry.szExeFile.ToString()));
            }

            more = PInvoke.Process32NextW(snapshot, ref entry);
        }

        var error = Marshal.GetLastPInvokeError();
        return error == NoMoreFiles ? processes : throw new IOException($"Could not read the process table (error {error}).");
    }

    private static RunningProcess Describe(uint id, uint parentId, string imageName)
    {
        uint? session = PInvoke.ProcessIdToSessionId(id, out var sessionId) ? sessionId : null;
        using var process = PInvoke.OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, id);
        if (process.IsInvalid)
        {
            return new RunningProcess { Id = id, ParentId = parentId, ImageName = imageName, SessionId = session };
        }

        Sid? owner = null;
        bool? elevated = null;
        if (PInvoke.OpenProcessToken(process, TOKEN_ACCESS_MASK.TOKEN_QUERY, out var token))
        {
            using (token)
            {
                owner = ReadOwner(token);
                elevated = ReadElevation(token);
            }
        }

        return new RunningProcess
        {
            Id = id,
            ParentId = parentId,
            ImageName = imageName,
            ImagePath = ReadImagePath(process),
            CommandLine = ReadCommandLine(process),
            SessionId = session,
            Owner = owner,
            IsElevated = elevated,
        };
    }

    /// <summary>Reads the full path of a process's image, in Win32 form, or null when Windows will not say.</summary>
    private static string? ReadImagePath(SafeFileHandle process)
    {
        Span<char> buffer = stackalloc char[512];
        var length = (uint)buffer.Length;
        if (PInvoke.QueryFullProcessImageName(process, PROCESS_NAME_FORMAT.PROCESS_NAME_WIN32, buffer, ref length))
        {
            return buffer[..(int)length].ToString();
        }

        if (Marshal.GetLastPInvokeError() != InsufficientBuffer)
        {
            return null;
        }

        // A long path: the longest Windows allows.
        var large = new char[short.MaxValue];
        length = (uint)large.Length;
        return PInvoke.QueryFullProcessImageName(process, PROCESS_NAME_FORMAT.PROCESS_NAME_WIN32, large, ref length) ? new string(large, 0, (int)length) : null;
    }

    /// <summary>Reads a process's command line, or null when Windows will not say.</summary>
    private static unsafe string? ReadCommandLine(SafeFileHandle process)
    {
        var added = false;
        try
        {
            process.DangerousAddRef(ref added);
            var handle = (HANDLE)process.DangerousGetHandle();

            // The first call gives the size needed: a UNICODE_STRING followed by its text.
            uint needed = 0;
            _ = NtDll.NtQueryInformationProcess(handle, PROCESSINFOCLASS.ProcessCommandLineInformation, null, 0, ref needed);
            if (needed < sizeof(UNICODE_STRING))
            {
                return null;
            }

            // The UNICODE_STRING holds a pointer, so the buffer is aligned to 8 bytes, as an array of longs is.
            var buffer = new long[(needed + sizeof(long) - 1) / sizeof(long)];
            fixed (long* start = buffer)
            {
                var status = NtDll.NtQueryInformationProcess(handle, PROCESSINFOCLASS.ProcessCommandLineInformation, start, needed, ref needed);
                if (status.Value < 0)
                {
                    return null;
                }

                var text = (UNICODE_STRING*)start;
                return text->Buffer.Value is null ? string.Empty : new string(text->Buffer.Value, 0, text->Length / sizeof(char));
            }
        }
        finally
        {
            if (added)
            {
                process.DangerousRelease();
            }
        }
    }

    /// <summary>Reads the account a token is for, or null when Windows will not say.</summary>
    private static unsafe Sid? ReadOwner(SafeFileHandle token)
    {
        // TOKEN_USER and the identifier it points to, which follows it: at most 8 + 8 + 68 bytes, aligned to 8.
        Span<long> buffer = stackalloc long[32];
        var bytes = MemoryMarshal.AsBytes(buffer);
        if (!PInvoke.GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenUser, bytes, out _))
        {
            return null;
        }

        fixed (byte* start = bytes)
        {
            var user = (TOKEN_USER*)start;
            return Sid.TryParse(new SecurityIdentifier((nint)user->User.Sid.Value).Value, out var sid) ? sid : null;
        }
    }

    /// <summary>Reads whether a token is elevated, or null when Windows will not say.</summary>
    private static bool? ReadElevation(SafeFileHandle token)
    {
        var elevation = default(TOKEN_ELEVATION);
        return PInvoke.GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenElevation, MemoryMarshal.AsBytes(new Span<TOKEN_ELEVATION>(ref elevation)), out _)
            ? elevation.TokenIsElevated != 0
            : null;
    }
}
