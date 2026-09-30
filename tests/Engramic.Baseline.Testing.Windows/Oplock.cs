using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Engramic.Baseline.Testing.Windows;

/// <summary>
/// A batch oplock on a file, held by a handle of its own and never given up: what anyone who may read the file
/// can take, to make each later open of it by another handle wait until the oplock is acknowledged, which this
/// holder never does. Disposing it closes the handle, which ends the oplock.
/// </summary>
/// <remarks>
/// The handle shares reading, writing and deleting, so that an open by someone else is held up by the oplock
/// alone, never refused for sharing.
/// </remarks>
public sealed unsafe partial class Oplock : IDisposable
{
    private const uint GenericRead = 0x8000_0000;
    private const uint ShareAll = 0x0000_0007;
    private const uint OpenExisting = 3;
    private const uint Overlapped = 0x4000_0000;
    private const uint FsctlRequestBatchOplock = 0x0009_0008;
    private const int ErrorIoPending = 997;

    private readonly SafeFileHandle _file;
    private readonly ManualResetEvent _broken;
    private readonly NativeOverlapped* _overlapped;
    private bool _disposed;

    private Oplock(SafeFileHandle file, ManualResetEvent broken, NativeOverlapped* overlapped)
    {
        _file = file;
        _broken = broken;
        _overlapped = overlapped;
    }

    /// <summary>Gets whether another open has asked for the oplock to be broken.</summary>
    public bool BreakRequested => _broken.WaitOne(0);

    /// <summary>Opens a file to read it, as this thread's account, and takes a batch oplock on it.</summary>
    /// <param name="path">The file: no other handle may be open on it.</param>
    /// <returns>The oplock, held until it is disposed.</returns>
    public static Oplock Take(string path)
    {
        var file = CreateFile(path, GenericRead, ShareAll, IntPtr.Zero, OpenExisting, Overlapped, IntPtr.Zero);
        if (file.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            file.Dispose();
            throw new Win32Exception(error, $"Could not open {path} to take an oplock on it");
        }

        var broken = new ManualResetEvent(false);
        var overlapped = (NativeOverlapped*)NativeMemory.AllocZeroed((nuint)sizeof(NativeOverlapped));
        overlapped->EventHandle = broken.SafeWaitHandle.DangerousGetHandle();

        // A granted oplock is a request left pending, which completes when something asks for it to be broken.
        if (DeviceIoControl(file, FsctlRequestBatchOplock, null, 0, null, 0, null, overlapped) || Marshal.GetLastPInvokeError() != ErrorIoPending)
        {
            var error = Marshal.GetLastPInvokeError();
            file.Dispose();
            broken.Dispose();
            NativeMemory.Free(overlapped);
            throw new Win32Exception(error, $"Windows did not grant a batch oplock on {path}");
        }

        return new Oplock(file, broken, overlapped);
    }

    /// <summary>Gives up the oplock by closing its handle, once the pending request is done with its memory.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _ = CancelIoEx(_file, _overlapped);
        _ = GetOverlappedResult(_file, _overlapped, out _, wait: true);
        _file.Dispose();
        _broken.Dispose();
        NativeMemory.Free(_overlapped);
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeviceIoControl(SafeFileHandle device, uint code, void* input, uint inputLength, void* output, uint outputLength, uint* returned, NativeOverlapped* overlapped);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CancelIoEx(SafeFileHandle file, NativeOverlapped* overlapped);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetOverlappedResult(SafeFileHandle file, NativeOverlapped* overlapped, out uint transferred, [MarshalAs(UnmanagedType.Bool)] bool wait);
}
