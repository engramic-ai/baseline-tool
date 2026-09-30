using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// The ways a reader of a file in the config folder can stop SecureStore reading it for as long as they like,
/// without changing it: each opened as the account of the thread that calls <see cref="Hold"/>, and held until
/// disposed. Windows honours a refusal to share reading only from a holder who may write to what they hold, so a
/// standard user, who may only read the config folder and what is in it, has the lock and the oplock alone
/// (<see cref="ReadOnlyHolderWays"/>); the tests' own account may write to its folders, so it has all four.
/// </summary>
internal static class Holders
{
    public const string FileHeldOpen = "the file held open without sharing";
    public const string FileLocked = "the file locked in part";
    public const string FileOplocked = "an oplock on the file that is never given up";
    public const string FolderHeldOpen = "its folder held open without sharing";

    /// <summary>Gets every way, for a holder who may write to the file and its folder.</summary>
    public static TheoryData<string> Ways => [FileHeldOpen, FileLocked, FileOplocked, FolderHeldOpen];

    /// <summary>Gets the ways that still stop a read when the holder may only read the file and its folder.</summary>
    public static TheoryData<string> ReadOnlyHolderWays => [FileLocked, FileOplocked];

    /// <summary>Gets the ways Windows ignores from a holder who may only read the file and its folder: refusals to share.</summary>
    public static TheoryData<string> WaysIgnoredFromReadOnlyHolder => [FileHeldOpen, FolderHeldOpen];

    /// <summary>Holds the file, or the folder it is in, in one of the <see cref="Ways"/>.</summary>
    /// <param name="way">How.</param>
    /// <param name="file">The file.</param>
    /// <param name="folder">The folder it is in.</param>
    /// <returns>What holds it.</returns>
    public static IDisposable Hold(string way, string file, string folder)
    {
        switch (way)
        {
            case FileHeldOpen:
                return new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None);
            case FileLocked:
                // Shared for reading, so the store opens it; the lock stops the read itself.
                var locked = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                locked.Lock(0, Math.Max(1, locked.Length));
                return locked;
            case FileOplocked:
                return TakeOplock(file);
            case FolderHeldOpen:
                return Native.OpenWithShare(folder, Native.FileListDirectory | Native.Synchronize, share: 0);
            default:
                throw new ArgumentOutOfRangeException(nameof(way), way, "Not a way these tests hold a file.");
        }
    }

    /// <summary>
    /// Takes a batch oplock, which Windows grants only while no other handle is open on the file: one that an
    /// antivirus scan of a file just written still holds is waited out.
    /// </summary>
    private static Oplock TakeOplock(string file)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return Oplock.Take(file);
            }
            catch (System.ComponentModel.Win32Exception) when (attempt < 20)
            {
                Thread.Sleep(50);
            }
        }
    }
}
