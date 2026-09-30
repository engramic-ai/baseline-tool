using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// The ways anyone who may read a file in the config folder, standard users included, can stop SecureStore reading
/// it for as long as they like, without being able to change it: each opened as the account of the thread that
/// calls <see cref="Hold"/>, and held until disposed.
/// </summary>
internal static class Holders
{
    public const string FileHeldOpen = "the file held open without sharing";
    public const string FileLocked = "the file locked in part";
    public const string FileOplocked = "an oplock on the file that is never given up";
    public const string FolderHeldOpen = "its folder held open without sharing";

    public static TheoryData<string> Ways => [FileHeldOpen, FileLocked, FileOplocked, FolderHeldOpen];

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
