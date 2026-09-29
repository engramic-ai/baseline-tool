namespace Engramic.Baseline.Platform;

/// <summary>
/// The machine data folder, checked through handles and held open while in use: the one place product
/// code writes files.
/// </summary>
/// <remarks>
/// Engramic.Baseline.Windows has the implementation, SecureStore, which says what is checked; the tests
/// share a fake. Not safe to use from more than one thread at a time.
/// </remarks>
public interface ISecureStore : IDisposable
{
    /// <summary>Gets the full path of the data folder, as Windows gives it for the handle held open on it.</summary>
    string RootPath { get; }

    /// <summary>
    /// Replaces a file in the data folder, or creates it, atomically: a reader sees the whole old file or
    /// the whole new one, never part of either.
    /// </summary>
    /// <param name="name">The name of the file, such as status.json: a plain name, never a path.</param>
    /// <param name="content">The whole content of the file.</param>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not a plain file name.</exception>
    /// <exception cref="SecureStoreException">The file cannot be written safely; the message says why.</exception>
    void WriteFile(string name, ReadOnlySpan<byte> content);
}
