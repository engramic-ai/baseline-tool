namespace Engramic.Baseline.Platform;

/// <summary>
/// Reads the files the tool keeps in the machine data folder, checked through handles and held open while in
/// use: all that reading administrators' config overrides needs.
/// </summary>
/// <remarks>
/// Engramic.Baseline.Windows has two implementations. SecureStore (<see cref="ISecureStore"/>) also writes,
/// and moves aside a folder it keeps that it cannot trust; ReadOnlySecureStore only reads, and refuses such a
/// folder, so that a run that promises to change nothing can read through it. Not safe to use from more than
/// one thread at a time.
/// </remarks>
public interface IDataFolderReader : IDisposable
{
    /// <summary>Gets the full path of the data folder, as Windows gives it for the handle held open on it.</summary>
    string RootPath { get; }

    /// <summary>
    /// Reads a whole file from one of the data folder's folders, if it is one the tool may trust: an
    /// ordinary file with one name, not a link, not stored online only, owned by a trusted account and
    /// changeable by no one else, and no longer than <paramref name="maxLength"/>.
    /// </summary>
    /// <param name="folder">The folder.</param>
    /// <param name="name">The name of the file: a plain name, never a path.</param>
    /// <param name="maxLength">The most bytes to read; a longer file is refused, not cut short.</param>
    /// <returns>The content, or null when there is no such file (or no such folder).</returns>
    /// <remarks>
    /// The folder is judged before anything in it is read. SecureStore moves aside one it cannot trust, and then
    /// reads nothing from it; ReadOnlySecureStore refuses it and changes nothing.
    /// </remarks>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not a plain file name.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxLength"/> is not positive, or is too large.</exception>
    /// <exception cref="SecureStoreException">The file, or the folder it is in, is not one the tool may trust, or could not be opened or read at the time (<see cref="SecureStoreException.IsUnavailable"/>); the message says why.</exception>
    byte[]? ReadFile(DataFolder folder, string name, int maxLength);
}
