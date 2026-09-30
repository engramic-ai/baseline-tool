namespace Engramic.Baseline.Platform;

/// <summary>
/// A folder for one run's scratch files, such as the input and output files of a Windows tool: made
/// locked from birth, under a random name, in the data folder's scratch folder, and held open so that
/// its path keeps naming it. Disposing it deletes it and everything in it, without following a link.
/// </summary>
/// <remarks>
/// Nothing elevated writes to or reads back from the temp folder, which for SYSTEM is shared with other
/// accounts: a tool is given paths in here instead. Use it, and dispose of it, while the store that made it
/// is open: the store holds the folders above it, which keeps its path naming it. Not safe to use from more
/// than one thread at a time.
/// </remarks>
public interface IScratchFolder : IDisposable
{
    /// <summary>Gets the full path of the folder, to give a tool the paths of its files.</summary>
    string Path { get; }

    /// <summary>Gets the full path a file of this name has in the folder, for a tool's command line.</summary>
    /// <param name="name">The name of the file: a plain name, never a path.</param>
    /// <returns>The path.</returns>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not a plain file name.</exception>
    string PathOf(string name);

    /// <summary>Replaces a file in the folder, or creates it, atomically.</summary>
    /// <param name="name">The name of the file: a plain name, never a path.</param>
    /// <param name="content">The whole content of the file.</param>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not a plain file name.</exception>
    /// <exception cref="SecureStoreException">The file cannot be written safely; the message says why.</exception>
    void WriteFile(string name, ReadOnlySpan<byte> content);

    /// <summary>Reads a whole file a tool wrote in the folder, with the rules of <see cref="ISecureStore.ReadFile"/>.</summary>
    /// <param name="name">The name of the file: a plain name, never a path.</param>
    /// <param name="maxLength">The most bytes to read; a longer file is refused, not cut short.</param>
    /// <returns>The content, or null when there is no such file.</returns>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not a plain file name.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxLength"/> is not positive, or is too large.</exception>
    /// <exception cref="SecureStoreException">The file is not one the tool may trust, or could not be opened or read at the time (<see cref="SecureStoreException.IsUnavailable"/>); the message says why.</exception>
    byte[]? ReadFile(string name, int maxLength);
}
