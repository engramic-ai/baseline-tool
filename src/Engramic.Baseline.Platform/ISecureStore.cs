namespace Engramic.Baseline.Platform;

/// <summary>
/// The machine data folder, checked through handles and held open while in use: the one place product
/// code writes files, and reads the files the tool keeps.
/// </summary>
/// <remarks>
/// Engramic.Baseline.Windows has the implementation, SecureStore, which says what is checked; the tests
/// share a fake. What only reads, such as the config trust gate, takes an <see cref="IDataFolderReader"/>.
/// Not safe to use from more than one thread at a time.
/// </remarks>
public interface ISecureStore : IDataFolderReader
{
    /// <summary>
    /// Gets what the store has done about items it could not trust, in order: each link it removed and
    /// each item it moved aside, naming where it went, each of which is also event 1003 in the Application
    /// log; and what the deletion of a scratch folder had to leave in place, and why.
    /// </summary>
    IReadOnlyList<string> Notices { get; }

    /// <summary>
    /// Replaces a file in the data folder, or creates it, atomically: a reader sees the whole old file or
    /// the whole new one, never part of either.
    /// </summary>
    /// <param name="name">The name of the file, such as status.json: a plain name, never a path.</param>
    /// <param name="content">The whole content of the file.</param>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not a plain file name.</exception>
    /// <exception cref="SecureStoreException">The file cannot be written safely; the message says why.</exception>
    void WriteFile(string name, ReadOnlySpan<byte> content);

    /// <summary>
    /// Replaces a file in one of the data folder's folders, or creates it, atomically. The folder is made,
    /// locked from birth, if it is missing.
    /// </summary>
    /// <param name="folder">The folder.</param>
    /// <param name="name">The name of the file: a plain name, never a path.</param>
    /// <param name="content">The whole content of the file.</param>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not a plain file name.</exception>
    /// <exception cref="SecureStoreException">The file cannot be written safely; the message says why.</exception>
    void WriteFile(DataFolder folder, string name, ReadOnlySpan<byte> content);

    /// <summary>
    /// Makes a new folder for one run's scratch files, such as a Windows tool's input and output, locked
    /// from birth under a random name in the data folder's scratch folder. Disposing it deletes it and
    /// everything in it, without following a link.
    /// </summary>
    /// <returns>The folder.</returns>
    /// <exception cref="SecureStoreException">It cannot be made safely; the message says why.</exception>
    IScratchFolder CreateScratchFolder();

    /// <summary>
    /// Deletes a file or a folder and everything in it from one of the data folder's folders, never
    /// following a link: a link is deleted as a link. Each folder is checked through its handle just
    /// before it is listed, and one the tool cannot trust is left in place, unlisted.
    /// </summary>
    /// <param name="folder">The folder it is in.</param>
    /// <param name="name">Its name: a plain name, never a path.</param>
    /// <returns>What was left in place, and why; empty when everything was deleted, or nothing was there.</returns>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not a plain file name, or names a folder the store keeps.</exception>
    /// <exception cref="SecureStoreException">The folder it is in cannot be used safely.</exception>
    IReadOnlyList<string> DeleteTree(DataFolder folder, string name);
}
