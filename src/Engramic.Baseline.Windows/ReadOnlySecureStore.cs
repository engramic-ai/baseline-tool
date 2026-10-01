using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows;

/// <summary>
/// The machine data folder opened only to read the files the tool keeps in it
/// (<see cref="SecureStore.OpenReadOnly(SecureStoreOptions)"/>): checked through handles and held open while in
/// use, by SecureStore's rules, and never changed.
/// </summary>
/// <remarks>
/// <para>
/// It has no way to write. It is not an <see cref="ISecureStore"/>, so no cast reaches a writer, and the
/// SecureStore it reads through is out of reach. A folder kept in the data folder is judged before anything
/// in it is read, as SecureStore judges it, but one that fails the trust rules is refused rather than moved
/// aside, and one that is missing reads as nothing rather than being made. So nothing is created, moved,
/// deleted or written, and nothing is recorded in the event log.
/// </para>
/// <para>Not safe to use from more than one thread at a time.</para>
/// </remarks>
public sealed class ReadOnlySecureStore : IDataFolderReader
{
    private readonly SecureStore _store;

    /// <summary>Makes the store over a SecureStore opened only to read.</summary>
    /// <param name="store">The store, opened by <see cref="SecureStore.OpenReadOnly(SecureStoreOptions, SecureStoreRules, SecureStoreHooks)"/>.</param>
    internal ReadOnlySecureStore(SecureStore store) => _store = store;

    /// <inheritdoc/>
    public string RootPath => _store.RootPath;

    /// <inheritdoc/>
    /// <remarks>
    /// The folder it is in is opened as itself, without waiting on an oplock, and judged by the trust rules
    /// through its handle, then held; a file is read as <see cref="SecureStore.ReadFile"/> reads one. A folder
    /// that fails the rules, or that this account may not open to judge, is refused with a
    /// <see cref="SecureStoreException"/> that says why, with <see cref="SecureStoreException.IsFolderRefused"/>
    /// set since nothing in it was opened, and left as it is. One that could not be opened at the
    /// time gives one with <see cref="SecureStoreException.IsUnavailable"/> set.
    /// </remarks>
    public byte[]? ReadFile(DataFolder folder, string name, int maxLength) => _store.ReadWithoutChanging(folder, name, maxLength);

    /// <summary>Closes the handles on the folders the store holds and on ProgramData.</summary>
    public void Dispose() => _store.Dispose();
}
