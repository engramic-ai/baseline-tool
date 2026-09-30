using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Testing;

/// <summary>
/// A data folder in memory, for code that writes through SecureStore: it keeps what is written, by folder
/// and name, hands out scratch folders in memory, and can be made to refuse a write.
/// </summary>
public sealed class FakeSecureStore : ISecureStore
{
    private readonly Dictionary<(DataFolder Folder, string Name), byte[]> _files = [];
    private readonly List<string> _notices = [];
    private readonly List<FakeScratchFolder> _scratchFolders = [];

    /// <summary>Makes the store.</summary>
    /// <param name="rootPath">The path it reports for the data folder.</param>
    public FakeSecureStore(string rootPath = @"C:\ProgramData\EngramicBaseline") => RootPath = rootPath;

    /// <inheritdoc/>
    public string RootPath { get; }

    /// <inheritdoc/>
    public IReadOnlyList<string> Notices => _notices;

    /// <summary>Gets the files written in the data folder itself, by name, each with its whole content.</summary>
    public IReadOnlyDictionary<string, byte[]> Files => FilesIn(DataFolder.Root);

    /// <summary>Gets the scratch folders handed out, in order.</summary>
    public IReadOnlyList<FakeScratchFolder> ScratchFolders => _scratchFolders;

    /// <summary>Gets or sets what a write throws, such as a SecureStoreException; null to write.</summary>
    public Exception? WriteError { get; set; }

    /// <summary>Gets or sets what runs at each write, before it is kept, such as a check the caller holds a lock.</summary>
    public Action<string>? OnWrite { get; set; }

    /// <summary>Gets whether it has been disposed.</summary>
    public bool IsDisposed { get; private set; }

    /// <summary>Gets the files written in one folder, by name.</summary>
    /// <param name="folder">The folder.</param>
    /// <returns>The files.</returns>
    public IReadOnlyDictionary<string, byte[]> FilesIn(DataFolder folder)
    {
        return _files.Where(f => f.Key.Folder == folder).ToDictionary(f => f.Key.Name, f => f.Value, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Records a notice, as the real store does when it moves something aside.</summary>
    /// <param name="notice">The notice.</param>
    public void AddNotice(string notice) => _notices.Add(notice);

    /// <inheritdoc/>
    public void WriteFile(string name, ReadOnlySpan<byte> content) => WriteFile(DataFolder.Root, name, content);

    /// <inheritdoc/>
    public void WriteFile(DataFolder folder, string name, ReadOnlySpan<byte> content)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        OnWrite?.Invoke(name);
        if (WriteError is not null)
        {
            throw WriteError;
        }

        _files[(folder, name)] = content.ToArray();
    }

    /// <inheritdoc/>
    public byte[]? ReadFile(DataFolder folder, string name, int maxLength)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxLength);
        if (!_files.TryGetValue((folder, name), out var content))
        {
            return null;
        }

        return content.Length <= maxLength
            ? content.ToArray()
            : throw new SecureStoreException($@"{RootPath}\{name} is {content.Length} bytes long, more than the {maxLength} bytes the tool reads from it.");
    }

    /// <inheritdoc/>
    public IScratchFolder CreateScratchFolder()
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        var folder = new FakeScratchFolder($@"{RootPath}\scratch\{_scratchFolders.Count:x32}");
        _scratchFolders.Add(folder);
        return folder;
    }

    /// <inheritdoc/>
    public IReadOnlyList<string> DeleteTree(DataFolder folder, string name)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        _ = _files.Remove((folder, name));
        return [];
    }

    /// <inheritdoc/>
    public void Dispose() => IsDisposed = true;

    /// <summary>A scratch folder in memory.</summary>
    public sealed class FakeScratchFolder : IScratchFolder
    {
        private readonly Dictionary<string, byte[]> _files = new(StringComparer.OrdinalIgnoreCase);

        internal FakeScratchFolder(string path) => Path = path;

        /// <inheritdoc/>
        public string Path { get; }

        /// <summary>Gets the files in it, by name.</summary>
        public IReadOnlyDictionary<string, byte[]> Files => _files;

        /// <summary>Gets whether it has been disposed, which deletes the real one.</summary>
        public bool IsDisposed { get; private set; }

        /// <inheritdoc/>
        public string PathOf(string name) => Path + @"\" + name;

        /// <inheritdoc/>
        public void WriteFile(string name, ReadOnlySpan<byte> content)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            _files[name] = content.ToArray();
        }

        /// <summary>Puts a file in it, as a tool run with it would.</summary>
        /// <param name="name">The name.</param>
        /// <param name="content">The content.</param>
        public void Plant(string name, byte[] content) => _files[name] = content;

        /// <inheritdoc/>
        public byte[]? ReadFile(string name, int maxLength)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxLength);
            return _files.TryGetValue(name, out var content) ? content.ToArray() : null;
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            IsDisposed = true;
            _files.Clear();
        }
    }
}
