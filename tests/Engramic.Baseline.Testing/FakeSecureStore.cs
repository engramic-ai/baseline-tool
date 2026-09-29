using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Testing;

/// <summary>
/// A data folder in memory, for code that writes through SecureStore: it keeps what is written, by name,
/// and can be made to refuse a write.
/// </summary>
public sealed class FakeSecureStore : ISecureStore
{
    private readonly Dictionary<string, byte[]> _files = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Makes the store.</summary>
    /// <param name="rootPath">The path it reports for the data folder.</param>
    public FakeSecureStore(string rootPath = @"C:\ProgramData\EngramicBaseline") => RootPath = rootPath;

    /// <inheritdoc/>
    public string RootPath { get; }

    /// <summary>Gets the files written, by name, each with its whole content.</summary>
    public IReadOnlyDictionary<string, byte[]> Files => _files;

    /// <summary>Gets or sets what a write throws, such as a SecureStoreException; null to write.</summary>
    public Exception? WriteError { get; set; }

    /// <summary>Gets or sets what runs at each write, before it is kept, such as a check the caller holds a lock.</summary>
    public Action<string>? OnWrite { get; set; }

    /// <summary>Gets whether it has been disposed.</summary>
    public bool IsDisposed { get; private set; }

    /// <inheritdoc/>
    public void WriteFile(string name, ReadOnlySpan<byte> content)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        OnWrite?.Invoke(name);
        if (WriteError is not null)
        {
            throw WriteError;
        }

        _files[name] = content.ToArray();
    }

    /// <inheritdoc/>
    public void Dispose() => IsDisposed = true;
}
