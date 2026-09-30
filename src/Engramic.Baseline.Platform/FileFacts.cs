namespace Engramic.Baseline.Platform;

/// <summary>
/// What a handle tells about the file or folder it is open on: read through the handle, never by path, so
/// it describes the item itself and not what a link leads to.
/// </summary>
public sealed record FileFacts
{
    /// <summary>Gets whether it is a folder.</summary>
    public bool IsDirectory { get; init; }

    /// <summary>Gets whether it is a reparse point: a junction, a symbolic link, a cloud file or any other kind.</summary>
    public bool IsReparsePoint { get; init; }

    /// <summary>
    /// Gets whether it is stored online only (offline, or recalled when opened or read), so that opening
    /// it would fetch it from elsewhere.
    /// </summary>
    public bool IsOnlineOnly { get; init; }

    /// <summary>Gets how many names (hard links) the file has: 1 for an ordinary file.</summary>
    public uint LinkCount { get; init; } = 1;

    /// <summary>Gets whether it has the read-only attribute.</summary>
    public bool IsReadOnly { get; init; }

    /// <summary>Gets the size of the file's content in bytes (its end of file); 0 for a folder.</summary>
    public long Length { get; init; }
}
