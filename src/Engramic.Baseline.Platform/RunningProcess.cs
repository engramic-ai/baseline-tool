namespace Engramic.Baseline.Platform;

/// <summary>
/// A process running on this device, as the process list read it: from the process table, then from the
/// process and its access token opened with query-only access.
/// </summary>
/// <remarks>
/// What this account may not read stays null: a process of another account, unless the reader is elevated or
/// SYSTEM; the token of a protected process; or a process that ended while the list was read. A process
/// identifier can be reused once its process ends, so a process is described as it was when it was opened.
/// </remarks>
public sealed record RunningProcess
{
    /// <summary>Gets the process identifier.</summary>
    public required uint Id { get; init; }

    /// <summary>Gets the identifier of the process that started it, which may since have ended or been reused.</summary>
    public required uint ParentId { get; init; }

    /// <summary>Gets the file name of its image from the process table, such as claude.exe, or System.</summary>
    public required string ImageName { get; init; }

    /// <summary>Gets the full path of its image, such as C:\Program Files\Claude\claude.exe, when it could be read.</summary>
    public string? ImagePath { get; init; }

    /// <summary>Gets its command line, as the process holds it now, when it could be read.</summary>
    public string? CommandLine { get; init; }

    /// <summary>Gets the session it runs in (0 for services), when it could be read.</summary>
    public uint? SessionId { get; init; }

    /// <summary>Gets the account it runs as, from its access token, when the token could be read.</summary>
    public Sid? Owner { get; init; }

    /// <summary>Gets whether its token is elevated (an administrator's full token, or SYSTEM's), when the token could be read.</summary>
    public bool? IsElevated { get; init; }
}
