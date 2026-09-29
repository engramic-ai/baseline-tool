namespace Engramic.Baseline.Engine;

/// <summary>
/// What could not be read in an audit, so a check can say that something may be missing from its result
/// instead of reporting that nothing was found.
/// </summary>
/// <remarks>
/// Records with the same location, kind, reason and topic are kept as one record with a count, as in the
/// PowerShell tool. A reason is a fixed text, never error text or file contents.
/// </remarks>
public sealed class NotReadLog
{
    private readonly Lock _gate = new();
    private readonly List<NotReadRecord> _records = [];
    private readonly Dictionary<(string Location, NotReadKind Kind, string Reason, string Topic), int> _index = [];

    /// <summary>Gets the records, in the order first added.</summary>
    public IReadOnlyList<NotReadRecord> Records
    {
        get
        {
            lock (_gate)
            {
                return [.. _records];
            }
        }
    }

    /// <summary>Records that a location was not read.</summary>
    /// <param name="location">Where, as reports show it, such as %USERPROFILE%\.vscode\extensions.</param>
    /// <param name="kind">What was not read there.</param>
    /// <param name="reason">Why, as a fixed text.</param>
    /// <param name="topic">What the location would have told, such as the AI tools it holds.</param>
    /// <param name="remedy">What would let it be read, or empty.</param>
    /// <param name="needsUserSession">Whether it can be read only in the user's own session.</param>
    public void Add(string location, NotReadKind kind, string reason, string topic, string remedy = "", bool needsUserSession = false)
    {
        ArgumentNullException.ThrowIfNull(location);
        ArgumentNullException.ThrowIfNull(reason);
        ArgumentNullException.ThrowIfNull(topic);
        ArgumentNullException.ThrowIfNull(remedy);
        var key = (location, kind, reason, topic);
        lock (_gate)
        {
            if (_index.TryGetValue(key, out var at))
            {
                _records[at] = _records[at] with { Count = _records[at].Count + 1 };
                return;
            }

            _index[key] = _records.Count;
            _records.Add(new NotReadRecord(location, kind, reason, remedy, topic, needsUserSession, 1));
        }
    }
}

/// <summary>What was not read at a location.</summary>
public enum NotReadKind
{
    /// <summary>The names in a folder.</summary>
    FolderListing,

    /// <summary>The contents of a file.</summary>
    FileContent,

    /// <summary>Whether something is there at all.</summary>
    Existence,
}

/// <summary>A location that was not read, with how many times it was met.</summary>
/// <param name="Location">Where, as reports show it.</param>
/// <param name="Kind">What was not read there.</param>
/// <param name="Reason">Why, as a fixed text.</param>
/// <param name="Remedy">What would let it be read, or empty.</param>
/// <param name="Topic">What the location would have told.</param>
/// <param name="NeedsUserSession">Whether it can be read only in the user's own session.</param>
/// <param name="Count">How many times it was met.</param>
public sealed record NotReadRecord(
    string Location,
    NotReadKind Kind,
    string Reason,
    string Remedy,
    string Topic,
    bool NeedsUserSession,
    int Count);
