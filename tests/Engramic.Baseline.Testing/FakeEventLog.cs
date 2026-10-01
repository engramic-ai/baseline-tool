using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Testing;

/// <summary>
/// An event log in memory: it keeps each entry written, so that no test writes to the real Application log,
/// and can be made to refuse them.
/// </summary>
public sealed class FakeEventLog : IEventLog
{
    private readonly List<(int Id, EventLogLevel Level, string Message)> _entries = [];

    /// <summary>Gets the entries written, in order.</summary>
    public IReadOnlyList<(int Id, EventLogLevel Level, string Message)> Entries => _entries;

    /// <summary>Gets or sets whether writes fail, as they do where the log cannot be written.</summary>
    public bool Refuses { get; set; }

    /// <inheritdoc/>
    public bool Write(int eventId, EventLogLevel level, string message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (Refuses)
        {
            return false;
        }

        _entries.Add((eventId, level, message));
        return true;
    }
}
