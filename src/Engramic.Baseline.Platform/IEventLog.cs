namespace Engramic.Baseline.Platform;

/// <summary>
/// The Application event log, under the tool's event source: where the tool records what it did that an
/// administrator should know about, such as moving an untrusted folder aside (event 1003).
/// </summary>
/// <remarks>
/// Engramic.Baseline.Windows has the implementation, WindowsEventLog; the tests share a fake, so no test
/// writes to the real log.
/// </remarks>
public interface IEventLog
{
    /// <summary>Writes an entry. A failure to write is not an error for the caller, only a false result.</summary>
    /// <param name="eventId">The event's identifier, such as 1003.</param>
    /// <param name="level">How serious it is.</param>
    /// <param name="message">What happened, in full sentences.</param>
    /// <returns>True when Windows accepted the entry.</returns>
    bool Write(int eventId, EventLogLevel level, string message);
}
