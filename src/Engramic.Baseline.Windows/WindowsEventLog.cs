using Engramic.Baseline.Platform;
using Windows.Win32;
using Windows.Win32.System.EventLog;

namespace Engramic.Baseline.Windows;

/// <summary>
/// The Application event log on Windows, written under one event source with the RegisterEventSource and
/// ReportEvent calls the PowerShell tool's Write-CEEventEntry makes.
/// </summary>
/// <remarks>
/// EventLog.WriteEntry is not used: it lists every log to find the source's, and fails where the Security
/// log cannot be read, even for SYSTEM. A source the install has not registered still works, as the module
/// relies on: Windows records the entry in the Application log with the message as its text. A message is
/// cut to 31,000 characters, as the module cuts it.
/// </remarks>
public sealed class WindowsEventLog : IEventLog
{
    /// <summary>The tool's event source, which the installer registers in the Application log.</summary>
    public const string ProductSource = "EngramicBaseline";

    private const int MaxMessageLength = 31_000;

    /// <summary>Makes the log for an event source.</summary>
    /// <param name="source">The event source: <see cref="ProductSource"/> for the product.</param>
    public WindowsEventLog(string source)
    {
        ArgumentException.ThrowIfNullOrEmpty(source);
        Source = source;
    }

    /// <summary>Gets the event source entries are written under.</summary>
    public string Source { get; }

    /// <inheritdoc/>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="eventId"/> is not between 0 and 65535, or <paramref name="level"/> is not a level.</exception>
    public bool Write(int eventId, EventLogLevel level, string message)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(eventId);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(eventId, ushort.MaxValue);
        ArgumentNullException.ThrowIfNull(message);
        var type = level switch
        {
            EventLogLevel.Error => REPORT_EVENT_TYPE.EVENTLOG_ERROR_TYPE,
            EventLogLevel.Warning => REPORT_EVENT_TYPE.EVENTLOG_WARNING_TYPE,
            EventLogLevel.Information => REPORT_EVENT_TYPE.EVENTLOG_INFORMATION_TYPE,
            _ => throw new ArgumentOutOfRangeException(nameof(level), level, "Not a level of an event."),
        };
        var text = message.Length > MaxMessageLength ? message[..MaxMessageLength] : message;
        using var source = PInvoke.RegisterEventSource(null, Source);
        return !source.IsInvalid && PInvoke.ReportEvent(source, type, 0, (uint)eventId, default, [text], default);
    }
}
