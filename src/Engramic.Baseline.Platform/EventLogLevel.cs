namespace Engramic.Baseline.Platform;

/// <summary>
/// How serious an entry in the event log is, as the PowerShell tool's Write-CEEventEntry names it.
/// </summary>
public enum EventLogLevel
{
    /// <summary>Something failed.</summary>
    Error,

    /// <summary>Something an administrator should look at, such as an untrusted folder moved aside.</summary>
    Warning,

    /// <summary>Something that went as it should.</summary>
    Information,
}
