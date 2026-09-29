namespace Engramic.Baseline.Engine;

/// <summary>
/// Everything a check may use, and nothing else: the device context, the typed config, the clock and the
/// not-read log. Readers of the operating system join as the checks that need them are ported.
/// </summary>
public sealed class CheckContext
{
    /// <summary>Makes the context the checks of an audit are given.</summary>
    /// <param name="device">What is known about the device.</param>
    /// <param name="config">The config the checks read.</param>
    /// <param name="time">The clock: checks never read the system clock directly, so tests can set the time.</param>
    /// <param name="notRead">The log of what could not be read; a new one when null.</param>
    public CheckContext(DeviceContext device, AuditConfig config, TimeProvider time, NotReadLog? notRead = null)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(time);
        Device = device;
        Config = config;
        Time = time;
        NotRead = notRead ?? new NotReadLog();
    }

    /// <summary>Gets what is known about the device.</summary>
    public DeviceContext Device { get; }

    /// <summary>Gets the config the checks read.</summary>
    public AuditConfig Config { get; }

    /// <summary>Gets the clock.</summary>
    public TimeProvider Time { get; }

    /// <summary>Gets the log of what could not be read.</summary>
    public NotReadLog NotRead { get; }
}
