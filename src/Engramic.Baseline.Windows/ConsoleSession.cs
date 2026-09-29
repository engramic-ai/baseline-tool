using Windows.Win32;

namespace Engramic.Baseline.Windows;

/// <summary>
/// The session attached to the physical console, where the person at the device signs in.
/// </summary>
public static class ConsoleSession
{
    private const uint NoSession = 0xFFFFFFFF;

    /// <summary>Gets the identifier of the session attached to the physical console.</summary>
    /// <returns>
    /// The session identifier, or null while no session is attached, as during a switch between sessions.
    /// Never 0, which is the session of services.
    /// </returns>
    public static uint? GetActiveSessionId()
    {
        var id = PInvoke.WTSGetActiveConsoleSessionId();
        return id == NoSession ? null : id;
    }
}
