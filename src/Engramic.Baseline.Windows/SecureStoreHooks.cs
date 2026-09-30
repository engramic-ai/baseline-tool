namespace Engramic.Baseline.Windows;

/// <summary>
/// Points where a test can step into SecureStore's write, to stage what an attacker could do between two
/// of its steps. Product code never sets them.
/// </summary>
internal sealed class SecureStoreHooks
{
    /// <summary>
    /// Gets the name to give the new file instead of a random one, from the target's name, so that a test
    /// can plant something at that name first.
    /// </summary>
    public Func<string, string>? TemporaryName { get; init; }

    /// <summary>
    /// Gets what to do just before each attempt to rename the new file over the target, given the target's
    /// path and the attempt's number from 1: after the target was checked, so a test can swap it.
    /// </summary>
    public Action<string, int>? BeforeRename { get; init; }
}
