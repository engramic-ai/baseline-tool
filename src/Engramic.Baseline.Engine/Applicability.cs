namespace Engramic.Baseline.Engine;

/// <summary>
/// Whether a check applies to a device, and if not, why not. A check that does not apply gives one
/// NotApplicable finding with the reason, and is not run.
/// </summary>
public sealed record Applicability
{
    /// <summary>The reason given when a check does not say why it does not apply.</summary>
    public const string DefaultReason = "Not applicable to this device.";

    private Applicability(bool isApplicable, string reason)
    {
        IsApplicable = isApplicable;
        Reason = reason;
    }

    /// <summary>Gets the applicability of a check that applies.</summary>
    public static Applicability Applicable { get; } = new(true, string.Empty);

    /// <summary>Gets whether the check applies.</summary>
    public bool IsApplicable { get; }

    /// <summary>Gets why the check does not apply; empty when it does.</summary>
    public string Reason { get; }

    /// <summary>Says that a check does not apply.</summary>
    /// <param name="reason">Why not, as the finding shows it.</param>
    /// <returns>The applicability.</returns>
    public static Applicability NotApplicable(string reason = DefaultReason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new Applicability(false, reason);
    }
}
