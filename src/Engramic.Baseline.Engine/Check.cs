namespace Engramic.Baseline.Engine;

/// <summary>
/// A check: one requirement, tested on this device. It gives one or more results, which the runner turns
/// into findings with the check's details.
/// </summary>
/// <remarks>
/// A check is registered in the catalog explicitly, never found by reflection. It reads the device only
/// through what <see cref="CheckContext"/> gives it. An exception it throws, or an empty result, becomes an
/// Error finding; it never stops the audit.
/// </remarks>
public abstract class Check
{
    /// <summary>Gets what the check is.</summary>
    public abstract CheckInfo Info { get; }

    /// <summary>Tells whether the check applies to a device. Applies by default.</summary>
    /// <param name="device">What is known about the device.</param>
    /// <returns>Whether it applies, and if not, why not.</returns>
    public virtual Applicability AppliesTo(DeviceContext device) => Applicability.Applicable;

    /// <summary>Runs the check.</summary>
    /// <param name="context">What the check may use.</param>
    /// <param name="cancel">Cancelled when the audit stops or the check runs out of time.</param>
    /// <returns>At least one result.</returns>
    public abstract ValueTask<IReadOnlyList<CheckResult>> RunAsync(CheckContext context, CancellationToken cancel);

    /// <summary>Names the check, for a test or a log.</summary>
    /// <returns>The identifier and the title.</returns>
    public override string ToString() => $"{Info.Id} {Info.Title}";
}
