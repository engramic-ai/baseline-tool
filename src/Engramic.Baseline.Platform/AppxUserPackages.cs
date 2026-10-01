namespace Engramic.Baseline.Platform;

/// <summary>
/// The Store packages registered for one user, or why they could not be read.
/// </summary>
/// <param name="User">The user's security identifier.</param>
/// <param name="Outcome">Whether the packages were read.</param>
/// <param name="Packages">The packages, in full-name order; empty unless <paramref name="Outcome"/> is Read.</param>
/// <param name="Detail">Why the packages could not be read, or what the source passed over; empty when there is nothing to say.</param>
public sealed record AppxUserPackages(Sid User, AppxReadOutcome Outcome, IReadOnlyList<AppxPackage> Packages, string Detail);
