using Engramic.Baseline.Model;

namespace Engramic.Baseline.Engine;

/// <summary>
/// One result a check gives. The runner adds the check's details to make a <see cref="Finding"/>.
/// </summary>
/// <param name="Status">The outcome.</param>
public sealed record CheckResult(FindingStatus Status)
{
    /// <summary>Gets what the requirement expects.</summary>
    public string Expected { get; init; } = string.Empty;

    /// <summary>Gets what the check found.</summary>
    public string Actual { get; init; } = string.Empty;

    /// <summary>Gets what to do about it.</summary>
    public string Recommendation { get; init; } = string.Empty;

    /// <summary>
    /// Gets what this result is about when the check gives several, such as an account or an app. It
    /// becomes part of the finding identifier, so keep it stable from run to run.
    /// </summary>
    public string Subject { get; init; } = string.Empty;

    /// <summary>Gets the details behind the result, one line each.</summary>
    public IReadOnlyList<string> Evidence { get; init; } = [];

    /// <summary>Gets the severity of this result when it differs from the check's; otherwise null.</summary>
    public Severity? Severity { get; init; }

    /// <summary>Gets the fix that would resolve the result, or null.</summary>
    public RemediationRef? Remediation { get; init; }
}
