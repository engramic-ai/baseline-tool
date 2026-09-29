using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// One result of one check, with the check's details: an entry of findings.json.
/// </summary>
/// <remarks>
/// All 17 fields of the PowerShell tool's findings, in its order and with its names. Changesets and
/// reports refer to a finding by <see cref="FindingId"/>, so its rule never changes.
/// </remarks>
public sealed record Finding
{
    /// <summary>Gets the identifier: the check's, or the check's, a colon and a slug of the subject.</summary>
    [JsonPropertyName("FindingId")]
    public required string FindingId { get; init; }

    /// <summary>Gets the identifier of the check, such as SU-01.</summary>
    [JsonPropertyName("CheckId")]
    public required string CheckId { get; init; }

    /// <summary>Gets the title of the check.</summary>
    [JsonPropertyName("Title")]
    public required string Title { get; init; }

    /// <summary>Gets what this result is about when a check has several, such as an account; otherwise empty.</summary>
    [JsonPropertyName("Subject")]
    public required string Subject { get; init; }

    /// <summary>Gets the theme of the check.</summary>
    [JsonPropertyName("Category")]
    public required CheckCategory Category { get; init; }

    /// <summary>Gets the frameworks the check evidences, such as CE v3.3, CE+ TC2 or NCSC.</summary>
    [JsonPropertyName("Frameworks")]
    public required IReadOnlyList<string> Frameworks { get; init; }

    /// <summary>Gets where the requirement comes from, in words.</summary>
    [JsonPropertyName("Reference")]
    public required string Reference { get; init; }

    /// <summary>Gets what the check assesses: the device or the signed-in person's own set-up.</summary>
    [JsonPropertyName("Scope")]
    public required CheckScope Scope { get; init; }

    /// <summary>Gets the outcome.</summary>
    [JsonPropertyName("Status")]
    public required FindingStatus Status { get; init; }

    /// <summary>Gets the severity, which is <see cref="Model.Severity.Info"/> for a result that passes, does not apply or only informs.</summary>
    [JsonPropertyName("Severity")]
    public required Severity Severity { get; init; }

    /// <summary>Gets whether this result fails a Cyber Essentials assessment outright: a failing result of an auto-fail check.</summary>
    [JsonPropertyName("AutoFail")]
    public required bool AutoFail { get; init; }

    /// <summary>Gets what the requirement expects.</summary>
    [JsonPropertyName("Expected")]
    public required string Expected { get; init; }

    /// <summary>Gets what the check found.</summary>
    [JsonPropertyName("Actual")]
    public required string Actual { get; init; }

    /// <summary>Gets what to do about it; empty when there is nothing to do.</summary>
    [JsonPropertyName("Recommendation")]
    public required string Recommendation { get; init; }

    /// <summary>Gets the details behind the result, one line each.</summary>
    [JsonPropertyName("Evidence")]
    public required IReadOnlyList<string> Evidence { get; init; }

    /// <summary>Gets the fix that would resolve the finding, or null when there is none.</summary>
    [JsonPropertyName("Remediation")]
    public RemediationRef? Remediation { get; init; }

    /// <summary>Gets the feature pack that added the check. Always null: code packs are retired, and the field stays for the file format.</summary>
    [JsonPropertyName("Pack")]
    public string? Pack { get; init; }
}
