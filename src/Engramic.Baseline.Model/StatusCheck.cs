using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// One check in status.json: its worst status and what the Intune rules need to judge it.
/// </summary>
public sealed record StatusCheck
{
    /// <summary>Gets the worst status among the check's findings.</summary>
    [JsonPropertyName("status")]
    public required FindingStatus Status { get; init; }

    /// <summary>Gets the frameworks the check evidences.</summary>
    [JsonPropertyName("frameworks")]
    public required IReadOnlyList<string> Frameworks { get; init; }

    /// <summary>Gets what the check assesses.</summary>
    [JsonPropertyName("scope")]
    public required CheckScope Scope { get; init; }

    /// <summary>Gets whether the check is an auto-fail check, whatever its status.</summary>
    [JsonPropertyName("autoFail")]
    public required bool AutoFail { get; init; }
}
