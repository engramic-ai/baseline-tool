using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// The frameworks block of status.json. A framework none of the checks evidences is left out.
/// </summary>
public sealed record StatusFrameworks
{
    /// <summary>Gets the Cyber Essentials v3.3 rollup, or null when no check evidences it.</summary>
    [JsonPropertyName("ce-v3.3")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public FrameworkRollup? CeV33 { get; init; }

    /// <summary>Gets the NCSC device hardening rollup, or null when no check evidences it.</summary>
    [JsonPropertyName("ncsc")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public FrameworkRollup? Ncsc { get; init; }

    /// <summary>Gets the Cyber Essentials Plus test case estimates, or null when there are none.</summary>
    [JsonPropertyName("ce-plus")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CePlusRollup? CePlus { get; init; }
}
