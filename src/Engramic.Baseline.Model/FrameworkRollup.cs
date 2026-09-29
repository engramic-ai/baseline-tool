using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// How the checks that evidence one framework stand, counted by check rather than by finding.
/// </summary>
public sealed record FrameworkRollup
{
    /// <summary>Gets the name of the framework, such as Cyber Essentials v3.3.</summary>
    [JsonPropertyName("label")]
    public required string Label { get; init; }

    /// <summary>Gets the checks that apply: met, attention and confirm together.</summary>
    [JsonPropertyName("applicable")]
    public int Applicable => Met + Attention + Confirm;

    /// <summary>Gets the checks that pass.</summary>
    [JsonPropertyName("met")]
    public required int Met { get; init; }

    /// <summary>Gets the checks that fail, warn or could not run.</summary>
    [JsonPropertyName("attention")]
    public required int Attention { get; init; }

    /// <summary>Gets the checks someone has to confirm or attest.</summary>
    [JsonPropertyName("confirm")]
    public required int Confirm { get; init; }

    /// <summary>Gets the checks that do not apply, only inform or were skipped.</summary>
    [JsonPropertyName("notApplicable")]
    public required int NotApplicable { get; init; }

    /// <summary>
    /// Gets the share of applicable checks that pass, as a whole percentage rounded half to even like the
    /// PowerShell tool's [math]::Round; 0 when none applies.
    /// </summary>
    [JsonPropertyName("metPct")]
    public int MetPct => Applicable > 0 ? (int)Math.Round((double)Met / Applicable * 100) : 0;
}
