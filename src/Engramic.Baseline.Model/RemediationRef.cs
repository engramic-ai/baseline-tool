using System.Text.Json;
using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// Points a finding at the fix that would resolve it, with the values the fix takes.
/// </summary>
/// <remarks>
/// The shape findings.json and changeset.json use today. The values stay as JSON until the fixes are
/// ported with typed parameter records, which validate them again before anything is applied.
/// </remarks>
public sealed record RemediationRef
{
    /// <summary>Gets the identifier of the fix, such as WindowsUpdate-Resume.</summary>
    [JsonPropertyName("Id")]
    public required string Id { get; init; }

    /// <summary>Gets the values the fix takes, by name. Empty when it takes none.</summary>
    [JsonPropertyName("Parameters")]
    public IReadOnlyDictionary<string, JsonElement> Parameters { get; init; } = new Dictionary<string, JsonElement>();
}
