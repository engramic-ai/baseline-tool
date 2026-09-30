using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// The estimate for one Cyber Essentials Plus test case, written as its words in status.json.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<CePlusState>))]
public enum CePlusState
{
    /// <summary>No finding that ran evidences the test case.</summary>
    [JsonStringEnumMemberName("Not assessed")]
    NotAssessed,

    /// <summary>A finding that evidences the test case fails.</summary>
    [JsonStringEnumMemberName("Likely fail")]
    LikelyFail,

    /// <summary>Nothing fails, but something needs checking, attesting or running again.</summary>
    [JsonStringEnumMemberName("Check")]
    Check,

    /// <summary>Everything that evidences the test case passes.</summary>
    [JsonStringEnumMemberName("Likely pass")]
    LikelyPass,
}
