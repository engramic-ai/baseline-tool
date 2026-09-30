using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// How much a failing finding matters, written by name in findings.json.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<Severity>))]
public enum Severity
{
    /// <summary>Fails the device on its own.</summary>
    [JsonStringEnumMemberName("Critical")]
    Critical,

    /// <summary>A serious gap.</summary>
    [JsonStringEnumMemberName("High")]
    High,

    /// <summary>A gap worth fixing.</summary>
    [JsonStringEnumMemberName("Medium")]
    Medium,

    /// <summary>A minor gap.</summary>
    [JsonStringEnumMemberName("Low")]
    Low,

    /// <summary>No gap: the severity of every finding that passes, does not apply or only informs.</summary>
    [JsonStringEnumMemberName("Info")]
    Info,
}
