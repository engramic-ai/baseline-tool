using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// What a check assesses, written by name in findings.json and status.json.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<CheckScope>))]
public enum CheckScope
{
    /// <summary>The device, whoever runs the audit, including SYSTEM.</summary>
    [JsonStringEnumMemberName("Machine")]
    Machine,

    /// <summary>
    /// What the signed-in person has set up for themselves, such as their AI tools, which only their own
    /// session can see.
    /// </summary>
    [JsonStringEnumMemberName("User")]
    User,
}
