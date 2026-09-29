using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// The outcome of a finding, written by name in findings.json and status.json.
/// </summary>
/// <remarks>
/// The members are in the PowerShell tool's order, which the counts in status.json keep. Each name is
/// fixed in the file format, so renaming a member does not change what is written.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<FindingStatus>))]
public enum FindingStatus
{
    /// <summary>The device meets the requirement.</summary>
    [JsonStringEnumMemberName("Pass")]
    Pass,

    /// <summary>The device does not meet the requirement.</summary>
    [JsonStringEnumMemberName("Fail")]
    Fail,

    /// <summary>The requirement is met for now, or only partly, and needs attention.</summary>
    [JsonStringEnumMemberName("Warn")]
    Warn,

    /// <summary>Someone has to confirm or attest the requirement.</summary>
    [JsonStringEnumMemberName("Manual")]
    Manual,

    /// <summary>Information that is neither a pass nor a failure.</summary>
    [JsonStringEnumMemberName("Info")]
    Info,

    /// <summary>The requirement does not apply to this device.</summary>
    [JsonStringEnumMemberName("NotApplicable")]
    NotApplicable,

    /// <summary>The check did not run, for example because it needs elevation.</summary>
    [JsonStringEnumMemberName("Skipped")]
    Skipped,

    /// <summary>The check failed to run to the end.</summary>
    [JsonStringEnumMemberName("Error")]
    Error,
}
