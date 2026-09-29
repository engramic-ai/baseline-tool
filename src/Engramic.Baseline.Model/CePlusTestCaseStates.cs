using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// The estimate for each of the five Cyber Essentials Plus test cases, keyed TC1 to TC5 in status.json.
/// </summary>
public sealed record CePlusTestCaseStates
{
    /// <summary>Gets the estimate for TC1, the remote vulnerability assessment.</summary>
    [JsonPropertyName("TC1")]
    public required CePlusState TC1 { get; init; }

    /// <summary>Gets the estimate for TC2, patching.</summary>
    [JsonPropertyName("TC2")]
    public required CePlusState TC2 { get; init; }

    /// <summary>Gets the estimate for TC3, malware protection.</summary>
    [JsonPropertyName("TC3")]
    public required CePlusState TC3 { get; init; }

    /// <summary>Gets the estimate for TC4, multi-factor authentication.</summary>
    [JsonPropertyName("TC4")]
    public required CePlusState TC4 { get; init; }

    /// <summary>Gets the estimate for TC5, account separation.</summary>
    [JsonPropertyName("TC5")]
    public required CePlusState TC5 { get; init; }

    /// <summary>Gets the five estimates, TC1 first.</summary>
    [JsonIgnore]
    public IReadOnlyList<CePlusState> All => [TC1, TC2, TC3, TC4, TC5];
}
