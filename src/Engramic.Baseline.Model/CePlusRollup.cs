using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// The Cyber Essentials Plus entry of the frameworks block: an estimate for each test case.
/// </summary>
public sealed record CePlusRollup
{
    /// <summary>Gets the name of the framework, Cyber Essentials Plus.</summary>
    [JsonPropertyName("label")]
    public string Label { get; init; } = "Cyber Essentials Plus";

    /// <summary>Gets the estimate for each test case.</summary>
    [JsonPropertyName("tcs")]
    public required CePlusTestCaseStates TestCases { get; init; }

    /// <summary>Gets the number of test cases estimated as likely to pass.</summary>
    [JsonPropertyName("onTrack")]
    public int OnTrack => TestCases.All.Count(s => s == CePlusState.LikelyPass);

    /// <summary>Gets the number of test cases, 5.</summary>
    [JsonPropertyName("total")]
    public int Total => TestCases.All.Count;
}
