using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// The number of findings with each status, the counts block of status.json. Every status is written,
/// including those with no findings.
/// </summary>
public sealed record StatusCounts
{
    /// <summary>Gets the number of findings that pass.</summary>
    [JsonPropertyName("Pass")]
    public int Pass { get; init; }

    /// <summary>Gets the number of findings that fail.</summary>
    [JsonPropertyName("Fail")]
    public int Fail { get; init; }

    /// <summary>Gets the number of findings that warn.</summary>
    [JsonPropertyName("Warn")]
    public int Warn { get; init; }

    /// <summary>Gets the number of findings to confirm or attest.</summary>
    [JsonPropertyName("Manual")]
    public int Manual { get; init; }

    /// <summary>Gets the number of findings that only inform.</summary>
    [JsonPropertyName("Info")]
    public int Info { get; init; }

    /// <summary>Gets the number of findings that do not apply.</summary>
    [JsonPropertyName("NotApplicable")]
    public int NotApplicable { get; init; }

    /// <summary>Gets the number of findings of checks that did not run.</summary>
    [JsonPropertyName("Skipped")]
    public int Skipped { get; init; }

    /// <summary>Gets the number of findings of checks that failed to run.</summary>
    [JsonPropertyName("Error")]
    public int Error { get; init; }

    /// <summary>Counts findings by status.</summary>
    /// <param name="statuses">The status of each finding.</param>
    /// <returns>The counts.</returns>
    public static StatusCounts Of(IEnumerable<FindingStatus> statuses)
    {
        ArgumentNullException.ThrowIfNull(statuses);
        var counts = new int[Enum.GetValues<FindingStatus>().Length];
        foreach (var status in statuses)
        {
            counts[(int)status]++;
        }

        return new StatusCounts
        {
            Pass = counts[(int)FindingStatus.Pass],
            Fail = counts[(int)FindingStatus.Fail],
            Warn = counts[(int)FindingStatus.Warn],
            Manual = counts[(int)FindingStatus.Manual],
            Info = counts[(int)FindingStatus.Info],
            NotApplicable = counts[(int)FindingStatus.NotApplicable],
            Skipped = counts[(int)FindingStatus.Skipped],
            Error = counts[(int)FindingStatus.Error],
        };
    }
}
