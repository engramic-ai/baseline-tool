using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// A disk in the hardware block of status.json.
/// </summary>
public sealed record StatusDisk
{
    /// <summary>Gets the model of the disk.</summary>
    [JsonPropertyName("model")]
    public required string Model { get; init; }

    /// <summary>Gets the firmware revision of the disk.</summary>
    [JsonPropertyName("firmware")]
    public required string Firmware { get; init; }
}
