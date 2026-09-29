using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// findings.json: every finding of an audit.
/// </summary>
/// <remarks>
/// The PowerShell tool's findings.json also holds the device context and the audit summary. They join
/// this document when the reports are ported; the findings already have the same name and shape.
/// </remarks>
public sealed record FindingsDocument
{
    /// <summary>Gets the findings, in the order the checks ran.</summary>
    [JsonPropertyName("Findings")]
    public required IReadOnlyList<Finding> Findings { get; init; }
}
