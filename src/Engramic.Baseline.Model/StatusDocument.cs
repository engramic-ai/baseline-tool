using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// status.json, schema 1: the compact result of a machine audit that the Intune scripts read.
/// </summary>
/// <remarks>
/// Every key and its casing is fixed by the Intune discovery and detection scripts already deployed in
/// tenants, so each is named explicitly rather than by a naming policy. The checks are the source of
/// truth; the framework rollups are derived from them. <see cref="StatusFile"/> writes the file.
/// </remarks>
public sealed record StatusDocument
{
    /// <summary>The schema this type writes, which the Intune scripts require.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>Gets the schema version, 1.</summary>
    [JsonPropertyName("schemaVersion")]
    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    /// <summary>Gets the version of the tool that wrote the file.</summary>
    [JsonPropertyName("toolVersion")]
    public required string ToolVersion { get; init; }

    /// <summary>Gets what was audited: always the machine in status.json.</summary>
    [JsonPropertyName("scope")]
    public CheckScope Scope { get; init; } = CheckScope.Machine;

    /// <summary>Gets the platform, windows.</summary>
    [JsonPropertyName("platform")]
    public string Platform { get; init; } = "windows";

    /// <summary>Gets the name of the computer.</summary>
    [JsonPropertyName("computerName")]
    public required string ComputerName { get; init; }

    /// <summary>Gets when the audit started, written in UTC in the round-trip format.</summary>
    [JsonPropertyName("auditTime")]
    [JsonConverter(typeof(IsoUtcTimeConverter))]
    public required DateTimeOffset AuditTime { get; init; }

    /// <summary>Gets the account the audit ran as, such as NT AUTHORITY\SYSTEM.</summary>
    [JsonPropertyName("runAs")]
    public required string RunAs { get; init; }

    /// <summary>Gets whether the audit ran elevated or as SYSTEM.</summary>
    [JsonPropertyName("elevated")]
    public required bool Elevated { get; init; }

    /// <summary>Gets the operating system in words, such as "Windows 11 24H2 Professional (26100.4946)".</summary>
    [JsonPropertyName("os")]
    public required string Os { get; init; }

    /// <summary>Gets the number of findings with each status.</summary>
    [JsonPropertyName("counts")]
    public required StatusCounts Counts { get; init; }

    /// <summary>Gets the number of auto-fail checks that fail or could not run.</summary>
    [JsonPropertyName("autoFailCount")]
    public int AutoFailCount => AutoFails.Count;

    /// <summary>Gets the identifiers of the auto-fail checks that fail or could not run, in identifier order.</summary>
    [JsonPropertyName("autoFails")]
    public required IReadOnlyList<string> AutoFails { get; init; }

    /// <summary>Gets each check that ran, by identifier, with its worst status.</summary>
    [JsonPropertyName("checks")]
    public required IReadOnlyDictionary<string, StatusCheck> Checks { get; init; }

    /// <summary>Gets the rollup of each framework the checks evidence.</summary>
    [JsonPropertyName("frameworks")]
    public required StatusFrameworks Frameworks { get; init; }

    /// <summary>Gets a summary of the hardware, or null when it was not read.</summary>
    [JsonPropertyName("hardware")]
    public StatusHardware? Hardware { get; init; }

    /// <summary>
    /// Gets the feature packs that were loaded: always empty, as code packs are retired, but kept for schema 1.
    /// Reading a file the PowerShell tool wrote with packs in it leaves this empty.
    /// </summary>
    [JsonPropertyName("packs")]
    public IReadOnlyList<string> Packs { get; } = [];

    /// <summary>Gets the folder of the full report, or empty when none was written.</summary>
    [JsonPropertyName("reportFolder")]
    public required string ReportFolder { get; init; }
}
