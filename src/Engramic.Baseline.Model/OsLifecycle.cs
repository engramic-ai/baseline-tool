using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// config/os-lifecycle.json: when each Windows release stops being supported, which SU-01 judges against.
/// </summary>
/// <remarks>
/// Dates stay as the text in the file (yyyy-MM-dd), as SU-01 shows some of them exactly as written.
/// Members the file does not have are null, except the three every run of SU-01 needs, whose absence
/// makes the file invalid. SU-01 fails with an error when it needs a member that is missing, as the
/// PowerShell tool does under strict mode.
/// </remarks>
public sealed record OsLifecycle
{
    /// <summary>Gets when the data was last reviewed, as written (yyyy-MM-dd).</summary>
    [JsonPropertyName("lastReviewed")]
    public required string LastReviewed { get; init; }

    /// <summary>Gets how many days after the review the data counts as out of date.</summary>
    [JsonPropertyName("reviewWarningDays")]
    public required int ReviewWarningDays { get; init; }

    /// <summary>Gets how many days before the end of support a release warns.</summary>
    [JsonPropertyName("upcomingEndWarningDays")]
    public required int UpcomingEndWarningDays { get; init; }

    /// <summary>Gets where the Windows 11 data comes from, as written.</summary>
    [JsonPropertyName("source")]
    public string? Source { get; init; }

    /// <summary>Gets the Windows 11 releases, or null when the file has none.</summary>
    [JsonPropertyName("windows11")]
    public IReadOnlyList<Windows11Release>? Windows11 { get; init; }

    /// <summary>Gets the Windows Server releases, or null when the file has none.</summary>
    [JsonPropertyName("windowsServer")]
    public IReadOnlyList<WindowsServerRelease>? WindowsServer { get; init; }

    /// <summary>Gets the end of Windows 10 support, or null when the file has none.</summary>
    [JsonPropertyName("windows10")]
    public Windows10Lifecycle? Windows10 { get; init; }
}

/// <summary>
/// A Windows 11 release in config/os-lifecycle.json.
/// </summary>
public sealed record Windows11Release
{
    /// <summary>Gets the build number, such as 26100.</summary>
    [JsonPropertyName("build")]
    public int Build { get; init; }

    /// <summary>Gets the version, such as 24H2.</summary>
    [JsonPropertyName("version")]
    public string? Version { get; init; }

    /// <summary>Gets the end of servicing for Home and Pro editions, as written, or null when not yet known.</summary>
    [JsonPropertyName("homePro")]
    public string? HomePro { get; init; }

    /// <summary>Gets the end of servicing for Enterprise and Education editions, as written, or null when not yet known.</summary>
    [JsonPropertyName("enterprise")]
    public string? Enterprise { get; init; }
}

/// <summary>
/// A Windows Server release in config/os-lifecycle.json.
/// </summary>
public sealed record WindowsServerRelease
{
    /// <summary>Gets the build number, such as 20348.</summary>
    [JsonPropertyName("build")]
    public int Build { get; init; }

    /// <summary>Gets the version, such as 2022.</summary>
    [JsonPropertyName("version")]
    public string? Version { get; init; }

    /// <summary>Gets the end of extended support, as written.</summary>
    [JsonPropertyName("extendedEnd")]
    public string? ExtendedEnd { get; init; }
}

/// <summary>
/// The end of Windows 10 support in config/os-lifecycle.json.
/// </summary>
public sealed record Windows10Lifecycle
{
    /// <summary>Gets the end of support, as written.</summary>
    [JsonPropertyName("endOfSupport")]
    public string? EndOfSupport { get; init; }

    /// <summary>Gets the end of consumer Extended Security Updates, as written.</summary>
    [JsonPropertyName("esuConsumerEnd")]
    public string? EsuConsumerEnd { get; init; }

    /// <summary>Gets the end of the third year of commercial Extended Security Updates, as written.</summary>
    [JsonPropertyName("esuCommercialYear3End")]
    public string? EsuCommercialYear3End { get; init; }
}
