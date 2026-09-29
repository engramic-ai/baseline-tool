using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// config/os-lifecycle.json: when each Windows release stops being supported, which SU-01 judges against.
/// </summary>
/// <remarks>
/// <para>
/// Dates stay as the text in the file (yyyy-MM-dd), as SU-01 shows some of them exactly as written.
/// The three members every run of SU-01 needs must be there, or the file is not valid. Any other member
/// the file does not have is null.
/// </para>
/// <para>
/// The PowerShell tool reads the file under strict mode, where reading a member an object does not have
/// is an error, but a member written as null is just null. So SU-01 must tell the two apart, and the
/// members it reads are tracked: each has a Has property that is true when the file wrote the member,
/// even as null. Setting a member in code counts as writing it. SU-01 fails with an error when the branch
/// it takes reads a member that is not there, as the PowerShell tool does, and a whole section that is
/// null counts as missing, as it does there too.
/// </para>
/// <para>
/// The JSON reader fills a tracked member through an internal twin with an ordinary setter, because the
/// generated code assigns every init-only property, whether the file has it or not.
/// </para>
/// </remarks>
public sealed record OsLifecycle
{
    private string? _source;

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
    [JsonIgnore]
    public string? Source
    {
        get => _source;
        init => SetSource(value);
    }

    /// <summary>Gets whether the file has a source member, null or not.</summary>
    [JsonIgnore]
    public bool HasSource { get; private set; }

    /// <summary>Gets or sets Source for the JSON reader, which calls the setter only when the member is there.</summary>
    [JsonInclude]
    [JsonPropertyName("source")]
    internal string? SourceMember
    {
        get => _source;
        set => SetSource(value);
    }

    private void SetSource(string? value)
    {
        _source = value;
        HasSource = true;
    }

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
    private int _build;
    private string? _version;
    private string? _homePro;
    private string? _enterprise;

    /// <summary>Gets the build number, such as 26100, or 0 when the entry has none.</summary>
    [JsonIgnore]
    public int Build
    {
        get => _build;
        init => SetBuild(value);
    }

    /// <summary>Gets whether the entry has a build member.</summary>
    [JsonIgnore]
    public bool HasBuild { get; private set; }

    /// <summary>Gets or sets Build for the JSON reader, which calls the setter only when the member is there.</summary>
    [JsonInclude]
    [JsonPropertyName("build")]
    internal int BuildMember
    {
        get => _build;
        set => SetBuild(value);
    }

    private void SetBuild(int value)
    {
        _build = value;
        HasBuild = true;
    }

    /// <summary>Gets the version, such as 24H2.</summary>
    [JsonIgnore]
    public string? Version
    {
        get => _version;
        init => SetVersion(value);
    }

    /// <summary>Gets whether the entry has a version member, null or not.</summary>
    [JsonIgnore]
    public bool HasVersion { get; private set; }

    /// <summary>Gets or sets Version for the JSON reader, which calls the setter only when the member is there.</summary>
    [JsonInclude]
    [JsonPropertyName("version")]
    internal string? VersionMember
    {
        get => _version;
        set => SetVersion(value);
    }

    private void SetVersion(string? value)
    {
        _version = value;
        HasVersion = true;
    }

    /// <summary>Gets the end of servicing for Home and Pro editions, as written, or null when not yet known.</summary>
    [JsonIgnore]
    public string? HomePro
    {
        get => _homePro;
        init => SetHomePro(value);
    }

    /// <summary>Gets whether the entry has a homePro member, null or not.</summary>
    [JsonIgnore]
    public bool HasHomePro { get; private set; }

    /// <summary>Gets or sets HomePro for the JSON reader, which calls the setter only when the member is there.</summary>
    [JsonInclude]
    [JsonPropertyName("homePro")]
    internal string? HomeProMember
    {
        get => _homePro;
        set => SetHomePro(value);
    }

    private void SetHomePro(string? value)
    {
        _homePro = value;
        HasHomePro = true;
    }

    /// <summary>Gets the end of servicing for Enterprise and Education editions, as written, or null when not yet known.</summary>
    [JsonIgnore]
    public string? Enterprise
    {
        get => _enterprise;
        init => SetEnterprise(value);
    }

    /// <summary>Gets whether the entry has an enterprise member, null or not.</summary>
    [JsonIgnore]
    public bool HasEnterprise { get; private set; }

    /// <summary>Gets or sets Enterprise for the JSON reader, which calls the setter only when the member is there.</summary>
    [JsonInclude]
    [JsonPropertyName("enterprise")]
    internal string? EnterpriseMember
    {
        get => _enterprise;
        set => SetEnterprise(value);
    }

    private void SetEnterprise(string? value)
    {
        _enterprise = value;
        HasEnterprise = true;
    }
}

/// <summary>
/// A Windows Server release in config/os-lifecycle.json.
/// </summary>
public sealed record WindowsServerRelease
{
    private int _build;
    private string? _version;

    /// <summary>Gets the build number, such as 20348, or 0 when the entry has none.</summary>
    [JsonIgnore]
    public int Build
    {
        get => _build;
        init => SetBuild(value);
    }

    /// <summary>Gets whether the entry has a build member.</summary>
    [JsonIgnore]
    public bool HasBuild { get; private set; }

    /// <summary>Gets or sets Build for the JSON reader, which calls the setter only when the member is there.</summary>
    [JsonInclude]
    [JsonPropertyName("build")]
    internal int BuildMember
    {
        get => _build;
        set => SetBuild(value);
    }

    private void SetBuild(int value)
    {
        _build = value;
        HasBuild = true;
    }

    /// <summary>Gets the version, such as 2022.</summary>
    [JsonIgnore]
    public string? Version
    {
        get => _version;
        init => SetVersion(value);
    }

    /// <summary>Gets whether the entry has a version member, null or not.</summary>
    [JsonIgnore]
    public bool HasVersion { get; private set; }

    /// <summary>Gets or sets Version for the JSON reader, which calls the setter only when the member is there.</summary>
    [JsonInclude]
    [JsonPropertyName("version")]
    internal string? VersionMember
    {
        get => _version;
        set => SetVersion(value);
    }

    private void SetVersion(string? value)
    {
        _version = value;
        HasVersion = true;
    }

    /// <summary>Gets the end of extended support, as written.</summary>
    [JsonPropertyName("extendedEnd")]
    public string? ExtendedEnd { get; init; }
}

/// <summary>
/// The end of Windows 10 support in config/os-lifecycle.json.
/// </summary>
public sealed record Windows10Lifecycle
{
    private string? _endOfSupport;

    /// <summary>Gets the end of support, as written.</summary>
    [JsonIgnore]
    public string? EndOfSupport
    {
        get => _endOfSupport;
        init => SetEndOfSupport(value);
    }

    /// <summary>Gets whether the section has an endOfSupport member, null or not.</summary>
    [JsonIgnore]
    public bool HasEndOfSupport { get; private set; }

    /// <summary>Gets or sets EndOfSupport for the JSON reader, which calls the setter only when the member is there.</summary>
    [JsonInclude]
    [JsonPropertyName("endOfSupport")]
    internal string? EndOfSupportMember
    {
        get => _endOfSupport;
        set => SetEndOfSupport(value);
    }

    private void SetEndOfSupport(string? value)
    {
        _endOfSupport = value;
        HasEndOfSupport = true;
    }

    /// <summary>Gets the end of consumer Extended Security Updates, as written.</summary>
    [JsonPropertyName("esuConsumerEnd")]
    public string? EsuConsumerEnd { get; init; }

    /// <summary>Gets the end of the third year of commercial Extended Security Updates, as written.</summary>
    [JsonPropertyName("esuCommercialYear3End")]
    public string? EsuCommercialYear3End { get; init; }
}
