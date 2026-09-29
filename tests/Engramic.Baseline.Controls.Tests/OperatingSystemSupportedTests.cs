using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;
using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Controls.Tests;

/// <summary>
/// SU-01 over registry states of every release it judges, against lifecycle data like the shipped file,
/// with the PowerShell tool's statuses, severities and words.
/// </summary>
public sealed class OperatingSystemSupportedTests
{
    private const string Lifecycle = """
        {
          "lastReviewed": "2026-09-16",
          "reviewWarningDays": 90,
          "upcomingEndWarningDays": 60,
          "source": "https://example.com/windows11-release-information",
          "windows11": [
            { "build": 22000, "version": "21H2", "homePro": "2023-10-10", "enterprise": "2024-10-08" },
            { "build": 22621, "version": "22H2", "homePro": "2024-10-08", "enterprise": "2025-10-14" },
            { "build": 22631, "version": "23H2", "homePro": "2025-11-11", "enterprise": "2026-11-10" },
            { "build": 26100, "version": "24H2", "homePro": "2026-10-13", "enterprise": "2027-10-12" },
            { "build": 26200, "version": "25H2", "homePro": "2027-10-12", "enterprise": "2028-10-10" },
            { "build": 28000, "version": "26H1", "homePro": null, "enterprise": null }
          ],
          "windowsServer": [
            { "build": 14393, "version": "2016", "extendedEnd": "2027-01-12" },
            { "build": 17763, "version": "2019", "extendedEnd": "2029-01-09" },
            { "build": 20348, "version": "2022", "extendedEnd": "2031-10-14" },
            { "build": 26100, "version": "2025", "extendedEnd": "2034-11-14" }
          ],
          "windows10": { "endOfSupport": "2025-10-14", "esuConsumerEnd": "2026-10-13", "esuCommercialYear3End": "2028-10-10" }
        }
        """;

    private static readonly DateOnly Today = new(2026, 9, 29);

    [Fact]
    public async Task Passes_a_supported_Windows_11_release()
    {
        var finding = Assert.Single(await Run(Devices.Windows11("26200", 9457, "25H2")));

        Assert.Equal("SU-01", finding.FindingId);
        Assert.Equal(FindingStatus.Pass, finding.Status);
        Assert.Equal(Severity.Info, finding.Severity);
        Assert.False(finding.AutoFail);
        Assert.Equal("Supported Windows version", finding.Expected);
        Assert.Equal("Windows 11 25H2 Professional (build 26200.9457): supported until 2027-10-12", finding.Actual);
        Assert.Equal(string.Empty, finding.Recommendation);
        Assert.Empty(finding.Evidence);
    }

    [Fact]
    public async Task Warns_when_a_Home_or_Pro_release_is_near_its_end_of_servicing()
    {
        // The PowerShell tool's own test: 24H2 Pro on 2026-09-16 warns about 2026-10-13.
        var finding = Assert.Single(await Run(Devices.Windows11("26100", 4946, "24H2"), new DateOnly(2026, 9, 16)));

        Assert.Equal(FindingStatus.Warn, finding.Status);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.False(finding.AutoFail);
        Assert.Equal("Windows 11 24H2 Professional (build 26100.4946): support ends 2026-10-13 (27 days)", finding.Actual);
        Assert.Equal("Plan the upgrade to the next Windows 11 feature update before this date, or the device drops out of scope.", finding.Recommendation);
    }

    [Fact]
    public async Task Fails_a_release_past_its_end_of_servicing_as_an_auto_fail()
    {
        var finding = Assert.Single(await Run(Devices.Windows11("22631", 6060, "23H2")));

        Assert.Equal(FindingStatus.Fail, finding.Status);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.True(finding.AutoFail);
        Assert.Equal("Supported Windows version", finding.Expected);
        Assert.Equal("Windows 11 23H2 Professional (build 22631.6060): support ended 2025-11-11", finding.Actual);
        Assert.Equal("Install the latest Windows 11 feature update now (Settings > Windows Update).", finding.Recommendation);
    }

    [Theory]
    [InlineData(2026, 8, 13, FindingStatus.Pass, "supported until 2026-10-13")]
    [InlineData(2026, 8, 14, FindingStatus.Warn, "support ends 2026-10-13 (60 days)")]
    [InlineData(2026, 10, 12, FindingStatus.Warn, "support ends 2026-10-13 (1 days)")]
    [InlineData(2026, 10, 13, FindingStatus.Warn, "support ends 2026-10-13 (0 days)")]
    [InlineData(2026, 10, 14, FindingStatus.Fail, "support ended 2026-10-13")]
    public async Task The_warning_starts_60_days_before_the_end_and_includes_the_last_day(int year, int month, int day, FindingStatus status, string ending)
    {
        var finding = Assert.Single(await Run(Devices.Windows11("26100", 4946, "24H2"), new DateOnly(year, month, day)));

        Assert.Equal(status, finding.Status);
        Assert.Equal("Windows 11 24H2 Professional (build 26100.4946): " + ending, finding.Actual);
    }

    [Theory]
    [InlineData("Enterprise", "2027-10-12")]
    [InlineData("EnterpriseN", "2027-10-12")]
    // LTSC and IoT editions are judged by the Enterprise date of their build, as in the PowerShell tool.
    [InlineData("EnterpriseS", "2027-10-12")]
    [InlineData("IoTEnterpriseS", "2027-10-12")]
    [InlineData("Education", "2027-10-12")]
    [InlineData("ProfessionalEducation", "2026-10-13")]
    [InlineData("ProfessionalWorkstation", "2026-10-13")]
    [InlineData("CoreSingleLanguage", "2026-10-13")]
    // Anything the edition classes do not know gets the Home and Pro date.
    [InlineData("ServerRdsh", "2026-10-13")]
    [InlineData("", "2026-10-13")]
    public async Task Enterprise_editions_get_the_Enterprise_date_and_the_rest_the_Home_and_Pro_date(string editionId, string end)
    {
        var finding = Assert.Single(await Run(Devices.Windows11("26100", 4946, "24H2", editionId), new DateOnly(2026, 1, 1)));

        Assert.Equal($"Windows 11 24H2 {editionId} (build 26100.4946): supported until {end}", finding.Actual);
    }

    [Fact]
    public async Task A_listed_release_without_a_date_needs_confirming()
    {
        var finding = Assert.Single(await Run(Devices.Windows11("28000", 1000, "26H1")));

        Assert.Equal(FindingStatus.Manual, finding.Status);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.False(finding.AutoFail);
        Assert.Equal("Known end-of-servicing date", finding.Expected);
        Assert.Equal("Windows 11 26H1 (Professional): end date not recorded", finding.Actual);
        Assert.Equal("Confirm the end-of-servicing date on Microsoft release health and add it to config/os-lifecycle.json.", finding.Recommendation);
    }

    [Fact]
    public async Task A_release_that_is_not_listed_needs_confirming()
    {
        var finding = Assert.Single(await Run(Devices.Windows11("27000", 1, "26H2")));

        Assert.Equal(FindingStatus.Manual, finding.Status);
        Assert.Equal("Build listed in config/os-lifecycle.json", finding.Expected);
        Assert.Equal("Windows 11 build 27000 (26H2) not in lifecycle data", finding.Actual);
        Assert.Equal("Check the build is in support on Microsoft release health and add it to config/os-lifecycle.json.", finding.Recommendation);
    }

    [Fact]
    public async Task Fails_Windows_10_whatever_the_build()
    {
        var finding = Assert.Single(await Run(Devices.Read(Devices.Registry("19045", 6456, "22H2", "Professional"))));

        Assert.Equal(FindingStatus.Fail, finding.Status);
        Assert.True(finding.AutoFail);
        Assert.Equal("Windows 10 build 19045.6456: support ended 2025-10-14", finding.Actual);
        Assert.Equal(
            "Upgrade to a supported Windows 11 release. A device enrolled in Extended Security Updates can remain in scope only while ESU is active and updates are applied; record the ESU evidence if so.",
            finding.Recommendation);
    }

    [Fact]
    public async Task Fails_a_release_older_than_Windows_10()
    {
        var registry = new FakeRegistry().Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "CurrentBuildNumber", RegistryValue.FromText("9600"));

        var finding = Assert.Single(await Run(Devices.Read(registry)));

        Assert.Equal(FindingStatus.Fail, finding.Status);
        Assert.True(finding.AutoFail);
        Assert.Equal("Unrecognised OS build 9600.0", finding.Actual);
        Assert.Equal("Move to a supported Windows 11 release.", finding.Recommendation);
    }

    [Fact]
    public async Task Fails_when_the_release_cannot_be_read_at_all()
    {
        var unreadable = new FakeRegistry().Deny(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey);

        var finding = Assert.Single(await Run(Devices.Read(unreadable)));

        Assert.Equal(FindingStatus.Fail, finding.Status);
        Assert.Equal("Unrecognised OS build 0.0", finding.Actual);
    }

    [Fact]
    public async Task Passes_a_supported_Windows_Server_release()
    {
        var finding = Assert.Single(await Run(Devices.Server("26100", 4946)));

        Assert.Equal(FindingStatus.Pass, finding.Status);
        Assert.Equal("Windows Server 2025 ServerDatacenter (build 26100.4946): supported until 2034-11-14", finding.Actual);
    }

    [Theory]
    // Server 2025 and Windows 11 24H2 share build 26100.
    [InlineData("Server", "Windows Server 2025 ServerStandard (build 26100.4946): supported until 2034-11-14")]
    [InlineData("Server Core", "Windows Server 2025 ServerStandard (build 26100.4946): supported until 2034-11-14")]
    [InlineData("Client", "Windows 11 24H2 ServerStandard (build 26100.4946): supported until 2026-10-13")]
    public async Task Build_26100_is_judged_as_Server_2025_or_Windows_11_24H2_by_its_installation_type(string installationType, string actual)
    {
        var device = Devices.Read(Devices.Registry("26100", 4946, "24H2", "ServerStandard", installationType));

        var finding = Assert.Single(await Run(device, new DateOnly(2026, 1, 1)));

        Assert.Equal(actual, finding.Actual);
    }

    [Fact]
    public async Task Warns_before_and_fails_after_the_end_of_extended_support_for_a_server()
    {
        var server2016 = Devices.Server("14393", 8000, "ServerStandard", "Windows Server 2016 Standard");

        var warn = Assert.Single(await Run(server2016, new DateOnly(2026, 12, 1)));
        // By then the lifecycle data is also more than 90 days old, which warns first under its own subject.
        var fail = Assert.Single(await Run(server2016, new DateOnly(2027, 2, 1)), f => f.Subject.Length == 0);

        Assert.Equal(FindingStatus.Warn, warn.Status);
        Assert.Equal(Severity.High, warn.Severity);
        Assert.Equal("Windows Server 2016 ServerStandard (build 14393.8000): support ends 2027-01-12 (42 days)", warn.Actual);
        Assert.Equal("Plan the migration to a newer Windows Server release (or ESU) before this date.", warn.Recommendation);
        Assert.Equal(FindingStatus.Fail, fail.Status);
        Assert.True(fail.AutoFail);
        Assert.Equal("Windows Server 2016 ServerStandard (build 14393.8000): support ended 2027-01-12", fail.Actual);
        Assert.Equal("Migrate to a supported Windows Server release, or enrol in Extended Security Updates and record the evidence.", fail.Recommendation);
    }

    [Fact]
    public async Task A_server_release_that_is_not_listed_needs_confirming()
    {
        var finding = Assert.Single(await Run(Devices.Server("9600", 1, "ServerStandard", "Windows Server 2012 R2 Standard")));

        Assert.Equal(FindingStatus.Manual, finding.Status);
        Assert.Equal("Build listed in config/os-lifecycle.json", finding.Expected);
        Assert.Equal("Windows Server build 9600.1 (Windows Server 2012 R2 Standard) is not in the lifecycle data", finding.Actual);
        Assert.Equal("Check this Windows Server release is still supported (Microsoft lifecycle pages) and add it to config/os-lifecycle.json.", finding.Recommendation);
    }

    [Fact]
    public async Task Warns_first_when_the_lifecycle_data_was_reviewed_more_than_90_days_ago()
    {
        var device = Devices.Windows11("26200", 9457, "25H2");

        var onTheDay = await Run(device, new DateOnly(2026, 12, 15));
        var dayAfter = await Run(device, new DateOnly(2026, 12, 16));

        Assert.Single(onTheDay);
        Assert.Equal(2, dayAfter.Count);
        var stale = dayAfter[0];
        Assert.Equal("SU-01:Lifecycle-data", stale.FindingId);
        Assert.Equal("Lifecycle data", stale.Subject);
        Assert.Equal(FindingStatus.Warn, stale.Status);
        Assert.Equal(Severity.Low, stale.Severity);
        Assert.Equal("Lifecycle data reviewed within 90 days", stale.Expected);
        Assert.Equal("config/os-lifecycle.json last reviewed 2026-09-16", stale.Actual);
        Assert.Equal("Update config/os-lifecycle.json from https://example.com/windows11-release-information.", stale.Recommendation);
        Assert.Equal(FindingStatus.Pass, dayAfter[1].Status);
    }

    [Theory]
    // 23:30 UTC on 12 October is already 13 October an hour east of Greenwich: the date is local, as (Get-Date).Date is.
    [InlineData(1, "support ends 2026-10-13 (0 days)")]
    [InlineData(0, "support ends 2026-10-13 (1 days)")]
    public async Task Days_are_counted_from_the_local_date(int utcOffsetHours, string ending)
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 10, 12, 23, 30, 0, TimeSpan.Zero));
        time.SetLocalTimeZone(TimeZoneInfo.CreateCustomTimeZone("Test", TimeSpan.FromHours(utcOffsetHours), "Test", "Test"));

        var finding = Assert.Single(await Run(Devices.Windows11("26100", 4946, "24H2"), time, Lifecycle));

        Assert.EndsWith(ending, finding.Actual, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, "Check failed: config/os-lifecycle.json is missing.")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }""", "Check failed: config/os-lifecycle.json has no windows11.")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60, "windows11": [ { "build": 26200, "version": "25H2", "homePro": "12/10/2027" } ] }""", null)]
    public async Task Lifecycle_data_the_check_needs_but_cannot_read_is_an_Error(string? lifecycle, string? actual)
    {
        var finding = Assert.Single(await Run(Devices.Windows11("26200", 9457, "25H2"), new FakeTimeProvider(new DateTimeOffset(2026, 9, 29, 12, 0, 0, TimeSpan.Zero)), lifecycle));

        Assert.Equal(FindingStatus.Error, finding.Status);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.StartsWith(actual ?? "Check failed: ", finding.Actual, StringComparison.Ordinal);
        Assert.Equal("Investigate manually; see Evidence.", finding.Recommendation);
    }

    [Fact]
    public async Task Windows_10_needs_its_end_of_support_in_the_lifecycle_data()
    {
        var finding = Assert.Single(await Run(
            Devices.Read(Devices.Registry("19045", 1, "22H2", "Professional")),
            new FakeTimeProvider(new DateTimeOffset(2026, 9, 29, 12, 0, 0, TimeSpan.Zero)),
            """{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }"""));

        Assert.Equal("Check failed: config/os-lifecycle.json has no windows10.", finding.Actual);
    }

    [Fact]
    public async Task Runs_with_the_shipped_lifecycle_data()
    {
        var context = new CheckContext(Devices.Windows11("26200", 9457, "25H2"), new AuditConfig(ShippedConfig.Files), new FakeTimeProvider(new DateTimeOffset(2026, 9, 29, 12, 0, 0, TimeSpan.Zero)));

        var findings = await new AuditRunner(BuiltInChecks.CreateCatalog()).RunAsync(new CheckSelection { Ids = ["SU-01"] }, context, TestContext.Current.CancellationToken);

        Assert.DoesNotContain(findings, f => f.Status == FindingStatus.Error);
        Assert.StartsWith("Windows 11 25H2 Professional (build 26200.9457): ", findings[^1].Actual, StringComparison.Ordinal);
    }

    private static Task<IReadOnlyList<Finding>> Run(DeviceContext device, DateOnly? today = null)
    {
        var noon = new DateTimeOffset((today ?? Today).ToDateTime(new TimeOnly(12, 0)), TimeSpan.Zero);
        return Run(device, new FakeTimeProvider(noon), Lifecycle);
    }

    private static Task<IReadOnlyList<Finding>> Run(DeviceContext device, TimeProvider time, string? lifecycle)
    {
        var files = new Dictionary<string, string>();
        if (lifecycle is not null)
        {
            files["os-lifecycle.json"] = lifecycle;
        }

        var context = new CheckContext(device, new AuditConfig(new InMemoryConfigFiles(files)), time);
        return new AuditRunner(BuiltInChecks.CreateCatalog()).RunAsync(new CheckSelection { Ids = ["SU-01"] }, context, TestContext.Current.CancellationToken);
    }

    private sealed class InMemoryConfigFiles(Dictionary<string, string> files) : IConfigFiles
    {
        public byte[]? Read(string name) => files.TryGetValue(name, out var text) ? System.Text.Encoding.UTF8.GetBytes(text) : null;
    }
}
