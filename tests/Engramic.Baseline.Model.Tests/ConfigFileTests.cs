using System.Text;
using System.Text.Json;

namespace Engramic.Baseline.Model.Tests;

public sealed class ConfigFileTests
{
    [Fact]
    public void Reads_the_lifecycle_data_with_dates_kept_as_written()
    {
        var lifecycle = ConfigFile.ReadOsLifecycle("""
            {
              "lastReviewed": "2026-09-16",
              "reviewWarningDays": 90,
              "upcomingEndWarningDays": 60,
              "source": "https://example.com/release-health",
              "notes": "Ignored: the tool reads only what it uses.",
              "windows11": [
                { "build": 26100, "version": "24H2", "homePro": "2026-10-13", "enterprise": "2027-10-12" },
                { "build": 28000, "version": "26H1", "homePro": null, "enterprise": null, "notes": "not yet known" }
              ],
              "windowsServer": [ { "build": 26100, "version": "2025", "extendedEnd": "2034-11-14" } ],
              "windows10": { "endOfSupport": "2025-10-14", "esuConsumerEnd": "2026-10-13", "esuCommercialYear3End": "2028-10-10" }
            }
            """u8);

        Assert.Equal("2026-09-16", lifecycle.LastReviewed);
        Assert.Equal(90, lifecycle.ReviewWarningDays);
        Assert.Equal(60, lifecycle.UpcomingEndWarningDays);
        Assert.Equal("https://example.com/release-health", lifecycle.Source);
        Assert.Equal(new Windows11Release { Build = 26100, Version = "24H2", HomePro = "2026-10-13", Enterprise = "2027-10-12" }, lifecycle.Windows11![0]);
        Assert.Null(lifecycle.Windows11[1].HomePro);
        Assert.Equal(new WindowsServerRelease { Build = 26100, Version = "2025", ExtendedEnd = "2034-11-14" }, Assert.Single(lifecycle.WindowsServer!));
        Assert.Equal("2025-10-14", lifecycle.Windows10!.EndOfSupport);
    }

    [Fact]
    public void Reads_it_as_PowerShell_would_with_a_byte_order_mark_other_casing_and_quoted_numbers()
    {
        var bytes = Utf8Bom.GetBytes("""{ "LastReviewed": "2026-09-16", "reviewwarningdays": "90", "upcomingEndWarningDays": 60, "windows11": [ { "build": "22631" } ] }""");

        var lifecycle = ConfigFile.ReadOsLifecycle(bytes);

        Assert.Equal("2026-09-16", lifecycle.LastReviewed);
        Assert.Equal(90, lifecycle.ReviewWarningDays);
        Assert.Equal(22631, Assert.Single(lifecycle.Windows11!).Build);
    }

    [Fact]
    public void Sections_the_file_does_not_have_are_null()
    {
        var lifecycle = ConfigFile.ReadOsLifecycle("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }"""u8);

        Assert.Null(lifecycle.Source);
        Assert.Null(lifecycle.Windows11);
        Assert.Null(lifecycle.WindowsServer);
        Assert.Null(lifecycle.Windows10);
    }

    [Theory]
    [InlineData("""{ "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }""")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "upcomingEndWarningDays": 60 }""")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90 }""")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": "ninety", "upcomingEndWarningDays": 60 }""")]
    [InlineData("""[]""")]
    [InlineData("""null""")]
    [InlineData("""{ "lastReviewed": """)]
    public void A_file_without_what_every_audit_needs_is_not_valid(string json)
    {
        Assert.Throws<JsonException>(() => ConfigFile.ReadOsLifecycle(Encoding.UTF8.GetBytes(json)));
    }
}
