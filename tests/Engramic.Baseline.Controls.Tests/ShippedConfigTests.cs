using System.Globalization;
using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;

namespace Engramic.Baseline.Controls.Tests;

public sealed class ShippedConfigTests
{
    [Fact]
    public void The_shipped_files_are_the_repository_s_config_folder_byte_for_byte()
    {
        Assert.Equal(["network.json", "os-lifecycle.json"], ShippedConfig.Names);
        foreach (var name in ShippedConfig.Names)
        {
            Assert.Equal(File.ReadAllBytes(Path.Combine(RepositoryRoot(), "config", name)), ShippedConfig.Files.Read(name));
        }
    }

    [Fact]
    public void A_file_that_does_not_ship_is_null()
    {
        Assert.Null(ShippedConfig.Files.Read("no-such-file.json"));
        Assert.Null(ShippedConfig.Files.Read("../config/os-lifecycle.json"));
    }

    [Fact]
    public void The_shipped_lifecycle_data_is_valid_and_every_date_reads()
    {
        var lifecycle = ConfigFile.ReadOsLifecycle(ShippedConfig.Files.Read(ConfigFile.OsLifecycleName));
        var windows11 = lifecycle.Windows11!;
        var servers = lifecycle.WindowsServer!;

        string?[] dates =
        [
            lifecycle.LastReviewed,
            lifecycle.Windows10!.EndOfSupport,
            .. windows11.SelectMany(r => new[] { r.HomePro, r.Enterprise }),
            .. servers.Select(r => r.ExtendedEnd),
        ];
        Assert.All(dates.Where(d => d is not null), d => DateOnly.ParseExact(d!, "yyyy-MM-dd", CultureInfo.InvariantCulture));
        Assert.All(servers, r => Assert.NotNull(r.ExtendedEnd));
        Assert.Equal(windows11.Count, windows11.Select(r => r.Build).Distinct().Count());
        Assert.Equal(servers.Count, servers.Select(r => r.Build).Distinct().Count());
        Assert.True(lifecycle.ReviewWarningDays > 0 && lifecycle.UpcomingEndWarningDays > 0);
        Assert.False(string.IsNullOrEmpty(lifecycle.Source));
    }

    [Fact]
    public void The_shipped_network_settings_name_no_proxy_and_leave_WinHTTP_and_WPAD_on()
    {
        var settings = NetworkSettings.Read(ShippedConfig.Files);

        Assert.Equal(string.Empty, settings.ProxyUrl);
        Assert.False(settings.ProxyUseDefaultCredentials);
        Assert.True(settings.UseWinHttpProxyWhenSystem);
        Assert.Equal(string.Empty, settings.ProxyAutoConfigUrl);
        Assert.True(settings.ProxyAutoDetect);
        Assert.Empty(settings.Problems);
    }

    private static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Baseline.slnx")))
            {
                return dir.FullName;
            }
        }

        throw new InvalidOperationException("Baseline.slnx was not found above " + AppContext.BaseDirectory);
    }
}
