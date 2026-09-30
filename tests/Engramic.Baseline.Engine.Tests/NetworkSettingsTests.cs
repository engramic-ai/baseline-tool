namespace Engramic.Baseline.Engine.Tests;

/// <summary>
/// The service client's proxy settings, read from network.json through the config files: the seam where
/// administrators' overrides will come in.
/// </summary>
public sealed class NetworkSettingsTests
{
    [Fact]
    public void Reads_the_settings_of_network_json()
    {
        var files = new ConfigFiles(new()
        {
            ["network.json"] = """
                {
                  "proxyUrl": "http://proxy.contoso.com:8080",
                  "proxyUseDefaultCredentials": true,
                  "useWinHttpProxyWhenSystem": false,
                  "proxyAutoConfigUrl": "https://pac.contoso.com/proxy.pac",
                  "proxyAutoDetect": false
                }
                """,
        });

        var settings = NetworkSettings.Read(files);

        Assert.Equal("http://proxy.contoso.com:8080", settings.ProxyUrl);
        Assert.True(settings.ProxyUseDefaultCredentials);
        Assert.False(settings.UseWinHttpProxyWhenSystem);
        Assert.Equal("https://pac.contoso.com/proxy.pac", settings.ProxyAutoConfigUrl);
        Assert.False(settings.ProxyAutoDetect);
        Assert.Empty(settings.Problems);
    }

    [Fact]
    public void A_missing_file_gives_the_defaults_and_says_so()
    {
        var settings = NetworkSettings.Read(new ConfigFiles());

        Assert.Equal(string.Empty, settings.ProxyUrl);
        Assert.True(settings.UseWinHttpProxyWhenSystem);
        Assert.True(settings.ProxyAutoDetect);
        Assert.Equal(["config/network.json is missing, so the proxy settings are the defaults."], settings.Problems);
    }

    [Fact]
    public void A_file_that_is_not_valid_gives_the_defaults_and_says_why()
    {
        var settings = NetworkSettings.Read(new ConfigFiles(new() { ["network.json"] = """{ "proxyUrl": "http://proxy.contoso.com:8080", """ }));

        Assert.Equal(string.Empty, settings.ProxyUrl);
        Assert.False(settings.ProxyUseDefaultCredentials);
        Assert.StartsWith("config/network.json is not valid, so the proxy settings are the defaults: ", Assert.Single(settings.Problems), StringComparison.Ordinal);
    }
}
