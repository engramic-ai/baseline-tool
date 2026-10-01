using System.Text;
using System.Text.Json;

namespace Engramic.Baseline.Model.Tests;

/// <summary>
/// config/network.json as the config model reads it: every member optional, and an odd value costing only
/// itself, as in the PowerShell tool.
/// </summary>
public sealed class NetworkConfigTests
{
    [Fact]
    public void Reads_every_member()
    {
        var network = ConfigFile.ReadNetwork("""
            {
              "notes": "Ignored: the tool reads only what it uses.",
              "proxyUrl": "http://proxy.contoso.com:8080",
              "proxyUseDefaultCredentials": true,
              "useWinHttpProxyWhenSystem": false,
              "proxyAutoConfigUrl": "https://pac.contoso.com/proxy.pac",
              "proxyAutoDetect": false
            }
            """u8);

        Assert.Equal(new NetworkConfig("http://proxy.contoso.com:8080", true, false, "https://pac.contoso.com/proxy.pac", false), network);
    }

    [Fact]
    public void A_member_the_file_does_not_have_takes_its_default()
    {
        var network = ConfigFile.ReadNetwork("{}"u8);

        Assert.Equal(new NetworkConfig(), network);
        Assert.Equal(string.Empty, network.ProxyUrl);
        Assert.False(network.ProxyUseDefaultCredentials);
        Assert.True(network.UseWinHttpProxyWhenSystem);
        Assert.Equal(string.Empty, network.ProxyAutoConfigUrl);
        Assert.True(network.ProxyAutoDetect);
    }

    [Fact]
    public void Reads_it_as_PowerShell_would_with_a_byte_order_mark_and_other_casing()
    {
        var network = ConfigFile.ReadNetwork(Utf8Bom.GetBytes("""{ "ProxyURL": "http://proxy.contoso.com:8080", "USEWINHTTPPROXYWHENSYSTEM": false }"""));

        Assert.Equal("http://proxy.contoso.com:8080", network.ProxyUrl);
        Assert.False(network.UseWinHttpProxyWhenSystem);
    }

    [Theory]
    [InlineData("true", true)]
    [InlineData("false", false)]
    [InlineData("null", false)]
    [InlineData("\"true\"", false)]
    [InlineData("\"yes\"", false)]
    [InlineData("1", false)]
    [InlineData("{ \"on\": true }", false)]
    [InlineData("[true]", false)]
    public void Sends_the_Windows_sign_in_only_for_a_JSON_true(string value, bool expected)
    {
        var network = ConfigFile.ReadNetwork(Encoding.UTF8.GetBytes($$"""{ "proxyUseDefaultCredentials": {{value}}, "proxyUrl": "http://proxy.contoso.com:8080" }"""));

        Assert.Equal(expected, network.ProxyUseDefaultCredentials);
        Assert.Equal("http://proxy.contoso.com:8080", network.ProxyUrl);
    }

    [Theory]
    [InlineData("false", false)]
    [InlineData("true", true)]
    [InlineData("null", true)]
    [InlineData("\"false\"", true)]
    [InlineData("0", true)]
    [InlineData("[]", true)]
    public void Turns_the_WinHTTP_proxy_and_WPAD_off_only_for_a_JSON_false(string value, bool expected)
    {
        var network = ConfigFile.ReadNetwork(Encoding.UTF8.GetBytes($$"""{ "useWinHttpProxyWhenSystem": {{value}}, "proxyAutoDetect": {{value}} }"""));

        Assert.Equal(expected, network.UseWinHttpProxyWhenSystem);
        Assert.Equal(expected, network.ProxyAutoDetect);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("8080")]
    [InlineData("true")]
    [InlineData("{ \"url\": \"http://proxy.contoso.com:8080\" }")]
    [InlineData("[\"http://proxy.contoso.com:8080\"]")]
    public void Reads_an_address_only_from_a_string(string value)
    {
        var network = ConfigFile.ReadNetwork(Encoding.UTF8.GetBytes($$"""{ "proxyUrl": {{value}}, "proxyAutoConfigUrl": {{value}}, "proxyAutoDetect": false }"""));

        Assert.Equal(string.Empty, network.ProxyUrl);
        Assert.Equal(string.Empty, network.ProxyAutoConfigUrl);
        Assert.False(network.ProxyAutoDetect);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("\"http://proxy.contoso.com:8080\"")]
    [InlineData("{ \"proxyUrl\": ")]
    [InlineData("")]
    public void A_file_that_is_not_a_JSON_object_is_not_valid(string json)
    {
        Assert.Throws<JsonException>(() => ConfigFile.ReadNetwork(Encoding.UTF8.GetBytes(json)));
    }
}
