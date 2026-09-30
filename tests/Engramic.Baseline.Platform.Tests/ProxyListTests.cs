namespace Engramic.Baseline.Platform.Tests;

/// <summary>
/// Reading WinHTTP proxy and bypass lists and PAC answers, with the PowerShell tool's cases (Select-CEWinHttpProxy
/// and Test-CEProxyBypass) and the few places this tool reads more.
/// </summary>
public sealed class ProxyListTests
{
    [Fact]
    public void One_proxy_serves_every_scheme()
    {
        Assert.Equal("http://proxy.contoso.com:8080/", ProxyChooser.SelectProxy("proxy.contoso.com:8080", "https")?.AbsoluteUri);
        Assert.Equal("http://proxy.contoso.com:8080/", ProxyChooser.SelectProxy("proxy.contoso.com:8080", "http")?.AbsoluteUri);
    }

    [Fact]
    public void Entries_for_a_scheme_apply_only_to_that_scheme()
    {
        const string Schemes = "http=web.contoso.com:80;https=secure.contoso.com:8443";

        Assert.Equal("secure.contoso.com:8443", ProxyChooser.SelectProxy(Schemes, "https")?.Authority);
        Assert.Equal("web.contoso.com", ProxyChooser.SelectProxy(Schemes, "http")?.Authority);
        Assert.Null(ProxyChooser.SelectProxy("http=web.contoso.com:80", "https"));
        Assert.Equal("secure.contoso.com:8443", ProxyChooser.SelectProxy("HTTPS=secure.contoso.com:8443", "https")?.Authority);
    }

    [Theory]
    [InlineData("https=https://secure.contoso.com:8443")]
    [InlineData("socks5://proxy.contoso.com:1080")]
    [InlineData("")]
    [InlineData(" ; ")]
    public void Only_an_http_proxy_is_used(string proxyList)
    {
        Assert.Null(ProxyChooser.SelectProxy(proxyList, "https"));
    }

    [Fact]
    public void Entries_may_be_separated_by_white_space_as_WinHTTP_allows()
    {
        // The PowerShell tool split on semicolons alone, so it read "a:80 b:80" as one entry and used no proxy.
        Assert.Equal("first.contoso.com:8080", ProxyChooser.SelectProxy("first.contoso.com:8080 second.contoso.com:8080", "https")?.Authority);
        Assert.Equal("secure.contoso.com", ProxyChooser.SelectProxy("http=web.contoso.com:80 https=secure.contoso.com:80", "https")?.Host);
    }

    [Fact]
    public void A_PAC_answer_gives_its_first_http_proxy()
    {
        Assert.Equal("first.contoso.com:8080", ProxyChooser.FirstProxy("first.contoso.com:8080;second.contoso.com:8080")?.Authority);
        Assert.Equal("second.contoso.com:8080", ProxyChooser.FirstProxy("socks=socks.contoso.com:1080; https://tls.contoso.com:443 second.contoso.com:8080")?.Authority);
        Assert.Null(ProxyChooser.FirstProxy("socks=socks.contoso.com:1080"));
        Assert.Null(ProxyChooser.FirstProxy(string.Empty));
    }

    [Fact]
    public void Splits_a_bypass_list_as_the_PowerShell_tool_does()
    {
        Assert.Equal(["<local>", "*.contoso.com", "10.*"], ProxyChooser.SplitBypassList("<local>;*.contoso.com, 10.*"));
        Assert.Empty(ProxyChooser.SplitBypassList(string.Empty));
    }

    [Theory]
    [InlineData("intranet", true)]
    [InlineData("files.contoso.com", true)]
    [InlineData("FILES.CONTOSO.COM", true)]
    [InlineData("contoso.com", false)]
    [InlineData("baseline.engramic.ai", false)]
    public void Matches_the_PowerShell_tool_s_bypass_cases(string host, bool bypassed)
    {
        Assert.Equal(bypassed, ProxyChooser.IsBypassed(host, ["<local>", "*.contoso.com"]));
    }

    [Theory]
    [InlineData("10.1.2.3", "10.*", true)]
    [InlineData("10.1.2.3", "10.?.2.3", true)]
    [InlineData("10.12.2.3", "10.?.2.3", false)]
    [InlineData("api.example.com", "http://api.example.com", true)]
    [InlineData("api.example.com", "*", true)]
    [InlineData("api.example.com", "*example*", true)]
    [InlineData("api.example.com", "api.example.co", false)]
    [InlineData("api.example.com", "<LOCAL>", false)]
    public void Matches_wildcards_without_regard_to_case_and_ignores_a_scheme(string host, string entry, bool bypassed)
    {
        Assert.Equal(bypassed, ProxyChooser.IsBypassed(host, [entry]));
    }

    [Fact]
    public void Takes_brackets_in_an_entry_as_written()
    {
        // PowerShell's -like read [ ] as a set of characters; WinHTTP's list has no such thing.
        Assert.True(ProxyChooser.WildcardMatch("[fd00::1]", "[fd00::1]"));
        Assert.False(ProxyChooser.WildcardMatch("f", "[fd00::1]"));
    }

    [Theory]
    [InlineData("localhost", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.0.0.2", true)]
    [InlineData("[::1]", true)]
    [InlineData("intranet", true)]
    [InlineData("baseline.engramic.ai", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("[fd00::1]", false)]
    public void Treats_this_device_and_names_without_a_dot_as_local(string host, bool local)
    {
        Assert.Equal(local, ProxyChooser.IsLocal(new UriBuilder("https", host, 443).Uri));
    }

    [Fact]
    public void Asks_a_PAC_file_about_the_scheme_host_and_port_alone()
    {
        Assert.Equal("https://baseline.engramic.ai/", ProxyChooser.PacTarget(new Uri("https://user:secret@baseline.engramic.ai/v1/firmware/dell/0CF1?token=x#top")).AbsoluteUri);
        Assert.Equal("https://baseline.engramic.ai:8443/", ProxyChooser.PacTarget(new Uri("https://baseline.engramic.ai:8443/v1")).AbsoluteUri);
    }
}
