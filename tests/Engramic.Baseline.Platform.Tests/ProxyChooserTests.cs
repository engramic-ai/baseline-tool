using Engramic.Baseline.Testing;
using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Platform.Tests;

/// <summary>
/// How the service client chooses each request's route, over made-up settings and a fake of what Windows says,
/// so that every branch is covered without a network: the order of the sources, what each passes over, and
/// when the Windows sign-in may go to a proxy.
/// </summary>
public sealed class ProxyChooserTests
{
    private static readonly Uri Catalog = new("https://baseline.engramic.ai/v1/firmware/dell/0CF1?serial=none");
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);
    private static readonly ProxySettings Shipped = new();
    private static readonly MachineProxy WinHttp = new("proxy.contoso.com:8080", "<local>");

    private readonly FakeSystemProxy _system = new();

    [Fact]
    public void Ships_with_no_proxy_named_the_WinHTTP_proxy_on_WPAD_on_and_no_sign_in()
    {
        Assert.Equal(string.Empty, Shipped.ProxyUrl);
        Assert.False(Shipped.ProxyUseDefaultCredentials);
        Assert.True(Shipped.UseWinHttpProxyWhenSystem);
        Assert.Equal(string.Empty, Shipped.ProxyAutoConfigUrl);
        Assert.True(Shipped.ProxyAutoDetect);
        Assert.Empty(Shipped.Problems);
    }

    [Fact]
    public async Task An_address_on_this_device_goes_direct_whatever_the_settings()
    {
        _system.Machine = WinHttp;
        var settings = Shipped with { ProxyUrl = "http://configured.contoso.com:3128", ProxyAutoConfigUrl = "https://pac.contoso.com/proxy.pac" };

        foreach (var local in new[] { new Uri("http://localhost:8787/v1"), new UriBuilder("https", "intranet", 443, "v1").Uri, new UriBuilder("http", "127.0.0.1", 8787).Uri })
        {
            var route = await Choose(settings, local);

            Assert.True(route.IsDirect);
            Assert.Equal(ProxySource.Local, route.Source);
            Assert.False(route.UseDefaultCredentials);
        }

        Assert.Equal(0, _system.MachineReads);
        Assert.Empty(_system.Lookups);
    }

    [Fact]
    public async Task Uses_proxyUrl_first_without_the_Windows_sign_in_unless_it_is_allowed()
    {
        _system.Machine = WinHttp;

        var route = await Choose(Shipped with { ProxyUrl = " http://configured.contoso.com:3128 " });
        var signedIn = await Choose(Shipped with { ProxyUrl = "http://configured.contoso.com:3128", ProxyUseDefaultCredentials = true });

        Assert.Equal("configured.contoso.com:3128", route.Proxy?.Authority);
        Assert.Equal(ProxySource.NetworkConfig, route.Source);
        Assert.False(route.UseDefaultCredentials);
        Assert.Empty(route.Notes);
        Assert.True(signedIn.UseDefaultCredentials);
        Assert.Equal(0, _system.MachineReads);
    }

    [Fact]
    public async Task Passes_over_an_https_proxyUrl_with_the_PowerShell_tool_s_warning()
    {
        _system.Machine = WinHttp;

        var route = await Choose(Shipped with { ProxyUrl = "https://proxy.contoso.com:8443" });

        Assert.Equal(ProxySource.WinHttp, route.Source);
        Assert.Equal(
            "Ignoring proxyUrl in network.json: use the proxy's http:// address. Requests to https sites still go through it encrypted, and Windows PowerShell can't use an https:// proxy address.",
            Assert.Single(route.Notes));
    }

    [Theory]
    [InlineData("socks5://x:1080")]
    [InlineData("proxy.contoso.com:8080")]
    [InlineData("not a url")]
    public async Task Passes_over_a_proxyUrl_that_is_not_http_to_the_WinHTTP_proxy(string proxyUrl)
    {
        _system.Machine = WinHttp;

        var route = await Choose(Shipped with { ProxyUrl = proxyUrl });

        Assert.Equal("proxy.contoso.com:8080", route.Proxy?.Authority);
        Assert.Equal(ProxySource.WinHttp, route.Source);
        Assert.Equal("Ignoring proxyUrl in network.json: it must be an http:// URL.", Assert.Single(route.Notes));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Uses_the_WinHTTP_proxy_as_SYSTEM_and_as_any_other_account(bool isSystem)
    {
        _system.Machine = WinHttp;

        var route = await Choose(Shipped, isSystem: isSystem);

        Assert.Equal("proxy.contoso.com:8080", route.Proxy?.Authority);
        Assert.Equal(ProxySource.WinHttp, route.Source);
        Assert.False(route.UseDefaultCredentials);
        Assert.Empty(_system.Lookups);
    }

    [Fact]
    public async Task Sends_the_WinHTTP_proxy_the_Windows_sign_in_only_when_allowed()
    {
        // The PowerShell tool always sent it; one setting now decides whether it leaves the device.
        _system.Machine = WinHttp;

        Assert.False((await Choose(Shipped)).UseDefaultCredentials);
        Assert.True((await Choose(Shipped with { ProxyUseDefaultCredentials = true })).UseDefaultCredentials);
    }

    [Fact]
    public async Task Skips_the_WinHTTP_proxy_as_SYSTEM_when_useWinHttpProxyWhenSystem_is_false()
    {
        _system.Machine = WinHttp;
        var settings = Shipped with { UseWinHttpProxyWhenSystem = false, ProxyAutoDetect = false };

        var asSystem = await Choose(settings, isSystem: true);
        var asUser = await Choose(settings, isSystem: false);

        Assert.True(asSystem.IsDirect);
        Assert.Equal(ProxySource.None, asSystem.Source);
        Assert.Equal(ProxySource.WinHttp, asUser.Source);
        Assert.Equal(1, _system.MachineReads);
    }

    [Fact]
    public async Task Goes_direct_for_a_host_on_the_WinHTTP_bypass_list()
    {
        _system.Machine = new MachineProxy("proxy.contoso.com:8080", "<local>;*.engramic.ai");

        var route = await Choose(Shipped);

        Assert.True(route.IsDirect);
        Assert.Equal(ProxySource.WinHttp, route.Source);
        Assert.Empty(route.Notes);
        Assert.Empty(_system.Lookups);
    }

    [Fact]
    public async Task Goes_direct_when_the_WinHTTP_proxy_is_set_only_for_another_scheme_as_WinHTTP_would()
    {
        _system.Machine = new MachineProxy("http=web.contoso.com:80", string.Empty);

        var https = await Choose(Shipped);
        var http = await Choose(Shipped, new Uri("http://intranet.contoso.com/x"));

        Assert.True(https.IsDirect);
        Assert.Equal(ProxySource.WinHttp, https.Source);
        Assert.Contains("names no http:// proxy for https addresses", Assert.Single(https.Notes), StringComparison.Ordinal);
        Assert.Equal("web.contoso.com", http.Proxy?.Authority);
        Assert.Empty(_system.Lookups);
    }

    [Fact]
    public async Task Picks_the_WinHTTP_proxy_for_the_address_s_scheme()
    {
        _system.Machine = new MachineProxy("http=web.contoso.com:80;https=secure.contoso.com:8443", string.Empty);

        var route = await Choose(Shipped);

        Assert.Equal("secure.contoso.com:8443", route.Proxy?.Authority);
    }

    [Fact]
    public async Task Goes_on_to_a_PAC_file_when_the_WinHTTP_proxy_cannot_be_read()
    {
        _system.MachineError = new IOException("Access is denied.");
        _system.AnswerAlways(AutoProxyAnswer.UseProxy("wpad-proxy.contoso.com:8080"));

        var route = await Choose(Shipped);

        Assert.Equal("wpad-proxy.contoso.com:8080", route.Proxy?.Authority);
        Assert.Equal(ProxySource.AutoDetect, route.Source);
        Assert.Equal("The machine's WinHTTP proxy could not be read, so it is not used: Access is denied.", Assert.Single(route.Notes));
    }

    [Fact]
    public async Task A_WinHTTP_setting_with_no_proxy_counts_as_none()
    {
        _system.Machine = new MachineProxy("  ", "<local>");
        _system.AnswerAlways(AutoProxyAnswer.GoDirect());

        var route = await Choose(Shipped);

        Assert.Equal(ProxySource.AutoDetect, route.Source);
    }

    [Fact]
    public async Task Asks_WPAD_about_the_scheme_host_and_port_alone_when_nothing_else_names_a_proxy()
    {
        _system.AnswerAlways(AutoProxyAnswer.UseProxy("wpad-proxy.contoso.com:8080;backup.contoso.com:8080"));

        var route = await Choose(Shipped);

        Assert.Equal("wpad-proxy.contoso.com:8080", route.Proxy?.Authority);
        Assert.Equal(ProxySource.AutoDetect, route.Source);
        Assert.False(route.UseDefaultCredentials);
        Assert.Empty(route.Notes);
        var lookup = Assert.Single(_system.Lookups);
        Assert.Equal("https://baseline.engramic.ai/", lookup.Target.AbsoluteUri);
        Assert.Null(lookup.Script);
        Assert.Equal(Wait, lookup.Timeout);
    }

    [Fact]
    public async Task Never_sends_a_proxy_WPAD_found_the_Windows_sign_in_and_says_why()
    {
        _system.AnswerAlways(AutoProxyAnswer.UseProxy("wpad-proxy.contoso.com:8080"));

        var route = await Choose(Shipped with { ProxyUseDefaultCredentials = true });

        Assert.Equal(ProxySource.AutoDetect, route.Source);
        Assert.False(route.UseDefaultCredentials);
        Assert.StartsWith("proxyUseDefaultCredentials does not apply to a proxy that WPAD found", Assert.Single(route.Notes), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Goes_direct_when_the_PAC_file_says_DIRECT()
    {
        _system.AnswerAlways(AutoProxyAnswer.GoDirect());

        var route = await Choose(Shipped);

        Assert.True(route.IsDirect);
        Assert.Equal(ProxySource.AutoDetect, route.Source);
        Assert.Empty(route.Notes);
    }

    [Fact]
    public async Task Goes_direct_with_a_note_when_WPAD_finds_nothing()
    {
        _system.AnswerAlways(AutoProxyAnswer.NotFound("No PAC file was found (WinHTTP error 12180)."));

        var route = await Choose(Shipped);

        Assert.True(route.IsDirect);
        Assert.Equal(ProxySource.None, route.Source);
        Assert.Equal("WPAD found no PAC file on the local network, so the request goes direct. No PAC file was found (WinHTTP error 12180).", Assert.Single(route.Notes));
    }

    [Fact]
    public async Task Goes_direct_with_a_note_when_the_PAC_file_WPAD_found_fails()
    {
        _system.AnswerAlways(AutoProxyAnswer.Failed("The PAC file's script failed."));

        var route = await Choose(Shipped);

        Assert.Equal(ProxySource.None, route.Source);
        Assert.Equal("The PAC file WPAD found could not be used, so the request goes direct. The PAC file's script failed.", Assert.Single(route.Notes));
    }

    [Fact]
    public async Task Goes_direct_with_a_note_when_the_PAC_file_names_no_proxy_it_can_use()
    {
        _system.AnswerAlways(AutoProxyAnswer.UseProxy("socks=socks.contoso.com:1080"));

        var route = await Choose(Shipped);

        Assert.True(route.IsDirect);
        Assert.Equal(ProxySource.AutoDetect, route.Source);
        Assert.Equal("The PAC file WPAD found named no proxy this tool can use (socks=socks.contoso.com:1080), so the request goes direct.", Assert.Single(route.Notes));
    }

    [Fact]
    public async Task Stops_waiting_for_a_PAC_file_after_its_time_and_goes_direct()
    {
        var time = new FakeTimeProvider();
        _system.NeverAnswer();

        // The wait's timer starts before the choice first yields, so the clock can move at once.
        var choosing = Choose(Shipped, time: time);
        Assert.False(choosing.IsCompleted);
        time.Advance(Wait);
        var route = await choosing.WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.True(route.IsDirect);
        Assert.Equal(ProxySource.None, route.Source);
        Assert.Equal("WPAD gave no answer within 10 seconds, so the request goes direct.", Assert.Single(route.Notes));
    }

    [Fact]
    public async Task Asks_the_configured_PAC_file_instead_of_WPAD_and_may_send_its_proxy_the_sign_in()
    {
        _system.AnswerAlways(AutoProxyAnswer.UseProxy("pac-proxy.contoso.com:3128"));

        var route = await Choose(Shipped with { ProxyAutoConfigUrl = "http://pac.contoso.com/proxy.pac" });
        var signedIn = await Choose(Shipped with { ProxyAutoConfigUrl = "https://pac.contoso.com/proxy.pac", ProxyUseDefaultCredentials = true });

        Assert.Equal("pac-proxy.contoso.com:3128", route.Proxy?.Authority);
        Assert.Equal(ProxySource.AutoConfigUrl, route.Source);
        Assert.False(route.UseDefaultCredentials);
        Assert.True(signedIn.UseDefaultCredentials);
        Assert.Empty(signedIn.Notes);
        Assert.Equal(["http://pac.contoso.com/proxy.pac", "https://pac.contoso.com/proxy.pac"], _system.Lookups.Select(l => l.Script?.AbsoluteUri));
    }

    [Fact]
    public async Task Does_not_fall_back_to_WPAD_when_the_configured_PAC_file_fails()
    {
        _system.Answer = (_, script) => Task.FromResult(script is null ? AutoProxyAnswer.UseProxy("wpad-proxy.contoso.com:8080") : AutoProxyAnswer.Failed("It could not be downloaded."));

        var route = await Choose(Shipped with { ProxyAutoConfigUrl = "http://pac.contoso.com/proxy.pac" });

        Assert.True(route.IsDirect);
        Assert.Equal(ProxySource.None, route.Source);
        Assert.Equal("The PAC file at http://pac.contoso.com/proxy.pac could not be used, so the request goes direct. It could not be downloaded.", Assert.Single(route.Notes));
        Assert.Single(_system.Lookups);
    }

    [Fact]
    public async Task Says_when_the_configured_PAC_file_gives_no_answer_in_time()
    {
        var time = new FakeTimeProvider();
        _system.NeverAnswer();

        var choosing = Choose(Shipped with { ProxyAutoConfigUrl = "http://pac.contoso.com/proxy.pac" }, time: time);
        time.Advance(Wait);
        var route = await choosing.WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal("The PAC file at http://pac.contoso.com/proxy.pac gave no answer within 10 seconds, so the request goes direct.", Assert.Single(route.Notes));
    }

    [Theory]
    [InlineData("ftp://pac.contoso.com/proxy.pac")]
    [InlineData("pac.contoso.com/proxy.pac")]
    public async Task Passes_over_a_PAC_address_that_is_not_http_or_https_to_WPAD(string pac)
    {
        _system.AnswerAlways(AutoProxyAnswer.GoDirect());

        var route = await Choose(Shipped with { ProxyAutoConfigUrl = pac });

        Assert.Equal(ProxySource.AutoDetect, route.Source);
        Assert.Equal("Ignoring proxyAutoConfigUrl in network.json: it must be an http:// or https:// URL.", Assert.Single(route.Notes));
        Assert.Null(Assert.Single(_system.Lookups).Script);
    }

    [Fact]
    public async Task Goes_direct_without_asking_when_WPAD_is_off_and_no_PAC_file_is_named()
    {
        var route = await Choose(Shipped with { ProxyAutoDetect = false });

        Assert.True(route.IsDirect);
        Assert.Equal(ProxySource.None, route.Source);
        Assert.Empty(route.Notes);
        Assert.Empty(_system.Lookups);
        Assert.Equal(1, _system.MachineReads);
    }

    [Fact]
    public async Task Carries_the_problems_of_reading_the_settings_into_every_route()
    {
        var settings = Shipped with { ProxyAutoDetect = false, Problems = ["config/network.json is not valid."] };

        Assert.Equal(["config/network.json is not valid."], (await Choose(settings)).Notes);
        Assert.Equal(["config/network.json is not valid."], (await Choose(settings, new Uri("http://localhost:1/"))).Notes);
    }

    [Fact]
    public async Task Stops_when_the_caller_cancels()
    {
        _system.NeverAnswer();
        using var cancel = new CancellationTokenSource();

        var choosing = new ProxyChooser(Shipped, _system, isSystem: true).ChooseAsync(Catalog, Wait, cancel.Token);
        await cancel.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => choosing.WaitAsync(Wait, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Refuses_a_relative_address_or_no_time_to_wait()
    {
        var chooser = new ProxyChooser(Shipped, _system, isSystem: false);

        await Assert.ThrowsAsync<ArgumentException>(() => chooser.ChooseAsync(new Uri("/v1", UriKind.Relative), Wait, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => chooser.ChooseAsync(Catalog, TimeSpan.Zero, TestContext.Current.CancellationToken));
    }

    private Task<ProxyRoute> Choose(ProxySettings settings, Uri? target = null, bool isSystem = true, TimeProvider? time = null)
    {
        return new ProxyChooser(settings, _system, isSystem, time).ChooseAsync(target ?? Catalog, Wait, TestContext.Current.CancellationToken);
    }
}
