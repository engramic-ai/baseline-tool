using System.Diagnostics;
using System.Text;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// The service client against servers on the loopback address, as a site, a proxy and the host of a PAC file,
/// so that what goes over the wire is seen without leaving the device. Nothing here changes the machine's
/// settings: where a test needs the machine's WinHTTP proxy it is a fake, and a PAC file is asked through the
/// real WinHTTP service, which fetches it from the loopback address.
/// </summary>
public sealed class ServiceClientLoopbackTests
{
    /// <summary>An address that is not on this device, which only a proxy ever sees the name of.</summary>
    private static readonly Uri Remote = new("https://service.test/v1/firmware/dell/0CF1?serial=none");

    private static readonly ProxySettings NoWpad = new() { ProxyAutoDetect = false };

    private readonly FakeSystemProxy _system = new();

    [Fact]
    public async Task Sends_a_GET_with_its_User_Agent_and_ETag_and_gives_back_the_response()
    {
        using var site = new LoopbackServer(_ => LoopbackReply.Ok("{\"releases\":[]}", "ETag", "\"v2\"", "Content-Type", "application/json"));

        var response = await Client().GetAsync(new ServiceRequest(site.At("/v1/firmware/dell/0CF1")) { ETag = "\"v1\"" }, TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("{\"releases\":[]}", Encoding.UTF8.GetString(response.Body.Span));
        Assert.Equal("\"v2\"", response.ETag);
        Assert.Equal(string.Empty, response.Error);
        Assert.Equal(ProxySource.Local, response.Route?.Source);
        var sent = Assert.Single(site.Requests);
        Assert.Equal("GET", sent.Method);
        Assert.Equal("/v1/firmware/dell/0CF1", sent.Target);
        Assert.Equal(ServiceClientOptions.DefaultUserAgent, sent.Header("User-Agent"));
        Assert.Equal("\"v1\"", sent.Header("If-None-Match"));
        Assert.Null(sent.Header("Authorization"));
        Assert.Null(sent.Header("Cookie"));
        Assert.Null(sent.Header("Accept-Encoding"));
    }

    [Fact]
    public async Task Gives_back_a_304_with_its_ETag()
    {
        using var site = new LoopbackServer(_ => LoopbackReply.Of(304, "Not Modified", "ETag", "\"v1\""));

        var response = await Client().GetAsync(new ServiceRequest(site.At("/v1")) { ETag = "\"v1\"" }, TestContext.Current.CancellationToken);

        Assert.Equal(304, response.StatusCode);
        Assert.True(response.Body.IsEmpty);
        Assert.Equal("\"v1\"", response.ETag);
        Assert.True(response.Succeeded);
    }

    [Fact]
    public async Task Refuses_a_response_larger_than_the_request_allows()
    {
        using var site = new LoopbackServer(_ => LoopbackReply.Ok(new string('x', 2_048)));

        var response = await Client().GetAsync(new ServiceRequest(site.At("/v1")) { MaxBytes = 1_024 }, TestContext.Current.CancellationToken);

        Assert.Equal(0, response.StatusCode);
        Assert.True(response.Body.IsEmpty);
        Assert.Contains("1024", response.Error, StringComparison.Ordinal);
        Assert.EndsWith(ProxyChooser.ProxyHint, response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Gives_up_on_a_site_that_does_not_answer_in_time()
    {
        using var site = new LoopbackServer(_ => LoopbackReply.Silence());
        var timer = Stopwatch.StartNew();

        var response = await Client().GetAsync(new ServiceRequest(site.At("/v1")) { Timeout = TimeSpan.FromSeconds(1) }, TestContext.Current.CancellationToken);

        Assert.Equal(0, response.StatusCode);
        Assert.Equal("The request timed out after 1 second. " + ProxyChooser.ProxyHint, response.Error);
        Assert.InRange(timer.Elapsed, TimeSpan.FromSeconds(0.9), TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task Reports_a_network_failure_as_data_never_an_exception()
    {
        Uri closed;
        using (var gone = new LoopbackServer(_ => LoopbackReply.Ok(string.Empty)))
        {
            closed = gone.At("/v1/firmware/dell/0CF1");
        }

        var response = await Client().GetAsync(new ServiceRequest(closed) { Timeout = TimeSpan.FromSeconds(5) }, TestContext.Current.CancellationToken);

        Assert.Equal(0, response.StatusCode);
        Assert.EndsWith("If this device uses a proxy, set proxyUrl in network.json.", response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Does_not_follow_a_redirect()
    {
        using var site = new LoopbackServer(_ => LoopbackReply.Of(302, "Found", "Location", "https://service.test/elsewhere"));

        var response = await Client().GetAsync(new ServiceRequest(site.At("/v1")), TestContext.Current.CancellationToken);

        Assert.Equal(302, response.StatusCode);
        Assert.Single(site.Requests);
    }

    [Fact]
    public async Task Sends_a_request_through_the_proxy_network_json_names_which_sees_the_host_alone()
    {
        using var proxy = new LoopbackServer(_ => LoopbackReply.Of(403, "Forbidden") with { Close = true });

        var response = await Client(NoWpad with { ProxyUrl = proxy.Address.AbsoluteUri }).GetAsync(new ServiceRequest(Remote), TestContext.Current.CancellationToken);

        Assert.Equal(0, response.StatusCode);
        Assert.Contains("403", response.Error, StringComparison.Ordinal);
        Assert.Equal(ProxySource.NetworkConfig, response.Route?.Source);
        Assert.Equal(proxy.Address, response.Route?.Proxy);
        var connect = Assert.Single(proxy.Requests);
        Assert.Equal("CONNECT", connect.Method);
        Assert.Equal("service.test:443", connect.Target);
        Assert.Null(connect.Header("Proxy-Authorization"));
        Assert.Equal(0, _system.MachineReads);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Answers_a_proxy_s_request_for_the_Windows_sign_in_only_when_allowed(bool allowed)
    {
        // The first CONNECT is asked for NTLM; with the sign-in allowed, the second carries its first message.
        using var proxy = new LoopbackServer(r => r.Header("Proxy-Authorization") is null
            ? LoopbackReply.Of(407, "Proxy Authentication Required", "Proxy-Authenticate", "NTLM")
            : LoopbackReply.Of(403, "Forbidden") with { Close = true });
        var settings = NoWpad with { ProxyUrl = proxy.Address.AbsoluteUri, ProxyUseDefaultCredentials = allowed };

        var response = await Client(settings).GetAsync(new ServiceRequest(Remote), TestContext.Current.CancellationToken);

        Assert.Equal(allowed, response.Route?.UseDefaultCredentials);
        Assert.Contains(allowed ? "403" : "407", response.Error, StringComparison.Ordinal);
        var signIns = proxy.Requests.Select(r => r.Header("Proxy-Authorization")).Where(h => h is not null).ToList();
        if (allowed)
        {
            Assert.StartsWith("NTLM ", Assert.Single(signIns), StringComparison.Ordinal);
        }
        else
        {
            Assert.Empty(signIns);
            Assert.Single(proxy.Requests);
        }
    }

    [Fact]
    public async Task Uses_the_machine_s_WinHTTP_proxy_and_its_bypass_list()
    {
        using var proxy = new LoopbackServer(_ => LoopbackReply.Of(403, "Forbidden") with { Close = true });
        _system.Machine = new MachineProxy($"127.0.0.1:{proxy.Port}", "<local>;*.bypassed.test");
        var client = Client();

        var proxied = await client.GetAsync(new ServiceRequest(Remote), TestContext.Current.CancellationToken);
        var bypassed = await client.GetAsync(new ServiceRequest(new Uri("https://api.bypassed.test/v1")) { Timeout = TimeSpan.FromSeconds(5) }, TestContext.Current.CancellationToken);

        Assert.Equal(ProxySource.WinHttp, proxied.Route?.Source);
        Assert.Equal(proxy.Port, proxied.Route?.Proxy?.Port);
        Assert.Equal(ProxySource.WinHttp, bypassed.Route?.Source);
        Assert.True(bypassed.Route?.IsDirect);
        Assert.Equal("service.test:443", Assert.Single(proxy.Requests).Target);
    }

    [Fact]
    public async Task Asks_a_PAC_file_through_WinHTTP_about_the_host_alone_and_sends_through_the_proxy_it_names()
    {
        using var proxy = new LoopbackServer(_ => LoopbackReply.Of(403, "Forbidden") with { Close = true });

        // The script names the proxy only if it was asked about the scheme and host alone, with no path or query.
        using var pac = new LoopbackServer(_ => LoopbackReply.Pac(
            $$"""function FindProxyForURL(url, host) { if (url == "https://service.test/" && host == "service.test") return "PROXY 127.0.0.1:{{proxy.Port}}; DIRECT"; return "DIRECT"; }"""));

        var response = await Client(NoWpad with { ProxyAutoConfigUrl = pac.At("/proxy.pac").AbsoluteUri }, new PacOnly()).GetAsync(new ServiceRequest(Remote), TestContext.Current.CancellationToken);

        Assert.Equal(ProxySource.AutoConfigUrl, response.Route?.Source);
        Assert.Equal(proxy.Port, response.Route?.Proxy?.Port);
        Assert.Empty(response.Route!.Notes);
        Assert.Equal("service.test:443", Assert.Single(proxy.Requests).Target);
        Assert.Equal("/proxy.pac", Assert.Single(pac.Requests).Target);
    }

    [Fact]
    public async Task Goes_direct_when_the_PAC_file_says_DIRECT()
    {
        using var pac = new LoopbackServer(_ => LoopbackReply.Pac("function FindProxyForURL(url, host) { return \"DIRECT\"; }"));

        var route = await Choose(NoWpad with { ProxyAutoConfigUrl = pac.At("/proxy.pac").AbsoluteUri });

        Assert.True(route.IsDirect);
        Assert.Equal(ProxySource.AutoConfigUrl, route.Source);
        Assert.Empty(route.Notes);
    }

    [Fact]
    public async Task Goes_direct_with_a_note_when_the_PAC_file_cannot_be_downloaded()
    {
        Uri closed;
        using (var gone = new LoopbackServer(_ => LoopbackReply.Ok(string.Empty)))
        {
            closed = gone.At("/proxy.pac");
        }

        var route = await Choose(NoWpad with { ProxyAutoConfigUrl = closed.AbsoluteUri });

        Assert.True(route.IsDirect);
        Assert.Equal(ProxySource.None, route.Source);
        Assert.Equal($"The PAC file at {closed} could not be used, so the request goes direct. It could not be downloaded (WinHTTP error 12167).", Assert.Single(route.Notes));
    }

    private ServiceClient Client(ProxySettings? settings = null, ISystemProxy? system = null)
    {
        return new ServiceClient(new ServiceClientOptions { Proxy = settings ?? NoWpad, IsSystem = false, SystemProxy = system ?? _system });
    }

    private static Task<ProxyRoute> Choose(ProxySettings settings)
    {
        return new ProxyChooser(settings, new PacOnly(), isSystem: false).ChooseAsync(Remote, TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// WinHTTP's PAC lookup, with no machine WinHTTP proxy, so that the test does not depend on this machine's
    /// setting, which it never changes.
    /// </summary>
    private sealed class PacOnly : ISystemProxy
    {
        private readonly WinHttpProxy _winHttp = new();

        public MachineProxy? ReadMachineProxy() => null;

        public Task<AutoProxyAnswer> FindAutoProxyAsync(Uri target, Uri? scriptUrl, TimeSpan timeout)
        {
            Assert.NotNull(scriptUrl);
            return _winHttp.FindAutoProxyAsync(target, scriptUrl, timeout);
        }
    }
}
