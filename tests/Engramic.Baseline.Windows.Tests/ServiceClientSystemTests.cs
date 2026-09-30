using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;
using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// The service client as SYSTEM, the account the scheduled audit runs as, which has no Internet settings of
/// its own: network.json's proxy, the machine's WinHTTP proxy set with netsh, a PAC file named in network.json,
/// and one that WPAD finds, each seen at a proxy on the loopback address; the computer account's sign-in sent
/// only where it is allowed; and plain http refused.
/// </summary>
/// <remarks>
/// These tests change the machine: its WinHTTP proxy, its hosts file and WinHTTP's record of what WPAD found,
/// each put back afterwards. So they are explicit, never run with the other tests, and skip unless the process
/// is SYSTEM. CI runs them on its throwaway runner through a scheduled task (tools/ci/Test-AsSystem.ps1).
/// </remarks>
[Trait("Context", "System")]
public sealed class ServiceClientSystemTests
{
    private const string NeedsSystem = "Changes the machine's proxy settings and needs SYSTEM, as CI runs it on a throwaway runner; skipped otherwise.";

    /// <summary>An address that is not on this device, which only a proxy ever sees the name of.</summary>
    private static readonly Uri Remote = new("https://service.test/v1/firmware/dell/0CF1");

    [Fact(Explicit = true)]
    public async Task Sends_through_network_json_s_proxy_with_the_computer_account_s_sign_in_only_when_allowed()
    {
        Assert.SkipUnless(Elevation.IsSystem, NeedsSystem);
        using var proxy = AskingForNtlm();
        var settings = new ProxySettings { ProxyUrl = proxy.Address.AbsoluteUri, ProxyAutoDetect = false };

        var plain = await Client(settings).GetAsync(new ServiceRequest(Remote), TestContext.Current.CancellationToken);
        var signedIn = await Client(settings with { ProxyUseDefaultCredentials = true }).GetAsync(new ServiceRequest(Remote), TestContext.Current.CancellationToken);

        Assert.Equal(ProxySource.NetworkConfig, plain.Route?.Source);
        Assert.False(plain.Route?.UseDefaultCredentials);
        Assert.True(signedIn.Route?.UseDefaultCredentials);
        Assert.All(proxy.Requests, r => Assert.Equal("service.test:443", r.Target));
        Assert.StartsWith("NTLM ", Assert.Single(SignIns(proxy)), StringComparison.Ordinal);
        Assert.Equal(3, proxy.Requests.Count);
    }

    [Fact(Explicit = true)]
    public async Task Uses_the_WinHTTP_proxy_netsh_sets_with_its_bypass_list_and_the_switch_that_skips_it()
    {
        Assert.SkipUnless(Elevation.IsSystem, NeedsSystem);
        using var proxy = AskingForNtlm();
        using var machine = MachineProxySettings.SetWinHttpProxy($"127.0.0.1:{proxy.Port}", "<local>;*.bypassed.test");
        var settings = new ProxySettings { ProxyAutoDetect = false };

        var read = new WinHttpProxy().ReadMachineProxy();
        Assert.Equal($"127.0.0.1:{proxy.Port}", read?.Proxy);
        Assert.Contains("*.bypassed.test", read?.Bypass, StringComparison.OrdinalIgnoreCase);
        var proxied = await Client(settings).GetAsync(new ServiceRequest(Remote), TestContext.Current.CancellationToken);
        var signedIn = await Client(settings with { ProxyUseDefaultCredentials = true }).GetAsync(new ServiceRequest(Remote), TestContext.Current.CancellationToken);
        var bypassed = await Client(settings).GetAsync(new ServiceRequest(new Uri("https://api.bypassed.test/v1")) { Timeout = TimeSpan.FromSeconds(5) }, TestContext.Current.CancellationToken);
        var skipped = await Client(settings with { UseWinHttpProxyWhenSystem = false }).GetAsync(new ServiceRequest(new Uri("https://skipped.test/v1")) { Timeout = TimeSpan.FromSeconds(5) }, TestContext.Current.CancellationToken);

        Assert.Equal(ProxySource.WinHttp, proxied.Route?.Source);
        Assert.Equal(proxy.Port, proxied.Route?.Proxy?.Port);
        Assert.False(proxied.Route?.UseDefaultCredentials);
        Assert.True(signedIn.Route?.UseDefaultCredentials);
        Assert.Equal(ProxySource.WinHttp, bypassed.Route?.Source);
        Assert.True(bypassed.Route?.IsDirect);
        Assert.Equal(ProxySource.None, skipped.Route?.Source);
        Assert.True(skipped.Route?.IsDirect);
        Assert.All(proxy.Requests, r => Assert.Equal("service.test:443", r.Target));
        Assert.StartsWith("NTLM ", Assert.Single(SignIns(proxy)), StringComparison.Ordinal);
    }

    [Fact(Explicit = true)]
    public async Task Sends_through_the_proxy_a_named_PAC_file_gives_with_the_sign_in_when_allowed()
    {
        Assert.SkipUnless(Elevation.IsSystem, NeedsSystem);
        using var proxy = AskingForNtlm();
        using var pac = new LoopbackServer(_ => LoopbackReply.Pac(Script(proxy.Port)));

        // The machine's WinHTTP proxy, whatever it is, is skipped as SYSTEM, so the PAC file decides.
        var settings = new ProxySettings { UseWinHttpProxyWhenSystem = false, ProxyAutoConfigUrl = pac.At("/proxy.pac").AbsoluteUri, ProxyUseDefaultCredentials = true };
        var response = await Client(settings).GetAsync(new ServiceRequest(Remote), TestContext.Current.CancellationToken);

        Assert.True(response.Route?.Source == ProxySource.AutoConfigUrl, "The route came from " + Describe(response.Route));
        Assert.Equal(proxy.Port, response.Route?.Proxy?.Port);
        Assert.True(response.Route?.UseDefaultCredentials);
        Assert.NotEmpty(pac.Requests);
        Assert.StartsWith("NTLM ", Assert.Single(SignIns(proxy)), StringComparison.Ordinal);
    }

    [Fact(Explicit = true)]
    public async Task Sends_through_the_proxy_a_PAC_file_WPAD_finds_and_never_with_the_sign_in()
    {
        Assert.SkipUnless(Elevation.IsSystem, NeedsSystem);
        using var proxy = AskingForNtlm();

        // WPAD asks DHCP and then DNS for wpad under this machine's DNS suffixes, and fetches /wpad.dat on port 80.
        using var wpad = new LoopbackServer(r => r.Target == "/wpad.dat" ? LoopbackReply.Pac(Script(proxy.Port)) : LoopbackReply.Of(404, "Not Found") with { Close = true }, port: 80);
        var names = MachineProxySettings.WpadNames();
        using var hosts = MachineProxySettings.AddHostNames(names);
        MachineProxySettings.ResetAutoProxy();
        try
        {
            var settings = new ProxySettings { UseWinHttpProxyWhenSystem = false, ProxyUseDefaultCredentials = true };
            var client = new ServiceClient(new ServiceClientOptions { Proxy = settings, IsSystem = true, AutoProxyTimeout = TimeSpan.FromSeconds(45) });
            var response = await client.GetAsync(new ServiceRequest(Remote) { Timeout = TimeSpan.FromSeconds(60) }, TestContext.Current.CancellationToken);

            var seen = string.Join(", ", wpad.Requests.Select(r => $"{r.Header("Host")}{r.Target}"));
            Assert.True(response.Route?.Source == ProxySource.AutoDetect, $"The route came from {Describe(response.Route)}. WPAD names in the hosts file: {string.Join(", ", names)}. Requests on port 80: {(seen.Length > 0 ? seen : "none")}.");
            Assert.Equal(proxy.Port, response.Route?.Proxy?.Port);
            Assert.False(response.Route?.UseDefaultCredentials);
            Assert.StartsWith("proxyUseDefaultCredentials does not apply to a proxy that WPAD found", Assert.Single(response.Route!.Notes), StringComparison.Ordinal);
            Assert.Equal("service.test:443", Assert.Single(proxy.Requests).Target);
            Assert.Empty(SignIns(proxy));
        }
        finally
        {
            MachineProxySettings.ResetAutoProxy();
        }
    }

    [Fact(Explicit = true)]
    public async Task Refuses_plain_http_except_to_this_device()
    {
        Assert.SkipUnless(Elevation.IsSystem, NeedsSystem);
        using var proxy = AskingForNtlm();
        using var site = new LoopbackServer(_ => LoopbackReply.Ok("ok"));
        var client = Client(new ProxySettings { ProxyUrl = proxy.Address.AbsoluteUri });

        var refused = await client.GetAsync(new ServiceRequest(new Uri("http://service.test/v1")), TestContext.Current.CancellationToken);
        var local = await client.GetAsync(new ServiceRequest(site.At("/v1")), TestContext.Current.CancellationToken);

        Assert.Equal("The address must be https (http only for localhost): http://service.test/v1", refused.Error);
        Assert.Null(refused.Route);
        Assert.Equal(200, local.StatusCode);
        Assert.Equal(ProxySource.Local, local.Route?.Source);
        Assert.Empty(proxy.Requests);
    }

    private static ServiceClient Client(ProxySettings settings)
    {
        return new ServiceClient(new ServiceClientOptions { Proxy = settings, IsSystem = true });
    }

    /// <summary>A proxy that asks each new CONNECT for NTLM, and refuses one that carries it.</summary>
    private static LoopbackServer AskingForNtlm()
    {
        return new LoopbackServer(r => r.Header("Proxy-Authorization") is null
            ? LoopbackReply.Of(407, "Proxy Authentication Required", "Proxy-Authenticate", "NTLM")
            : LoopbackReply.Of(403, "Forbidden") with { Close = true });
    }

    private static List<string> SignIns(LoopbackServer proxy)
    {
        return [.. proxy.Requests.Select(r => r.Header("Proxy-Authorization")).OfType<string>()];
    }

    private static string Script(int proxyPort)
    {
        return $$"""function FindProxyForURL(url, host) { if (host == "service.test") return "PROXY 127.0.0.1:{{proxyPort}}"; return "DIRECT"; }""";
    }

    private static string Describe(ProxyRoute? route)
    {
        return route is null ? "nowhere: the request was refused" : $"{route.Source} ({string.Join(" | ", route.Notes)})";
    }
}
