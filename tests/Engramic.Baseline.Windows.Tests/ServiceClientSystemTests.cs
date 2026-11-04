using System.Globalization;
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

    /// <summary>How many times the WPAD test asks, when WPAD answers that it found nothing or could not use it.</summary>
    private const int WpadAttempts = 4;

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
        Assert.StartsWith("NTLM ", Assert.Single(SignIns(proxy.Requests)), StringComparison.Ordinal);
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

        // The WinHTTP proxy is the whole machine's, so while it is set other programs, such as Windows' own as SYSTEM,
        // send their requests through it too. Only this test's own, to the .test addresses, are this client's.
        var ours = proxy.Requests.Where(r => r.Target.EndsWith(".test:443", StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.All(ours, r => Assert.Equal("service.test:443", r.Target));
        Assert.StartsWith("NTLM ", Assert.Single(SignIns(ours)), StringComparison.Ordinal);
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
        Assert.StartsWith("NTLM ", Assert.Single(SignIns(proxy.Requests)), StringComparison.Ordinal);
    }

    [Fact(Explicit = true)]
    public async Task Sends_through_the_proxy_a_PAC_file_WPAD_finds_and_never_with_the_sign_in()
    {
        Assert.SkipUnless(Elevation.IsSystem, NeedsSystem);
        using var proxy = AskingForNtlm();

        // WPAD asks DHCP and then DNS for wpad under this machine's DNS suffixes, and fetches /wpad.dat on port 80,
        // which may already be in use, so it is served through http.sys for those names only.
        var names = MachineProxySettings.WpadNames();
        using var wpad = new WpadServer(names, Script(proxy.Port));
        using var hosts = MachineProxySettings.AddHostNames(names);
        var edited = wpad.Elapsed;
        var cancellationToken = TestContext.Current.CancellationToken;
        var unresolved = await MachineProxySettings.WaitForHostNamesAsync(names, TimeSpan.FromSeconds(15), cancellationToken);
        var setup = string.Create(CultureInfo.InvariantCulture, $"WPAD names in the hosts file: {string.Join(", ", names)}, added and the DNS cache flushed by {edited.TotalSeconds:0.000} s; {(unresolved.Count > 0 ? "these did not resolve to 127.0.0.1: " + string.Join(", ", unresolved) : "all resolved to 127.0.0.1")} by {wpad.Elapsed.TotalSeconds:0.000} s");
        var attempts = new List<string>();
        try
        {
            // The WinHTTP Web Proxy Auto-Discovery service keeps what WPAD found, or that it found nothing, until a
            // reset, and looks for the machine's other programs too. On CI a lookup straight after the reset has
            // answered that WPAD found nothing (WinHTTP error 12180) although wpad.dat was requested, and passed
            // when run again. So the names must resolve first, and only a route WPAD gave nothing for (none found,
            // unusable or too slow) is asked for again, after another reset and a pause in which a look the reset
            // starts can end. The attempts that go direct never reach the proxy, so the checks below hold for all.
            ServiceResponse response;
            for (var attempt = 1; ; attempt++)
            {
                var reset = wpad.Elapsed;
                MachineProxySettings.ResetAutoProxy();
                if (attempt > 1)
                {
                    await Task.Delay(TimeSpan.FromSeconds(attempt), cancellationToken);
                }

                var started = wpad.Elapsed;
                var settings = new ProxySettings { UseWinHttpProxyWhenSystem = false, ProxyUseDefaultCredentials = true };
                var client = new ServiceClient(new ServiceClientOptions { Proxy = settings, IsSystem = true, AutoProxyTimeout = TimeSpan.FromSeconds(45) });
                response = await client.GetAsync(new ServiceRequest(Remote) { Timeout = TimeSpan.FromSeconds(60) }, cancellationToken);
                attempts.Add(string.Create(CultureInfo.InvariantCulture, $"attempt {attempt}, reset at {reset.TotalSeconds:0.000} s, asked from {started.TotalSeconds:0.000} s to {wpad.Elapsed.TotalSeconds:0.000} s: {Describe(response.Route)}"));
                if (response.Route?.Source != ProxySource.None || attempt == WpadAttempts)
                {
                    break;
                }
            }

            var seen = string.Join(", ", wpad.Requests);
            Assert.True(
                response.Route?.Source == ProxySource.AutoDetect,
                $"The route came from {Describe(response.Route)}. Times are from when port 80 was served. {setup}. Attempts: {string.Join("; ", attempts)}. Requests on port 80: {(seen.Length > 0 ? seen : "none")}. The WinHTTP Web Proxy Auto-Discovery service: {MachineProxySettings.AutoProxyServiceState()}.");
            TestContext.Current.TestOutputHelper?.WriteLine($"WPAD's proxy was used. Times are from when port 80 was served. {setup}. Attempts: {string.Join("; ", attempts)}. Requests on port 80: {seen}.");
            Assert.Equal(proxy.Port, response.Route?.Proxy?.Port);
            Assert.False(response.Route?.UseDefaultCredentials);
            Assert.StartsWith("proxyUseDefaultCredentials does not apply to a proxy that WPAD found", Assert.Single(response.Route!.Notes), StringComparison.Ordinal);
            Assert.Contains(wpad.Requests, r => r.EndsWith(": the PAC file", StringComparison.Ordinal));
            Assert.Equal("service.test:443", Assert.Single(proxy.Requests).Target);
            Assert.Empty(SignIns(proxy.Requests));
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

    private static List<string> SignIns(IEnumerable<LoopbackRequest> requests)
    {
        return [.. requests.Select(r => r.Header("Proxy-Authorization")).OfType<string>()];
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
