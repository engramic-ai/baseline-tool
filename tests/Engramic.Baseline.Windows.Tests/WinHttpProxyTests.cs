using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// What WinHTTP says about proxies, read for real: the machine's WinHTTP proxy, which is only read, and PAC files
/// served from the loopback address, which the WinHTTP service fetches and runs outside this process.
/// </summary>
public sealed class WinHttpProxyTests
{
    private static readonly Uri Target = new("https://service.test/");
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    private readonly WinHttpProxy _winHttp = new();

    [Fact]
    public void Reads_the_machine_s_WinHTTP_proxy_the_same_way_twice()
    {
        var first = _winHttp.ReadMachineProxy();
        var second = _winHttp.ReadMachineProxy();

        Assert.Equal(first, second);
        Assert.True(first is null || first.Proxy.Trim().Length > 0);
    }

    [Fact]
    public async Task Hears_the_proxies_a_PAC_file_names_without_its_fallback_to_DIRECT()
    {
        using var pac = new LoopbackServer(_ => LoopbackReply.Pac("function FindProxyForURL(url, host) { return \"PROXY first.contoso.com:8080; PROXY second.contoso.com:8080; DIRECT\"; }"));

        var answer = await _winHttp.FindAutoProxyAsync(Target, pac.At("/proxy.pac"), Wait).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(AutoProxyOutcome.Proxy, answer.Outcome);
        Assert.StartsWith("first.contoso.com:8080", answer.Proxy, StringComparison.Ordinal);
        Assert.Contains("second.contoso.com:8080", answer.Proxy, StringComparison.Ordinal);
        Assert.DoesNotContain("DIRECT", answer.Proxy, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Hears_DIRECT_from_a_PAC_file()
    {
        using var pac = new LoopbackServer(_ => LoopbackReply.Pac("function FindProxyForURL(url, host) { return \"DIRECT\"; }"));

        var answer = await _winHttp.FindAutoProxyAsync(Target, pac.At("/proxy.pac"), Wait).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(AutoProxyAnswer.GoDirect(), answer);
    }

    [Fact]
    public async Task Says_when_a_PAC_file_s_script_fails()
    {
        using var pac = new LoopbackServer(_ => LoopbackReply.Pac("function FindProxyForURL(url, host) { return notDefined(); }"));

        var answer = await _winHttp.FindAutoProxyAsync(Target, pac.At("/proxy.pac"), Wait).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(AutoProxyAnswer.Failed("Its script failed or gave no answer (WinHTTP error 12166)."), answer);
    }

    [Fact]
    public async Task Never_sends_the_server_of_a_PAC_file_the_Windows_sign_in()
    {
        using var pac = new LoopbackServer(_ => LoopbackReply.Of(401, "Unauthorized", "WWW-Authenticate", "NTLM"));

        var answer = await _winHttp.FindAutoProxyAsync(Target, pac.At("/proxy.pac"), Wait).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(AutoProxyOutcome.Failed, answer.Outcome);
        Assert.NotEmpty(pac.Requests);
        Assert.All(pac.Requests, r => Assert.Null(r.Header("Authorization")));
    }

    [Theory]
    [InlineData(12180, false, AutoProxyOutcome.NotFound, "Neither DHCP nor DNS named one (WinHTTP error 12180).")]
    [InlineData(12180, true, AutoProxyOutcome.Failed, "The lookup failed (WinHTTP error 12180).")]
    [InlineData(12167, true, AutoProxyOutcome.Failed, "It could not be downloaded (WinHTTP error 12167).")]
    [InlineData(12166, false, AutoProxyOutcome.Failed, "Its script failed or gave no answer (WinHTTP error 12166).")]
    [InlineData(12178, false, AutoProxyOutcome.Failed, "The WinHTTP Web Proxy Auto-Discovery service, which runs it outside this process, could not be used (WinHTTP error 12178).")]
    [InlineData(12015, true, AutoProxyOutcome.Failed, "Its server asked for a sign-in, which it is never sent (WinHTTP error 12015).")]
    [InlineData(12002, true, AutoProxyOutcome.Failed, "The lookup timed out (WinHTTP error 12002).")]
    [InlineData(12005, true, AutoProxyOutcome.Failed, "WinHTTP did not accept the address (WinHTTP error 12005).")]
    [InlineData(5, true, AutoProxyOutcome.Failed, "The lookup failed (WinHTTP error 5).")]
    public void Says_what_each_WinHTTP_error_means(int error, bool named, AutoProxyOutcome outcome, string detail)
    {
        Assert.Equal(new AutoProxyAnswer(outcome, string.Empty, detail), WinHttpProxy.Answer(error, named));
    }

    [Fact]
    public async Task Refuses_no_time_to_look()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _winHttp.FindAutoProxyAsync(Target, null, TimeSpan.Zero));
    }
}
