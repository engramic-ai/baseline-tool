using System.Net;
using System.Reflection;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;
using Engramic.Baseline.Testing.Windows;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// The service client without a network: the handler each route gets, what it refuses before choosing a route,
/// and its options.
/// </summary>
public sealed class ServiceClientTests
{
    private static readonly Uri Proxy = new("http://proxy.contoso.com:8080/");
    private static readonly TimeSpan Connect = TimeSpan.FromSeconds(7);

    [Fact]
    public void A_direct_route_gets_a_handler_with_no_proxy_at_all()
    {
        using var handler = ServiceClient.CreateHandler(new ProxyRoute { Source = ProxySource.WinHttp }, Connect);

        // Not the default proxy either, which follows environment variables and, as SYSTEM, SYSTEM's own settings.
        Assert.False(handler.UseProxy);
        Assert.Null(handler.Proxy);
        AssertTheSiteGetsOnlyTheRequest(handler);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void A_proxy_route_gets_a_handler_with_that_proxy_alone_and_the_sign_in_only_when_allowed(bool signIn)
    {
        using var handler = ServiceClient.CreateHandler(new ProxyRoute { Proxy = Proxy, Source = ProxySource.NetworkConfig, UseDefaultCredentials = signIn }, Connect);

        Assert.True(handler.UseProxy);
        var proxy = Assert.IsType<WebProxy>(handler.Proxy);
        Assert.Equal(Proxy, proxy.Address);
        Assert.Equal(signIn, proxy.UseDefaultCredentials);
        Assert.Same(signIn ? CredentialCache.DefaultCredentials : null, proxy.Credentials);
        Assert.False(proxy.BypassProxyOnLocal);
        Assert.Empty(proxy.BypassList);
        AssertTheSiteGetsOnlyTheRequest(handler);
    }

    [Theory]
    [InlineData("http://baseline.engramic.ai/v1/firmware/dell/0CF1")]
    [InlineData("ftp://localhost/v1")]
    [InlineData("file:///C:/Windows/win.ini")]
    public async Task Refuses_an_address_that_is_not_https_or_http_to_this_device_before_choosing_a_route(string address)
    {
        var system = new FakeSystemProxy { Machine = new MachineProxy("proxy.contoso.com:8080", string.Empty) };
        var client = new ServiceClient(new ServiceClientOptions { Proxy = new ProxySettings(), IsSystem = true, SystemProxy = system });

        var response = await client.GetAsync(new ServiceRequest(new Uri(address)), TestContext.Current.CancellationToken);

        Assert.Equal(0, response.StatusCode);
        Assert.Equal("The address must be https (http only for localhost): " + new Uri(address), response.Error);
        Assert.False(response.Succeeded);
        Assert.Null(response.Route);
        Assert.Equal(0, system.MachineReads);
        Assert.Empty(system.Lookups);
    }

    [Fact]
    public void Names_itself_and_its_version_in_the_User_Agent_as_the_PowerShell_tool_does()
    {
        var version = typeof(ServiceClient).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;

        Assert.Equal("EngramicBaseline/" + version, ServiceClientOptions.DefaultUserAgent);
        Assert.DoesNotContain("+", version, StringComparison.Ordinal);
        Assert.Equal(ServiceClientOptions.DefaultUserAgent, new ServiceClientOptions { Proxy = new ProxySettings(), IsSystem = false }.UserAgent);
    }

    [Fact]
    public void Asks_WinHTTP_and_waits_10_seconds_for_a_PAC_file_by_default()
    {
        var options = new ServiceClientOptions { Proxy = new ProxySettings(), IsSystem = false };

        Assert.IsType<WinHttpProxy>(options.SystemProxy);
        Assert.Equal(TimeSpan.FromSeconds(10), options.AutoProxyTimeout);
        Assert.Same(TimeProvider.System, options.Time);
    }

    [Fact]
    public void Reads_whether_this_process_runs_as_SYSTEM_from_its_token()
    {
        var settings = new ProxySettings { ProxyUrl = "http://proxy.contoso.com:8080" };

        var options = ServiceClientOptions.ForThisProcess(settings);

        Assert.Equal(Elevation.IsSystem, options.IsSystem);
        Assert.Same(settings, options.Proxy);
    }

    [Fact]
    public void Refuses_options_with_no_time_for_a_PAC_file_or_no_User_Agent()
    {
        var options = new ServiceClientOptions { Proxy = new ProxySettings(), IsSystem = false };

        Assert.Throws<ArgumentOutOfRangeException>(() => new ServiceClient(options with { AutoProxyTimeout = TimeSpan.Zero }));
        Assert.Throws<ArgumentException>(() => new ServiceClient(options with { UserAgent = " " }));
    }

    [Fact]
    public void Reports_the_innermost_message_as_a_sentence()
    {
        var wrapped = new HttpRequestException("An error occurred while sending the request.", new IOException("Unable to read data from the transport connection", new InvalidOperationException("No such host is known")));

        Assert.Equal("No such host is known.", ServiceClient.Innermost(wrapped));
        Assert.Equal("Done!", ServiceClient.Innermost(new IOException("Done!")));
        Assert.Equal("The request failed.", ServiceClient.Innermost(new IOException(" ")));
    }

    private static void AssertTheSiteGetsOnlyTheRequest(SocketsHttpHandler handler)
    {
        Assert.Null(handler.Credentials);
        Assert.Null(handler.DefaultProxyCredentials);
        Assert.False(handler.PreAuthenticate);
        Assert.False(handler.UseCookies);
        Assert.False(handler.AllowAutoRedirect);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);

        // The operating system's trusted roots decide, with no pinning and no certificate of this device's.
        Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.Null(handler.SslOptions.ClientCertificates);
        Assert.Equal(Connect, handler.ConnectTimeout);
        Assert.True(handler.MaxResponseHeadersLength <= 64);
    }
}
