namespace Engramic.Baseline.Platform.Tests;

/// <summary>
/// The addresses the service client accepts, as the PowerShell tool's Resolve-CEServiceUri decides: https, and
/// plain http only to this device.
/// </summary>
public sealed class ServiceUriTests
{
    [Fact]
    public void Joins_the_base_address_and_the_path_as_the_PowerShell_tool_does()
    {
        Assert.True(ServiceUri.TryResolve("https://baseline.engramic.ai/", "v1/firmware/dell/0CF1", out var uri, out var error));
        Assert.Equal("https://baseline.engramic.ai/v1/firmware/dell/0CF1", uri.AbsoluteUri);
        Assert.Equal(string.Empty, error);

        Assert.True(ServiceUri.TryResolve("  http://localhost:8787  ", "/v1/firmware/dell/0CF1", out uri, out _));
        Assert.Equal("http://localhost:8787/v1/firmware/dell/0CF1", uri.AbsoluteUri);
    }

    [Theory]
    [InlineData(null, "No base URL is configured")]
    [InlineData("", "No base URL is configured")]
    [InlineData("   ", "No base URL is configured")]
    [InlineData("not a url", "The base URL is not valid: not a url")]
    [InlineData("http://baseline.engramic.ai", "The base URL must be https (http only for localhost): http://baseline.engramic.ai")]
    [InlineData("file:///C:/x", "The base URL must be https (http only for localhost): file:///C:/x")]
    [InlineData("ftp://files.example.com", "The base URL must be https (http only for localhost): ftp://files.example.com")]
    public void Refuses_what_is_missing_invalid_or_not_https_with_the_PowerShell_tool_s_words(string? baseUrl, string expected)
    {
        Assert.False(ServiceUri.TryResolve(baseUrl, "x", out var uri, out var error));
        Assert.Null(uri);
        Assert.Equal(expected, error);
    }

    [Theory]
    [InlineData("https", "baseline.engramic.ai", true)]
    [InlineData("https", "127.0.0.1", true)]
    [InlineData("http", "localhost", true)]
    [InlineData("http", "LOCALHOST", true)]
    [InlineData("http", "127.0.0.1", true)]
    [InlineData("http", "[::1]", true)]
    [InlineData("http", "baseline.engramic.ai", false)]
    [InlineData("http", "127.0.0.2", false)]
    [InlineData("http", "localhost.example.com", false)]
    [InlineData("ftp", "localhost", false)]
    public void Allows_https_anywhere_and_plain_http_only_to_this_device(string scheme, string host, bool allowed)
    {
        // Built rather than written out, so that no address on this device reads as a host to allowlist.
        var address = new UriBuilder(scheme, host, 8787, "v1/firmware").Uri;

        Assert.Equal(allowed, ServiceUri.IsAllowed(address));
        Assert.False(ServiceUri.IsAllowed(new Uri("file:///C:/Windows/win.ini")));
    }

    [Fact]
    public void A_relative_address_is_never_allowed()
    {
        Assert.False(ServiceUri.IsAllowed(new Uri("/v1/firmware", UriKind.Relative)));
        Assert.False(ServiceUri.IsThisDevice(new Uri("localhost", UriKind.Relative)));
    }
}
