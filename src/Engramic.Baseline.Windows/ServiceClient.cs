using System.Globalization;
using System.Net;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows;

/// <summary>
/// The service client on Windows: sends each request through an HttpClient and handler of its own, with the
/// route <see cref="ProxyChooser"/> chose for it, as the PowerShell tool's Invoke-CEHttpRequest does.
/// </summary>
/// <remarks>
/// <para>
/// The one file allowed to make an HttpClient or a handler (src/BannedApiExemptions.txt). Each handler is built
/// for one request, from its route: no proxy at all, or the one proxy named, so .NET's default proxy, which
/// follows environment variables and, as SYSTEM, SYSTEM's own Internet settings, is never used. The Windows
/// sign-in goes only to a proxy the route allows it, never to the site; cookies are not kept, redirects are not
/// followed, and nothing is decompressed. The site's certificate is checked against the operating system's
/// trusted roots, with no pinning.
/// </para>
/// <para>
/// Only https addresses are sent, and plain http to this device (<see cref="ServiceUri.IsAllowed"/>); anything
/// else is refused before a route is chosen. A response larger than the request allows, or slower, fails it. A
/// failure comes back as a response with an error, never as an exception.
/// </para>
/// </remarks>
public sealed class ServiceClient : IServiceClient
{
    private readonly ServiceClientOptions _options;
    private readonly ProxyChooser _chooser;

    /// <summary>Makes the client.</summary>
    /// <param name="options">The proxy settings and the rest; <see cref="ServiceClientOptions.ForThisProcess"/> for this process's.</param>
    public ServiceClient(ServiceClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(options.AutoProxyTimeout, TimeSpan.Zero);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.UserAgent);
        _options = options;
        _chooser = new ProxyChooser(options.Proxy, options.SystemProxy, options.IsSystem, options.Time);
    }

    /// <inheritdoc/>
    public async Task<ServiceResponse> GetAsync(ServiceRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!ServiceUri.IsAllowed(request.Uri))
        {
            return new ServiceResponse { Error = "The address must be https (http only for localhost): " + request.Uri };
        }

        var wait = request.Timeout < _options.AutoProxyTimeout ? request.Timeout : _options.AutoProxyTimeout;
        var route = await _chooser.ChooseAsync(request.Uri, wait, cancellationToken).ConfigureAwait(false);
        try
        {
            return await SendAsync(request, route, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (TaskCanceledException e) when (e.InnerException is TimeoutException)
        {
            return Failed(route, $"The request timed out after {Describe(request.Timeout)}.");
        }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException or IOException)
        {
            return Failed(route, Innermost(e));
        }
    }

    /// <summary>
    /// The handler for one request: no proxy, or the route's alone, with the Windows sign-in only for a proxy the
    /// route allows it, and nothing sent to the site but the request.
    /// </summary>
    internal static SocketsHttpHandler CreateHandler(ProxyRoute route, TimeSpan connectTimeout)
    {
        ArgumentNullException.ThrowIfNull(route);
        var proxy = route.Proxy is null ? null : new WebProxy(route.Proxy) { UseDefaultCredentials = route.UseDefaultCredentials };
#pragma warning disable RS0030 // The service client: a handler for one request, with the route chosen for it, never .NET's default proxy
        return new SocketsHttpHandler
        {
            UseProxy = proxy is not null,
            Proxy = proxy,
            DefaultProxyCredentials = null,
            Credentials = null,
            PreAuthenticate = false,
            UseCookies = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = connectTimeout,
        };
#pragma warning restore RS0030
    }

    /// <summary>The innermost message of a failure, which HttpClient wraps, as a sentence, as the PowerShell tool's Get-CEHttpErrorText gives it.</summary>
    internal static string Innermost(Exception failure)
    {
        var inner = failure;
        while (inner.InnerException is not null)
        {
            inner = inner.InnerException;
        }

        var message = inner.Message.Trim();
        if (message.Length == 0)
        {
            message = "The request failed";
        }

        return message[^1] is '.' or '!' or '?' ? message : message + ".";
    }

    private static ServiceResponse Failed(ProxyRoute route, string message)
    {
        return new ServiceResponse { Error = message + " " + ProxyChooser.ProxyHint, Route = route };
    }

    private static string Describe(TimeSpan time)
    {
        var seconds = time.TotalSeconds;
        return string.Create(CultureInfo.InvariantCulture, $"{seconds:0.###} second{(seconds == 1 ? string.Empty : "s")}");
    }

    private async Task<ServiceResponse> SendAsync(ServiceRequest request, ProxyRoute route, CancellationToken cancellationToken)
    {
        using var message = new HttpRequestMessage(HttpMethod.Get, request.Uri);
        _ = message.Headers.TryAddWithoutValidation("User-Agent", _options.UserAgent);
        if (!string.IsNullOrEmpty(request.ETag))
        {
            _ = message.Headers.TryAddWithoutValidation("If-None-Match", request.ETag);
        }

#pragma warning disable RS0030 // The service client: sends the request through its own handler and client, which buffer at most the request's bytes, for at most its time
        using var handler = CreateHandler(route, request.Timeout);
        using var client = new HttpClient(handler, disposeHandler: false) { Timeout = request.Timeout, MaxResponseContentBufferSize = request.MaxBytes };
        using var response = await client.SendAsync(message, HttpCompletionOption.ResponseContentRead, cancellationToken).ConfigureAwait(false);
#pragma warning restore RS0030
        var body = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        return new ServiceResponse
        {
            StatusCode = (int)response.StatusCode,
            Body = body,
            ETag = response.Headers.ETag?.ToString() ?? string.Empty,
            Route = route,
        };
    }
}
