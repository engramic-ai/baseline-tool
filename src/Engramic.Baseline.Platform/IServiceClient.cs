namespace Engramic.Baseline.Platform;

/// <summary>
/// The service client: the one way product code sends an HTTP request, to the tool's own services such as the
/// firmware catalog. It chooses the proxy for each request itself (<see cref="ProxyChooser"/>) and never uses
/// the platform's default proxy.
/// </summary>
/// <remarks>
/// <para>
/// Engramic.Baseline.Windows has the implementation, ServiceClient. Each request is a GET to an https address,
/// or plain http to this device; any other address is refused before anything is sent. The response is
/// limited in size and time, and redirects are not followed. The site is never sent the Windows sign-in, and
/// its certificate is checked against the operating system's trusted roots, with no pinning.
/// </para>
/// <para>
/// A request that fails comes back as a response with an <see cref="ServiceResponse.Error"/>, never as an
/// exception, as in the PowerShell tool.
/// </para>
/// </remarks>
public interface IServiceClient
{
    /// <summary>Sends one GET request.</summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">Stops the request.</param>
    /// <returns>The response; a status code of 0 and an error when there was none.</returns>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    Task<ServiceResponse> GetAsync(ServiceRequest request, CancellationToken cancellationToken = default);
}
