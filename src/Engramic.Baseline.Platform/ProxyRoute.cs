namespace Engramic.Baseline.Platform;

/// <summary>
/// How the service client sends one request: straight to its address, or through one proxy, and why.
/// </summary>
public sealed record ProxyRoute
{
    /// <summary>Gets the proxy's address, always an http:// one; null to connect directly.</summary>
    public Uri? Proxy { get; init; }

    /// <summary>Gets where the choice came from.</summary>
    public ProxySource Source { get; init; }

    /// <summary>
    /// Gets whether the proxy may be sent this account's Windows sign-in (NTLM or Kerberos) when it asks for
    /// one; as SYSTEM, the computer account's. Never true without a proxy, and the address itself never gets it.
    /// </summary>
    public bool UseDefaultCredentials { get; init; }

    /// <summary>
    /// Gets what the choice passed over or could not use, as sentences, such as a proxyUrl that is not an
    /// http:// address or a PAC file that could not be read.
    /// </summary>
    public IReadOnlyList<string> Notes { get; init; } = [];

    /// <summary>Gets whether the request goes straight to its address.</summary>
    public bool IsDirect => Proxy is null;
}
