namespace Engramic.Baseline.Platform;

/// <summary>
/// The proxy settings the service client follows: those of config/network.json, as the config model reads
/// them.
/// </summary>
/// <remarks>
/// <see cref="ProxyChooser"/> says how each is used. The defaults are the shipped file's: no proxy named, the
/// machine's WinHTTP proxy as SYSTEM too, no PAC file, WPAD on, and the Windows sign-in sent to no proxy.
/// </remarks>
public sealed record ProxySettings
{
    /// <summary>Gets the proxy's http:// address (proxyUrl), or empty for none.</summary>
    public string ProxyUrl { get; init; } = string.Empty;

    /// <summary>
    /// Gets whether a proxy an administrator named may be sent this account's Windows sign-in
    /// (proxyUseDefaultCredentials): as SYSTEM, the computer account's. A proxy that WPAD found never is.
    /// </summary>
    public bool ProxyUseDefaultCredentials { get; init; }

    /// <summary>Gets whether a process running as SYSTEM uses the machine's WinHTTP proxy (useWinHttpProxyWhenSystem).</summary>
    public bool UseWinHttpProxyWhenSystem { get; init; } = true;

    /// <summary>Gets the address of a PAC file to ask, instead of WPAD (proxyAutoConfigUrl), or empty for none.</summary>
    public string ProxyAutoConfigUrl { get; init; } = string.Empty;

    /// <summary>Gets whether WPAD may look for a PAC file on the local network when nothing else names a proxy (proxyAutoDetect).</summary>
    public bool ProxyAutoDetect { get; init; } = true;

    /// <summary>
    /// Gets what went wrong reading the settings, as sentences, such as a network.json that is not valid; the
    /// service client reports them with every request, since it used the defaults instead.
    /// </summary>
    public IReadOnlyList<string> Problems { get; init; } = [];
}
