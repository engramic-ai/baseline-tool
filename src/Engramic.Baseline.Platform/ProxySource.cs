namespace Engramic.Baseline.Platform;

/// <summary>
/// Where the service client's choice of route for a request came from.
/// </summary>
public enum ProxySource
{
    /// <summary>Nothing named a proxy, or nothing that did could be used: the request goes direct.</summary>
    None,

    /// <summary>The address is this device, or a name without a dot: the request goes direct, whatever the settings say.</summary>
    Local,

    /// <summary>proxyUrl in network.json.</summary>
    NetworkConfig,

    /// <summary>The machine's WinHTTP proxy (netsh winhttp set proxy): its proxy, or direct when its bypass list names the host.</summary>
    WinHttp,

    /// <summary>The PAC file at proxyAutoConfigUrl in network.json.</summary>
    AutoConfigUrl,

    /// <summary>A PAC file that WPAD found on the local network.</summary>
    AutoDetect,
}
