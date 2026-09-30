namespace Engramic.Baseline.Platform;

/// <summary>
/// What came of asking a PAC file about an address.
/// </summary>
public enum AutoProxyOutcome
{
    /// <summary>The file named one or more proxies.</summary>
    Proxy,

    /// <summary>The file said to go direct.</summary>
    Direct,

    /// <summary>WPAD found no PAC file on the local network.</summary>
    NotFound,

    /// <summary>The file could not be downloaded or run, or the lookup failed for another reason.</summary>
    Failed,
}
