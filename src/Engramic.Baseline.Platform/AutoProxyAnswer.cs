namespace Engramic.Baseline.Platform;

/// <summary>
/// What a PAC file said about an address, or why there was no answer.
/// </summary>
/// <param name="Outcome">Whether the file named proxies, said to go direct, or could not be found or used.</param>
/// <param name="Proxy">For <see cref="AutoProxyOutcome.Proxy"/>: the proxies it named, in order, such as proxy:8080;backup:8080.</param>
/// <param name="Detail">For <see cref="AutoProxyOutcome.NotFound"/> and <see cref="AutoProxyOutcome.Failed"/>: why, as a sentence.</param>
public sealed record AutoProxyAnswer(AutoProxyOutcome Outcome, string Proxy, string Detail)
{
    /// <summary>An answer that names proxies.</summary>
    /// <param name="proxy">The proxies, in order.</param>
    /// <returns>The answer.</returns>
    public static AutoProxyAnswer UseProxy(string proxy) => new(AutoProxyOutcome.Proxy, proxy, string.Empty);

    /// <summary>An answer that says to go direct.</summary>
    /// <returns>The answer.</returns>
    public static AutoProxyAnswer GoDirect() => new(AutoProxyOutcome.Direct, string.Empty, string.Empty);

    /// <summary>An answer that says WPAD found no PAC file.</summary>
    /// <param name="detail">Why, as a sentence.</param>
    /// <returns>The answer.</returns>
    public static AutoProxyAnswer NotFound(string detail) => new(AutoProxyOutcome.NotFound, string.Empty, detail);

    /// <summary>An answer that says the PAC file could not be fetched or run.</summary>
    /// <param name="detail">Why, as a sentence.</param>
    /// <returns>The answer.</returns>
    public static AutoProxyAnswer Failed(string detail) => new(AutoProxyOutcome.Failed, string.Empty, detail);
}
