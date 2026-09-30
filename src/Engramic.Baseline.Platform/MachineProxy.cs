namespace Engramic.Baseline.Platform;

/// <summary>
/// The machine's WinHTTP proxy setting (netsh winhttp set proxy), as Windows gives it.
/// </summary>
/// <param name="Proxy">
/// The proxy list: one proxy for every scheme, such as proxy:8080, or one for each, such as
/// http=web:80;https=secure:8443. Entries are separated by semicolons or white space.
/// </param>
/// <param name="Bypass">
/// The bypass list, such as &lt;local&gt;;*.contoso.com: host names with * and ? wildcards, and &lt;local&gt;
/// for names without a dot. Empty for none.
/// </param>
public sealed record MachineProxy(string Proxy, string Bypass);
