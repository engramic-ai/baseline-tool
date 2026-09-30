using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace Engramic.Baseline.Platform;

/// <summary>
/// Chooses how the service client sends each request: directly, or through one proxy, which it names itself.
/// The platform's default proxy is never used: as SYSTEM it reads SYSTEM's own Internet settings, and .NET's
/// also follows environment variables that whoever starts the process sets.
/// </summary>
/// <remarks>
/// <para>For each address, the first of these that applies decides:</para>
/// <list type="number">
/// <item>An address on this device (localhost, a loopback address) or a name without a dot goes direct, as the
/// PowerShell tool's proxies were told to bypass local addresses.</item>
/// <item>proxyUrl in network.json, when it is an http:// address. Anything else is passed over with a note,
/// in the PowerShell tool's words.</item>
/// <item>The machine's WinHTTP proxy, unless the process runs as SYSTEM and useWinHttpProxyWhenSystem is
/// false: direct when its bypass list names the host, as WinHTTP would; otherwise its proxy for the scheme,
/// which is http:// only, or direct when it has none for the scheme.</item>
/// <item>A PAC file: the one at proxyAutoConfigUrl in network.json when it is set, or else, when
/// proxyAutoDetect is true, the one WPAD finds on the local network. The file is asked about the scheme, host
/// and port alone, never the path or query, and the first http proxy it names is used, or none when it says
/// DIRECT. A lookup that finds nothing, fails or takes longer than its time goes direct, with a note.</item>
/// <item>Otherwise the request goes direct.</item>
/// </list>
/// <para>
/// The Windows sign-in goes to a proxy only when proxyUseDefaultCredentials is true, and never to one that
/// WPAD found: whoever answers WPAD on the local network could otherwise collect it, and as SYSTEM it is the
/// computer account's.
/// </para>
/// </remarks>
public sealed partial class ProxyChooser
{
    /// <summary>What an error suggests, in the PowerShell tool's words, as a proxy is the likeliest cause.</summary>
    public const string ProxyHint = "If this device uses a proxy, set proxyUrl in network.json.";

    private const string HttpsProxyUrlNote = "Ignoring proxyUrl in network.json: use the proxy's http:// address. Requests to https sites still go through it encrypted, and Windows PowerShell can't use an https:// proxy address.";
    private const string NotHttpProxyUrlNote = "Ignoring proxyUrl in network.json: it must be an http:// URL.";
    private const string BadAutoConfigUrlNote = "Ignoring proxyAutoConfigUrl in network.json: it must be an http:// or https:// URL.";
    private const string NoCredentialsForWpadNote = "proxyUseDefaultCredentials does not apply to a proxy that WPAD found, as whoever answers WPAD on the local network could collect the Windows sign-in: name the proxy in proxyUrl, or its PAC file in proxyAutoConfigUrl.";

    private readonly ProxySettings _settings;
    private readonly ISystemProxy _system;
    private readonly bool _isSystem;
    private readonly TimeProvider _time;

    /// <summary>Makes the chooser for a process.</summary>
    /// <param name="settings">The settings of network.json.</param>
    /// <param name="system">What the operating system says about proxies.</param>
    /// <param name="isSystem">Whether the process runs as SYSTEM, for useWinHttpProxyWhenSystem.</param>
    /// <param name="time">The clock the wait for a PAC file is timed by; the system's when null.</param>
    public ProxyChooser(ProxySettings settings, ISystemProxy system, bool isSystem, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(system);
        _settings = settings;
        _system = system;
        _isSystem = isSystem;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Chooses how to send a request to an address.</summary>
    /// <param name="target">The absolute address.</param>
    /// <param name="autoProxyTimeout">How long to wait for a PAC file's answer before going direct.</param>
    /// <param name="cancellationToken">Stops the choice, and the request.</param>
    /// <returns>The route, with notes on what was passed over.</returns>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public async Task<ProxyRoute> ChooseAsync(Uri target, TimeSpan autoProxyTimeout, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (!target.IsAbsoluteUri)
        {
            throw new ArgumentException("Choose a route for an absolute address.", nameof(target));
        }

        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(autoProxyTimeout, TimeSpan.Zero);
        cancellationToken.ThrowIfCancellationRequested();
        var notes = new List<string>(_settings.Problems);
        if (IsLocal(target))
        {
            return Direct(ProxySource.Local, notes);
        }

        var proxyUrl = _settings.ProxyUrl.Trim();
        if (proxyUrl.Length > 0)
        {
            if (Uri.TryCreate(proxyUrl, UriKind.Absolute, out var named) && named.Scheme == Uri.UriSchemeHttp)
            {
                return Through(named, ProxySource.NetworkConfig, _settings.ProxyUseDefaultCredentials, notes);
            }

            notes.Add(named?.Scheme == Uri.UriSchemeHttps ? HttpsProxyUrlNote : NotHttpProxyUrlNote);
        }

        if ((_settings.UseWinHttpProxyWhenSystem || !_isSystem) && ReadMachineProxy(notes) is { } machine)
        {
            if (IsBypassed(target.Host, SplitBypassList(machine.Bypass)))
            {
                return Direct(ProxySource.WinHttp, notes);
            }

            var scheme = target.Scheme == Uri.UriSchemeHttp ? "http" : "https";
            if (SelectProxy(machine.Proxy, scheme) is { } address)
            {
                return Through(address, ProxySource.WinHttp, _settings.ProxyUseDefaultCredentials, notes);
            }

            // Set only for other schemes, or not an http proxy: WinHTTP itself would connect directly.
            notes.Add($"The machine's WinHTTP proxy ({machine.Proxy}) names no http:// proxy for {scheme} addresses, so the request goes direct, as WinHTTP would.");
            return Direct(ProxySource.WinHttp, notes);
        }

        return await ChooseAutoProxyAsync(target, autoProxyTimeout, notes, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Whether an address is local, so that it never goes through a proxy: this device by name or loopback
    /// address, or a name without a dot, as .NET's BypassProxyOnLocal treated it for the PowerShell tool.
    /// </summary>
    internal static bool IsLocal(Uri target)
    {
        if (ServiceUri.IsThisDevice(target))
        {
            return true;
        }

        return target.HostNameType switch
        {
            UriHostNameType.IPv4 or UriHostNameType.IPv6 => IPAddress.TryParse(target.DnsSafeHost, out var address) && IPAddress.IsLoopback(address),
            UriHostNameType.Dns => !target.Host.Contains('.', StringComparison.Ordinal),
            _ => false,
        };
    }

    /// <summary>
    /// The proxy for a scheme in a WinHTTP proxy list, as an http address, or null for none. As in WinHTTP and
    /// the PowerShell tool's Select-CEWinHttpProxy, entries for a scheme (http=a:80;https=b:443) apply only to
    /// that scheme; otherwise the first entry applies to every scheme. Unlike the PowerShell tool, entries may be
    /// separated by white space as well as semicolons, as WinHTTP allows.
    /// </summary>
    internal static Uri? SelectProxy(string proxyList, string scheme)
    {
        var entries = SplitProxyList(proxyList);
        string? chosen = null;
        if (entries.Exists(e => e.Contains('=', StringComparison.Ordinal)))
        {
            var prefix = scheme + "=";
            var hit = entries.Find(e => e.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
            chosen = hit?[prefix.Length..];
        }
        else if (entries.Count > 0)
        {
            chosen = entries[0];
        }

        return chosen is null ? null : ToHttpProxy(chosen);
    }

    /// <summary>
    /// The first proxy a PAC file named that can be used: an http proxy, from an entry such as proxy:8080. Other
    /// kinds of entry, such as a SOCKS proxy, are passed over.
    /// </summary>
    internal static Uri? FirstProxy(string proxyList)
    {
        foreach (var entry in SplitProxyList(proxyList))
        {
            if (!entry.Contains('=', StringComparison.Ordinal) && ToHttpProxy(entry) is { } proxy)
            {
                return proxy;
            }
        }

        return null;
    }

    /// <summary>A proxy entry as an http address, with http:// added when it names no scheme; null unless it is http.</summary>
    internal static Uri? ToHttpProxy(string entry)
    {
        var text = entry.Trim();
        if (text.Length == 0)
        {
            return null;
        }

        if (!SchemePrefix().IsMatch(text))
        {
            text = "http://" + text;
        }

        // Only http proxies: the request to an https site still goes through one encrypted (CONNECT).
        return Uri.TryCreate(text, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttp ? uri : null;
    }

    /// <summary>The entries of a WinHTTP bypass list, split on semicolons, commas and white space, as the PowerShell tool splits them.</summary>
    internal static List<string> SplitBypassList(string bypass)
    {
        return [.. BypassSeparators().Split(bypass).Where(e => e.Length > 0)];
    }

    /// <summary>
    /// Whether a host is on a WinHTTP bypass list, as the PowerShell tool's Test-CEProxyBypass decides: an entry
    /// matches the host without regard to case, with * for any run of characters and ? for one; &lt;local&gt;
    /// matches a name without a dot; a scheme before an entry is ignored.
    /// </summary>
    internal static bool IsBypassed(string host, IEnumerable<string> bypass)
    {
        foreach (var raw in bypass)
        {
            var entry = SchemePrefix().Replace(raw, string.Empty, 1).Trim();
            if (entry.Length == 0)
            {
                continue;
            }

            if (string.Equals(entry, "<local>", StringComparison.OrdinalIgnoreCase))
            {
                if (!host.Contains('.', StringComparison.Ordinal))
                {
                    return true;
                }

                continue;
            }

            if (WildcardMatch(host, entry))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The address a PAC file is asked about: the scheme, host and port alone, as browsers give it for https, so
    /// that a script found on the network never sees a path or query.
    /// </summary>
    internal static Uri PacTarget(Uri target) => new(target.Scheme + "://" + target.Authority + "/");

    /// <summary>Matches text against a pattern with * and ? wildcards, without regard to case.</summary>
    internal static bool WildcardMatch(string text, string pattern)
    {
        int t = 0, p = 0, star = -1, resume = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || char.ToUpperInvariant(pattern[p]) == char.ToUpperInvariant(text[t])))
            {
                t++;
                p++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                resume = t;
            }
            else if (star >= 0)
            {
                p = star + 1;
                t = ++resume;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }

        return p == pattern.Length;
    }

    private static List<string> SplitProxyList(string proxyList)
    {
        return [.. ProxySeparators().Split(proxyList).Where(e => e.Length > 0)];
    }

    private static ProxyRoute Direct(ProxySource source, List<string> notes) => new() { Source = source, Notes = notes };

    private static ProxyRoute Through(Uri proxy, ProxySource source, bool useDefaultCredentials, List<string> notes)
    {
        return new ProxyRoute { Proxy = proxy, Source = source, UseDefaultCredentials = useDefaultCredentials, Notes = notes };
    }

    private static string Seconds(TimeSpan time) => time.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture);

    private MachineProxy? ReadMachineProxy(List<string> notes)
    {
        MachineProxy? machine;
        try
        {
            machine = _system.ReadMachineProxy();
        }
        catch (IOException e)
        {
            notes.Add("The machine's WinHTTP proxy could not be read, so it is not used: " + e.Message);
            return null;
        }

        return machine is null || string.IsNullOrWhiteSpace(machine.Proxy) ? null : machine;
    }

    private async Task<ProxyRoute> ChooseAutoProxyAsync(Uri target, TimeSpan timeout, List<string> notes, CancellationToken cancellationToken)
    {
        Uri? script = null;
        var configured = _settings.ProxyAutoConfigUrl.Trim();
        if (configured.Length > 0)
        {
            if (Uri.TryCreate(configured, UriKind.Absolute, out var url) && (url.Scheme == Uri.UriSchemeHttp || url.Scheme == Uri.UriSchemeHttps))
            {
                script = url;
            }
            else
            {
                notes.Add(BadAutoConfigUrlNote);
            }
        }

        if (script is null && !_settings.ProxyAutoDetect)
        {
            return Direct(ProxySource.None, notes);
        }

        var source = script is null ? ProxySource.AutoDetect : ProxySource.AutoConfigUrl;
        var what = script is null ? "WPAD" : $"The PAC file at {script}";
        var lookup = _system.FindAutoProxyAsync(PacTarget(target), script, timeout);
        AutoProxyAnswer answer;
        try
        {
            answer = await lookup.WaitAsync(timeout, _time, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException timedOut) when (lookup.Exception?.InnerException != timedOut)
        {
            notes.Add($"{what} gave no answer within {Seconds(timeout)} seconds, so the request goes direct.");
            return Direct(ProxySource.None, notes);
        }

        switch (answer.Outcome)
        {
            case AutoProxyOutcome.Proxy when FirstProxy(answer.Proxy) is { } proxy:
                var credentials = _settings.ProxyUseDefaultCredentials && source == ProxySource.AutoConfigUrl;
                if (_settings.ProxyUseDefaultCredentials && !credentials)
                {
                    notes.Add(NoCredentialsForWpadNote);
                }

                return Through(proxy, source, credentials, notes);
            case AutoProxyOutcome.Proxy:
                notes.Add($"{(script is null ? "The PAC file WPAD found" : what)} named no proxy this tool can use ({answer.Proxy}), so the request goes direct.");
                return Direct(source, notes);
            case AutoProxyOutcome.Direct:
                return Direct(source, notes);
            case AutoProxyOutcome.NotFound:
                notes.Add($"WPAD found no PAC file on the local network, so the request goes direct. {answer.Detail}".TrimEnd());
                return Direct(ProxySource.None, notes);
            default:
                notes.Add($"{(script is null ? "The PAC file WPAD found" : what)} could not be used, so the request goes direct. {answer.Detail}".TrimEnd());
                return Direct(ProxySource.None, notes);
        }
    }

    [GeneratedRegex("^[a-z0-9+.-]+://", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SchemePrefix();

    [GeneratedRegex(@"[;\s]+", RegexOptions.CultureInvariant)]
    private static partial Regex ProxySeparators();

    [GeneratedRegex(@"[;,\s]+", RegexOptions.CultureInvariant)]
    private static partial Regex BypassSeparators();
}
