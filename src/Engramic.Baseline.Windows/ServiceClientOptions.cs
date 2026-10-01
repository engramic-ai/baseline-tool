using System.Reflection;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows;

/// <summary>
/// What the service client follows: the proxy settings, whether the process runs as SYSTEM, where it asks
/// Windows about proxies, and how long it waits for a PAC file.
/// </summary>
/// <remarks>
/// <see cref="ForThisProcess"/> gives this process's. Everything is settable so that tests can use a fake of
/// what Windows says, and never change the machine's settings.
/// </remarks>
public sealed record ServiceClientOptions
{
    /// <summary>Gets the User-Agent every request sends, as the PowerShell tool's does: EngramicBaseline/ and the version.</summary>
    public static string DefaultUserAgent { get; } =
        "EngramicBaseline/" + (typeof(ServiceClientOptions).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0");

    /// <summary>Gets the proxy settings of network.json.</summary>
    public required ProxySettings Proxy { get; init; }

    /// <summary>Gets whether the process runs as SYSTEM, for useWinHttpProxyWhenSystem.</summary>
    public required bool IsSystem { get; init; }

    /// <summary>Gets where the client asks what Windows says about proxies: WinHTTP by default.</summary>
    public ISystemProxy SystemProxy { get; init; } = new WinHttpProxy();

    /// <summary>
    /// Gets how long a request waits for a PAC file's answer before it goes direct, at most: 10 seconds by
    /// default, and never longer than the request's own time.
    /// </summary>
    public TimeSpan AutoProxyTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Gets the clock the wait for a PAC file is timed by.</summary>
    public TimeProvider Time { get; init; } = TimeProvider.System;

    /// <summary>Gets the User-Agent every request sends.</summary>
    public string UserAgent { get; init; } = DefaultUserAgent;

    /// <summary>Gets this process's options: the settings given, and whether it runs as SYSTEM from its token.</summary>
    /// <param name="proxy">The proxy settings of network.json.</param>
    /// <returns>The options.</returns>
    public static ServiceClientOptions ForThisProcess(ProxySettings proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        return new ServiceClientOptions { Proxy = proxy, IsSystem = CurrentProcess.ReadAccount().IsLocalSystem };
    }
}
