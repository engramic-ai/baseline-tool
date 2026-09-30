using System.Text.Json;
using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Engine;

/// <summary>
/// The proxy settings of config/network.json, read through the config files, as the service client takes them.
/// </summary>
/// <remarks>
/// The config files are where administrators' overrides will come in: today they are the copy shipped inside
/// the tool; an override that passes the trust checks will replace it whole, as in the PowerShell tool. A file
/// that is missing or is not valid gives the defaults, as the PowerShell tool's proxy settings fell back to
/// them, and the problem goes with the settings so that every request reports it.
/// </remarks>
public static class NetworkSettings
{
    /// <summary>Reads the proxy settings.</summary>
    /// <param name="files">Where the config files come from.</param>
    /// <returns>The settings; the defaults, with the problem, when network.json is missing or not valid.</returns>
    public static ProxySettings Read(IConfigFiles files)
    {
        ArgumentNullException.ThrowIfNull(files);
        var bytes = files.Read(ConfigFile.NetworkName);
        if (bytes is null)
        {
            return new ProxySettings { Problems = [$"config/{ConfigFile.NetworkName} is missing, so the proxy settings are the defaults."] };
        }

        NetworkConfig network;
        try
        {
            network = ConfigFile.ReadNetwork(bytes);
        }
        catch (JsonException e)
        {
            return new ProxySettings { Problems = [$"config/{ConfigFile.NetworkName} is not valid, so the proxy settings are the defaults: {e.Message}"] };
        }

        return new ProxySettings
        {
            ProxyUrl = network.ProxyUrl,
            ProxyUseDefaultCredentials = network.ProxyUseDefaultCredentials,
            UseWinHttpProxyWhenSystem = network.UseWinHttpProxyWhenSystem,
            ProxyAutoConfigUrl = network.ProxyAutoConfigUrl,
            ProxyAutoDetect = network.ProxyAutoDetect,
        };
    }
}
