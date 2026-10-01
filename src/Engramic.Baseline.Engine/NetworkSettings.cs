using System.Text.Json;
using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Engine;

/// <summary>
/// The proxy settings of config/network.json, read through the config files, as the service client takes them.
/// </summary>
/// <remarks>
/// <para>
/// Read them through the run's config, as a check does through <see cref="AuditConfig.Network"/>: in the scheduled
/// audit and an elevated audit that is the config trust gate (<see cref="ConfigTrustGate"/>), so an administrator's
/// override of network.json that passes every rule replaces the shipped copy whole, as in the PowerShell tool, and
/// one that is refused leaves the shipped copy, with the gate's notice. Never the shipped files alone where the run
/// has a gate.
/// </para>
/// <para>
/// A file that is missing or is not valid gives the defaults, as the PowerShell tool's proxy settings fell back to
/// them, and the problem goes with the settings so that every request reports it. Through the gate that is only a
/// shipped copy, which the tests hold valid: an override that is not valid is refused before it gets here. A file
/// that could not be read is neither: the IOException goes to the caller, so the check that needs the settings
/// reports an Error rather than send requests with defaults that whoever held the override up would have chosen.
/// </para>
/// </remarks>
public static class NetworkSettings
{
    /// <summary>Reads the proxy settings.</summary>
    /// <param name="files">Where the config files come from: the run's, which is the config trust gate where it has one.</param>
    /// <returns>The settings; the defaults, with the problem, when network.json is missing or not valid.</returns>
    /// <exception cref="IOException">network.json could not be read, such as an override the gate could not read.</exception>
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
