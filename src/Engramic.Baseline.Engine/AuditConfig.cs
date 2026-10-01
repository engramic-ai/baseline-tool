using System.Text.Json;
using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Engine;

/// <summary>
/// The config the checks read, typed. Each file is read on first use and kept for the audit.
/// </summary>
/// <remarks>
/// <para>
/// A file that is missing or does not parse throws when a check first reads it, so only the checks that
/// need it fail, each with an Error finding, as in the PowerShell tool. The proxy settings are the exception:
/// a network.json that is missing or not valid gives the defaults, with the problem (<see cref="NetworkSettings"/>).
/// </para>
/// <para>
/// The files come from the run's config: the config trust gate (<see cref="ConfigTrustGate"/>) in the scheduled
/// audit and an elevated audit, and otherwise the shipped files. A file the gate could not read throws for
/// every reader, the proxy settings included, so the checks that need it fail.
/// </para>
/// </remarks>
public sealed class AuditConfig
{
    private readonly IConfigFiles _files;
    private readonly Lazy<OsLifecycle> _osLifecycle;
    private readonly Lazy<ProxySettings> _network;

    /// <summary>Makes the config of an audit, read from the given files.</summary>
    /// <param name="files">Where the files come from.</param>
    public AuditConfig(IConfigFiles files)
    {
        ArgumentNullException.ThrowIfNull(files);
        _files = files;
        _osLifecycle = new Lazy<OsLifecycle>(() => Read(ConfigFile.OsLifecycleName, ConfigFile.ReadOsLifecycle));
        _network = new Lazy<ProxySettings>(() => NetworkSettings.Read(_files));
    }

    /// <summary>Gets config/os-lifecycle.json.</summary>
    /// <exception cref="InvalidDataException">The file is missing or is not valid.</exception>
    public OsLifecycle OsLifecycle => _osLifecycle.Value;

    /// <summary>
    /// Gets the proxy settings of config/network.json, as the service client takes them: what a check that sends a
    /// request gives it, so that an administrator's override reaches it through the config trust gate.
    /// </summary>
    /// <exception cref="IOException">
    /// network.json could not be read, as for an administrator's override the gate could not read: no defaults are
    /// given in its place.
    /// </exception>
    public ProxySettings Network => _network.Value;

    private delegate T Parser<out T>(ReadOnlySpan<byte> utf8);

    private T Read<T>(string name, Parser<T> parse)
    {
        var bytes = _files.Read(name) ?? throw new InvalidDataException($"config/{name} is missing.");
        try
        {
            return parse(bytes);
        }
        catch (JsonException e)
        {
            throw new InvalidDataException($"config/{name} is not valid: {e.Message}", e);
        }
    }
}
