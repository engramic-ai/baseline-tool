using System.Text.Json;
using Engramic.Baseline.Model;

namespace Engramic.Baseline.Engine;

/// <summary>
/// The config the checks read, typed. Each file is read on first use and kept for the audit.
/// </summary>
/// <remarks>
/// A file that is missing or does not parse throws when a check first reads it, so only the checks that
/// need it fail, each with an Error finding, as in the PowerShell tool.
/// </remarks>
public sealed class AuditConfig
{
    private readonly IConfigFiles _files;
    private readonly Lazy<OsLifecycle> _osLifecycle;

    /// <summary>Makes the config of an audit, read from the given files.</summary>
    /// <param name="files">Where the files come from.</param>
    public AuditConfig(IConfigFiles files)
    {
        ArgumentNullException.ThrowIfNull(files);
        _files = files;
        _osLifecycle = new Lazy<OsLifecycle>(() => Read(ConfigFile.OsLifecycleName, ConfigFile.ReadOsLifecycle));
    }

    /// <summary>Gets config/os-lifecycle.json.</summary>
    /// <exception cref="InvalidDataException">The file is missing or is not valid.</exception>
    public OsLifecycle OsLifecycle => _osLifecycle.Value;

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
