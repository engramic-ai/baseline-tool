using System.Text.Json;

namespace Engramic.Baseline.Model;

/// <summary>
/// Reads the config files, by the names they have in the config folder.
/// </summary>
public static class ConfigFile
{
    /// <summary>The name of the Windows lifecycle data that SU-01 judges against.</summary>
    public const string OsLifecycleName = "os-lifecycle.json";

    /// <summary>The name of the proxy settings for the tool's own requests.</summary>
    public const string NetworkName = "network.json";

    /// <summary>Reads config/os-lifecycle.json, with or without a byte order mark.</summary>
    /// <param name="utf8">The bytes of the file.</param>
    /// <returns>The lifecycle data.</returns>
    /// <exception cref="JsonException">
    /// The bytes are not JSON of that shape, or lack lastReviewed, reviewWarningDays or upcomingEndWarningDays.
    /// </exception>
    public static OsLifecycle ReadOsLifecycle(ReadOnlySpan<byte> utf8)
    {
        return ModelJson.Read(utf8, ModelJson.OsLifecycleReader);
    }

    /// <summary>Reads config/network.json, with or without a byte order mark.</summary>
    /// <param name="utf8">The bytes of the file.</param>
    /// <returns>The settings, with the default of each member the file does not give as a value of its type.</returns>
    /// <exception cref="JsonException">The bytes are not a JSON object.</exception>
    public static NetworkConfig ReadNetwork(ReadOnlySpan<byte> utf8)
    {
        return ModelJson.Read(utf8, ModelJson.NetworkReader);
    }
}
