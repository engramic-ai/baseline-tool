using Engramic.Baseline.Engine;

namespace Engramic.Baseline.Controls;

/// <summary>
/// The config files that ship with the tool: the repository's config folder, which the PowerShell tool
/// also reads, built into this library.
/// </summary>
/// <remarks>
/// Built in rather than read from beside the executable, so no code reads a file by path (only the secure
/// data folder and the profile reader touch files) and the shipped values cannot be changed on disk.
/// Administrators' overrides, which replace a shipped file whole, come through the secure data folder and
/// the config trust gate (<see cref="ConfigTrustGate"/>), in front of this source. Each file built in here has
/// a schema in <see cref="Model.ConfigFile"/>, which an override of it must meet.
/// </remarks>
public static class ShippedConfig
{
    /// <summary>Gets the shipped config files.</summary>
    public static IConfigFiles Files { get; } = new EmbeddedConfigFiles();

    /// <summary>Gets the names of the shipped config files, such as os-lifecycle.json.</summary>
    public static IReadOnlyList<string> Names { get; } =
        [.. typeof(ShippedConfig).Assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(EmbeddedConfigFiles.Prefix, StringComparison.Ordinal))
            .Select(n => n[EmbeddedConfigFiles.Prefix.Length..])
            .Order(StringComparer.Ordinal)];

    private sealed class EmbeddedConfigFiles : IConfigFiles
    {
        public const string Prefix = "config/";

        public byte[]? Read(string name)
        {
            ArgumentNullException.ThrowIfNull(name);
            using var stream = typeof(ShippedConfig).Assembly.GetManifestResourceStream(Prefix + name);
            if (stream is null)
            {
                return null;
            }

            var bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
            return bytes;
        }
    }
}
