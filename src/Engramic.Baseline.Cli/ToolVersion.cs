using System.Reflection;

namespace Engramic.Baseline.Cli;

/// <summary>The version of the tool, as status.json and the summaries give it.</summary>
internal static class ToolVersion
{
    /// <summary>Gets the version from Directory.Build.props, such as 1.0.0-alpha.0.</summary>
    public static string Current { get; } =
        typeof(ToolVersion).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";
}
