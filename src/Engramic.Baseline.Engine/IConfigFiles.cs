namespace Engramic.Baseline.Engine;

/// <summary>
/// Where the config files come from, by name, such as os-lifecycle.json.
/// </summary>
/// <remarks>
/// The seam for administrators' overrides: today the only source is the copy shipped inside the tool.
/// Overrides, read through the secure data folder and its trust checks, will replace a shipped file
/// whole, as in the PowerShell tool.
/// </remarks>
public interface IConfigFiles
{
    /// <summary>Reads a config file.</summary>
    /// <param name="name">The file name, such as os-lifecycle.json.</param>
    /// <returns>The bytes of the file, or null when there is no file of that name.</returns>
    byte[]? Read(string name);
}
