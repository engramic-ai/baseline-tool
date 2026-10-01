namespace Engramic.Baseline.Engine;

/// <summary>
/// Where the config files come from, by name, such as os-lifecycle.json.
/// </summary>
/// <remarks>
/// The seam for administrators' overrides: the copy shipped inside the tool is one source, and
/// <see cref="ConfigTrustGate"/> puts in front of it an administrator's override that passes every rule,
/// read through the secure data folder, which replaces the shipped file whole, as in the PowerShell tool.
/// </remarks>
public interface IConfigFiles
{
    /// <summary>Reads a config file.</summary>
    /// <param name="name">The file name, such as os-lifecycle.json.</param>
    /// <returns>The bytes of the file, or null when there is no file of that name.</returns>
    /// <exception cref="IOException">The file could not be read, and nothing is given in its place.</exception>
    byte[]? Read(string name);
}
