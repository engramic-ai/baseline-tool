namespace Engramic.Baseline.Platform;

/// <summary>
/// The registry primitive: the only way product code reads the registry. Every read names its view.
/// </summary>
/// <remarks>
/// Engramic.Baseline.Windows implements it; Engramic.Baseline.Testing has a fake. Values are returned as
/// stored, and readers decide what they mean.
/// </remarks>
public interface IRegistry
{
    /// <summary>Reads one registry value.</summary>
    /// <param name="hive">The hive, such as HKEY_LOCAL_MACHINE.</param>
    /// <param name="view">The view: the 64-bit view for the operating system's settings.</param>
    /// <param name="keyPath">The key below the hive, such as SOFTWARE\Microsoft\Windows NT\CurrentVersion.</param>
    /// <param name="valueName">The name of the value; empty for the key's default value.</param>
    /// <returns>The value, or null when the key or the value does not exist.</returns>
    /// <exception cref="UnauthorizedAccessException">The key exists, but this account may not read it.</exception>
    /// <exception cref="IOException">The value could not be read for another reason.</exception>
    RegistryValue? GetValue(RegistryHive hive, RegistryView view, string keyPath, string valueName);
}
