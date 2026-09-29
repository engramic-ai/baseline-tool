using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows;

/// <summary>
/// Where SecureStore finds the machine data folder and its seal, and the clock it waits by.
/// </summary>
/// <remarks>
/// <see cref="ForMachine"/> gives this device's. Everything is settable so that tests work in folders
/// of their own, never in the real ProgramData folder or registry key.
/// </remarks>
public sealed record SecureStoreOptions
{
    /// <summary>The registry key, under HKEY_LOCAL_MACHINE, of the install's seal: the one the installer writes.</summary>
    public const string MachineSealKeyPath = @"SOFTWARE\EngramicBaseline.DataRoot";

    /// <summary>The registry value that records that an install made the data folder locked.</summary>
    public const string MachineSealValueName = "DataRootSealed";

    /// <summary>
    /// Gets the full path of the ProgramData folder, on a drive with a letter, that holds the data
    /// folder (EngramicBaseline).
    /// </summary>
    public required string ProgramDataPath { get; init; }

    /// <summary>Gets the registry primitive the seal is read through.</summary>
    public required IRegistry Registry { get; init; }

    /// <summary>
    /// Gets the key of the seal under HKEY_LOCAL_MACHINE, read in the 64-bit view. Only administrators can
    /// write there, so a standard user cannot forge it.
    /// </summary>
    public string SealKeyPath { get; init; } = MachineSealKeyPath;

    /// <summary>Gets the name of the seal value: text that is not empty (the installer writes its version).</summary>
    public string SealValueName { get; init; } = MachineSealValueName;

    /// <summary>Gets the clock SecureStore waits by between attempts to replace a file that is open.</summary>
    public TimeProvider Time { get; init; } = TimeProvider.System;

    /// <summary>
    /// Gets this device's: the ProgramData folder from the known-folder API, checked against the drive
    /// Windows is installed on, and the installer's seal.
    /// </summary>
    /// <param name="registry">The registry primitive.</param>
    /// <param name="time">The clock.</param>
    /// <returns>The options.</returns>
    /// <exception cref="SecureStoreException">The ProgramData folder Windows gives is not on the Windows drive.</exception>
    public static SecureStoreOptions ForMachine(IRegistry registry, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(time);
        return new SecureStoreOptions { ProgramDataPath = SecureStore.FindProgramData(), Registry = registry, Time = time };
    }
}
