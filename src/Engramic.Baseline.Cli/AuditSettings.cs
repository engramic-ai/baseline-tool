using Engramic.Baseline.Controls;
using Engramic.Baseline.Engine;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Windows;

namespace Engramic.Baseline.Cli;

/// <summary>
/// What baseline audit runs with: this device's (<see cref="ForThisDevice"/>), or a test's, which never names
/// the product's ProgramData folder or registry key.
/// </summary>
internal sealed record AuditSettings
{
    /// <summary>Gets the account the audit runs as: administrators' config overrides are read only when it is elevated.</summary>
    public required ProcessAccount Account { get; init; }

    /// <summary>Gets the registry primitive the device context is read through.</summary>
    public required IRegistry Registry { get; init; }

    /// <summary>Gets the clock.</summary>
    public required TimeProvider Time { get; init; }

    /// <summary>Gets the name of the computer.</summary>
    public required string ComputerName { get; init; }

    /// <summary>
    /// Gets what opens the data folder only to read administrators' config overrides from it, for an elevated
    /// run: SecureStore's read-only way in on this device, which gives null when there is no data folder and
    /// throws a <see cref="SecureStoreException"/> that says why when it refuses one. Never SecureStore.Open,
    /// which may move an untrusted folder aside, or make a missing one, when a file in it is read.
    /// </summary>
    public required Func<IDataFolderReader?> OpenDataFolder { get; init; }

    /// <summary>Gets the version of the tool, written as toolVersion.</summary>
    public string ToolVersion { get; init; } = Cli.ToolVersion.Current;

    /// <summary>Gets the checks.</summary>
    public CheckCatalog Catalog { get; init; } = BuiltInChecks.CreateCatalog();

    /// <summary>
    /// Gets the config files that ship with the tool, in front of which the config trust gate puts each
    /// administrator's override that passes every rule (<see cref="ConfigTrustGate"/>).
    /// </summary>
    public IConfigFiles Config { get; init; } = ShippedConfig.Files;

    /// <summary>Gets this device's settings: the process's account, the real registry, the system clock and SecureStore's read-only way in.</summary>
    /// <returns>The settings.</returns>
    public static AuditSettings ForThisDevice()
    {
        var registry = new WindowsRegistry();
        var time = TimeProvider.System;

        // Typed to give the read-only store, so SecureStore.Open cannot take its place without changing this type,
        // which the tests check: Open would move an untrusted config folder aside, with an event, in a run that
        // promises to change nothing.
        ReadOnlySecureStore? OpenReadOnly() => SecureStore.OpenReadOnly(SecureStoreOptions.ForMachine(registry, time));

        return new AuditSettings
        {
            Account = CurrentProcess.ReadAccount(),
            Registry = registry,
            Time = time,
            ComputerName = Environment.MachineName,
            OpenDataFolder = OpenReadOnly,
        };
    }
}
