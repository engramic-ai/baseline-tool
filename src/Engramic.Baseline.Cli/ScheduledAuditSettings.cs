using Engramic.Baseline.Controls;
using Engramic.Baseline.Engine;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Windows;

namespace Engramic.Baseline.Cli;

/// <summary>
/// What the scheduled audit runs with: this device's (<see cref="ForThisDevice"/>), or a test's, which never
/// names the product's mutex, ProgramData folder or registry key.
/// </summary>
internal sealed record ScheduledAuditSettings
{
    /// <summary>Gets the account the audit runs as, which must be SYSTEM.</summary>
    public required ProcessAccount Account { get; init; }

    /// <summary>Gets the registry primitive the device context is read through.</summary>
    public required IRegistry Registry { get; init; }

    /// <summary>Gets the clock.</summary>
    public required TimeProvider Time { get; init; }

    /// <summary>Gets the name of the computer.</summary>
    public required string ComputerName { get; init; }

    /// <summary>Gets what opens and checks the data folder: SecureStore on this device.</summary>
    public required Func<ISecureStore> OpenStore { get; init; }

    /// <summary>Gets the version of the tool, written as toolVersion.</summary>
    public required string ToolVersion { get; init; }

    /// <summary>Gets the name of the audit mutex.</summary>
    public string MutexName { get; init; } = AuditMutex.MachineName;

    /// <summary>Gets how long to wait for another audit or an install to release the mutex: 30 minutes, as the module waits.</summary>
    public TimeSpan MutexWait { get; init; } = TimeSpan.FromMinutes(30);

    /// <summary>Gets the checks.</summary>
    public CheckCatalog Catalog { get; init; } = BuiltInChecks.CreateCatalog();

    /// <summary>
    /// Gets the config files that ship with the tool, in front of which the config trust gate puts each
    /// administrator's override in the data folder that passes every rule (<see cref="ConfigTrustGate"/>).
    /// </summary>
    public IConfigFiles Config { get; init; } = ShippedConfig.Files;

    /// <summary>Gets this device's settings: the process's account, the real registry, the system clock and SecureStore.</summary>
    /// <returns>The settings.</returns>
    public static ScheduledAuditSettings ForThisDevice()
    {
        var registry = new WindowsRegistry();
        var time = TimeProvider.System;
        return new ScheduledAuditSettings
        {
            Account = CurrentProcess.ReadAccount(),
            Registry = registry,
            Time = time,
            ComputerName = Environment.MachineName,
            OpenStore = () => SecureStore.Open(SecureStoreOptions.ForMachine(registry, time)),
            ToolVersion = Cli.ToolVersion.Current,
        };
    }
}
