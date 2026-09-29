using Engramic.Baseline.Engine;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Controls;

/// <summary>
/// Reads the device context an audit starts with, as the PowerShell tool's Get-CEDeviceContext does.
/// </summary>
/// <remarks>
/// The Windows release comes from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion in the 64-bit view.
/// A value that is missing or cannot be read takes the PowerShell tool's default: build and revision 0,
/// empty text, and Client for the installation type. The family comes from the installation type first,
/// since Windows Server and Windows 11 share build numbers, then from the build.
/// </remarks>
public static class DeviceContextReader
{
    /// <summary>The key that describes the Windows release.</summary>
    public const string CurrentVersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    /// <summary>Reads the device context.</summary>
    /// <param name="registry">The registry primitive.</param>
    /// <param name="computerName">The name of the computer.</param>
    /// <param name="account">The account the audit runs as.</param>
    /// <param name="auditTime">When the audit started.</param>
    /// <returns>The device context.</returns>
    public static DeviceContext Read(IRegistry registry, string computerName, ProcessAccount account, DateTimeOffset auditTime)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(computerName);
        ArgumentNullException.ThrowIfNull(account);

        var build = RegistryReads.ToInt32(Value(registry, "CurrentBuildNumber"), 0);
        var ubr = RegistryReads.ToInt32(Value(registry, "UBR"), 0);
        var displayVersion = RegistryReads.ToText(Value(registry, "DisplayVersion"), string.Empty);
        var editionId = RegistryReads.ToText(Value(registry, "EditionID"), string.Empty);
        var productName = RegistryReads.ToText(Value(registry, "ProductName"), string.Empty);
        var installationType = RegistryReads.ToText(Value(registry, "InstallationType"), "Client");
        var family = WindowsFamily.FromBuild(build, installationType);

        return new DeviceContext
        {
            ComputerName = computerName,
            OSFamily = family,
            InstallationType = installationType,
            ProductName = productName,
            EditionId = editionId,
            EditionClass = EditionClass.FromEdition(family, editionId),
            DisplayVersion = displayVersion,
            Build = build,
            Ubr = ubr,
            RunningAs = account.Name,
            IsElevated = account.IsElevated,
            IsSystem = account.IsLocalSystem,
            AuditTime = auditTime,
        };
    }

    private static RegistryValue? Value(IRegistry registry, string name) => RegistryReads.LocalMachine(registry, CurrentVersionKey, name);
}
