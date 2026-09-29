using Engramic.Baseline.Engine;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;

namespace Engramic.Baseline.Controls.Tests;

/// <summary>Registry states of Windows releases, and the device contexts read from them.</summary>
internal static class Devices
{
    public static readonly ProcessAccount User = new(@"CONTOSO\alex", IsAdministrator: false, IsLocalSystem: false);

    public static readonly DateTimeOffset AuditTime = new(2026, 9, 29, 14, 3, 49, TimeSpan.Zero);

    /// <summary>A registry with the CurrentVersion values Windows writes: text, and UBR as a REG_DWORD.</summary>
    public static FakeRegistry Registry(string build, uint ubr, string displayVersion, string editionId, string installationType = "Client", string productName = "Windows 10 Pro")
    {
        return new FakeRegistry()
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "CurrentBuildNumber", RegistryValue.FromText(build))
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "UBR", RegistryValue.FromDWord(ubr))
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "DisplayVersion", RegistryValue.FromText(displayVersion))
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "EditionID", RegistryValue.FromText(editionId))
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "ProductName", RegistryValue.FromText(productName))
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "InstallationType", RegistryValue.FromText(installationType));
    }

    public static DeviceContext Read(IRegistry registry, ProcessAccount? account = null)
    {
        return DeviceContextReader.Read(registry, "DEVICE01", account ?? User, AuditTime);
    }

    public static DeviceContext Windows11(string build, uint ubr, string displayVersion, string editionId = "Professional")
    {
        return Read(Registry(build, ubr, displayVersion, editionId));
    }

    public static DeviceContext Server(string build, uint ubr, string editionId = "ServerDatacenter", string productName = "Windows Server 2025 Datacenter", string installationType = "Server")
    {
        return Read(Registry(build, ubr, string.Empty, editionId, installationType, productName));
    }
}
