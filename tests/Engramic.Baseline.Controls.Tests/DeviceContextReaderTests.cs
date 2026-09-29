using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;

namespace Engramic.Baseline.Controls.Tests;

public sealed class DeviceContextReaderTests
{
    [Fact]
    public void Reads_the_release_from_CurrentVersion_in_the_64_bit_view()
    {
        var registry = Devices.Registry("26200", 9457, "25H2", "Professional");

        var device = Devices.Read(registry);

        Assert.Equal("DEVICE01", device.ComputerName);
        Assert.Equal("Windows 11", device.OSFamily);
        Assert.Equal("Client", device.InstallationType);
        Assert.Equal("Windows 10 Pro", device.ProductName);
        Assert.Equal("Professional", device.EditionId);
        Assert.Equal("Pro", device.EditionClass);
        Assert.Equal("25H2", device.DisplayVersion);
        Assert.Equal(26200, device.Build);
        Assert.Equal(9457, device.Ubr);
        Assert.Equal("26200.9457", device.FullBuild);
        Assert.Equal(Devices.AuditTime, device.AuditTime);
        Assert.All(registry.Reads, r => Assert.Equal((RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion"), (r.Hive, r.View, r.Key)));
        Assert.Equal(["CurrentBuildNumber", "UBR", "DisplayVersion", "EditionID", "ProductName", "InstallationType"], registry.Reads.Select(r => r.Name));
    }

    [Fact]
    public void Values_only_the_32_bit_view_holds_are_not_read()
    {
        var registry = new FakeRegistry().Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "CurrentBuildNumber", RegistryValue.FromText("26100"), RegistryView.Registry32);

        Assert.Equal(0, Devices.Read(registry).Build);
    }

    [Theory]
    // Server 2025 and Windows 11 24H2 are both build 26100: the installation type decides.
    [InlineData("26100", "Server", "Windows Server", "Server")]
    [InlineData("26100", "Server Core", "Windows Server", "Server")]
    [InlineData("26100", "Client", "Windows 11", "Enterprise")]
    [InlineData("17763", "server", "Windows Server", "Server")]
    [InlineData("19045", "Client", "Windows 10", "Enterprise")]
    [InlineData("9600", "Client", "Unknown", "Enterprise")]
    public void The_family_comes_from_the_installation_type_first(string build, string installationType, string family, string editionClass)
    {
        var device = Devices.Read(Devices.Registry(build, 1, "24H2", "Enterprise", installationType));

        Assert.Equal(family, device.OSFamily);
        Assert.Equal(editionClass, device.EditionClass);
    }

    [Fact]
    public void Values_that_are_missing_take_the_PowerShell_tool_s_defaults()
    {
        var device = Devices.Read(new FakeRegistry());

        Assert.Equal(0, device.Build);
        Assert.Equal(0, device.Ubr);
        Assert.Equal("0.0", device.FullBuild);
        Assert.Equal(string.Empty, device.DisplayVersion);
        Assert.Equal(string.Empty, device.EditionId);
        Assert.Equal(string.Empty, device.ProductName);
        Assert.Equal("Client", device.InstallationType);
        Assert.Equal("Unknown", device.OSFamily);
        Assert.Equal("Unknown", device.EditionClass);
    }

    [Fact]
    public void A_key_that_cannot_be_read_counts_as_missing()
    {
        var registry = Devices.Registry("26200", 9457, "25H2", "Professional").Deny(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey);

        var device = Devices.Read(registry);

        Assert.Equal((0, "Unknown"), (device.Build, device.OSFamily));
    }

    [Fact]
    public void An_empty_installation_type_is_read_as_empty_not_as_the_default()
    {
        var device = Devices.Read(Devices.Registry("26100", 1, "24H2", "Professional", installationType: string.Empty));

        Assert.Equal(string.Empty, device.InstallationType);
        Assert.Equal("Windows 11", device.OSFamily);
    }

    [Theory]
    [InlineData(false, false, false, false)]
    [InlineData(true, false, true, false)]
    [InlineData(false, true, true, true)]
    public void Takes_who_runs_the_audit_from_the_account(bool administrator, bool system, bool elevated, bool isSystem)
    {
        var account = new ProcessAccount(system ? @"NT AUTHORITY\SYSTEM" : @"CONTOSO\alex", administrator, system);

        var device = Devices.Read(new FakeRegistry(), account);

        Assert.Equal(account.Name, device.RunningAs);
        Assert.Equal(elevated, device.IsElevated);
        Assert.Equal(isSystem, device.IsSystem);
    }

    [Fact]
    public void A_build_stored_as_a_number_is_read_as_well()
    {
        var registry = new FakeRegistry()
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "CurrentBuildNumber", RegistryValue.FromDWord(26100))
            .Set(RegistryHive.LocalMachine, DeviceContextReader.CurrentVersionKey, "UBR", RegistryValue.FromText(" 4946 "));

        var device = Devices.Read(registry);

        Assert.Equal("26100.4946", device.FullBuild);
    }
}
