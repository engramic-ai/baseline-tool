namespace Engramic.Baseline.Controls.Tests;

public sealed class WindowsFamilyTests
{
    [Theory]
    // Server 2025 and Windows 11 24H2 share build 26100: the installation type tells them apart.
    [InlineData(26100, "Server", "Windows Server")]
    [InlineData(26100, "Client", "Windows 11")]
    [InlineData(26100, "Server Core", "Windows Server")]
    [InlineData(14393, "server", "Windows Server")]
    [InlineData(22000, "Client", "Windows 11")]
    [InlineData(21999, "Client", "Windows 10")]
    [InlineData(19045, "Client", "Windows 10")]
    [InlineData(10240, "Client", "Windows 10")]
    [InlineData(9600, "Client", "Unknown")]
    [InlineData(0, "Client", "Unknown")]
    // The PowerShell tool reads a missing InstallationType as Client.
    [InlineData(26100, null, "Windows 11")]
    public void Names_the_family_as_the_PowerShell_tool_does(int build, string? installationType, string expected)
    {
        Assert.Equal(expected, WindowsFamily.FromBuild(build, installationType));
    }
}
