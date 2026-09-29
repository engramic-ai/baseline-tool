using Engramic.Baseline.Controls;

namespace Engramic.Baseline.Windows.Tests;

public sealed class DeviceContextTests
{
    [Fact]
    public void Reads_this_device_s_context_through_the_real_registry()
    {
        var account = CurrentProcess.ReadAccount();
        var time = new DateTimeOffset(2026, 9, 29, 14, 3, 49, TimeSpan.Zero);

        var device = DeviceContextReader.Read(new WindowsRegistry(), Environment.MachineName, account, time);

        Assert.True(device.Build >= 14393, $"Build {device.Build}");
        Assert.Contains(device.OSFamily, new[] { WindowsFamily.Windows10, WindowsFamily.Windows11, WindowsFamily.Server });
        Assert.NotEmpty(device.EditionId);
        Assert.NotEmpty(device.ProductName);
        Assert.Equal($"{device.Build}.{device.Ubr}", device.FullBuild);
        Assert.Equal(account.IsElevated, device.IsElevated);
        Assert.Equal(time, device.AuditTime);
    }
}
