using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// Where SecureStore looks for ProgramData. The known-folder API answers %SystemDrive%\ProgramData from
/// the process environment, so a process started with SystemDrive changed is told another folder; the
/// answer must be ProgramData on the drive Windows is installed on.
/// </summary>
public sealed class ProgramDataTests
{
    [Theory]
    [InlineData(@"C:\ProgramData", @"C:\WINDOWS")]
    [InlineData(@"c:\programdata", @"C:\Windows")]
    [InlineData(@"D:\ProgramData", @"d:\Windows")]
    public void Takes_ProgramData_on_the_drive_Windows_is_installed_on(string knownFolder, string windows)
    {
        Assert.Equal(knownFolder, SecureStore.CheckProgramData(knownFolder, windows));
    }

    [Theory]
    [InlineData(@"Z:\ProgramData")] // SystemDrive=Z:
    [InlineData(@"C:\Temp\ProgramData")] // SystemDrive=C:\Temp
    [InlineData(@"C:\Users\Public\ProgramData")]
    [InlineData(@"C:\Data\ProgramData")] // moved, which is not supported
    [InlineData(@"C:\ProgramData2")]
    [InlineData(@"C:\ProgramData\")]
    public void Refuses_a_ProgramData_folder_anywhere_else(string knownFolder)
    {
        var e = Assert.Throws<SecureStoreException>(() => SecureStore.CheckProgramData(knownFolder, @"C:\WINDOWS"));

        Assert.Equal(
            $@"Windows gives the ProgramData folder as {knownFolder}, not C:\ProgramData on the drive Windows is installed on. It builds that path from the SystemDrive environment variable, which whoever started this process can change, so it is not used. A ProgramData folder moved elsewhere is not supported.",
            e.Message);
    }

    [Theory]
    [InlineData(@"\\?\C:\Windows")]
    [InlineData(@"\\server\share\Windows")]
    [InlineData("Windows")]
    [InlineData("")]
    public void Refuses_when_Windows_is_not_on_a_drive_with_a_letter(string windows)
    {
        Assert.Throws<SecureStoreException>(() => SecureStore.CheckProgramData(@"C:\ProgramData", windows));
    }

    [Fact]
    public void Finds_this_device_s_ProgramData_folder()
    {
        // This process's environment is the one it was started with, so both give the real folder.
        var expected = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        Assert.Equal(expected, SecureStore.FindProgramData(), ignoreCase: true);
        Assert.EndsWith(@":\ProgramData", SecureStore.FindProgramData(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void The_machine_options_use_this_device_s_ProgramData_and_the_installer_s_seal()
    {
        var registry = new FakeRegistry();
        var time = TimeProvider.System;

        var options = SecureStoreOptions.ForMachine(registry, time);

        Assert.Equal(SecureStore.FindProgramData(), options.ProgramDataPath);
        Assert.Equal(@"SOFTWARE\EngramicBaseline.DataRoot", options.SealKeyPath);
        Assert.Equal("DataRootSealed", options.SealValueName);
        Assert.Same(registry, options.Registry);
        Assert.Same(time, options.Time);
    }
}
