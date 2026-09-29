using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>Reads values every supported Windows has, through the real registry.</summary>
public sealed class WindowsRegistryTests
{
    private const string CurrentVersion = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    private const string WindowsCurrentVersion = @"SOFTWARE\Microsoft\Windows\CurrentVersion";

    private readonly WindowsRegistry _registry = new();

    [Fact]
    public void Reads_text_and_numbers_as_stored()
    {
        var build = _registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, CurrentVersion, "CurrentBuildNumber");
        var ubr = _registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, CurrentVersion, "UBR");
        var installTime = _registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, CurrentVersion, "InstallTime");

        Assert.Equal(RegistryValueKind.Text, build!.Kind);
        Assert.True(int.Parse(build.Text!, System.Globalization.CultureInfo.InvariantCulture) >= 14393, $"Build {build.Text}");
        Assert.Equal(RegistryValueKind.DWord, ubr!.Kind);
        Assert.Equal(RegistryValueKind.QWord, installTime!.Kind);
        Assert.True(installTime.Number > 0);
    }

    [Fact]
    public void Reads_a_list_and_bytes()
    {
        var list = _registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, @"SYSTEM\CurrentControlSet\Control\ServiceGroupOrder", "List");
        var productId = _registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, CurrentVersion, "DigitalProductId");

        Assert.Equal(RegistryValueKind.MultiText, list!.Kind);
        Assert.NotEmpty(list.Lines);
        Assert.Equal(RegistryValueKind.Binary, productId!.Kind);
        Assert.False(productId.Bytes.IsEmpty);
    }

    [Fact]
    public void Leaves_expandable_text_as_written()
    {
        var path = _registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, WindowsCurrentVersion, "ProgramFilesPath");

        Assert.Equal(RegistryValueKind.ExpandText, path!.Kind);
        Assert.Equal("%ProgramFiles%", path.Text);
    }

    [Fact]
    public void Reads_the_view_it_is_given()
    {
        // 64-bit Windows keeps a copy of this key for 32-bit programs, which names the x86 folder.
        var native = _registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, WindowsCurrentVersion, "ProgramFilesDir");
        var wow = _registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry32, WindowsCurrentVersion, "ProgramFilesDir");

        Assert.EndsWith(@"\Program Files", native!.Text, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith(@"\Program Files (x86)", wow!.Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_missing_key_or_value_is_null()
    {
        Assert.Null(_registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Engramic Baseline Test\No Such Key", "Value"));
        Assert.Null(_registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, CurrentVersion, "No Such Value"));
    }

    [Fact]
    public void A_key_this_account_cannot_read_throws_access_denied()
    {
        // Only SYSTEM may open the SAM database's key; administrators are denied too.
        Assert.Throws<UnauthorizedAccessException>(() => _registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, @"SAM\SAM", string.Empty));
    }

    [Fact]
    public void Refuses_an_empty_key_path()
    {
        Assert.Throws<ArgumentException>(() => _registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, string.Empty, "Value"));
    }
}
