using Engramic.Baseline.Platform;
using Engramic.Baseline.Testing.Windows;

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
    public void Converts_what_RegistryKey_returns_for_each_type()
    {
        Assert.Equal(RegistryValue.FromText("26200"), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.String, "26200"));
        Assert.Equal(RegistryValue.FromExpandText("%ProgramFiles%"), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.ExpandString, "%ProgramFiles%"));
        Assert.Equal(RegistryValue.FromMultiText(["a", "b"]), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.MultiString, new[] { "a", "b" }));
        Assert.Equal(RegistryValue.FromDWord(uint.MaxValue), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.DWord, -1));
        Assert.Equal(RegistryValue.FromQWord(ulong.MaxValue), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.QWord, -1L));
        Assert.Equal(RegistryValue.FromBinary([1, 2]), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.Binary, new byte[] { 1, 2 }));
        Assert.Equal(RegistryValue.FromOther([3]), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.None, new byte[] { 3 }));
    }

    [Fact]
    public void A_value_whose_data_does_not_match_its_type_is_Other_rather_than_an_exception()
    {
        // RegistryKey.GetValue gives a long for a REG_DWORD of 5 to 8 bytes, bytes for a longer REG_DWORD or
        // REG_QWORD, and the value can change type between reading it and asking its type.
        Assert.Equal(RegistryValue.FromOther([5, 0, 0, 0, 1, 0, 0, 0]), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.DWord, 0x1_0000_0005L));
        Assert.Equal(RegistryValue.FromOther([1, 2, 3, 4, 5, 6, 7, 8, 9]), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.DWord, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 }));
        Assert.Equal(RegistryValue.FromOther([1, 2, 3, 4, 5, 6, 7, 8, 9]), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.QWord, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 }));
        Assert.Equal(RegistryValue.FromOther([7, 0, 0, 0]), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.QWord, 7));
        Assert.Equal(RegistryValue.FromOther([]), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.DWord, "7"));
        Assert.Equal(RegistryValue.FromOther([]), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.String, new[] { "a" }));
        Assert.Equal(RegistryValue.FromOther([]), WindowsRegistry.ToRegistryValue(Microsoft.Win32.RegistryValueKind.MultiString, "a"));
    }

    [Fact]
    public void Lists_a_key_s_subkeys_and_the_hives_loaded_under_HKEY_USERS()
    {
        var current = _registry.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, CurrentVersion);
        var hives = _registry.GetSubKeyNames(RegistryHive.Users, RegistryView.Registry64, string.Empty);

        Assert.Contains("ProfileList", current!, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("S-1-5-18", hives!, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(Elevation.CurrentUser.Value, hives!, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void Listing_a_missing_key_is_null_and_one_this_account_cannot_read_throws_access_denied()
    {
        Assert.Null(_registry.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Engramic Baseline Test\No Such Key"));
        Assert.Throws<UnauthorizedAccessException>(() => _registry.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, @"SAM\SAM"));
    }

    [Fact]
    public void Refuses_an_empty_key_path()
    {
        Assert.Throws<ArgumentException>(() => _registry.GetValue(RegistryHive.LocalMachine, RegistryView.Registry64, string.Empty, "Value"));
    }
}
