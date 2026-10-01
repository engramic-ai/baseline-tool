namespace Engramic.Baseline.Platform.Tests;

public sealed class AppxPackageTests
{
    [Fact]
    public void Reads_each_part_of_a_full_name()
    {
        var package = AppxPackage.Parse("Claude_2.16120.0.0_x64__pzs8sxrjxfjjc");

        Assert.Equal("Claude_2.16120.0.0_x64__pzs8sxrjxfjjc", package.FullName);
        Assert.Equal("Claude", package.Name);
        Assert.Equal(new Version(2, 16120, 0, 0), package.Version);
        Assert.Equal("x64", package.Architecture);
        Assert.Equal(string.Empty, package.ResourceId);
        Assert.Equal("pzs8sxrjxfjjc", package.PublisherId);
        Assert.Equal("Claude_pzs8sxrjxfjjc", package.FamilyName);
        Assert.Equal(string.Empty, package.InstallLocation);
        Assert.Equal(package.FullName, package.ToString());
    }

    [Theory]
    [InlineData("OpenAI.ChatGPT-Desktop_1.2025.112.0_x64__2p2nqsd0c76g0", "OpenAI.ChatGPT-Desktop", "")]
    [InlineData("Microsoft.Copilot_2026.924.820.0_neutral_~_8wekyb3d8bbwe", "Microsoft.Copilot", "~")]
    [InlineData("Microsoft.Paint_11.2605.81.0_neutral_split.scale-125_8wekyb3d8bbwe", "Microsoft.Paint", "split.scale-125")]
    [InlineData("1527c705-839a-4832-9118-54d4Bd6a0c89_10.0.19640.1000_neutral_neutral_cw5n1h2txyewy", "1527c705-839a-4832-9118-54d4Bd6a0c89", "neutral")]
    [InlineData("Microsoft.VCLibs.140.00_14.0.33519.0_arm64__8wekyb3d8bbwe", "Microsoft.VCLibs.140.00", "")]
    [InlineData("Vendor.App_65535.65535.65535.65535_x86a64__ABCDEFGHJKMNP", "Vendor.App", "")]
    public void Reads_names_resource_identifiers_and_architectures_Windows_uses(string fullName, string name, string resourceId)
    {
        Assert.True(AppxPackage.TryParse(fullName, out var package));
        Assert.Equal(name, package.Name);
        Assert.Equal(resourceId, package.ResourceId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Claude")]
    [InlineData("Claude_2.16120.0.0_x64_pzs8sxrjxfjjc")]
    [InlineData("Claude_2.16120.0.0_x64___pzs8sxrjxfjjc")]
    [InlineData("Cl_2.16120.0.0_x64__pzs8sxrjxfjjc")]
    [InlineData("Claude!_2.16120.0.0_x64__pzs8sxrjxfjjc")]
    [InlineData("Claude_2.16120.0_x64__pzs8sxrjxfjjc")]
    [InlineData("Claude_2.65536.0.0_x64__pzs8sxrjxfjjc")]
    [InlineData("Claude_2.-1.0.0_x64__pzs8sxrjxfjjc")]
    [InlineData("Claude_2. 1.0.0_x64__pzs8sxrjxfjjc")]
    [InlineData("Claude_2.16120.0.0_amd64__pzs8sxrjxfjjc")]
    [InlineData("Claude_2.16120.0.0_x64_a~_pzs8sxrjxfjjc")]
    [InlineData("Claude_2.16120.0.0_x64_resource-identifier-over-thirty_pzs8sxrjxfjjc")]
    [InlineData("Claude_2.16120.0.0_x64__pzs8sxrjxfjj")]
    [InlineData("Claude_2.16120.0.0_x64__pzs8sxrjxfjjcc")]
    [InlineData("Claude_2.16120.0.0_x64__pzs8sxrjxfjjo")]
    [InlineData("Claude_2.16120.0.0_x64__pzs8sxrjxfjj\u0661")]
    public void Refuses_anything_else(string? text)
    {
        Assert.False(AppxPackage.TryParse(text, out var package));
        Assert.Null(package);
    }

    [Fact]
    public void Parse_says_what_a_full_name_looks_like()
    {
        var e = Assert.Throws<FormatException>(() => AppxPackage.Parse("Claude"));

        Assert.Contains("Claude_2.16120.0.0_x64__pzs8sxrjxfjjc", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Full_names_compare_without_regard_to_case_as_in_Windows()
    {
        Assert.True(AppxPackage.FullNameComparer.Equals("claude_2.16120.0.0_X64__PZS8SXRJXFJJC", "Claude_2.16120.0.0_x64__pzs8sxrjxfjjc"));
        Assert.True(AppxPackage.TryParse("claude_2.16120.0.0_X64__PZS8SXRJXFJJC", out _));
    }

    [Fact]
    public void Keeps_the_install_location_it_is_given()
    {
        var package = AppxPackage.Parse("Claude_2.16120.0.0_x64__pzs8sxrjxfjjc") with { InstallLocation = @"C:\Program Files\WindowsApps\Claude_2.16120.0.0_x64__pzs8sxrjxfjjc" };

        Assert.EndsWith(package.FullName, package.InstallLocation, StringComparison.Ordinal);
    }
}
