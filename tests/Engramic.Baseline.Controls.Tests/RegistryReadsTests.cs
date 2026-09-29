using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Controls.Tests;

/// <summary>
/// The values are those Windows PowerShell 5.1 gives for [int] and [string] casts of the same data, except
/// where the cast throws, which counts as missing here (-1).
/// </summary>
public sealed class RegistryReadsTests
{
    [Theory]
    [InlineData("26100", 26100)]
    [InlineData("", 0)]
    [InlineData(" 42 ", 42)]
    [InlineData("+42", 42)]
    [InlineData("-7", -7)]
    [InlineData("007", 7)]
    // A fraction rounds half to even; thousands separators and exponents are allowed.
    [InlineData("42.5", 42)]
    [InlineData("43.5", 44)]
    [InlineData("4,2", 42)]
    [InlineData("1e3", 1000)]
    // [int] throws on these.
    [InlineData(" ", -1)]
    [InlineData("abc", -1)]
    [InlineData("2147483648", -1)]
    [InlineData("NaN", -1)]
    // [int] reads hexadecimal; this reader does not.
    [InlineData("0x10", -1)]
    public void Text_becomes_a_number_as_PowerShell_s_int_cast_makes_it(string text, int expected)
    {
        Assert.Equal(expected, RegistryReads.ToInt32(RegistryValue.FromText(text), -1));
    }

    [Fact]
    public void Numbers_are_signed_as_PowerShell_sees_them()
    {
        Assert.Equal(-1, RegistryReads.ToInt32(RegistryValue.FromDWord(uint.MaxValue), 0));
        Assert.Equal(4946, RegistryReads.ToInt32(RegistryValue.FromDWord(4946), 0));
        Assert.Equal(-1, RegistryReads.ToInt32(RegistryValue.FromQWord(ulong.MaxValue), 0));
        Assert.Equal(7, RegistryReads.ToInt32(RegistryValue.FromQWord(7), 0));
        Assert.Equal(99, RegistryReads.ToInt32(RegistryValue.FromQWord(1UL << 40), 99));
    }

    [Fact]
    public void Lists_bytes_and_missing_values_are_not_numbers()
    {
        Assert.Equal(99, RegistryReads.ToInt32(RegistryValue.FromMultiText(["5"]), 99));
        Assert.Equal(99, RegistryReads.ToInt32(RegistryValue.FromBinary([5]), 99));
        Assert.Equal(99, RegistryReads.ToInt32(null, 99));
    }

    [Fact]
    public void Values_become_text_as_PowerShell_s_string_cast_makes_them()
    {
        Assert.Equal("24H2", RegistryReads.ToText(RegistryValue.FromText("24H2"), "x"));
        Assert.Equal("%SystemRoot%", RegistryReads.ToText(RegistryValue.FromExpandText("%SystemRoot%"), "x"));
        Assert.Equal("a b", RegistryReads.ToText(RegistryValue.FromMultiText(["a", "b"]), "x"));
        Assert.Equal("-1", RegistryReads.ToText(RegistryValue.FromDWord(uint.MaxValue), "x"));
        Assert.Equal("4946", RegistryReads.ToText(RegistryValue.FromQWord(4946), "x"));
        Assert.Equal("1 2 255", RegistryReads.ToText(RegistryValue.FromBinary([1, 2, 255]), "x"));
        Assert.Equal(string.Empty, RegistryReads.ToText(RegistryValue.FromText(string.Empty), "x"));
        Assert.Equal("Client", RegistryReads.ToText(null, "Client"));
    }
}
