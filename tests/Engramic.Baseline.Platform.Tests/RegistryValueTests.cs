namespace Engramic.Baseline.Platform.Tests;

public sealed class RegistryValueTests
{
    [Fact]
    public void Text_keeps_its_kind_and_text_and_has_no_number()
    {
        var value = RegistryValue.FromText("26100");

        Assert.Equal(RegistryValueKind.Text, value.Kind);
        Assert.Equal("26100", value.Text);
        Assert.Null(value.Number);
        Assert.Empty(value.Lines);
        Assert.True(value.Bytes.IsEmpty);
    }

    [Fact]
    public void Expandable_text_is_kept_as_written()
    {
        var value = RegistryValue.FromExpandText("%ProgramFiles%");

        Assert.Equal(RegistryValueKind.ExpandText, value.Kind);
        Assert.Equal("%ProgramFiles%", value.Text);
    }

    [Fact]
    public void Numbers_keep_all_their_bits()
    {
        Assert.Equal(0xFFFFFFFFUL, RegistryValue.FromDWord(uint.MaxValue).Number);
        Assert.Equal(ulong.MaxValue, RegistryValue.FromQWord(ulong.MaxValue).Number);
        Assert.Equal(RegistryValueKind.DWord, RegistryValue.FromDWord(1).Kind);
        Assert.Equal(RegistryValueKind.QWord, RegistryValue.FromQWord(1).Kind);
        Assert.Null(RegistryValue.FromDWord(1).Text);
    }

    [Fact]
    public void A_list_and_bytes_are_copied()
    {
        string[] lines = ["a", "b"];
        byte[] bytes = [1, 2, 3];

        var list = RegistryValue.FromMultiText(lines);
        var binary = RegistryValue.FromBinary(bytes);
        lines[0] = "changed";
        bytes[0] = 9;

        Assert.Equal(["a", "b"], list.Lines);
        Assert.Equal([1, 2, 3], binary.Bytes.ToArray());
        Assert.Equal(RegistryValueKind.Other, RegistryValue.FromOther([7]).Kind);
    }

    [Fact]
    public void A_list_cannot_hold_null()
    {
        Assert.Throws<ArgumentException>(() => RegistryValue.FromMultiText(["a", null!]));
    }

    [Fact]
    public void Values_are_equal_when_kind_and_data_are()
    {
        Assert.Equal(RegistryValue.FromMultiText(["a", "b"]), RegistryValue.FromMultiText(["a", "b"]));
        Assert.Equal(RegistryValue.FromBinary([1, 2]), RegistryValue.FromBinary([1, 2]));
        Assert.Equal(RegistryValue.FromMultiText(["a"]).GetHashCode(), RegistryValue.FromMultiText(["a"]).GetHashCode());
        Assert.NotEqual(RegistryValue.FromText("1"), RegistryValue.FromExpandText("1"));
        Assert.NotEqual(RegistryValue.FromDWord(1), RegistryValue.FromQWord(1));
        Assert.NotEqual(RegistryValue.FromText("a"), RegistryValue.FromText("A"));
        Assert.False(RegistryValue.FromText("a").Equals(null));
    }

    [Fact]
    public void Describes_itself_for_a_test_or_a_log()
    {
        Assert.Equal("Text \"26100\"", RegistryValue.FromText("26100").ToString());
        Assert.Equal("DWord 4946", RegistryValue.FromDWord(4946).ToString());
        Assert.Equal("MultiText [\"a\", \"b\"]", RegistryValue.FromMultiText(["a", "b"]).ToString());
        Assert.Equal("Binary 0102FF", RegistryValue.FromBinary([1, 2, 255]).ToString());
    }

    [Fact]
    public void The_account_is_elevated_when_it_is_an_administrator_or_SYSTEM()
    {
        Assert.False(new ProcessAccount(@"CONTOSO\alex", IsAdministrator: false, IsLocalSystem: false).IsElevated);
        Assert.True(new ProcessAccount(@"CONTOSO\alex", IsAdministrator: true, IsLocalSystem: false).IsElevated);
        Assert.True(new ProcessAccount(@"NT AUTHORITY\SYSTEM", IsAdministrator: false, IsLocalSystem: true).IsElevated);
    }
}
