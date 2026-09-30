using System.Text;

namespace Engramic.Baseline.Model.Tests;

public sealed class Utf8BomTests
{
    [Fact]
    public void Text_follows_the_byte_order_mark()
    {
        Assert.Equal([0xEF, 0xBB, 0xBF, (byte)'{', (byte)'}'], Utf8Bom.GetBytes("{}"));
    }

    [Fact]
    public void Text_beyond_ASCII_is_written_as_UTF8()
    {
        // e with an acute accent, as a Windows PowerShell 5.1 reader must see it: C3 A9 after the mark.
        Assert.Equal([0xEF, 0xBB, 0xBF, (byte)'c', (byte)'a', (byte)'f', 0xC3, 0xA9], Utf8Bom.GetBytes("caf\u00E9"));
    }

    [Fact]
    public void An_unpaired_surrogate_throws_rather_than_becoming_a_replacement_character()
    {
        Assert.Throws<EncoderFallbackException>(() => Utf8Bom.GetBytes("before \ud800 after"));
    }

    [Fact]
    public void The_encoding_writes_the_mark_as_its_preamble()
    {
        Assert.Equal(Utf8Bom.Preamble.ToArray(), Utf8Bom.Encoding.GetPreamble());
    }
}
