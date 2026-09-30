namespace Engramic.Baseline.Platform.Tests;

public sealed class SidTests
{
    [Theory]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-21-1004336348-1177238915-682003330-512")]
    [InlineData("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")]
    [InlineData("S-1-281474976710655-4294967295")]
    [InlineData("S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15")]
    public void Reads_a_security_identifier_unchanged(string text)
    {
        Assert.True(Sid.TryParse(text, out var sid));
        Assert.Equal(text, sid.Value);
    }

    [Theory]
    [InlineData("")]
    [InlineData("S")]
    [InlineData("S-1")]
    [InlineData("S-1-5")]
    [InlineData("S-2-5-18")]
    [InlineData("S-01-5-18")]
    [InlineData("S-1-5-018")]
    [InlineData("S-1-5-18-")]
    [InlineData("S-1--18")]
    [InlineData(" S-1-5-18")]
    [InlineData("S-1-5-18 ")]
    [InlineData("S-1-5-+18")]
    [InlineData("S-1-0x5-18")]
    [InlineData("S-1-281474976710656-18")]
    [InlineData("S-1-5-4294967296")]
    [InlineData("S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16")]
    [InlineData("S-1-5-\u0661\u0668")]
    [InlineData("X-1-5-18")]
    [InlineData(null)]
    public void Refuses_anything_else(string? text)
    {
        Assert.False(Sid.TryParse(text, out var sid));
        Assert.Null(sid);
    }

    [Fact]
    public void Reads_a_lower_case_s_as_upper_case_and_matches_the_well_known_value()
    {
        var sid = Sid.Parse("s-1-5-18");

        Assert.Equal("S-1-5-18", sid.ToString());
        Assert.Equal(Sid.LocalSystem, sid);
    }

    [Fact]
    public void The_well_known_identifiers_are_the_ones_Windows_uses()
    {
        Assert.Equal("S-1-5-18", Sid.LocalSystem.Value);
        Assert.Equal("S-1-5-32-544", Sid.Administrators.Value);
        Assert.Equal("S-1-5-32-545", Sid.Users.Value);
        Assert.Equal("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", Sid.TrustedInstaller.Value);
        Assert.Equal("S-1-3-0", Sid.CreatorOwner.Value);
    }

    [Fact]
    public void Parse_throws_on_text_that_is_not_one()
    {
        Assert.Throws<FormatException>(() => Sid.Parse("Administrators"));
    }
}
