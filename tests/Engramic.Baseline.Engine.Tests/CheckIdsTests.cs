namespace Engramic.Baseline.Engine.Tests;

public sealed class CheckIdsTests
{
    [Theory]
    [InlineData("SU-01")]
    [InlineData("FW-07")]
    [InlineData("NC-08")]
    public void Accepts_two_capital_letters_a_hyphen_and_two_digits(string id)
    {
        Assert.True(CheckIds.IsWellFormed(id));
    }

    [Theory]
    [InlineData("su-01")]
    [InlineData("SU-1")]
    [InlineData("SU-001")]
    [InlineData("SU01")]
    [InlineData("SU_01")]
    [InlineData("S-01")]
    [InlineData(" SU-01")]
    [InlineData("")]
    [InlineData(null)]
    // Arabic-Indic digits one and two, which a .NET regex \d would accept.
    [InlineData("SU-\u0661\u0662")]
    // Fullwidth S, which is a letter, but not an ASCII one.
    [InlineData("\uFF33U-01")]
    public void Refuses_anything_else(string? id)
    {
        Assert.False(CheckIds.IsWellFormed(id));
    }
}
