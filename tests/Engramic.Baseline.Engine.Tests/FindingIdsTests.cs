namespace Engramic.Baseline.Engine.Tests;

public sealed class FindingIdsTests
{
    /// <summary>
    /// Each subject with the finding identifier Windows PowerShell 5.1 gave for it, from the PowerShell
    /// module's own ConvertTo-CEFinding on an en-GB machine. PowerShell 7 gives the same for all of these.
    /// </summary>
    [Theory]
    [InlineData("Lifecycle data", "SU-01:Lifecycle-data")]
    [InlineData("Automatic updates", "SU-01:Automatic-updates")]
    [InlineData("Path C:\\Tools", "SU-01:Path-C-Tools")]
    [InlineData("  leading and trailing  ", "SU-01:leading-and-trailing")]
    [InlineData("!!!", "SU-01:")]
    [InlineData(" ", "SU-01:")]
    [InlineData("-", "SU-01:")]
    [InlineData("a--b", "SU-01:a-b")]
    [InlineData("a\u0009b\u000ac\u000d\u000ad", "SU-01:a-b-c-d")]
    [InlineData("KB5034441", "SU-01:KB5034441")]
    [InlineData("Microsoft 365 / Entra ID", "SU-01:Microsoft-365-Entra-ID")]
    [InlineData("Google Chrome", "SU-01:Google-Chrome")]
    [InlineData("7zip.7zip", "SU-01:7zip-7zip")]
    [InlineData("Caf\u00e9 cr\u00e8me", "SU-01:Caf-cr-me")]
    // -replace ignores case, so [A-Za-z] matches the capital I with a dot and the Kelvin sign, whose lower
    // case is an ASCII letter: both stay in the slug.
    [InlineData("\u0130stanbul", "SU-01:\u0130stanbul")]
    [InlineData("5 \u212aelvin", "SU-01:5-\u212aelvin")]
    [InlineData("\u212a\u212a-\u0130", "SU-01:\u212a\u212a-\u0130")]
    [InlineData("I\u0131i\u0130", "SU-01:I-i\u0130")]
    // Other letters outside ASCII go, even those whose upper case is an ASCII letter (long s, dotless i).
    [InlineData("Stra\u00dfe", "SU-01:Stra-e")]
    [InlineData("\u017fecure", "SU-01:ecure")]
    [InlineData("\u0131\u015f\u0131k", "SU-01:k")]
    [InlineData("\uff21\uff22\uff23", "SU-01:")]
    [InlineData("Chrome \ud83d\ude00 extension", "SU-01:Chrome-extension")]
    [InlineData("\u041f\u0440\u0438\u0432\u0435\u0442 world", "SU-01:world")]
    [InlineData("\u4e2d\u6587 app", "SU-01:app")]
    [InlineData("x\u00a0y\u2011z", "SU-01:x-y-z")]
    [InlineData("a\u0301b", "SU-01:a-b")]
    [InlineData("---abc---", "SU-01:abc")]
    [InlineData("\u00e9\u00e9abc\u00e9\u00e9", "SU-01:abc")]
    // Cut to 40 characters after trimming, which can leave a hyphen at the end.
    [InlineData("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810", "SU-01:Microsoft-Visual-C-2015-2022-Redistribut")]
    [InlineData("123456789012345678901234567890123456789 x", "SU-01:123456789012345678901234567890123456789-")]
    [InlineData("1234567890123456789012345678901234567890", "SU-01:1234567890123456789012345678901234567890")]
    [InlineData("12345678901234567890123456789012345678901", "SU-01:1234567890123456789012345678901234567890")]
    [InlineData(
        "\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130",
        "SU-01:\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130\u0130")]
    public void Makes_the_identifier_byte_for_byte_as_the_PowerShell_tool(string subject, string expected)
    {
        Assert.Equal(expected, FindingIds.For("SU-01", subject));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void A_result_without_a_subject_has_the_check_s_identifier(string? subject)
    {
        Assert.Equal("SU-01", FindingIds.For("SU-01", subject));
    }

    [Fact]
    public void Only_ASCII_letters_and_digits_and_the_two_case_folding_letters_survive()
    {
        // Every UTF-16 code unit on its own: what PowerShell keeps is exactly [A-Za-z0-9], U+0130 and U+212A.
        var kept = Enumerable.Range(0, 0x10000)
            .Select(c => (char)c)
            .Where(c => FindingIds.Slug("a" + c + "b") == "a" + c + "b" && c != '-')
            .ToList();

        Assert.Equal(62 + 2, kept.Count);
        Assert.Equal(['\u0130', '\u212a'], kept.Where(c => c > 0x7F));
    }
}
