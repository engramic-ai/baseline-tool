using Engramic.Baseline.Model;
using static Engramic.Baseline.Engine.Tests.StatusBuilderTests;

namespace Engramic.Baseline.Engine.Tests;

public sealed class CePlusTestCasesTests
{
    [Fact]
    public void Lists_the_five_test_cases_with_the_PowerShell_tool_s_words()
    {
        Assert.Equal(["TC1", "TC2", "TC3", "TC4", "TC5"], CePlusTestCases.All.Select(t => t.Id));
        Assert.Equal(["CE+ TC1", "CE+ TC2", "CE+ TC3", "CE+ TC4", "CE+ TC5"], CePlusTestCases.All.Select(t => t.Tag));
        Assert.Equal("Check patching (authenticated scan)", CePlusTestCases.All[1].Name);
        Assert.Equal("OS and application fixes older than 14 days (CVSS >= 7, critical/high, or unrated).", CePlusTestCases.All[1].Scope);
        Assert.Equal("MP-11", CePlusTestCases.All[2].EvidenceCheck);
        Assert.All(CePlusTestCases.All.Where(t => t.Id != "TC3"), t => Assert.Null(t.EvidenceCheck));
    }

    [Fact]
    public void A_test_case_no_finding_evidences_is_not_assessed()
    {
        Assert.All(CePlusTestCases.Evaluate([]), o => Assert.Equal(CePlusState.NotAssessed, o.State));
    }

    [Theory]
    [InlineData(FindingStatus.Fail, CePlusState.LikelyFail)]
    [InlineData(FindingStatus.Warn, CePlusState.Check)]
    [InlineData(FindingStatus.Manual, CePlusState.Check)]
    [InlineData(FindingStatus.Skipped, CePlusState.Check)]
    [InlineData(FindingStatus.Error, CePlusState.Check)]
    [InlineData(FindingStatus.Pass, CePlusState.LikelyPass)]
    [InlineData(FindingStatus.Info, CePlusState.LikelyPass)]
    [InlineData(FindingStatus.NotApplicable, CePlusState.LikelyPass)]
    public void Each_finding_status_moves_the_estimate(FindingStatus status, CePlusState expected)
    {
        var findings = new[] { Finding("SU-04", FindingStatus.Pass, frameworks: ["CE+ TC2"]), Finding("SU-05", status, subject: "app", frameworks: ["CE+ TC2"]) };

        Assert.Equal(expected, CePlusTestCases.Evaluate(findings)[1].State);
    }

    [Fact]
    public void A_failure_outweighs_anything_to_check_and_is_named()
    {
        var findings = new[]
        {
            Finding("SU-03", FindingStatus.Warn, subject: "Due"),
            Finding("SU-05", FindingStatus.Fail, subject: "7zip.7zip"),
            Finding("SU-05", FindingStatus.Fail, subject: "Git.Git"),
        };

        var tc2 = CePlusTestCases.Evaluate(findings)[1];

        Assert.Equal(CePlusState.LikelyFail, tc2.State);
        Assert.Equal(["SU-05:7zip-7zip", "SU-05:Git-Git"], tc2.Failing);
    }

    [Theory]
    [InlineData(null, CePlusState.Check)]
    [InlineData(FindingStatus.Pass, CePlusState.LikelyPass)]
    [InlineData(FindingStatus.NotApplicable, CePlusState.Check)]
    [InlineData(FindingStatus.Info, CePlusState.Check)]
    public void TC3_is_likely_to_pass_only_once_the_malware_download_test_has_passed(FindingStatus? mp11, CePlusState expected)
    {
        var findings = new List<Finding> { Finding("MP-01", FindingStatus.Pass) };
        if (mp11 is { } status)
        {
            findings.Add(Finding("MP-11", status));
        }

        Assert.Equal(expected, CePlusTestCases.Evaluate(findings)[2].State);
    }

    [Fact]
    public void Tags_match_without_regard_to_case()
    {
        Assert.Equal(CePlusState.LikelyFail, CePlusTestCases.Evaluate([Finding("SU-01", FindingStatus.Fail, frameworks: ["ce+ tc2"])])[1].State);
    }
}
