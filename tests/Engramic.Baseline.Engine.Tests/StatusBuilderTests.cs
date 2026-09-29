using System.Reflection;
using System.Text.Json.Nodes;
using Engramic.Baseline.Model;

namespace Engramic.Baseline.Engine.Tests;

public sealed class StatusBuilderTests
{
    private const string ReportFolder = @"C:\ProgramData\EngramicBaseline\reports\DEVICE01-20260929-150349";

    [Fact]
    public void Builds_the_status_json_the_PowerShell_module_built_from_the_same_findings()
    {
        // Golden/module-findings.json holds findings the module made with its own checks' details, and
        // Golden/module-status.json what its ConvertTo-CEStatus wrote for them: every status, an auto-fail
        // check that fails and one that errors, a warning beside a pass, and all five CE+ test cases.
        var findings = FindingsFile.Parse(Golden("module-findings.json")).Findings;
        var device = Samples.Device() with { AuditTime = Samples.AuditTime };

        var status = StatusBuilder.Build(findings, ModuleCatalog(), device, "0.3.2", ReportFolder);

        var ours = Flatten(JsonNode.Parse(StatusFile.ToBytes(status).AsSpan(3))!);
        var theirs = Flatten(JsonNode.Parse(Golden("module-status.json"))!);
        Assert.Equal(theirs, ours);
    }

    [Fact]
    public void Each_check_keeps_its_worst_status_whatever_the_order_of_its_findings()
    {
        // Worst first: Fail, Error, Warn, Manual, Skipped, Pass, Info, NotApplicable.
        FindingStatus[] worstFirst = [FindingStatus.Fail, FindingStatus.Error, FindingStatus.Warn, FindingStatus.Manual, FindingStatus.Skipped, FindingStatus.Pass, FindingStatus.Info, FindingStatus.NotApplicable];
        for (var worse = 0; worse < worstFirst.Length; worse++)
        {
            for (var better = worse; better < worstFirst.Length; better++)
            {
                FindingStatus[][] orders = [[worstFirst[worse], worstFirst[better]], [worstFirst[better], worstFirst[worse]]];
                foreach (var order in orders)
                {
                    var findings = order.Select((s, i) => Finding("SU-05", s, subject: "app" + i)).ToList();

                    Assert.Equal(worstFirst[worse], StatusBuilder.CheckMap(findings, ModuleCatalog())["SU-05"].Status);
                }
            }
        }
    }

    [Fact]
    public void A_check_is_marked_auto_fail_whatever_its_status_and_listed_only_when_it_fails_or_errors()
    {
        var findings = new[]
        {
            Finding("UA-07", FindingStatus.Manual),
            Finding("SU-01", FindingStatus.Pass),
            Finding("SU-05", FindingStatus.Error),
            Finding("SU-03", FindingStatus.Fail),
            Finding("FW-02", FindingStatus.Fail),
            Finding("XX-99", FindingStatus.Fail),
        };

        var status = Build(findings);

        Assert.True(status.Checks["SU-01"].AutoFail);
        Assert.True(status.Checks["UA-07"].AutoFail);
        Assert.False(status.Checks["FW-02"].AutoFail);
        // A check the catalog does not have is not an auto-fail check.
        Assert.False(status.Checks["XX-99"].AutoFail);
        Assert.Equal(["SU-03", "SU-05"], status.AutoFails);
        Assert.Equal(2, status.AutoFailCount);
    }

    [Fact]
    public void Checks_are_listed_by_identifier_and_counts_are_by_finding()
    {
        var findings = new[]
        {
            Finding("SU-05", FindingStatus.Fail, subject: "a"),
            Finding("SU-05", FindingStatus.Fail, subject: "b"),
            Finding("FW-01", FindingStatus.Pass),
            Finding("MP-01", FindingStatus.Pass),
        };

        var status = Build(findings);

        Assert.Equal(["FW-01", "MP-01", "SU-05"], status.Checks.Keys);
        Assert.Equal(new StatusCounts { Pass = 2, Fail = 2 }, status.Counts);
    }

    [Fact]
    public void Takes_the_device_and_the_run_from_the_context()
    {
        var device = Samples.Device(system: true) with { DisplayVersion = string.Empty, OSFamily = "Windows 10", Build = 19045, Ubr = 0 };

        var status = StatusBuilder.Build([Finding("SU-01", FindingStatus.Fail)], ModuleCatalog(), device, "1.0.0-alpha.0", ReportFolder);

        Assert.Equal(1, status.SchemaVersion);
        Assert.Equal("1.0.0-alpha.0", status.ToolVersion);
        Assert.Equal(CheckScope.Machine, status.Scope);
        Assert.Equal("windows", status.Platform);
        Assert.Equal("DEVICE01", status.ComputerName);
        Assert.Equal(Samples.AuditTime, status.AuditTime);
        Assert.Equal(@"NT AUTHORITY\SYSTEM", status.RunAs);
        Assert.True(status.Elevated);
        // "$OSFamily $DisplayVersion $EditionID ($FullBuild)", two spaces where the version is empty.
        Assert.Equal("Windows 10  Professional (19045.0)", status.Os);
        Assert.Null(status.Hardware);
        Assert.Empty(status.Packs);
        Assert.Equal(ReportFolder, status.ReportFolder);
    }

    [Theory]
    [InlineData(FindingStatus.Pass, 1, 0, 0, 0)]
    [InlineData(FindingStatus.Fail, 0, 1, 0, 0)]
    [InlineData(FindingStatus.Warn, 0, 1, 0, 0)]
    [InlineData(FindingStatus.Error, 0, 1, 0, 0)]
    [InlineData(FindingStatus.Manual, 0, 0, 1, 0)]
    [InlineData(FindingStatus.Info, 0, 0, 0, 1)]
    [InlineData(FindingStatus.NotApplicable, 0, 0, 0, 1)]
    [InlineData(FindingStatus.Skipped, 0, 0, 0, 1)]
    public void A_framework_counts_each_check_in_one_bucket(FindingStatus status, int met, int attention, int confirm, int notApplicable)
    {
        var rollup = Build([Finding("SU-02", status, frameworks: [FrameworkTags.CeV33, FrameworkTags.Ncsc])]).Frameworks;

        foreach (var framework in new[] { rollup.CeV33!, rollup.Ncsc! })
        {
            Assert.Equal((met, attention, confirm, notApplicable), (framework.Met, framework.Attention, framework.Confirm, framework.NotApplicable));
        }
    }

    [Fact]
    public void Cyber_Essentials_counts_tags_that_start_CE_v3_3_and_NCSC_only_the_NCSC_tag()
    {
        var findings = new[]
        {
            Finding("SU-02", FindingStatus.Pass, frameworks: ["ce v3.3 A6.4"]),
            Finding("NC-05", FindingStatus.Pass, frameworks: ["NCSC hardening"]),
            Finding("NC-06", FindingStatus.Fail, frameworks: ["ncsc"]),
        };

        var frameworks = Build(findings).Frameworks;

        Assert.Equal(1, frameworks.CeV33!.Met);
        Assert.Equal(1, frameworks.CeV33.Applicable);
        Assert.Equal((0, 1), (frameworks.Ncsc!.Met, frameworks.Ncsc.Attention));
        Assert.Equal("Cyber Essentials v3.3", frameworks.CeV33.Label);
        Assert.Equal("NCSC device hardening", frameworks.Ncsc.Label);
    }

    [Fact]
    public void A_framework_no_check_evidences_is_left_out_and_CE_plus_is_always_there()
    {
        var onlyNcsc = Build([Finding("NC-04", FindingStatus.Pass, frameworks: [FrameworkTags.Ncsc])]).Frameworks;
        var nothing = Build([]).Frameworks;

        Assert.Null(onlyNcsc.CeV33);
        Assert.NotNull(onlyNcsc.Ncsc);
        Assert.Null(nothing.CeV33);
        Assert.Null(nothing.Ncsc);
        Assert.All(nothing.CePlus!.TestCases.All, s => Assert.Equal(CePlusState.NotAssessed, s));
    }

    [Fact]
    public void An_SU_01_run_gives_Cyber_Essentials_and_the_TC2_estimate_only()
    {
        var status = Build([Finding("SU-01", FindingStatus.Pass, frameworks: [FrameworkTags.CeV33, FrameworkTags.CePlusTC2])]);

        Assert.Equal(100, status.Frameworks.CeV33!.MetPct);
        Assert.Null(status.Frameworks.Ncsc);
        Assert.Equal([CePlusState.NotAssessed, CePlusState.LikelyPass, CePlusState.NotAssessed, CePlusState.NotAssessed, CePlusState.NotAssessed], status.Frameworks.CePlus!.TestCases.All);
        Assert.Equal(1, status.Frameworks.CePlus.OnTrack);
        Assert.Empty(status.AutoFails);
    }

    internal static CheckCatalog ModuleCatalog()
    {
        // The checks the golden findings come from, with the PowerShell module's frameworks and auto-fail flags.
        (string Id, string[] Frameworks, bool AutoFail)[] checks =
        [
            ("FW-01", ["CE v3.3", "NCSC"], false),
            ("FW-02", ["CE v3.3", "CE+ TC1"], false),
            ("SU-01", ["CE v3.3", "CE+ TC2"], true),
            ("SU-03", ["CE v3.3", "CE+ TC2"], true),
            ("SU-05", ["CE v3.3", "CE+ TC2"], true),
            ("UA-01", ["CE v3.3", "CE+ TC5", "NCSC"], false),
            ("UA-07", ["CE v3.3", "CE+ TC4"], true),
            ("MP-01", ["CE v3.3", "CE+ TC3"], false),
            ("MP-09", ["NCSC", "CE v3.3"], false),
            ("MP-11", ["CE+ TC3"], false),
            ("NC-01", ["NCSC"], false),
            ("NC-03", ["NCSC"], false),
            ("NC-04", ["NCSC"], false),
        ];
        return Samples.Catalog([.. checks.Select(c => new FakeCheck(Samples.Info(c.Id, frameworks: c.Frameworks, autoFail: c.AutoFail)))]);
    }

    internal static Finding Finding(string checkId, FindingStatus status, string subject = "", IReadOnlyList<string>? frameworks = null)
    {
        var info = ModuleCatalog().Find(checkId)?.Info ?? Samples.Info(checkId);
        return new Finding
        {
            FindingId = FindingIds.For(checkId, subject),
            CheckId = checkId,
            Title = info.Title,
            Subject = subject,
            Category = info.Category,
            Frameworks = frameworks ?? info.Frameworks,
            Reference = info.Reference,
            Scope = info.Scope,
            Status = status,
            Severity = Severity.High,
            AutoFail = info.AutoFail && status == FindingStatus.Fail,
            Expected = string.Empty,
            Actual = string.Empty,
            Recommendation = string.Empty,
            Evidence = [],
        };
    }

    private static StatusDocument Build(IReadOnlyList<Finding> findings)
    {
        return StatusBuilder.Build(findings, ModuleCatalog(), Samples.Device(), "1.0.0-alpha.0");
    }

    private static byte[] Golden(string name)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Golden/" + name)!;
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    /// <summary>Every value in the document with its path, in document order, so key order counts too.</summary>
    private static List<string> Flatten(JsonNode node, string path = "$")
    {
        return node switch
        {
            JsonObject o => [.. o.SelectMany(p => p.Value is null ? [$"{path}.{p.Key} = null"] : Flatten(p.Value, $"{path}.{p.Key}"))],
            JsonArray a => a.Count == 0 ? [$"{path} = []"] : [.. a.SelectMany((v, i) => v is null ? [$"{path}[{i}] = null"] : Flatten(v, $"{path}[{i}]"))],
            _ => [$"{path} = {node.ToJsonString()}"],
        };
    }
}
