using Engramic.Baseline.Model;

namespace Engramic.Baseline.Engine;

/// <summary>
/// Builds status.json from an audit, as the PowerShell tool's ConvertTo-CEStatus does.
/// </summary>
/// <remarks>
/// The checks are the source of truth: one entry per check with its worst status, where Fail is worst,
/// then Error, Warn, Manual, Skipped, Pass, Info and NotApplicable. The framework rollups count those
/// checks, and the Cyber Essentials Plus estimates come from the findings themselves.
/// </remarks>
public static class StatusBuilder
{
    /// <summary>How bad each status is, worst first: the PowerShell tool's $CEStatusRank.</summary>
    private static readonly FindingStatus[] WorstFirst =
    [
        FindingStatus.Fail,
        FindingStatus.Error,
        FindingStatus.Warn,
        FindingStatus.Manual,
        FindingStatus.Skipped,
        FindingStatus.Pass,
        FindingStatus.Info,
        FindingStatus.NotApplicable,
    ];

    /// <summary>Builds the status document of a machine audit.</summary>
    /// <param name="findings">The findings of the audit.</param>
    /// <param name="catalog">The checks, which say which are auto-fail checks.</param>
    /// <param name="device">What is known about the device.</param>
    /// <param name="toolVersion">The version of the tool, written as toolVersion.</param>
    /// <param name="reportFolder">The folder of the full report, or empty when none was written.</param>
    /// <returns>The status document.</returns>
    public static StatusDocument Build(IReadOnlyList<Finding> findings, CheckCatalog catalog, DeviceContext device, string toolVersion, string reportFolder = "")
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(toolVersion);
        ArgumentNullException.ThrowIfNull(reportFolder);

        var checks = CheckMap(findings, catalog);
        return new StatusDocument
        {
            ToolVersion = toolVersion,
            ComputerName = device.ComputerName,
            AuditTime = device.AuditTime,
            RunAs = device.RunningAs,
            Elevated = device.IsElevated,
            Os = $"{device.OSFamily} {device.DisplayVersion} {device.EditionId} ({device.FullBuild})",
            Counts = StatusCounts.Of(findings.Select(f => f.Status)),
            AutoFails = [.. checks.Where(c => c.Value.AutoFail && c.Value.Status is FindingStatus.Fail or FindingStatus.Error).Select(c => c.Key)],
            Checks = checks,
            Frameworks = Frameworks(checks, findings),
            Hardware = null,
            ReportFolder = reportFolder,
        };
    }

    /// <summary>
    /// One entry per check, in identifier order, with the worst status among its findings, its frameworks
    /// and scope, and whether it is an auto-fail check at all (not whether it failed).
    /// </summary>
    /// <param name="findings">The findings.</param>
    /// <param name="catalog">The checks, which say which are auto-fail checks.</param>
    /// <returns>The entries by check identifier.</returns>
    public static IReadOnlyDictionary<string, StatusCheck> CheckMap(IReadOnlyList<Finding> findings, CheckCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(catalog);
        var map = new SortedDictionary<string, StatusCheck>(StringComparer.Ordinal);
        foreach (var finding in findings)
        {
            if (map.TryGetValue(finding.CheckId, out var current) && Rank(finding.Status) >= Rank(current.Status))
            {
                continue;
            }

            map[finding.CheckId] = new StatusCheck
            {
                Status = finding.Status,
                Frameworks = [.. finding.Frameworks],
                Scope = finding.Scope,
                AutoFail = catalog.Find(finding.CheckId)?.Info.AutoFail ?? false,
            };
        }

        return map;
    }

    /// <summary>
    /// The frameworks block: Cyber Essentials v3.3 (checks with a tag starting CE v3.3) and NCSC (checks
    /// tagged NCSC), each left out when no check has its tag, then the Cyber Essentials Plus estimates.
    /// </summary>
    /// <param name="checks">The check entries.</param>
    /// <param name="findings">The findings, which the Cyber Essentials Plus estimates are made from.</param>
    /// <returns>The frameworks block.</returns>
    public static StatusFrameworks Frameworks(IReadOnlyDictionary<string, StatusCheck> checks, IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(checks);
        ArgumentNullException.ThrowIfNull(findings);
        var outcomes = CePlusTestCases.Evaluate(findings);
        return new StatusFrameworks
        {
            CeV33 = Rollup(checks, "Cyber Essentials v3.3", tag => tag.StartsWith(FrameworkTags.CeV33, StringComparison.OrdinalIgnoreCase)),
            Ncsc = Rollup(checks, "NCSC device hardening", tag => string.Equals(tag, FrameworkTags.Ncsc, StringComparison.OrdinalIgnoreCase)),
            CePlus = new CePlusRollup
            {
                TestCases = new CePlusTestCaseStates
                {
                    TC1 = outcomes[0].State,
                    TC2 = outcomes[1].State,
                    TC3 = outcomes[2].State,
                    TC4 = outcomes[3].State,
                    TC5 = outcomes[4].State,
                },
            },
        };
    }

    private static int Rank(FindingStatus status) => Array.IndexOf(WorstFirst, status);

    private static FrameworkRollup? Rollup(IReadOnlyDictionary<string, StatusCheck> checks, string label, Func<string, bool> hasTag)
    {
        int met = 0, attention = 0, confirm = 0, notApplicable = 0;
        var present = false;
        foreach (var check in checks.Values.Where(c => c.Frameworks.Any(hasTag)))
        {
            present = true;
            switch (check.Status)
            {
                case FindingStatus.Pass:
                    met++;
                    break;
                case FindingStatus.Fail or FindingStatus.Warn or FindingStatus.Error:
                    attention++;
                    break;
                case FindingStatus.Manual:
                    confirm++;
                    break;
                default:
                    notApplicable++;
                    break;
            }
        }

        return present
            ? new FrameworkRollup { Label = label, Met = met, Attention = attention, Confirm = confirm, NotApplicable = notApplicable }
            : null;
    }
}
