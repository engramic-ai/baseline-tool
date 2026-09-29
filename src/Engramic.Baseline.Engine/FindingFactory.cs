using Engramic.Baseline.Model;

namespace Engramic.Baseline.Engine;

/// <summary>
/// Turns a check's result into a finding, as the PowerShell tool's ConvertTo-CEFinding does.
/// </summary>
internal static class FindingFactory
{
    /// <summary>
    /// Makes the finding. Its severity is the result's own or else the check's, and Info for a result that
    /// passes, does not apply or only informs. It is an auto-fail finding when an auto-fail check fails;
    /// an error is not.
    /// </summary>
    public static Finding Create(CheckInfo check, CheckResult result)
    {
        var severity = result.Severity ?? check.Severity;
        return new Finding
        {
            FindingId = FindingIds.For(check.Id, result.Subject),
            CheckId = check.Id,
            Title = check.Title,
            Subject = result.Subject ?? string.Empty,
            Category = check.Category,
            Frameworks = [.. check.Frameworks],
            Reference = check.Reference,
            Scope = check.Scope,
            Status = result.Status,
            Severity = result.Status is FindingStatus.Pass or FindingStatus.NotApplicable or FindingStatus.Info ? Severity.Info : severity,
            AutoFail = check.AutoFail && result.Status == FindingStatus.Fail,
            Expected = result.Expected ?? string.Empty,
            Actual = result.Actual ?? string.Empty,
            Recommendation = result.Recommendation ?? string.Empty,
            Evidence = [.. result.Evidence ?? []],
            Remediation = result.Remediation,
            Pack = null,
        };
    }
}
