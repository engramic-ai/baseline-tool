using Engramic.Baseline.Model;

namespace Engramic.Baseline.Engine;

/// <summary>
/// A Cyber Essentials Plus test case, which the checks tagged CE+ TC1 to CE+ TC5 evidence.
/// </summary>
/// <param name="Id">The test case, TC1 to TC5.</param>
/// <param name="Name">What the assessor tests.</param>
/// <param name="Scope">What the test covers, and how much of it a device audit can see.</param>
/// <param name="EvidenceCheck">
/// A check that must have passed before the estimate can be Likely pass, or null. TC3 needs MP-11, the
/// malware download test, since the other TC3 checks cannot show that malware is actually stopped.
/// </param>
public sealed record CePlusTestCase(string Id, string Name, string Scope, string? EvidenceCheck = null)
{
    /// <summary>Gets the framework tag of the test case, such as CE+ TC2.</summary>
    public string Tag => "CE+ " + Id;
}

/// <summary>
/// The estimate for one test case, from the findings of an audit.
/// </summary>
/// <param name="TestCase">The test case.</param>
/// <param name="State">The estimate.</param>
/// <param name="Failing">The identifiers of the failing findings that evidence it.</param>
public sealed record CePlusOutcome(CePlusTestCase TestCase, CePlusState State, IReadOnlyList<string> Failing);

/// <summary>
/// The five Cyber Essentials Plus test cases, and how a device audit estimates each, as the PowerShell
/// tool's Get-CESummary does.
/// </summary>
public static class CePlusTestCases
{
    /// <summary>Gets the test cases, TC1 first.</summary>
    public static IReadOnlyList<CePlusTestCase> All { get; } =
    [
        new("TC1", "Remote vulnerability assessment", "Internet-facing services. Tested externally by the assessor; this device audit only covers local firewall exposure."),
        new("TC2", "Check patching (authenticated scan)", "OS and application fixes older than 14 days (CVSS >= 7, critical/high, or unrated)."),
        new("TC3", "Check malware protection", "Email attachment and browser download tests; anti-malware operational and updated.", "MP-11"),
        new("TC4", "Check MFA configuration", "MFA prompt on every cloud service for user and admin accounts (attestation)."),
        new("TC5", "Check account separation", "Admin actions from the user account must require separate credentials."),
    ];

    /// <summary>
    /// Estimates each test case from the findings tagged with it, finding by finding: Not assessed when there
    /// are none, Likely fail when one fails, Check when one warns, needs confirming, was skipped or could
    /// not run, and otherwise Likely pass, unless the test case's evidence check has not passed.
    /// </summary>
    /// <param name="findings">The findings of the audit.</param>
    /// <returns>The estimate for each test case, TC1 first.</returns>
    public static IReadOnlyList<CePlusOutcome> Evaluate(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        return [.. All.Select(tc => Evaluate(tc, findings))];
    }

    private static CePlusOutcome Evaluate(CePlusTestCase testCase, IReadOnlyList<Finding> findings)
    {
        var tagged = findings.Where(f => f.Frameworks.Contains(testCase.Tag, StringComparer.OrdinalIgnoreCase)).ToList();
        var state = tagged.Count == 0 ? CePlusState.NotAssessed
            : tagged.Exists(f => f.Status == FindingStatus.Fail) ? CePlusState.LikelyFail
            : tagged.Exists(f => f.Status is FindingStatus.Warn or FindingStatus.Manual or FindingStatus.Skipped or FindingStatus.Error) ? CePlusState.Check
            : CePlusState.LikelyPass;
        if (state == CePlusState.LikelyPass && testCase.EvidenceCheck is { } evidence)
        {
            var proof = tagged.Where(f => string.Equals(f.CheckId, evidence, StringComparison.OrdinalIgnoreCase)).ToList();
            if (proof.Count == 0 || proof.Exists(f => f.Status != FindingStatus.Pass))
            {
                state = CePlusState.Check;
            }
        }

        return new CePlusOutcome(testCase, state, [.. tagged.Where(f => f.Status == FindingStatus.Fail).Select(f => f.FindingId)]);
    }
}
