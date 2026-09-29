namespace Engramic.Baseline.Engine;

/// <summary>
/// The framework tags a check can carry, exactly as findings.json and status.json write them.
/// </summary>
public static class FrameworkTags
{
    /// <summary>Cyber Essentials v3.3 (Danzell).</summary>
    public const string CeV33 = "CE v3.3";

    /// <summary>NCSC device hardening guidance.</summary>
    public const string Ncsc = "NCSC";

    /// <summary>Cyber Essentials Plus test case 1, the remote vulnerability assessment.</summary>
    public const string CePlusTC1 = "CE+ TC1";

    /// <summary>Cyber Essentials Plus test case 2, patching.</summary>
    public const string CePlusTC2 = "CE+ TC2";

    /// <summary>Cyber Essentials Plus test case 3, malware protection.</summary>
    public const string CePlusTC3 = "CE+ TC3";

    /// <summary>Cyber Essentials Plus test case 4, multi-factor authentication.</summary>
    public const string CePlusTC4 = "CE+ TC4";

    /// <summary>Cyber Essentials Plus test case 5, account separation.</summary>
    public const string CePlusTC5 = "CE+ TC5";

    /// <summary>Gets every tag, in the order above.</summary>
    public static IReadOnlyList<string> All { get; } = [CeV33, Ncsc, CePlusTC1, CePlusTC2, CePlusTC3, CePlusTC4, CePlusTC5];
}
