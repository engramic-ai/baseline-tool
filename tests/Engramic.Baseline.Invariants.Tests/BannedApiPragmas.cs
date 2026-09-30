using System.Text.RegularExpressions;

namespace Engramic.Baseline.Invariants.Tests;

/// <summary>
/// The pragmas that mark an exempt use of a banned API: "#pragma warning disable RS0030 // reason" before
/// it and "#pragma warning restore RS0030" after it.
/// </summary>
internal static partial class BannedApiPragmas
{
    /// <summary>
    /// Tells which lines of a file sit inside an exempt region, from its disable line to its restore line.
    /// A region that is never restored runs to the end of the file; the exemption tests reject that.
    /// </summary>
    public static bool[] ExemptLines(IReadOnlyList<string> lines)
    {
        var inside = new bool[lines.Count];
        var open = false;
        for (var i = 0; i < lines.Count; i++)
        {
            if (Disable().IsMatch(lines[i]))
            {
                open = true;
            }

            inside[i] = open;
            if (Restore().IsMatch(lines[i]))
            {
                open = false;
            }
        }

        return inside;
    }

    [GeneratedRegex(@"^\s*#pragma\s+warning\s+disable\s+RS0030\s*(//(?<reason>.*))?$")]
    public static partial Regex Disable();

    [GeneratedRegex(@"^\s*#pragma\s+warning\s+restore\s+RS0030\s*(//.*)?$")]
    public static partial Regex Restore();
}
