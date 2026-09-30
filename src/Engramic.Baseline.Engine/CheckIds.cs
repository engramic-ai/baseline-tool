namespace Engramic.Baseline.Engine;

/// <summary>
/// The rule for check identifiers, such as SU-01: two capital letters naming the area, a hyphen and
/// two digits.
/// </summary>
/// <remarks>
/// Finding identifiers, changesets and the status files refer to checks by these identifiers, so an
/// identifier never changes once its check ships. Only ASCII letters and digits are accepted: the
/// PowerShell tool's pattern also matched lower case and other scripts' digits, which no check uses.
/// </remarks>
public static class CheckIds
{
    /// <summary>Tells whether text is a well-formed check identifier.</summary>
    /// <param name="id">The text to test, such as SU-01.</param>
    /// <returns>True for two ASCII capital letters, a hyphen and two ASCII digits, and nothing else.</returns>
    public static bool IsWellFormed(string? id)
    {
        return id is { Length: 5 }
            && char.IsAsciiLetterUpper(id[0])
            && char.IsAsciiLetterUpper(id[1])
            && id[2] == '-'
            && char.IsAsciiDigit(id[3])
            && char.IsAsciiDigit(id[4]);
    }
}
