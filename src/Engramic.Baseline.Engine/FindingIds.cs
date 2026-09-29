using System.Text;

namespace Engramic.Baseline.Engine;

/// <summary>
/// The rule for finding identifiers, which changesets and reports refer to, byte for byte as the
/// PowerShell tool's ConvertTo-CEFinding makes them.
/// </summary>
/// <remarks>
/// <para>
/// A result without a subject has the check's identifier, such as SU-01. One with a subject adds a colon
/// and a slug of it, such as SU-01:Lifecycle-data: each run of characters other than letters and digits
/// becomes one hyphen, hyphens at either end go, and the slug is cut to its first 40 characters, which
/// can leave a hyphen at the end. A subject with nothing left gives an empty slug, such as SU-01:.
/// </para>
/// <para>
/// The PowerShell rule is ($subject -replace '[^A-Za-z0-9]+', '-').Trim('-'), and -replace ignores case,
/// so [A-Za-z] also matches the two characters whose lower case is an ASCII letter: LATIN CAPITAL LETTER I
/// WITH DOT ABOVE (U+0130, lower case i) and KELVIN SIGN (U+212A, lower case k). Windows PowerShell 5.1
/// keeps both in the slug in every culture, Turkish included; nothing else outside ASCII survives.
/// </para>
/// </remarks>
public static class FindingIds
{
    /// <summary>The longest slug, in UTF-16 code units.</summary>
    public const int MaxSlugLength = 40;

    /// <summary>Makes the identifier of a finding.</summary>
    /// <param name="checkId">The identifier of the check, such as SU-01.</param>
    /// <param name="subject">What the result is about, or null or empty when the check gives one result.</param>
    /// <returns>The finding identifier.</returns>
    public static string For(string checkId, string? subject)
    {
        ArgumentNullException.ThrowIfNull(checkId);
        return string.IsNullOrEmpty(subject) ? checkId : checkId + ":" + Slug(subject);
    }

    /// <summary>Makes the slug of a subject.</summary>
    /// <param name="subject">The subject.</param>
    /// <returns>The slug, which may be empty.</returns>
    public static string Slug(string subject)
    {
        ArgumentNullException.ThrowIfNull(subject);
        var slug = new StringBuilder(subject.Length);
        var inRun = false;
        foreach (var c in subject)
        {
            if (IsKept(c))
            {
                slug.Append(c);
                inRun = false;
            }
            else if (!inRun)
            {
                slug.Append('-');
                inRun = true;
            }
        }

        var trimmed = slug.ToString().Trim('-');
        return trimmed.Length > MaxSlugLength ? trimmed[..MaxSlugLength] : trimmed;
    }

    private static bool IsKept(char c) => char.IsAsciiLetterOrDigit(c) || c is '\u0130' or '\u212A';
}
