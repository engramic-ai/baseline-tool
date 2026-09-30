using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Engramic.Baseline.Platform;

/// <summary>
/// A security identifier in its string form, such as S-1-5-18.
/// </summary>
/// <remarks>
/// Owners and access entries are kept as text, so portable code can decide who is trusted without the
/// Windows-only <c>SecurityIdentifier</c> type. Parsing is strict: revision 1, a decimal identifier
/// authority below 2^48, and one to fifteen decimal sub-authorities below 2^32, with no leading zeros,
/// signs or spaces. The only change made to the text is an upper-case S.
/// </remarks>
public sealed record Sid
{
    private const int MaxSubAuthorities = 15;
    private const ulong MaxAuthority = (1UL << 48) - 1;

    private Sid(string value) => Value = value;

    /// <summary>Gets the local system account, S-1-5-18.</summary>
    public static Sid LocalSystem { get; } = new("S-1-5-18");

    /// <summary>Gets the built-in Administrators group, S-1-5-32-544.</summary>
    public static Sid Administrators { get; } = new("S-1-5-32-544");

    /// <summary>Gets the built-in Users group, S-1-5-32-545.</summary>
    public static Sid Users { get; } = new("S-1-5-32-545");

    /// <summary>Gets the TrustedInstaller service, which owns most of the Windows folder.</summary>
    public static Sid TrustedInstaller { get; } = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    /// <summary>Gets the identifier in its string form, starting with an upper-case S.</summary>
    public string Value { get; }

    /// <summary>Reads a security identifier from its string form.</summary>
    /// <param name="text">The text to read, such as S-1-5-32-544.</param>
    /// <returns>The identifier.</returns>
    /// <exception cref="FormatException"><paramref name="text"/> is not a security identifier.</exception>
    public static Sid Parse(string text)
    {
        return TryParse(text, out var sid)
            ? sid
            : throw new FormatException("The text is not a security identifier in its string form, such as S-1-5-18.");
    }

    /// <summary>Tries to read a security identifier from its string form.</summary>
    /// <param name="text">The text to read, such as S-1-5-32-544.</param>
    /// <param name="sid">The identifier, when the text is one.</param>
    /// <returns>True when the text is a security identifier.</returns>
    public static bool TryParse([NotNullWhen(true)] string? text, [NotNullWhen(true)] out Sid? sid)
    {
        sid = null;
        if (text is null || text.Length < 2 || (text[0] != 'S' && text[0] != 's') || text[1] != '-')
        {
            return false;
        }

        var parts = text[2..].Split('-');
        if (parts.Length < 3 || parts.Length > MaxSubAuthorities + 2 || parts[0] != "1")
        {
            return false;
        }

        if (!TryReadNumber(parts[1], MaxAuthority))
        {
            return false;
        }

        for (var i = 2; i < parts.Length; i++)
        {
            if (!TryReadNumber(parts[i], uint.MaxValue))
            {
                return false;
            }
        }

        sid = new Sid(string.Concat("S", text.AsSpan(1)));
        return true;
    }

    /// <summary>Returns the identifier in its string form.</summary>
    /// <returns>The identifier, such as S-1-5-18.</returns>
    public override string ToString() => Value;

    private static bool TryReadNumber(string part, ulong max)
    {
        if (part.Length == 0 || (part.Length > 1 && part[0] == '0'))
        {
            return false;
        }

        foreach (var c in part)
        {
            if (!char.IsAsciiDigit(c))
            {
                return false;
            }
        }

        return ulong.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out var value) && value <= max;
    }
}
