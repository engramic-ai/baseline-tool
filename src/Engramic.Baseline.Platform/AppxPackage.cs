using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Engramic.Baseline.Platform;

/// <summary>
/// A Store package (MSIX or Appx) registered for a user: its identity, read from its full name, and the folder it
/// is installed in.
/// </summary>
/// <remarks>
/// A full name is <c>Name_Version_Architecture_ResourceId_PublisherId</c>, such as
/// <c>Claude_2.16120.0.0_x64__pzs8sxrjxfjjc</c>, and identifies one package exactly. Windows compares full names,
/// and each of their parts, without regard to case; so do <see cref="FullNameComparer"/> and the readers. The
/// publisher itself (its certificate's subject) is not in the full name: the publisher identifier is a hash of it.
/// </remarks>
public sealed record AppxPackage
{
    private const int MinNameLength = 3;
    private const int MaxNameLength = 50;
    private const int MaxResourceIdLength = 30;
    private const int PublisherIdLength = 13;

    private static readonly string[] Architectures = ["x86", "x64", "arm", "arm64", "neutral", "x86a64"];

    private AppxPackage(string fullName, string name, Version version, string architecture, string resourceId, string publisherId)
    {
        FullName = fullName;
        Name = name;
        Version = version;
        Architecture = architecture;
        ResourceId = resourceId;
        PublisherId = publisherId;
    }

    /// <summary>Gets a comparer of full names, and of the other parts of an identity, that ignores case, as Windows does.</summary>
    public static StringComparer FullNameComparer => StringComparer.OrdinalIgnoreCase;

    /// <summary>Gets the full name, as the source wrote it.</summary>
    public string FullName { get; }

    /// <summary>Gets the package name, such as <c>Claude</c> or <c>OpenAI.ChatGPT-Desktop</c>: what ai-tools.json's <c>appx</c> entries name.</summary>
    public string Name { get; }

    /// <summary>Gets the version, four numbers.</summary>
    public Version Version { get; }

    /// <summary>Gets the processor architecture as the full name writes it: x86, x64, arm, arm64, neutral or x86a64.</summary>
    public string Architecture { get; }

    /// <summary>Gets the resource identifier, empty for most packages.</summary>
    public string ResourceId { get; }

    /// <summary>Gets the publisher identifier, 13 characters derived from the publisher's name.</summary>
    public string PublisherId { get; }

    /// <summary>Gets the family name, <c>Name_PublisherId</c>, which every version of the package shares.</summary>
    public string FamilyName => Name + "_" + PublisherId;

    /// <summary>Gets the folder the package is installed in, as the source gives it; empty when it gives none.</summary>
    public string InstallLocation { get; init; } = string.Empty;

    /// <summary>Reads a package's identity from its full name.</summary>
    /// <param name="fullName">The full name, such as <c>Claude_2.16120.0.0_x64__pzs8sxrjxfjjc</c>.</param>
    /// <returns>The package, with no install location.</returns>
    /// <exception cref="FormatException"><paramref name="fullName"/> is not a package full name.</exception>
    public static AppxPackage Parse(string fullName)
    {
        return TryParse(fullName, out var package)
            ? package
            : throw new FormatException("The text is not a package full name, such as Claude_2.16120.0.0_x64__pzs8sxrjxfjjc.");
    }

    /// <summary>Tries to read a package's identity from its full name.</summary>
    /// <param name="fullName">The full name, such as <c>Claude_2.16120.0.0_x64__pzs8sxrjxfjjc</c>.</param>
    /// <param name="package">The package, with no install location, when the text is a full name.</param>
    /// <returns>
    /// True when the text has the five parts of a full name and each is well formed: a name of 3 to 50 letters,
    /// digits, dots and dashes; a version of four numbers from 0 to 65535; a known architecture; a resource
    /// identifier of up to 30 such characters, or <c>~</c> for a bundle; and a 13-character publisher identifier.
    /// </returns>
    public static bool TryParse([NotNullWhen(true)] string? fullName, [NotNullWhen(true)] out AppxPackage? package)
    {
        package = null;
        if (fullName is null)
        {
            return false;
        }

        var parts = fullName.Split('_');
        if (parts.Length != 5)
        {
            return false;
        }

        var (name, versionText, architecture, resourceId, publisherId) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
        if (name.Length is < MinNameLength or > MaxNameLength || !IsIdentityText(name)
            || !TryReadVersion(versionText, out var version)
            || !Architectures.Contains(architecture, StringComparer.OrdinalIgnoreCase)
            || !(resourceId == "~" || (resourceId.Length <= MaxResourceIdLength && IsIdentityText(resourceId)))
            || publisherId.Length != PublisherIdLength || !publisherId.All(IsPublisherIdCharacter))
        {
            return false;
        }

        package = new AppxPackage(fullName, name, version, architecture, resourceId, publisherId);
        return true;
    }

    /// <summary>Returns the full name.</summary>
    /// <returns>The full name.</returns>
    public override string ToString() => FullName;

    private static bool IsIdentityText(string text) => text.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-');

    // Crockford's base 32, which the publisher identifier is written in: digits and letters without i, l, o and u.
    private static bool IsPublisherIdCharacter(char c) => char.IsAsciiDigit(c) || (char.IsAsciiLetter(c) && char.ToLowerInvariant(c) is not ('i' or 'l' or 'o' or 'u'));

    private static bool TryReadVersion(string text, [NotNullWhen(true)] out Version? version)
    {
        version = null;
        var numbers = text.Split('.');
        if (numbers.Length != 4)
        {
            return false;
        }

        var values = new int[4];
        for (var i = 0; i < 4; i++)
        {
            if (numbers[i].Length is 0 or > 5 || !numbers[i].All(char.IsAsciiDigit)
                || !ushort.TryParse(numbers[i], NumberStyles.None, CultureInfo.InvariantCulture, out var value))
            {
                return false;
            }

            values[i] = value;
        }

        version = new Version(values[0], values[1], values[2], values[3]);
        return true;
    }
}
