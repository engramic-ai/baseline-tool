using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// The only packages the Appx comparisons let a source miss, each seen on CI's runner and reviewed: packages
/// Get-AppxPackage lists as installed for runneradmin that runneradmin's package repository in the registry does not
/// list. Which of Windows' views is right about them is not known (docs/DOTNET.md, spike 8).
/// </summary>
/// <remarks>
/// A miss is let off only when the package is named here and the user's own repository does not list it either, so
/// that the source read what the registry holds and the difference is between Windows' views, not a fault of the
/// source. The list is by package name, since the runner's image brings new versions of these. None may be a package
/// <c>ai-tools.json</c> names, which a test holds. A new difference fails the comparison until someone looks at it.
/// </remarks>
internal static class AppxKnownDifferences
{
    /// <summary>Gets the names of the packages seen missing from runneradmin's repository on CI's runner.</summary>
    public static IReadOnlySet<string> RunnerMisses { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft.SecHealthUI",
        "Microsoft.Windows.NarratorQuickStart",
        "Microsoft.WindowsFeedbackHub",
        "MicrosoftCorporationII.WindowsSubsystemForLinux",
    };

    /// <summary>Says why a package a source missed for a user is not counted against it, or null when it is.</summary>
    /// <param name="fullName">The package's full name, as Get-AppxPackage gave it.</param>
    /// <param name="userRepositoryLacksIt">Whether the user's package repository was read and does not list the package.</param>
    /// <returns>The reason, or null.</returns>
    public static string? Excuse(string fullName, bool userRepositoryLacksIt)
    {
        return userRepositoryLacksIt && AppxPackage.TryParse(fullName, out var package) && RunnerMisses.Contains(package.Name)
            ? "a known difference on CI's runner: the user's package repository does not list it either, and why Get-AppxPackage does is not known"
            : null;
    }
}
