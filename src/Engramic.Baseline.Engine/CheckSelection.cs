using Engramic.Baseline.Model;

namespace Engramic.Baseline.Engine;

/// <summary>
/// Which checks an audit runs. An empty list does not filter; every list that is not empty must match.
/// </summary>
/// <remarks>
/// The same filters as the PowerShell tool's Invoke-CEAuditCore. Identifiers match without regard to
/// case; a framework matches a check that has a tag starting with it, so CE matches CE v3.3 and CE+ TC2.
/// </remarks>
public sealed record CheckSelection
{
    /// <summary>Gets a selection of every check.</summary>
    public static CheckSelection All { get; } = new();

    /// <summary>Gets the identifiers of the checks to run.</summary>
    public IReadOnlyList<string> Ids { get; init; } = [];

    /// <summary>Gets the themes whose checks to run.</summary>
    public IReadOnlyList<CheckCategory> Categories { get; init; } = [];

    /// <summary>Gets the starts of the framework tags whose checks to run, such as CE or NCSC.</summary>
    public IReadOnlyList<string> Frameworks { get; init; } = [];

    /// <summary>Gets the scopes whose checks to run.</summary>
    public IReadOnlyList<CheckScope> Scopes { get; init; } = [];

    /// <summary>Gets the identifiers of checks not to run, whatever else matches.</summary>
    public IReadOnlyList<string> ExcludeIds { get; init; } = [];

    /// <summary>Tells whether a check is selected.</summary>
    /// <param name="check">What the check is.</param>
    /// <returns>True when every filter that is set matches and the check is not excluded.</returns>
    public bool Matches(CheckInfo check)
    {
        ArgumentNullException.ThrowIfNull(check);
        return (Ids.Count == 0 || Ids.Contains(check.Id, StringComparer.OrdinalIgnoreCase))
            && (Categories.Count == 0 || Categories.Contains(check.Category))
            && (Scopes.Count == 0 || Scopes.Contains(check.Scope))
            && (Frameworks.Count == 0 || Frameworks.Any(f => check.Frameworks.Any(tag => tag.StartsWith(f, StringComparison.OrdinalIgnoreCase))))
            && !ExcludeIds.Contains(check.Id, StringComparer.OrdinalIgnoreCase);
    }
}
