using Engramic.Baseline.Model;

namespace Engramic.Baseline.Engine;

/// <summary>
/// What a check is: its identity and the requirement it maps to. Every finding of the check carries it.
/// </summary>
/// <param name="Id">The identifier, such as SU-01 (<see cref="CheckIds"/>), which never changes once the check ships.</param>
/// <param name="Title">The title, as reports show it.</param>
/// <param name="Category">The theme the check belongs to.</param>
/// <param name="Severity">How much a failure matters, unless a result sets its own.</param>
/// <param name="Frameworks">The frameworks the check evidences (<see cref="FrameworkTags"/>).</param>
/// <param name="Reference">Where the requirement comes from, in words.</param>
/// <param name="Scope">What the check assesses: the device, or the signed-in person's own set-up.</param>
/// <param name="AutoFail">Whether failing the check fails a Cyber Essentials assessment outright.</param>
/// <param name="RequiresAdmin">Whether the check needs elevation; without it the check is skipped.</param>
public sealed record CheckInfo(
    string Id,
    string Title,
    CheckCategory Category,
    Severity Severity,
    IReadOnlyList<string> Frameworks,
    string Reference,
    CheckScope Scope = CheckScope.Machine,
    bool AutoFail = false,
    bool RequiresAdmin = false);
