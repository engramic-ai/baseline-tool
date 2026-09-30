using Engramic.Baseline.Controls.Checks;
using Engramic.Baseline.Engine;

namespace Engramic.Baseline.Controls;

/// <summary>
/// The checks that ship with the tool, listed by hand: one list per theme, the themes in report order and
/// each theme's checks by identifier, as the PowerShell tool registers them. A test proves every check in
/// this library is listed once.
/// </summary>
/// <remarks>
/// Only ported checks are listed. The rest join their theme's list as they are ported.
/// </remarks>
public static class BuiltInChecks
{
    /// <summary>Makes the catalog of every shipped check.</summary>
    /// <returns>The catalog.</returns>
    public static CheckCatalog CreateCatalog()
    {
        return new CheckCatalog.Builder()
            .AddRange(SecurityUpdateManagement())
            .Build();
    }

    private static Check[] SecurityUpdateManagement() => [new OperatingSystemSupported()];
}
