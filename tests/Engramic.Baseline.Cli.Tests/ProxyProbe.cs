using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Cli.Tests;

/// <summary>
/// A machine check that reads the proxy settings, as the first check to send a request will, and keeps what it was
/// given: to show where an audit's checks get them from.
/// </summary>
internal sealed class ProxyProbe : Check
{
    public override CheckInfo Info { get; } = new("SU-08", "Proxy probe", CheckCategory.SecurityUpdateManagement, Severity.High, [FrameworkTags.CeV33], "Proxy probe");

    /// <summary>Gets the proxy settings the check was given, or null before it ran.</summary>
    public ProxySettings? Seen { get; private set; }

    /// <summary>Gets a catalog of this check alone.</summary>
    /// <returns>The catalog.</returns>
    public CheckCatalog Catalog() => new CheckCatalog.Builder().Add(this).Build();

    public override ValueTask<IReadOnlyList<CheckResult>> RunAsync(CheckContext context, CancellationToken cancel)
    {
        Seen = context.Config.Network;
        return ValueTask.FromResult<IReadOnlyList<CheckResult>>([new CheckResult(FindingStatus.Pass)]);
    }
}
