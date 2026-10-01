namespace Engramic.Baseline.Platform;

/// <summary>
/// Lists the Store packages (MSIX and Appx) registered for each user of the device: main and framework packages,
/// as Get-AppxPackage lists them, not the resource packages and bundles that come with them.
/// </summary>
/// <remarks>
/// Engramic.Baseline.Windows implements it without WinRT, which is not AOT-ready. A user the source cannot read,
/// such as one whose registry is not loaded, is listed with the reason, never left out, so that a check can tell
/// "not installed" from "not known".
/// </remarks>
public interface IAppxPackageSource
{
    /// <summary>Lists the packages registered for each user the source knows of.</summary>
    /// <returns>One entry for each user, in the order of their security identifiers.</returns>
    /// <exception cref="UnauthorizedAccessException">The machine's list of packages cannot be read by this account.</exception>
    /// <exception cref="IOException">The machine's list of packages could not be read.</exception>
    IReadOnlyList<AppxUserPackages> ReadInstalled();
}
