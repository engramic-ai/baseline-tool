namespace Engramic.Baseline.Platform;

/// <summary>
/// The owner and the access list (DACL) of a file or folder, read through a handle open on it.
/// </summary>
/// <param name="Owner">The owner, or null when it has none the tool can read.</param>
/// <param name="Dacl">
/// The entries of the access list in their order, inherited and inherit-only entries included; null when
/// the item has no access list, which lets everyone do anything to it.
/// </param>
public sealed record ItemSecurity(Sid? Owner, IReadOnlyList<AccessEntry>? Dacl);
