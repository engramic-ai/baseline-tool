namespace Engramic.Baseline.Platform;

/// <summary>
/// One entry of an access list, as stored.
/// </summary>
/// <param name="Type">Whether the entry grants rights, denies them, or is of another kind.</param>
/// <param name="Trustee">The account or group the entry names, or null when it names none the tool can read.</param>
/// <param name="Mask">The access mask as stored, generic rights included, not mapped to the rights of files.</param>
public sealed record AccessEntry(AccessEntryType Type, Sid? Trustee, uint Mask);
