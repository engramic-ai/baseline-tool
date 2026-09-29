namespace Engramic.Baseline.Platform;

/// <summary>
/// What an entry of an access list does.
/// </summary>
public enum AccessEntryType
{
    /// <summary>Grants rights: an allowed entry, including an object or conditional entry that allows.</summary>
    Allow,

    /// <summary>Denies rights: a denied entry, including an object or conditional entry that denies.</summary>
    Deny,

    /// <summary>
    /// Any other kind, such as an audit entry or one the tool does not recognise, so what it does to access
    /// cannot be judged.
    /// </summary>
    Other,
}
