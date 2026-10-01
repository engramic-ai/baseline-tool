namespace Engramic.Baseline.Platform;

/// <summary>
/// Whether a user's Store packages could be read, and if not, why.
/// </summary>
public enum AppxReadOutcome
{
    /// <summary>The user's packages were read: the list is all of them, and may be empty.</summary>
    Read,

    /// <summary>
    /// The registry the source reads for the user is not loaded, as for a user who is not signed in: their packages
    /// are not known, which is not the same as having none.
    /// </summary>
    NotLoaded,

    /// <summary>This account may not read the user's packages.</summary>
    Denied,

    /// <summary>The user's packages could not be read for another reason, which the detail gives.</summary>
    Failed,
}
