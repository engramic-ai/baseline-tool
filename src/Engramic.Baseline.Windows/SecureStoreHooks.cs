namespace Engramic.Baseline.Windows;

/// <summary>
/// Points where a test can step into SecureStore, to stage what an attacker could do between two of its
/// steps. Product code never sets them.
/// </summary>
internal sealed class SecureStoreHooks
{
    /// <summary>
    /// Gets the name to give the new file instead of a random one, from the target's name, so that a test
    /// can plant something at that name first.
    /// </summary>
    public Func<string, string>? TemporaryName { get; init; }

    /// <summary>
    /// Gets what to do just before each attempt to rename the new file over the target, given the target's
    /// path and the attempt's number from 1: after the target was checked, so a test can swap it.
    /// </summary>
    public Action<string, int>? BeforeRename { get; init; }

    /// <summary>
    /// Gets the random identifiers to use instead of new ones, one per call: for the names of scratch folders
    /// and of items moved aside, so that a test can plant something at a name first, or know the name.
    /// </summary>
    public Func<string>? NewId { get; init; }

    /// <summary>
    /// Gets what to do just before the store creates a folder, given its path: after the store found nothing
    /// at the name, so a test can put something there first.
    /// </summary>
    public Action<string>? BeforeCreate { get; init; }

    /// <summary>
    /// Gets what to do just before each attempt to move an untrusted item aside, given its path and the
    /// attempt's number from 1, so a test can hold something in it open, or let it go.
    /// </summary>
    public Action<string, int>? BeforeMoveAside { get; init; }

    /// <summary>
    /// Gets what to do just before a tree delete opens each item, given its path: after its folder was listed,
    /// so a test can swap the item for a link.
    /// </summary>
    public Action<string>? BeforeOpenInTree { get; init; }

    /// <summary>
    /// Gets whether to delete as Windows 10 before version 1709 must: without the POSIX semantics and the
    /// read-only override that newer builds offer, so that the older way is tested on any build.
    /// </summary>
    public bool ClassicDelete { get; init; }
}
