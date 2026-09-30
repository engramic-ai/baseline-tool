using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Engramic.Baseline.Platform;

/// <summary>
/// Decides whether a process running as SYSTEM or elevated may trust the machine data folder, a file in
/// it, or the ProgramData folder it sits in, from what handles open on them tell: the rules of the
/// PowerShell tool's Get-CEDataPathProblem and of the Intune scripts that read status.json.
/// </summary>
/// <remarks>
/// <para>
/// Trust is judged, not an exact security descriptor. An item is trusted when it is not a reparse point
/// (a junction, a symbolic link or any other kind) and is not stored online only; is owned by a trusted
/// account, which a standard user cannot make themselves; has an access list; gives no other account a
/// right to write, add, delete, change its permissions or take ownership (<see cref="WriteRights"/>,
/// generic rights included); and denies a trusted account nothing, since a deny entry could stop the
/// tool replacing a forged file. Inherited and inherit-only entries count too, as new items take them.
/// </para>
/// <para>
/// Rights to read are fine for anyone, so a folder an administrator has shared read-only is kept, and so
/// is an entry for CREATOR OWNER, which reaches only new items and so only those who may create them. An
/// entry of a kind the tool does not recognise fails, as its effect cannot be judged.
/// </para>
/// <para>
/// Each method returns null when the item passes, or the first problem found as a sentence that names
/// the item. Nothing here changes an item: an untrusted one is refused, never repaired, because a handle
/// a user opened while they could change it keeps that access after any later lock.
/// </para>
/// </remarks>
public sealed class DataFolderTrust
{
    /// <summary>
    /// The rights that let an account change an item: FILE_WRITE_DATA (add a file to a folder),
    /// FILE_APPEND_DATA (add a folder), FILE_WRITE_EA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, DELETE,
    /// WRITE_DAC, WRITE_OWNER, GENERIC_WRITE and GENERIC_ALL; the PowerShell tool's $CEWriteRightsMask.
    /// </summary>
    public const uint WriteRights =
        0x0000_0002 | 0x0000_0004 | 0x0000_0010 | 0x0000_0040 | 0x0000_0100
        | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x4000_0000 | 0x1000_0000;

    private readonly HashSet<Sid> _trusted;

    /// <summary>Makes the rules for a set of trusted accounts.</summary>
    /// <param name="trusted">The accounts that may own an item and hold any right on it.</param>
    public DataFolderTrust(IEnumerable<Sid> trusted)
    {
        ArgumentNullException.ThrowIfNull(trusted);
        _trusted = [.. trusted];
        if (_trusted.Count == 0 || _trusted.Contains(null!))
        {
            throw new ArgumentException("Name at least one trusted account, and no null.", nameof(trusted));
        }
    }

    /// <summary>
    /// Gets the rules of the machine data folder: SYSTEM, Administrators and TrustedInstaller are trusted,
    /// none of which a standard user can make the owner of an item.
    /// </summary>
    public static DataFolderTrust Machine { get; } = new([Sid.LocalSystem, Sid.Administrators, Sid.TrustedInstaller]);

    /// <summary>Gets the trusted accounts.</summary>
    public IReadOnlyCollection<Sid> Trusted => _trusted;

    /// <summary>Tells whether an account is trusted.</summary>
    /// <param name="sid">The account, or null for one the tool could not read.</param>
    /// <returns>True when it is one of the trusted accounts.</returns>
    public bool IsTrusted([NotNullWhen(true)] Sid? sid) => sid is not null && _trusted.Contains(sid);

    /// <summary>
    /// Checks the ProgramData folder the data folder sits in. Only what makes it the real one: not a link,
    /// a folder, and a trusted owner. Its access list lets standard users create folders, by design.
    /// </summary>
    /// <param name="path">The path, for the message.</param>
    /// <param name="facts">What its handle tells.</param>
    /// <param name="owner">Its owner, or null when none could be read.</param>
    /// <returns>Null when it passes; otherwise the problem.</returns>
    public string? FindProgramDataProblem(string path, FileFacts facts, Sid? owner)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(facts);
        return FindLinkProblem(path, facts)
            ?? (facts.IsDirectory ? null : $"{path} is a file, not a folder.")
            ?? FindOwnerProblem(path, owner);
    }

    /// <summary>
    /// Checks an existing data folder: not a link, a folder, sealed by the install that made it locked,
    /// and trusted (<see cref="FindSecurityProblem"/>). An unsealed folder is refused even when it looks
    /// locked now: nothing about its current state shows that no standard user ever controlled it.
    /// </summary>
    /// <param name="path">The path, for the message.</param>
    /// <param name="facts">What its handle tells.</param>
    /// <param name="security">Its owner and access list.</param>
    /// <param name="isSealed">Whether the install recorded that it made the folder locked (the DataRootSealed marker).</param>
    /// <returns>Null when it passes; otherwise the problem.</returns>
    public string? FindDataFolderProblem(string path, FileFacts facts, ItemSecurity security, bool isSealed)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(security);
        return FindLinkProblem(path, facts)
            ?? (facts.IsDirectory ? null : $"{path} is a file, not a folder.")
            ?? (isSealed
                ? null
                : $"{path} was not created locked by an install of this tool (its DataRootSealed marker is missing), so a standard user may once have been able to change it, and a handle they opened then would keep that access.")
            ?? FindSecurityProblem(path, security);
    }

    /// <summary>
    /// Checks a file this tool has just created in the data folder before anything is written to it: an
    /// ordinary file with one name, owned by a trusted account and changeable by no one else.
    /// </summary>
    /// <param name="path">The path, for the message.</param>
    /// <param name="facts">What its handle tells.</param>
    /// <param name="security">Its owner and access list.</param>
    /// <returns>Null when it passes; otherwise the problem.</returns>
    public string? FindNewFileProblem(string path, FileFacts facts, ItemSecurity security)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(security);
        return FindFileProblem(path, facts) ?? FindSecurityProblem(path, security);
    }

    /// <summary>
    /// Checks a folder in the data folder that the tool keeps, makes or walks, such as reports, a scratch
    /// folder or a folder it is deleting: not a link, not stored online only, a folder, and trusted
    /// (<see cref="FindSecurityProblem"/>). The data folder itself also needs its seal
    /// (<see cref="FindDataFolderProblem"/>).
    /// </summary>
    /// <param name="path">The path, for the message.</param>
    /// <param name="facts">What its handle tells.</param>
    /// <param name="security">Its owner and access list.</param>
    /// <returns>Null when it passes; otherwise the problem.</returns>
    public string? FindFolderProblem(string path, FileFacts facts, ItemSecurity security)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(security);
        return FindLinkProblem(path, facts)
            ?? (facts.IsDirectory ? null : $"{path} is a file, not a folder.")
            ?? FindSecurityProblem(path, security);
    }

    /// <summary>
    /// Checks a file in the data folder before the tool reads it, such as an administrator's config
    /// override or a cached answer: an ordinary file with one name, not a link and not stored online only,
    /// owned by a trusted account and changeable by no one else, and no longer than the tool reads.
    /// </summary>
    /// <param name="path">The path, for the message.</param>
    /// <param name="facts">What a handle open on the file itself tells.</param>
    /// <param name="security">Its owner and access list.</param>
    /// <param name="maxLength">The most bytes the tool reads from it.</param>
    /// <returns>Null when it may be read; otherwise the problem.</returns>
    public string? FindReadProblem(string path, FileFacts facts, ItemSecurity security, long maxLength)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(security);
        return FindFileProblem(path, facts)
            ?? FindSecurityProblem(path, security)
            ?? (facts.Length <= maxLength
                ? null
                : string.Create(CultureInfo.InvariantCulture, $"{path} is {facts.Length} bytes long, more than the {maxLength} bytes the tool reads from it."));
    }

    /// <summary>
    /// Checks a file that a new one is about to replace: an ordinary file with one name that can be
    /// replaced. A link, a folder, a file with other names (hard links) or a read-only file is left alone.
    /// </summary>
    /// <param name="path">The path, for the message.</param>
    /// <param name="facts">What a handle open on the file, not on what it may lead to, tells.</param>
    /// <returns>Null when it may be replaced; otherwise the problem.</returns>
    public static string? FindReplaceProblem(string path, FileFacts facts)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(facts);
        return FindFileProblem(path, facts)
            ?? (facts.IsReadOnly ? $"{path} is read-only, so it cannot be replaced." : null);
    }

    /// <summary>
    /// Checks the owner and the access list: a trusted owner, an access list, no right to change the item
    /// for anyone but the trusted accounts and CREATOR OWNER, no deny entry against a trusted account, and
    /// no entry of a kind the tool does not recognise.
    /// </summary>
    /// <param name="path">The path, for the message.</param>
    /// <param name="security">The owner and access list.</param>
    /// <returns>Null when they pass; otherwise the problem.</returns>
    public string? FindSecurityProblem(string path, ItemSecurity security)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(security);
        if (FindOwnerProblem(path, security.Owner) is { } ownerProblem)
        {
            return ownerProblem;
        }

        if (security.Dacl is null)
        {
            return $"{path} has no access list, so anyone may change it.";
        }

        foreach (var entry in security.Dacl)
        {
            switch (entry.Type)
            {
                case AccessEntryType.Deny when IsTrusted(entry.Trustee):
                    return $"{path} denies {entry.Trustee} some rights, so the tool may be unable to replace it.";
                case AccessEntryType.Deny:
                    continue;
                case AccessEntryType.Allow when IsTrusted(entry.Trustee) || entry.Trustee == Sid.CreatorOwner:
                    continue;
                case AccessEntryType.Allow when (entry.Mask & WriteRights) != 0:
                    return entry.Trustee is null
                        ? $"{path} can be changed by an account the tool cannot read, not only administrators."
                        : $"{path} can be changed by {entry.Trustee}, not only administrators.";
                case AccessEntryType.Allow:
                    continue;
                default:
                    return $"{path} has an access entry of a kind the tool does not recognise, so who may change it cannot be judged.";
            }
        }

        return null;
    }

    private static string? FindLinkProblem(string path, FileFacts facts)
    {
        if (facts.IsReparsePoint)
        {
            return $"{path} is a junction, symbolic link or other reparse point, so where it leads cannot be trusted.";
        }

        return facts.IsOnlineOnly ? $"{path} is stored online only, so opening it would fetch it from elsewhere." : null;
    }

    private static string? FindFileProblem(string path, FileFacts facts)
    {
        return FindLinkProblem(path, facts)
            ?? (facts.IsDirectory ? $"{path} is a folder, not a file." : null)
            ?? (facts.LinkCount == 1
                ? null
                : string.Create(CultureInfo.InvariantCulture, $"{path} has {facts.LinkCount} names (hard links), not one, so it may also be a file somewhere else."));
    }

    private string? FindOwnerProblem(string path, Sid? owner)
    {
        if (IsTrusted(owner))
        {
            return null;
        }

        return owner is null
            ? $"{path} has no owner the tool can read."
            : $"{path} is owned by {owner}, not SYSTEM, Administrators or TrustedInstaller.";
    }
}
