using System.Text.RegularExpressions;

namespace Engramic.Baseline.Platform;

/// <summary>
/// The layout of the machine data folder, as the PowerShell tool and its installer make it: the folders
/// kept in it, where an untrusted item is moved aside to, and what the tool says when it does that.
/// </summary>
/// <remarks>
/// <para>
/// An untrusted item is always moved out of the data folder, never to a name inside it: to a sibling of
/// the data folder named <c>EngramicBaseline.untrusted-&lt;id&gt;</c> for the data folder itself, and
/// <c>EngramicBaseline.untrusted-&lt;id&gt;-&lt;name&gt;</c> for an item in it, where the identifier is 32
/// random hexadecimal digits. These are the names the module's Get-CEDataAsidePath and the installer's
/// Get-CEAsidePath give, so an administrator finds both tools' quarantines the same way. Nothing ever
/// reads, lists or deletes a moved-aside item: it is for an administrator to check and delete.
/// </para>
/// <para>
/// Each item moved aside, and each link removed, is a notice, and an event in the Application log with
/// the identifier <see cref="NoticeEventId"/>, worded as the module words it.
/// </para>
/// </remarks>
public static partial class DataFolderLayout
{
    /// <summary>
    /// The identifier of the Application event for each untrusted item moved aside or link removed: 1003,
    /// as the PowerShell tool writes it.
    /// </summary>
    public const int NoticeEventId = 1003;

    /// <summary>The name of the folder, in the data folder, that holds a folder for each run's scratch files.</summary>
    public const string ScratchFolderName = "scratch";

    /// <summary>What follows the data folder's name in the name of a moved-aside item, before its identifier.</summary>
    public const string UntrustedMarker = ".untrusted-";

    /// <summary>
    /// Gets the names of the folders kept in the data folder, each made locked from birth: logs, reports,
    /// config, cache, undo and scratch. The PowerShell tool's packs folder is not among them: code packs are
    /// not part of this tool, and a packs folder an older install left is left alone.
    /// </summary>
    public static IReadOnlyList<string> KeptFolderNames { get; } = ["logs", "reports", "config", "cache", "undo", ScratchFolderName];

    /// <summary>Gets the name of a folder in the data folder.</summary>
    /// <param name="folder">The folder; not <see cref="DataFolder.Root"/>, which is the data folder itself.</param>
    /// <returns>Its name, such as reports.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="folder"/> is the data folder itself, or not a folder.</exception>
    public static string NameOf(DataFolder folder)
    {
        return folder switch
        {
            DataFolder.Logs => "logs",
            DataFolder.Reports => "reports",
            DataFolder.Config => "config",
            DataFolder.Cache => "cache",
            DataFolder.Undo => "undo",
            _ => throw new ArgumentOutOfRangeException(nameof(folder), folder, "Name a folder in the data folder, not the data folder itself."),
        };
    }

    /// <summary>
    /// Tells whether standard users may read a kept folder: only config, whose overrides the desktop app
    /// reads, as the installer grants.
    /// </summary>
    /// <param name="keptFolderName">The name of the kept folder.</param>
    /// <returns>True for config.</returns>
    public static bool UsersMayRead(string keptFolderName) => string.Equals(keptFolderName, "config", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Gets the name, in the folder that holds the data folder, that an untrusted item is moved aside to.
    /// </summary>
    /// <param name="dataFolderName">The data folder's name, such as EngramicBaseline.</param>
    /// <param name="id">32 lower-case hexadecimal digits, chosen at random.</param>
    /// <param name="relativePath">The item's path within the data folder, such as reports; null or empty for the data folder itself.</param>
    /// <returns>Such as EngramicBaseline.untrusted-0123456789abcdef0123456789abcdef-reports.</returns>
    /// <exception cref="ArgumentException">The name or the identifier is not what the tool makes.</exception>
    public static string AsideName(string dataFolderName, string id, string? relativePath = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(dataFolderName);
        ArgumentNullException.ThrowIfNull(id);
        if (!AsideId().IsMatch(id))
        {
            throw new ArgumentException($"'{id}' is not 32 lower-case hexadecimal digits.", nameof(id));
        }

        var name = dataFolderName + UntrustedMarker + id;
        return string.IsNullOrEmpty(relativePath) ? name : name + "-" + Separators().Replace(relativePath, "-");
    }

    /// <summary>
    /// Tells whether a name is one an item was moved aside to, by either tool: such a name is never listed,
    /// walked or deleted by the tool, only by an administrator.
    /// </summary>
    /// <param name="name">A file or folder name.</param>
    /// <returns>True when it holds <see cref="UntrustedMarker"/>, in any case.</returns>
    public static bool IsAsideName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return name.Contains(UntrustedMarker, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The notice for an untrusted item moved aside, as the module's Move-CEDataItemAsideWithNotice words it.</summary>
    /// <param name="path">Where the item was.</param>
    /// <param name="aside">Where it is now.</param>
    /// <param name="reason">Why it was not trusted: a sentence, whose full stop is dropped.</param>
    /// <returns>The notice.</returns>
    public static string MovedAsideNotice(string path, string aside, string reason)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(aside);
        ArgumentNullException.ThrowIfNull(reason);
        return $"Moved an untrusted {path} aside to {aside} ({reason.TrimEnd('.', ' ')}) and made a fresh, locked one in its place. Nothing in it is used again; check it, then delete it.";
    }

    /// <summary>The notice for a link removed from where the tool keeps a folder, as the installer's Remove-CELink words it.</summary>
    /// <param name="path">Where the link was.</param>
    /// <returns>The notice.</returns>
    public static string LinkRemovedNotice(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        return $"{path} was a link (a junction, symbolic link or other reparse point), not a folder. A standard user may have made it to redirect the tool's data, so the link was removed; what it leads to was left alone.";
    }

    /// <summary>The message of the Application event for a notice, as the module writes it.</summary>
    /// <param name="notice">The notice.</param>
    /// <returns>The message.</returns>
    public static string EventMessage(string notice)
    {
        ArgumentNullException.ThrowIfNull(notice);
        return "Engramic Baseline - data folder: " + notice;
    }

    [GeneratedRegex("^[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex AsideId();

    [GeneratedRegex(@"[\\/]+", RegexOptions.CultureInvariant)]
    private static partial Regex Separators();
}
