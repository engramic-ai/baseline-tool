using System.Text;
using Engramic.Baseline.Model;

namespace Engramic.Baseline.Contracts.Tests;

/// <summary>
/// A deliberate change to a copy of the reader probe's status.json, never to the product: what it changes, what
/// the golden test must then say, and whether the Intune scripts can see it.
/// </summary>
/// <param name="Name">A short name, for the test's data.</param>
/// <param name="Change">What changes, in words.</param>
/// <param name="Apply">Makes the changed copy.</param>
/// <param name="GoldenSays">Part of the difference the golden comparison must report.</param>
/// <param name="ReadersSee">Whether what the Intune scripts print changes.</param>
/// <param name="Why">Why they do, or do not, see it.</param>
internal sealed record StatusMutation(string Name, string Change, Func<byte[], byte[]> Apply, string GoldenSays, bool ReadersSee, string Why);

/// <summary>The changes to a key, its casing and the byte order mark that the contract tests make.</summary>
internal static class StatusMutations
{
    /// <summary>Gets every change.</summary>
    public static IReadOnlyList<StatusMutation> All { get; } =
    [
        new(
            "key-renamed",
            "autoFailCount becomes autoFailTotal",
            file => Replace(file, "\"autoFailCount\":", "\"autoFailTotal\":"),
            "autoFailCount is missing.",
            ReadersSee: true,
            "Both scripts read autoFailCount, which is 2 in the probe: the discovery script reports 0, and the detection script's state is no longer AUTO-FAIL."),
        new(
            "nested-key-renamed",
            "the status of SU-03 becomes its state",
            file => ReplaceAfter(file, "\"SU-03\": {", "\"status\":", "\"state\":"),
            "checks.SU-03.status is missing.",
            ReadersSee: true,
            "Both scripts count the checks that fail by their status, and SU-03 fails in the probe."),
        new(
            "framework-key-renamed",
            "ce-v3.3 becomes ce-v3.4",
            file => Replace(file, "\"ce-v3.3\":", "\"ce-v3.4\":"),
            "frameworks.ce-v3.3 is missing.",
            ReadersSee: true,
            "The discovery script reports the Cyber Essentials score from ce-v3.3, which is 33 in the probe, and -1 without it."),
        new(
            "check-id-recased",
            "the key SU-03 becomes su-03",
            file => Replace(file, "\"SU-03\": {", "\"su-03\": {"),
            "checks.SU-03 is written 'su-03': the contract spells the key 'SU-03'.",
            ReadersSee: true,
            "The discovery script lists the failing checks by their keys, as written, so CEFailing names su-03."),
        new(
            "key-recased",
            "autoFailCount becomes AutoFailCount",
            file => Replace(file, "\"autoFailCount\":", "\"AutoFailCount\":"),
            "autoFailCount is written 'AutoFailCount': the contract spells the key 'autoFailCount'.",
            ReadersSee: false,
            "PowerShell finds a property whatever its case (the discovery script itself asks for SchemaVersion and AuditTime), so only the golden test guards the casing of a fixed key."),
        new(
            "framework-key-recased",
            "ce-v3.3 becomes CE-v3.3",
            file => Replace(file, "\"ce-v3.3\":", "\"CE-v3.3\":"),
            "frameworks.ce-v3.3 is written 'CE-v3.3': the contract spells the key 'ce-v3.3'.",
            ReadersSee: false,
            "PowerShell finds a property whatever its case, so only the golden test guards the casing of a fixed key."),
        new(
            "bom-removed",
            "the byte order mark is removed",
            RemoveByteOrderMark,
            "The file does not start with the UTF-8 byte order mark",
            ReadersSee: true,
            "The scripts read status.json without naming an encoding, so Windows PowerShell 5.1 reads a file without the mark in the ANSI code page, and the probe's toolVersion, 1.0.0-caf\u00e9, reaches both of them garbled."),
    ];

    /// <summary>Gets a change by its name.</summary>
    public static StatusMutation Named(string name) => All.Single(m => m.Name == name);

    private static byte[] Replace(byte[] file, string find, string replacement) => EditText(file, text =>
    {
        var at = IndexOfOnly(text, find, 0);
        return string.Concat(text.AsSpan(0, at), replacement, text.AsSpan(at + find.Length));
    });

    private static byte[] ReplaceAfter(byte[] file, string anchor, string find, string replacement) => EditText(file, text =>
    {
        var start = IndexOfOnly(text, anchor, 0);
        var at = text.IndexOf(find, start, StringComparison.Ordinal);
        if (at < 0)
        {
            throw new InvalidOperationException($"{find} is not after {anchor} in the file, so the change would change nothing.");
        }

        return string.Concat(text.AsSpan(0, at), replacement, text.AsSpan(at + find.Length));
    });

    private static byte[] RemoveByteOrderMark(byte[] file)
    {
        if (!file.AsSpan().StartsWith(Utf8Bom.Preamble))
        {
            throw new InvalidOperationException("The file has no byte order mark to remove.");
        }

        return file[Utf8Bom.Preamble.Length..];
    }

    /// <summary>Changes the text after the byte order mark, keeping the mark if there is one.</summary>
    private static byte[] EditText(byte[] file, Func<string, string> edit)
    {
        var marked = file.AsSpan().StartsWith(Utf8Bom.Preamble);
        var text = Encoding.UTF8.GetString(marked ? file[Utf8Bom.Preamble.Length..] : file);
        var edited = Encoding.UTF8.GetBytes(edit(text));
        return marked ? [.. Utf8Bom.Preamble, .. edited] : edited;
    }

    /// <summary>Where the text is, which must be once only, so each change is exactly the one it names.</summary>
    private static int IndexOfOnly(string text, string find, int start)
    {
        var at = text.IndexOf(find, start, StringComparison.Ordinal);
        if (at < 0 || text.IndexOf(find, at + 1, StringComparison.Ordinal) >= 0)
        {
            throw new InvalidOperationException($"{find} is not in the file exactly once, so the change would not be the one it names.");
        }

        return at;
    }
}
