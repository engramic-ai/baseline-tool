using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Unicode;

namespace Engramic.Baseline.Model;

/// <summary>
/// Reads the config files, by the names they have in the config folder, and holds the schema of each: what
/// an administrator's copy of a file must be before it may replace the one the tool ships.
/// </summary>
/// <remarks>
/// <para>
/// A file's schema is its model, read by the reader generated for it at build time: the same reader the
/// checks use, so a copy that meets the schema is one they can read. Around that, a copy must be one plain
/// JSON document (<see cref="FindProblem"/>): UTF-8, one object and nothing after it, no member named twice
/// in one object, whatever the case of its letters, since the reader matches names without regard to case,
/// no comments or trailing commas, and no more than <see cref="MaxDepth"/> objects and arrays deep. Members
/// a model does not have are allowed and not read, as the shipped files carry notes the tool never reads.
/// </para>
/// <para>
/// UTF-8 is the one encoding taken, one strict format for a file SYSTEM trusts: not the UTF-16 that Windows
/// PowerShell 5.1's &gt; and Out-File write, nor the ANSI its Set-Content writes, both of which the module
/// read. The problem says which a refused copy seems to be, and how to save it as UTF-8.
/// </para>
/// <para>
/// A file joins <see cref="Names"/>, with its reader, in the change that first reads it: every file the tool
/// ships needs a schema, or no administrator's copy of it is used.
/// </para>
/// </remarks>
public static class ConfigFile
{
    /// <summary>The name of the Windows lifecycle data that SU-01 judges against.</summary>
    public const string OsLifecycleName = "os-lifecycle.json";

    /// <summary>The name of the proxy settings for the tool's own requests.</summary>
    public const string NetworkName = "network.json";

    /// <summary>The deepest a config file's objects and arrays may nest: 64, as the JSON reader allows.</summary>
    public const int MaxDepth = 64;

    /// <summary>The reader of each file, by name, which throws <see cref="JsonException"/> for a copy that is not valid.</summary>
    private static readonly Dictionary<string, Reader> Schemas = new(StringComparer.OrdinalIgnoreCase)
    {
        [OsLifecycleName] = utf8 => _ = ReadOsLifecycle(utf8),
    };

    private delegate void Reader(ReadOnlySpan<byte> utf8);

    /// <summary>Gets the names of the config files the tool reads, each of which has a schema, in order.</summary>
    public static IReadOnlyList<string> Names { get; } = [.. Schemas.Keys.Order(StringComparer.Ordinal)];

    /// <summary>Gets the byte order mark of UTF-16 little-endian, FF FE, which Windows PowerShell 5.1's Out-File writes.</summary>
    private static ReadOnlySpan<byte> Utf16LittleEndianBom => [0xFF, 0xFE];

    /// <summary>Gets the byte order mark of UTF-16 big-endian: FE FF.</summary>
    private static ReadOnlySpan<byte> Utf16BigEndianBom => [0xFE, 0xFF];

    /// <summary>Reads config/os-lifecycle.json, with or without a byte order mark.</summary>
    /// <param name="utf8">The bytes of the file.</param>
    /// <returns>The lifecycle data.</returns>
    /// <exception cref="JsonException">
    /// The bytes are not JSON of that shape, or lack lastReviewed, reviewWarningDays or upcomingEndWarningDays.
    /// </exception>
    public static OsLifecycle ReadOsLifecycle(ReadOnlySpan<byte> utf8)
    {
        return ModelJson.Read(utf8, ModelJson.OsLifecycleReader);
    }

    /// <summary>Reads config/network.json, with or without a byte order mark.</summary>
    /// <param name="utf8">The bytes of the file.</param>
    /// <returns>The settings, with the default of each member the file does not give as a value of its type.</returns>
    /// <exception cref="JsonException">The bytes are not a JSON object.</exception>
    public static NetworkConfig ReadNetwork(ReadOnlySpan<byte> utf8)
    {
        return ModelJson.Read(utf8, ModelJson.NetworkReader);
    }

    /// <summary>
    /// Checks a copy of a config file against the file's schema, as an administrator's copy must pass before it
    /// replaces the shipped one: one plain JSON document in UTF-8, with or without a byte order mark, that the
    /// file's reader accepts. A copy saved as UTF-16 or ANSI is refused, and the problem says which it seems to
    /// be and how to save it again.
    /// </summary>
    /// <param name="name">The name of the file, such as os-lifecycle.json: one of <see cref="Names"/>.</param>
    /// <param name="path">Where the copy is, for the message.</param>
    /// <param name="utf8">The bytes of the copy.</param>
    /// <returns>Null when it passes; otherwise the problem, as a sentence that names the copy.</returns>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not a config file the tool reads.</exception>
    public static string? FindProblem(string name, string path, ReadOnlySpan<byte> utf8)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(path);
        if (!Schemas.TryGetValue(name, out var read))
        {
            throw new ArgumentException($"{name} is not a config file the tool reads, so it has no schema.", nameof(name));
        }

        var json = utf8.StartsWith(Utf8Bom.Preamble) ? utf8[Utf8Bom.Preamble.Length..] : utf8;
        if (FindEncodingProblem(path, utf8, json) is { } encoding)
        {
            return encoding;
        }

        if (FindStructureProblem(path, json) is { } problem)
        {
            return problem;
        }

        try
        {
            read(json);
            return null;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException)
        {
            return $"{path} is not a valid {name}: {e.Message}";
        }
    }

    /// <summary>
    /// Checks that a copy is UTF-8, and when it is not, says what it seems to be instead, since an administrator
    /// who wrote it with Windows PowerShell 5.1 may not know: UTF-16, which its &gt; and Out-File write, or ANSI,
    /// which its Set-Content writes.
    /// </summary>
    /// <param name="path">Where the copy is, for the message.</param>
    /// <param name="copy">The bytes of the copy.</param>
    /// <param name="json">The bytes after a UTF-8 byte order mark, if there is one.</param>
    private static string? FindEncodingProblem(string path, ReadOnlySpan<byte> copy, ReadOnlySpan<byte> json)
    {
        const string SaveAsUtf8 = "save it as UTF-8, for example with Set-Content -Encoding utf8.";
        if (copy.StartsWith(Utf16LittleEndianBom))
        {
            return $"{path} is saved as UTF-16, as Windows PowerShell 5.1's > and Out-File save text, not as UTF-8; {SaveAsUtf8}";
        }

        if (copy.StartsWith(Utf16BigEndianBom))
        {
            return $"{path} is saved as UTF-16 big-endian, not as UTF-8; {SaveAsUtf8}";
        }

        if (Utf8.IsValid(json))
        {
            return null;
        }

        var invalid = 0;
        while (Rune.DecodeFromUtf8(json[invalid..], out _, out var length) == OperationStatus.Done)
        {
            invalid += length;
        }

        var line = json[..invalid].Count((byte)'\n') + 1;
        return string.Create(CultureInfo.InvariantCulture, $"{path} is not UTF-8 (line {line}), so it may have been saved as ANSI; {SaveAsUtf8}");
    }

    /// <summary>
    /// Checks that UTF-8 text is one plain JSON object: well formed, with nothing after it, no comments or
    /// trailing commas, no member named twice in one object whatever its case, and not too deep.
    /// </summary>
    private static string? FindStructureProblem(string path, ReadOnlySpan<byte> json)
    {
        // The reader's defaults refuse comments, trailing commas and anything but white space after the value.
        var reader = new Utf8JsonReader(json, new JsonReaderOptions { MaxDepth = MaxDepth });

        // The names of the members met so far in each object that is open, and null for each open array.
        var open = new Stack<HashSet<string>?>();
        try
        {
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return $"{path} is not a JSON object.";
            }

            open.Push(new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        open.Push(new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                        break;
                    case JsonTokenType.StartArray:
                        open.Push(null);
                        break;
                    case JsonTokenType.EndObject or JsonTokenType.EndArray:
                        _ = open.Pop();
                        break;
                    case JsonTokenType.PropertyName:
                        var member = reader.GetString()!;
                        if (!open.Peek()!.Add(member))
                        {
                            var line = json[..(int)reader.TokenStartIndex].Count((byte)'\n') + 1;
                            return string.Create(CultureInfo.InvariantCulture, $"{path} names {member} more than once in one object (line {line}), so which value counts is not clear.");
                        }

                        break;
                    default:
                        break;
                }
            }

            return null;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException)
        {
            // GetString throws InvalidOperationException for a name that is an escaped lone surrogate, such as
            // "\ud800", which is well formed JSON but no string.
            return $"{path} is not valid JSON: {e.Message}";
        }
    }
}
