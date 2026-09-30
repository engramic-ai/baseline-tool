using System.Globalization;
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
/// A file joins <see cref="Names"/>, with its reader, in the change that first reads it: every file the tool
/// ships needs a schema, or no administrator's copy of it is used.
/// </para>
/// </remarks>
public static class ConfigFile
{
    /// <summary>The name of the Windows lifecycle data that SU-01 judges against.</summary>
    public const string OsLifecycleName = "os-lifecycle.json";

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

    /// <summary>
    /// Checks a copy of a config file against the file's schema, as an administrator's copy must pass before it
    /// replaces the shipped one: one plain JSON document, with or without a byte order mark, that the file's
    /// reader accepts.
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
        if (!Utf8.IsValid(json))
        {
            return $"{path} is not UTF-8 text.";
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
