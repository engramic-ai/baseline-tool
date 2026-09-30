using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace Engramic.Baseline.Model;

/// <summary>
/// The contract types, with serialisation code generated at build time: no reflection, so AOT-safe.
/// </summary>
[JsonSerializable(typeof(StatusDocument))]
[JsonSerializable(typeof(FindingsDocument))]
[JsonSerializable(typeof(OsLifecycle))]
[JsonSerializable(typeof(NetworkConfig))]
internal sealed partial class ModelJsonContext : JsonSerializerContext;

/// <summary>
/// How the contract files are written and read.
/// </summary>
internal static class ModelJson
{
    /// <summary>
    /// Files Baseline writes for scripts to read: indented by two spaces, with Windows line ends. Text
    /// outside ASCII is written as UTF-8 rather than escaped, as the PowerShell tool writes it (the byte
    /// order mark tells Windows PowerShell 5.1 to read it as UTF-8), and so are + and &gt;: the files are
    /// data for scripts, never embedded in a web page, which is all the stricter default encoder guards.
    /// </summary>
    private static readonly ModelJsonContext Writer = new(new JsonSerializerOptions
    {
        WriteIndented = true,
        NewLine = "\r\n",
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    });

    /// <summary>
    /// Files Baseline reads. Names match without regard to case and numbers may be quoted, as PowerShell's
    /// ConvertFrom-Json and [int] casts allow, which the shipped files and administrators' copies rely on.
    /// </summary>
    private static readonly ModelJsonContext Reader = new(new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
    });

    public static JsonTypeInfo<StatusDocument> StatusWriter => Writer.StatusDocument;

    public static JsonTypeInfo<StatusDocument> StatusReader => Reader.StatusDocument;

    public static JsonTypeInfo<FindingsDocument> FindingsWriter => Writer.FindingsDocument;

    public static JsonTypeInfo<FindingsDocument> FindingsReader => Reader.FindingsDocument;

    public static JsonTypeInfo<OsLifecycle> OsLifecycleReader => Reader.OsLifecycle;

    public static JsonTypeInfo<NetworkConfig> NetworkReader => Reader.NetworkConfig;

    /// <summary>Writes a document as a file: UTF-8 with a byte order mark, ending with a line end.</summary>
    public static byte[] ToFileBytes<T>(T document, JsonTypeInfo<T> typeInfo)
    {
        return Utf8Bom.GetBytes(JsonSerializer.Serialize(document, typeInfo) + "\r\n");
    }

    /// <summary>Reads a document from UTF-8, with or without a byte order mark.</summary>
    /// <exception cref="JsonException">The text is not a document of this type.</exception>
    public static T Read<T>(ReadOnlySpan<byte> utf8, JsonTypeInfo<T> typeInfo)
    {
        if (utf8.StartsWith(Utf8Bom.Preamble))
        {
            utf8 = utf8[Utf8Bom.Preamble.Length..];
        }

        return JsonSerializer.Deserialize(utf8, typeInfo)
            ?? throw new JsonException($"Expected a JSON object for {typeof(T).Name}, not null.");
    }
}
