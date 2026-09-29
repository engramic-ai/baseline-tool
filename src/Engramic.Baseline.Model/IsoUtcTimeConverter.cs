using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// Writes a time in UTC in the round-trip format, such as 2026-09-29T14:03:49.1675407Z, as the PowerShell
/// tool writes auditTime with ToUniversalTime().ToString('o'). Reads any ISO 8601 time, taking one
/// without an offset as UTC.
/// </summary>
/// <remarks>
/// System.Text.Json's own format drops trailing zeros from the fraction and writes an offset instead of Z.
/// </remarks>
internal sealed class IsoUtcTimeConverter : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var text = reader.TokenType == JsonTokenType.String ? reader.GetString() : null;
        if (text is null || !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time))
        {
            throw new JsonException("Expected a time in ISO 8601 format, such as 2026-09-29T14:03:49.1675407Z.");
        }

        return time.ToUniversalTime();
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStringValue(value.UtcDateTime.ToString("o", CultureInfo.InvariantCulture));
    }
}
