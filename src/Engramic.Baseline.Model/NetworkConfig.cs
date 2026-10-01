using System.Text.Json;
using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// config/network.json: the proxy for the tool's own requests, such as those to the firmware catalog.
/// </summary>
/// <remarks>
/// <para>
/// Every member is optional, and one that is missing, null or of another type takes its default, so that one
/// odd value never costs the rest of the file, as in the PowerShell tool. A switch is read only from a JSON true
/// or false: proxyUseDefaultCredentials is on only for true, and useWinHttpProxyWhenSystem and proxyAutoDetect
/// are off only for false. An address is read only from a string.
/// </para>
/// <para>
/// The PowerShell tool reads proxyUrl, proxyUseDefaultCredentials and useWinHttpProxyWhenSystem; the PAC file
/// (proxyAutoConfigUrl) and WPAD (proxyAutoDetect) are this tool's alone.
/// </para>
/// </remarks>
/// <param name="ProxyUrl">The proxy's http:// address, or empty for none.</param>
/// <param name="ProxyUseDefaultCredentials">Whether a proxy an administrator named may be sent the Windows sign-in.</param>
/// <param name="UseWinHttpProxyWhenSystem">Whether a process running as SYSTEM uses the machine's WinHTTP proxy.</param>
/// <param name="ProxyAutoConfigUrl">The address of a PAC file to ask instead of WPAD, or empty for none.</param>
/// <param name="ProxyAutoDetect">Whether WPAD may look for a PAC file on the local network.</param>
public sealed record NetworkConfig(
    [property: JsonPropertyName("proxyUrl"), JsonConverter(typeof(TextOnlyConverter))] string ProxyUrl = "",
    [property: JsonPropertyName("proxyUseDefaultCredentials"), JsonConverter(typeof(OnlyTrueConverter))] bool ProxyUseDefaultCredentials = false,
    [property: JsonPropertyName("useWinHttpProxyWhenSystem"), JsonConverter(typeof(OnlyFalseConverter))] bool UseWinHttpProxyWhenSystem = true,
    [property: JsonPropertyName("proxyAutoConfigUrl"), JsonConverter(typeof(TextOnlyConverter))] string ProxyAutoConfigUrl = "",
    [property: JsonPropertyName("proxyAutoDetect"), JsonConverter(typeof(OnlyFalseConverter))] bool ProxyAutoDetect = true);

/// <summary>Reads a switch that is on only when the file says true; any other value leaves it off.</summary>
internal sealed class OnlyTrueConverter : JsonConverter<bool>
{
    public override bool HandleNull => true;

    public override bool Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var on = reader.TokenType == JsonTokenType.True;
        reader.Skip();
        return on;
    }

    public override void Write(Utf8JsonWriter writer, bool value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteBooleanValue(value);
    }
}

/// <summary>Reads a switch that is off only when the file says false; any other value leaves it on.</summary>
internal sealed class OnlyFalseConverter : JsonConverter<bool>
{
    public override bool HandleNull => true;

    public override bool Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var off = reader.TokenType == JsonTokenType.False;
        reader.Skip();
        return !off;
    }

    public override void Write(Utf8JsonWriter writer, bool value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteBooleanValue(value);
    }
}

/// <summary>Reads text from a JSON string; any other value reads as empty.</summary>
internal sealed class TextOnlyConverter : JsonConverter<string>
{
    public override bool HandleNull => true;

    public override string Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            return reader.GetString() ?? string.Empty;
        }

        reader.Skip();
        return string.Empty;
    }

    public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStringValue(value);
    }
}
