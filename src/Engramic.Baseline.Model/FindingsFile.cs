using System.Text.Json;

namespace Engramic.Baseline.Model;

/// <summary>
/// Writes and reads findings.json.
/// </summary>
public static class FindingsFile
{
    /// <summary>The name of the file in a report folder.</summary>
    public const string FileName = "findings.json";

    /// <summary>
    /// Gets the bytes of findings.json: UTF-8 with a byte order mark, indented JSON with Windows line ends.
    /// </summary>
    /// <param name="findings">The findings to write.</param>
    /// <returns>The bytes of the file.</returns>
    /// <remarks>
    /// Text that is not valid UTF-16, such as a lone surrogate a registry value can hold, is written as the
    /// replacement character U+FFFD, as the PowerShell tool's UTF-8 encoder writes it, rather than failing
    /// the whole file.
    /// </remarks>
    public static byte[] ToBytes(FindingsDocument findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        return ModelJson.ToFileBytes(findings, ModelJson.FindingsWriter);
    }

    /// <summary>Reads findings.json, with or without a byte order mark.</summary>
    /// <param name="utf8">The bytes of the file.</param>
    /// <returns>The findings.</returns>
    /// <exception cref="JsonException">The bytes are not a findings document.</exception>
    public static FindingsDocument Parse(ReadOnlySpan<byte> utf8)
    {
        return ModelJson.Read(utf8, ModelJson.FindingsReader);
    }
}
