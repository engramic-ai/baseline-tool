using System.Text.Json;

namespace Engramic.Baseline.Model;

/// <summary>
/// Writes and reads status.json.
/// </summary>
public static class StatusFile
{
    /// <summary>The name of the file in the data folder.</summary>
    public const string FileName = "status.json";

    /// <summary>
    /// Gets the bytes of status.json for a status: UTF-8 with a byte order mark, which Windows PowerShell
    /// 5.1 needs to read it as UTF-8, indented JSON with Windows line ends.
    /// </summary>
    /// <param name="status">The status to write.</param>
    /// <returns>The bytes of the file.</returns>
    /// <remarks>
    /// Text that is not valid UTF-16, such as a lone surrogate a registry value can hold, is written as the
    /// replacement character U+FFFD, as the PowerShell tool's UTF-8 encoder writes it, rather than failing
    /// the whole file.
    /// </remarks>
    public static byte[] ToBytes(StatusDocument status)
    {
        ArgumentNullException.ThrowIfNull(status);
        return ModelJson.ToFileBytes(status, ModelJson.StatusWriter);
    }

    /// <summary>Reads status.json, with or without a byte order mark.</summary>
    /// <param name="utf8">The bytes of the file.</param>
    /// <returns>The status.</returns>
    /// <exception cref="JsonException">The bytes are not a status document.</exception>
    public static StatusDocument Parse(ReadOnlySpan<byte> utf8)
    {
        return ModelJson.Read(utf8, ModelJson.StatusReader);
    }
}
