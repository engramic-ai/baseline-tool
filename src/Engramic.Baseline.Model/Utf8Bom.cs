using System.Text;

namespace Engramic.Baseline.Model;

/// <summary>
/// UTF-8 with a byte order mark: the encoding of every file Baseline writes for a script to read.
/// </summary>
/// <remarks>
/// Windows PowerShell 5.1 reads a file that has no byte order mark in the ANSI code page, so the
/// Intune scripts already deployed would misread any non-ASCII text in a file written without one.
/// The encoding is strict: text that is not valid UTF-16, such as an unpaired surrogate, throws
/// instead of being written as a replacement character.
/// </remarks>
public static class Utf8Bom
{
    private static readonly UTF8Encoding Strict = new(encoderShouldEmitUTF8Identifier: true, throwOnInvalidBytes: true);

    /// <summary>Gets the byte order mark: EF BB BF.</summary>
    public static ReadOnlySpan<byte> Preamble => [0xEF, 0xBB, 0xBF];

    /// <summary>Gets the strict UTF-8 encoding, whose preamble is the byte order mark.</summary>
    public static Encoding Encoding => Strict;

    /// <summary>Encodes text as the byte order mark followed by the text in strict UTF-8.</summary>
    /// <param name="text">The text to encode.</param>
    /// <returns>The byte order mark and the encoded text.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="text"/> is null.</exception>
    /// <exception cref="EncoderFallbackException"><paramref name="text"/> is not valid UTF-16.</exception>
    public static byte[] GetBytes(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var bytes = new byte[Preamble.Length + Strict.GetByteCount(text)];
        Preamble.CopyTo(bytes);
        _ = Strict.GetBytes(text, bytes.AsSpan(Preamble.Length));
        return bytes;
    }
}
