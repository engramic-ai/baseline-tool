using System.Globalization;

namespace Engramic.Baseline.Platform;

/// <summary>
/// A registry value as stored: its type and its data, uninterpreted.
/// </summary>
/// <remarks>
/// Readers decide what a value means, such as how a build number stored as text becomes a number; the
/// primitive only reports what is there. Text of type REG_EXPAND_SZ is kept as written, as expanding it
/// would depend on the environment of whoever started the process.
/// </remarks>
public sealed class RegistryValue : IEquatable<RegistryValue>
{
    private readonly string? _text;
    private readonly string[] _lines;
    private readonly ulong _number;
    private readonly byte[] _bytes;

    private RegistryValue(RegistryValueKind kind, string? text = null, string[]? lines = null, ulong number = 0, byte[]? bytes = null)
    {
        Kind = kind;
        _text = text;
        _lines = lines ?? [];
        _number = number;
        _bytes = bytes ?? [];
    }

    /// <summary>Gets the type of the value.</summary>
    public RegistryValueKind Kind { get; }

    /// <summary>Gets the text of a REG_SZ or REG_EXPAND_SZ value; null for any other type.</summary>
    public string? Text => _text;

    /// <summary>Gets the lines of a REG_MULTI_SZ value; empty for any other type.</summary>
    public IReadOnlyList<string> Lines => _lines;

    /// <summary>Gets the number of a REG_DWORD or REG_QWORD value; null for any other type.</summary>
    public ulong? Number => Kind is RegistryValueKind.DWord or RegistryValueKind.QWord ? _number : null;

    /// <summary>Gets the bytes of a REG_BINARY value or a value of another type; empty for text and numbers.</summary>
    public ReadOnlyMemory<byte> Bytes => _bytes;

    /// <summary>Makes a REG_SZ value.</summary>
    /// <param name="text">The text.</param>
    /// <returns>The value.</returns>
    public static RegistryValue FromText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return new RegistryValue(RegistryValueKind.Text, text: text);
    }

    /// <summary>Makes a REG_EXPAND_SZ value, kept as written.</summary>
    /// <param name="text">The text, which may name environment variables such as %SystemRoot%.</param>
    /// <returns>The value.</returns>
    public static RegistryValue FromExpandText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return new RegistryValue(RegistryValueKind.ExpandText, text: text);
    }

    /// <summary>Makes a REG_MULTI_SZ value.</summary>
    /// <param name="lines">The lines.</param>
    /// <returns>The value.</returns>
    public static RegistryValue FromMultiText(IEnumerable<string> lines)
    {
        ArgumentNullException.ThrowIfNull(lines);
        var copy = lines.ToArray();
        return Array.Exists(copy, l => l is null)
            ? throw new ArgumentException("A line of a REG_MULTI_SZ value cannot be null.", nameof(lines))
            : new RegistryValue(RegistryValueKind.MultiText, lines: copy);
    }

    /// <summary>Makes a REG_DWORD value.</summary>
    /// <param name="number">The number.</param>
    /// <returns>The value.</returns>
    public static RegistryValue FromDWord(uint number) => new(RegistryValueKind.DWord, number: number);

    /// <summary>Makes a REG_QWORD value.</summary>
    /// <param name="number">The number.</param>
    /// <returns>The value.</returns>
    public static RegistryValue FromQWord(ulong number) => new(RegistryValueKind.QWord, number: number);

    /// <summary>Makes a REG_BINARY value.</summary>
    /// <param name="bytes">The bytes, which are copied.</param>
    /// <returns>The value.</returns>
    public static RegistryValue FromBinary(ReadOnlySpan<byte> bytes) => new(RegistryValueKind.Binary, bytes: bytes.ToArray());

    /// <summary>Makes a value of type REG_NONE or any type without a member of its own, from its bytes.</summary>
    /// <param name="bytes">The bytes, which are copied.</param>
    /// <returns>The value.</returns>
    public static RegistryValue FromOther(ReadOnlySpan<byte> bytes) => new(RegistryValueKind.Other, bytes: bytes.ToArray());

    /// <inheritdoc/>
    public bool Equals(RegistryValue? other)
    {
        return other is not null
            && Kind == other.Kind
            && string.Equals(_text, other._text, StringComparison.Ordinal)
            && _lines.AsSpan().SequenceEqual(other._lines, StringComparer.Ordinal)
            && _number == other._number
            && _bytes.AsSpan().SequenceEqual(other._bytes);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as RegistryValue);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Kind);
        hash.Add(_text, StringComparer.Ordinal);
        foreach (var line in _lines)
        {
            hash.Add(line, StringComparer.Ordinal);
        }

        hash.Add(_number);
        hash.AddBytes(_bytes);
        return hash.ToHashCode();
    }

    /// <summary>Describes the value for a test or a log, such as "DWord 1".</summary>
    /// <returns>The type and the data.</returns>
    public override string ToString()
    {
        return Kind switch
        {
            RegistryValueKind.Text or RegistryValueKind.ExpandText => $"{Kind} \"{_text}\"",
            RegistryValueKind.MultiText => $"{Kind} [{string.Join(", ", _lines.Select(l => "\"" + l + "\""))}]",
            RegistryValueKind.DWord or RegistryValueKind.QWord => string.Create(CultureInfo.InvariantCulture, $"{Kind} {_number}"),
            _ => $"{Kind} {Convert.ToHexString(_bytes)}",
        };
    }
}
