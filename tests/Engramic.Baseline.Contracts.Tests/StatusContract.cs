using System.Globalization;
using System.Text;
using System.Text.Json;
using Engramic.Baseline.Model;

namespace Engramic.Baseline.Contracts.Tests;

/// <summary>
/// Compares a status.json with its golden file as the contract sees it: the byte order mark, UTF-8, the
/// name, casing and order of every key, the kind and value of every value, the line ends and, last, the
/// bytes themselves. Each difference is one sentence that says where it is.
/// </summary>
/// <remarks>
/// Key names are compared by ordinal, so a key whose casing changed is reported as spelt differently: the
/// Intune scripts would still find it, since PowerShell looks up properties whatever their case, but other
/// readers of the file need not.
/// </remarks>
internal static class StatusContract
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>Gets every difference between a golden file and a file, or none when they are the same.</summary>
    /// <param name="golden">The golden file's bytes.</param>
    /// <param name="actual">The bytes to check.</param>
    /// <returns>The differences, in the order above.</returns>
    public static IReadOnlyList<string> Differences(byte[] golden, byte[] actual)
    {
        ArgumentNullException.ThrowIfNull(golden);
        ArgumentNullException.ThrowIfNull(actual);
        var differences = new List<string>();
        var goldenBody = WithoutByteOrderMark(golden, out var goldenMarked);
        var actualBody = WithoutByteOrderMark(actual, out var actualMarked);
        if (goldenMarked && !actualMarked)
        {
            differences.Add("The file does not start with the UTF-8 byte order mark (EF BB BF), so Windows PowerShell 5.1 reads it in the ANSI code page.");
        }
        else if (!goldenMarked && actualMarked)
        {
            differences.Add("The file starts with a UTF-8 byte order mark, which the golden file does not.");
        }

        if (actualBody.AsSpan().StartsWith(Utf8Bom.Preamble))
        {
            differences.Add("The file starts with a second byte order mark.");
        }

        string actualText;
        try
        {
            actualText = StrictUtf8.GetString(actualBody);
        }
        catch (DecoderFallbackException e)
        {
            differences.Add("The file is not valid UTF-8: " + e.Message);
            return differences;
        }

        JsonDocument actualJson;
        try
        {
            actualJson = JsonDocument.Parse(actualBody);
        }
        catch (JsonException e)
        {
            differences.Add("The file is not JSON: " + e.Message);
            return differences;
        }

        using (actualJson)
        using (var goldenJson = JsonDocument.Parse(goldenBody))
        {
            CompareElement(goldenJson.RootElement, actualJson.RootElement, string.Empty, differences);
        }

        CompareLineEnds(StrictUtf8.GetString(goldenBody), actualText, differences);
        if (differences.Count == 0 && !golden.AsSpan().SequenceEqual(actual))
        {
            differences.Add(FirstByteDifference(golden, actual));
        }

        return differences;
    }

    private static byte[] WithoutByteOrderMark(byte[] bytes, out bool marked)
    {
        marked = bytes.AsSpan().StartsWith(Utf8Bom.Preamble);
        return marked ? bytes[Utf8Bom.Preamble.Length..] : bytes;
    }

    private static void CompareElement(JsonElement golden, JsonElement actual, string path, List<string> differences)
    {
        if (IsBoolean(golden) && IsBoolean(actual))
        {
            if (golden.ValueKind != actual.ValueKind)
            {
                differences.Add($"{Name(path)} is {Kind(actual.ValueKind)}, not {Kind(golden.ValueKind)}.");
            }

            return;
        }

        if (golden.ValueKind != actual.ValueKind)
        {
            differences.Add($"{Name(path)} is {Kind(actual.ValueKind)}, not {Kind(golden.ValueKind)}.");
            return;
        }

        switch (golden.ValueKind)
        {
            case JsonValueKind.Object:
                CompareObject(golden, actual, path, differences);
                break;
            case JsonValueKind.Array:
                CompareArray(golden, actual, path, differences);
                break;
            case JsonValueKind.String when !string.Equals(golden.GetString(), actual.GetString(), StringComparison.Ordinal):
                differences.Add($"{Name(path)} is \"{actual.GetString()}\", not \"{golden.GetString()}\".");
                break;
            case JsonValueKind.Number when !string.Equals(golden.GetRawText(), actual.GetRawText(), StringComparison.Ordinal):
                differences.Add($"{Name(path)} is {actual.GetRawText()}, not {golden.GetRawText()}.");
                break;
            default:
                break;
        }
    }

    private static void CompareObject(JsonElement golden, JsonElement actual, string path, List<string> differences)
    {
        var goldenNames = golden.EnumerateObject().Select(p => p.Name).ToList();
        var actualNames = actual.EnumerateObject().Select(p => p.Name).ToList();
        foreach (var repeated in actualNames.GroupBy(n => n, StringComparer.Ordinal).Where(g => g.Count() > 1))
        {
            differences.Add($"{Name(Join(path, repeated.Key))} appears {repeated.Count()} times.");
        }

        var recased = new HashSet<string>(StringComparer.Ordinal);
        foreach (var name in goldenNames.Where(n => !actualNames.Contains(n, StringComparer.Ordinal)))
        {
            var spelling = actualNames.FirstOrDefault(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase) && !goldenNames.Contains(n, StringComparer.Ordinal));
            if (spelling is null)
            {
                differences.Add($"{Name(Join(path, name))} is missing.");
            }
            else
            {
                recased.Add(spelling);
                differences.Add($"{Name(Join(path, name))} is written '{spelling}': the contract spells the key '{name}'.");
            }
        }

        foreach (var name in actualNames.Distinct(StringComparer.Ordinal).Where(n => !goldenNames.Contains(n, StringComparer.Ordinal) && !recased.Contains(n)))
        {
            differences.Add($"{Name(Join(path, name))} is not in the contract.");
        }

        var common = goldenNames.Where(n => actualNames.Contains(n, StringComparer.Ordinal)).ToList();
        var actualOrder = actualNames.Where(n => common.Contains(n, StringComparer.Ordinal)).Distinct(StringComparer.Ordinal).ToList();
        if (!common.SequenceEqual(actualOrder, StringComparer.Ordinal))
        {
            differences.Add($"{Keys(path)} are in the order {string.Join(", ", actualOrder)}, not {string.Join(", ", common)}.");
        }

        foreach (var name in common)
        {
            CompareElement(golden.GetProperty(name), actual.GetProperty(name), Join(path, name), differences);
        }
    }

    private static void CompareArray(JsonElement golden, JsonElement actual, string path, List<string> differences)
    {
        var goldenItems = golden.EnumerateArray().ToList();
        var actualItems = actual.EnumerateArray().ToList();
        if (goldenItems.Count != actualItems.Count)
        {
            differences.Add(string.Create(CultureInfo.InvariantCulture, $"{Name(path)} has {actualItems.Count} items, not {goldenItems.Count}."));
        }

        for (var i = 0; i < Math.Min(goldenItems.Count, actualItems.Count); i++)
        {
            CompareElement(goldenItems[i], actualItems[i], string.Create(CultureInfo.InvariantCulture, $"{path}[{i}]"), differences);
        }
    }

    private static void CompareLineEnds(string golden, string actual, List<string> differences)
    {
        if (!golden.Contains("\r\n", StringComparison.Ordinal))
        {
            return;
        }

        var line = 1;
        for (var i = 0; i < actual.Length; i++)
        {
            if (actual[i] == '\n' && (i == 0 || actual[i - 1] != '\r'))
            {
                differences.Add(string.Create(CultureInfo.InvariantCulture, $"Line {line} ends with LF alone: the file's lines end with CR LF."));
                return;
            }

            if (actual[i] == '\r' && (i + 1 == actual.Length || actual[i + 1] != '\n'))
            {
                differences.Add(string.Create(CultureInfo.InvariantCulture, $"Line {line} ends with CR alone: the file's lines end with CR LF."));
                return;
            }

            if (actual[i] == '\n')
            {
                line++;
            }
        }

        if (!actual.EndsWith("\r\n", StringComparison.Ordinal))
        {
            differences.Add("The file does not end with a line end.");
        }
    }

    private static string FirstByteDifference(byte[] golden, byte[] actual)
    {
        var at = golden.AsSpan().CommonPrefixLength(actual);
        var line = actual.AsSpan(0, at).Count((byte)'\n') + 1;
        return string.Create(
            CultureInfo.InvariantCulture,
            $"The bytes differ from the golden file at byte {at}, on line {line}: the golden file has {Snippet(golden, at)} and the file has {Snippet(actual, at)}.");
    }

    private static string Snippet(byte[] bytes, int at)
    {
        if (at >= bytes.Length)
        {
            return "nothing more";
        }

        var text = new StringBuilder("'");
        foreach (var b in bytes.AsSpan(at, Math.Min(16, bytes.Length - at)))
        {
            text.Append(b is >= 0x20 and < 0x7F ? ((char)b).ToString() : string.Create(CultureInfo.InvariantCulture, $"\\x{b:X2}"));
        }

        return text.Append('\'').ToString();
    }

    private static bool IsBoolean(JsonElement element) => element.ValueKind is JsonValueKind.True or JsonValueKind.False;

    private static string Join(string path, string name) => path.Length == 0 ? name : path + "." + name;

    private static string Name(string path) => path.Length == 0 ? "The document" : path;

    private static string Keys(string path) => path.Length == 0 ? "The top-level keys" : $"The keys of {path}";

    private static string Kind(JsonValueKind kind) => kind switch
    {
        JsonValueKind.Object => "an object",
        JsonValueKind.Array => "a list",
        JsonValueKind.String => "text",
        JsonValueKind.Number => "a number",
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null => "null",
        _ => "missing",
    };
}
