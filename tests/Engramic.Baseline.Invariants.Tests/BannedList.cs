namespace Engramic.Baseline.Invariants.Tests;

/// <summary>Reads src/BannedSymbols.txt and src/BannedApiExemptions.txt.</summary>
internal static class BannedList
{
    private static readonly Lazy<IReadOnlyDictionary<string, string>> Symbols = new(() => Read("src/BannedSymbols.txt"));
    private static readonly Lazy<IReadOnlyDictionary<string, string>> ExemptFiles = new(() => Read("src/BannedApiExemptions.txt"));

    /// <summary>Gets the banned documentation IDs, each with the message the build shows.</summary>
    public static IReadOnlyDictionary<string, string> Banned => Symbols.Value;

    /// <summary>Gets the files allowed to use a banned API, relative to the root, each with the reason.</summary>
    public static IReadOnlyDictionary<string, string> Exemptions => ExemptFiles.Value;

    /// <summary>Reads "key;text" lines, skipping blank lines and // comments, as the analyser does.</summary>
    private static Dictionary<string, string> Read(string relativePath)
    {
        var entries = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in File.ReadAllLines(Repository.PathOf(relativePath)))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            var split = line.IndexOf(';', StringComparison.Ordinal);
            var key = (split < 0 ? line : line[..split]).Trim();
            var text = split < 0 ? string.Empty : line[(split + 1)..].Trim();
            Assert.True(entries.TryAdd(key, text), $"{relativePath} lists {key} twice.");
        }

        return entries;
    }
}
