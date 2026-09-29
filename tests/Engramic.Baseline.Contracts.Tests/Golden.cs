namespace Engramic.Baseline.Contracts.Tests;

/// <summary>The golden files, built into the tests: Golden/status-&lt;sample&gt;.json.</summary>
internal static class Golden
{
    /// <summary>Gets the golden status.json of a sample in <see cref="ContractSamples"/>, byte for byte.</summary>
    public static byte[] Status(string sample)
    {
        var name = $"Golden/status-{sample}.json";
        using var stream = typeof(Golden).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"{name} is not built into the tests; add it to the Golden folder.");
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }
}
