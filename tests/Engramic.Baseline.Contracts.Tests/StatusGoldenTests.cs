using System.Text;
using System.Text.Json;
using Engramic.Baseline.Model;

namespace Engramic.Baseline.Contracts.Tests;

/// <summary>
/// status.json, schema 1, byte for byte: the golden files are the contract that the Intune scripts already
/// deployed in tenants read. A golden file changes only with the contract, never to make a test pass.
/// </summary>
public sealed class StatusGoldenTests
{
    public static TheoryData<string> Samples => [.. ContractSamples.Names];

    public static TheoryData<string> Mutations => [.. StatusMutations.All.Select(m => m.Name)];

    [Theory]
    [MemberData(nameof(Samples))]
    public void Baseline_writes_each_sample_byte_for_byte_as_its_golden_file(string sample)
    {
        var golden = Golden.Status(sample);

        var written = StatusFile.ToBytes(ContractSamples.Named(sample));

        var differences = StatusContract.Differences(golden, written);
        Assert.True(differences.Count == 0, $"status-{sample}.json:\n" + string.Join('\n', differences));
        Assert.Equal(golden, written);
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Each_golden_file_reads_back_as_the_document_it_holds(string sample)
    {
        var golden = Golden.Status(sample);

        Assert.Equal(golden, StatusFile.ToBytes(StatusFile.Parse(golden)));
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Each_golden_file_is_UTF8_with_a_byte_order_mark_and_Windows_line_ends(string sample)
    {
        var golden = Golden.Status(sample);

        Assert.Equal(Utf8Bom.Preamble.ToArray(), golden[..3]);
        var text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(golden, 3, golden.Length - 3);
        var withoutLineEnds = text.Replace("\r\n", string.Empty, StringComparison.Ordinal);
        Assert.False(withoutLineEnds.Contains('\r', StringComparison.Ordinal) || withoutLineEnds.Contains('\n', StringComparison.Ordinal), "A line ends with CR or LF alone.");
        Assert.EndsWith("}\r\n", text, StringComparison.Ordinal);
    }

    [Fact]
    public void The_values_the_Intune_scripts_read_are_in_the_golden_files_by_their_exact_names()
    {
        // intune\Discover-CECompliance.ps1 and Detect-CECompliance.ps1 read these. PowerShell would find them in
        // any casing, but the contract spells them exactly, for every other reader of the file.
        string[][] read =
        [
            ["schemaVersion"], ["toolVersion"], ["auditTime"], ["autoFailCount"], ["autoFails"], ["checks"],
            ["checks", "SU-01", "status"], ["checks", "SU-01", "frameworks"],
            ["frameworks", "ce-v3.3", "metPct"], ["frameworks", "ncsc", "metPct"],
            ["frameworks", "ce-plus", "tcs", "TC2"], ["frameworks", "ce-plus", "tcs", "TC3"],
            ["frameworks", "ce-plus", "tcs", "TC4"], ["frameworks", "ce-plus", "tcs", "TC5"],
        ];
        using var probe = JsonDocument.Parse(Golden.Status("reader-probe").AsMemory(3));

        var missing = read.Where(path => !Has(probe.RootElement, path)).Select(path => string.Join(" > ", path)).ToList();

        Assert.True(missing.Count == 0, "Not in status-reader-probe.json by these exact names: " + string.Join(", ", missing));
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void The_comparison_finds_nothing_between_a_golden_file_and_a_copy_of_it(string sample)
    {
        var golden = Golden.Status(sample);

        Assert.Empty(StatusContract.Differences(golden, [.. golden]));
    }

    [Theory]
    [MemberData(nameof(Mutations))]
    public void The_golden_test_fails_when_a_copy_of_status_json_has_a_key_its_casing_or_the_byte_order_mark_changed(string name)
    {
        var mutation = StatusMutations.Named(name);
        var golden = Golden.Status("reader-probe");

        var changed = mutation.Apply(golden);

        Assert.NotEqual(golden, changed);
        var differences = StatusContract.Differences(golden, changed);
        Assert.True(
            differences.Any(d => d.Contains(mutation.GoldenSays, StringComparison.Ordinal)),
            $"When {mutation.Change}, the golden comparison should say \"{mutation.GoldenSays}\", but it said:\n" + string.Join('\n', differences));
    }

    [Fact]
    public void The_golden_test_fails_when_text_is_escaped_rather_than_written_as_UTF8()
    {
        // The same document with its e acute written as \u00e9: equal as JSON, but not the bytes the contract fixes.
        var golden = Golden.Status("reader-probe");
        var text = Encoding.UTF8.GetString(golden, 3, golden.Length - 3).Replace("\u00e9", "\\u00e9", StringComparison.Ordinal);

        var differences = StatusContract.Differences(golden, Utf8Bom.GetBytes(text));

        Assert.Contains(differences, d => d.StartsWith("The bytes differ from the golden file", StringComparison.Ordinal));
    }

    [Fact]
    public void The_golden_test_fails_when_the_lines_end_with_LF_alone()
    {
        var golden = Golden.Status("su01-pass");
        var text = Encoding.UTF8.GetString(golden, 3, golden.Length - 3).ReplaceLineEndings("\n");

        var differences = StatusContract.Differences(golden, Utf8Bom.GetBytes(text));

        Assert.Contains("Line 1 ends with LF alone: the file's lines end with CR LF.", differences);
    }

    private static bool Has(JsonElement element, string[] path)
    {
        foreach (var name in path)
        {
            // TryGetProperty matches names by ordinal, so casing counts.
            if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(name, out element))
            {
                return false;
            }
        }

        return true;
    }
}
