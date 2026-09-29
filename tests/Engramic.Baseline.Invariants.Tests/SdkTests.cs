using System.Text.Json;
using System.Text.RegularExpressions;

namespace Engramic.Baseline.Invariants.Tests;

/// <summary>
/// CI must build with exactly the SDK in global.json. Some implicit packages (the trimming and AOT tools)
/// take their version from the SDK, and the committed lock files record it, so a newer patch SDK fails
/// the locked restore.
/// </summary>
public sealed partial class SdkTests
{
    private const string Workflow = ".github/workflows/dotnet.yml";

    [Fact]
    public void Global_json_names_one_exact_SDK()
    {
        using var json = JsonDocument.Parse(File.ReadAllText(Repository.PathOf("global.json")));
        var version = json.RootElement.GetProperty("sdk").GetProperty("version").GetString();

        Assert.Matches(ExactVersion(), version);
    }

    [Fact]
    public void CI_installs_the_SDK_by_its_exact_version()
    {
        // Given global-json-file with rollForward latestPatch, setup-dotnet installs the newest patch of the
        // feature band (a 10.0.4xx channel), not the version global.json names.
        var text = File.ReadAllText(Repository.PathOf(Workflow));
        var installs = SetupDotnet().Count(text);
        var exact = Regex.Count(text, Regex.Escape("dotnet-version: ${{ steps.sdk.outputs.version }}"));

        Assert.False(GlobalJsonInput().IsMatch(text), $"{Workflow} passes global-json-file to setup-dotnet.");
        Assert.True(installs > 0, $"{Workflow} no longer installs the SDK with setup-dotnet; update this test.");
        Assert.True(installs == exact, $"Each setup-dotnet step in {Workflow} must pass dotnet-version: ${{{{ steps.sdk.outputs.version }}}}, read from global.json.");
    }

    [GeneratedRegex(@"^\d+\.\d+\.\d+$")]
    private static partial Regex ExactVersion();

    [GeneratedRegex(@"^\s*global-json-file\s*:", RegexOptions.Multiline)]
    private static partial Regex GlobalJsonInput();

    [GeneratedRegex(@"uses:\s*actions/setup-dotnet@")]
    private static partial Regex SetupDotnet();
}
