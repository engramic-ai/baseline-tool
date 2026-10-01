using System.Text.Json;
using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// What the Appx comparisons count against a source, on answers made up here: only the reviewed differences seen on
/// CI's runner are let off, and only when the user's own repository lacks them too.
/// </summary>
public sealed class AppxComparisonTests
{
    private const string Alex = "S-1-5-21-1004336348-1177238915-682003330-1001";
    private const string Sam = "S-1-5-21-1004336348-1177238915-682003330-1002";
    private const string Claude = "Claude_2.16120.0.0_x64__pzs8sxrjxfjjc";
    private const string ChatGpt = "OpenAI.ChatGPT-Desktop_1.2025.112.0_x64__2p2nqsd0c76g0";
    private const string SecHealth = "Microsoft.SecHealthUI_1000.26100.33438.0_x64__8wekyb3d8bbwe";

    [Fact]
    public void A_known_runner_difference_the_user_s_repository_lacks_is_reported_and_not_counted()
    {
        var comparison = Compare(Oracle((Alex, [Claude, SecHealth])), Read(Alex, Claude), userRepositoryLacksIt: true);

        Assert.Empty(comparison.DifferencesOf("registry"));
        Assert.Contains("missed: " + SecHealth + " (not counted: a known difference on CI's runner", comparison.Report, StringComparison.Ordinal);
        Assert.Contains("not counting 1 known differences", comparison.Report, StringComparison.Ordinal);
    }

    [Fact]
    public void A_known_runner_difference_the_user_s_repository_lists_counts()
    {
        // The source missed a package its own input holds: a fault of the source, whatever the package.
        var comparison = Compare(Oracle((Alex, [Claude, SecHealth])), Read(Alex, Claude), userRepositoryLacksIt: false);

        Assert.Equal(["registry missed " + SecHealth + " for " + Alex], comparison.DifferencesOf("registry"));
    }

    [Fact]
    public void Any_other_miss_counts_even_when_the_user_s_repository_lacks_it()
    {
        var comparison = Compare(Oracle((Alex, [Claude, ChatGpt])), Read(Alex, Claude), userRepositoryLacksIt: true);

        Assert.Equal(["registry missed " + ChatGpt + " for " + Alex], comparison.DifferencesOf("registry"));
    }

    [Fact]
    public void A_user_not_loaded_or_unsupported_is_reported_and_one_denied_counts()
    {
        var users = new List<AppxUserPackages>
        {
            new(Sid.Parse(Alex), AppxReadOutcome.NotLoaded, [], "not loaded"),
            new(Sid.LocalSystem, AppxReadOutcome.Unsupported, [], "a service account"),
            new(Sid.Parse(Sam), AppxReadOutcome.Denied, [], "denied"),
        };

        var comparison = Compare(Oracle((Alex, [Claude]), ("S-1-5-18", [Claude]), (Sam, [ChatGpt])), users, userRepositoryLacksIt: true);

        Assert.Equal(["registry could not read " + Sam + ": Denied. denied"], comparison.DifferencesOf("registry"));
        Assert.Contains("NotLoaded, so these 1 are not known to it", comparison.Report, StringComparison.Ordinal);
        Assert.Contains("Unsupported, so these 1 are not known to it", comparison.Report, StringComparison.Ordinal);
    }

    [Fact]
    public void No_known_runner_difference_is_a_package_ai_tools_json_names()
    {
        // A tool the checks look for may never be let off: a miss of one fails the comparison, wherever it is seen.
        using var tools = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(RepositoryRoot(), "config", "ai-tools.json")));
        var names = new List<string>();
        CollectAppxNames(tools.RootElement, names);

        Assert.Contains("Claude", names);
        Assert.DoesNotContain(names, AppxKnownDifferences.RunnerMisses.Contains);
    }

    private static AppxComparison Compare(OracleAnswer oracle, IReadOnlyList<AppxUserPackages> users, bool userRepositoryLacksIt)
    {
        return AppxComparison.Compare(oracle, [("registry", users, TimeSpan.Zero)], (_, name) => ("why", AppxKnownDifferences.Excuse(name, userRepositoryLacksIt)));
    }

    private static List<AppxUserPackages> Read(string sid, params string[] packages)
    {
        return [new AppxUserPackages(Sid.Parse(sid), AppxReadOutcome.Read, [.. packages.Select(AppxPackage.Parse)], string.Empty)];
    }

    private static OracleAnswer Oracle(params (string Sid, string[] Installed)[] users)
    {
        var installed = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (sid, names) in users)
        {
            installed[sid] = new HashSet<string>(names, AppxPackage.FullNameComparer);
        }

        return new OracleAnswer("Get-AppxPackage -AllUsers", installed, new(StringComparer.OrdinalIgnoreCase), new(AppxPackage.FullNameComparer), TimeSpan.Zero);
    }

    private static void CollectAppxNames(JsonElement element, List<string> names)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("appx") && property.Value.ValueKind == JsonValueKind.Array)
                {
                    names.AddRange(property.Value.EnumerateArray().Select(n => n.GetString() ?? string.Empty));
                }
                else
                {
                    CollectAppxNames(property.Value, names);
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                CollectAppxNames(item, names);
            }
        }
    }

    private static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Baseline.slnx")))
            {
                return dir.FullName;
            }
        }

        throw new InvalidOperationException("Baseline.slnx was not found above " + AppContext.BaseDirectory);
    }
}
