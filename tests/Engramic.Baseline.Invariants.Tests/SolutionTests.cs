using System.Text.Json;
using System.Xml.Linq;

namespace Engramic.Baseline.Invariants.Tests;

/// <summary>CI builds Baseline.slnx on Windows and Baseline.Portable.slnf on Linux, so both must be complete.</summary>
public sealed class SolutionTests
{
    [Fact]
    public void The_solution_lists_every_project()
    {
        var listed = SolutionProjects();
        var missing = Projects().Where(p => !listed.Contains(p)).ToList();
        var stale = listed.Where(p => !File.Exists(Repository.PathOf(p))).ToList();

        Assert.True(missing.Count == 0, "Add to Baseline.slnx:\n" + string.Join('\n', missing));
        Assert.True(stale.Count == 0, "Baseline.slnx lists projects that do not exist:\n" + string.Join('\n', stale));
    }

    [Fact]
    public void The_portable_filter_lists_exactly_the_projects_that_do_not_need_Windows()
    {
        using var filter = JsonDocument.Parse(File.ReadAllText(Repository.PathOf("Baseline.Portable.slnf")));
        var solution = filter.RootElement.GetProperty("solution");
        var listed = solution.GetProperty("projects").EnumerateArray().Select(p => p.GetString()!.Replace('\\', '/')).Order(StringComparer.Ordinal).ToList();
        var portable = Projects().Where(p => !NeedsWindows(p)).ToList();

        Assert.Equal("Baseline.slnx", solution.GetProperty("path").GetString());
        Assert.Equal(portable, listed);
    }

    [Fact]
    public void Every_library_has_a_test_project()
    {
        var untested = Projects()
            .Where(p => p.StartsWith("src/", StringComparison.Ordinal) && !IsApplication(p))
            .Select(p => Path.GetFileNameWithoutExtension(p))
            .Where(name => !File.Exists(Repository.PathOf($"tests/{name}.Tests/{name}.Tests.csproj")))
            .ToList();

        Assert.True(untested.Count == 0, "These libraries have no tests/<name>.Tests project:\n" + string.Join('\n', untested));
    }

    [Fact]
    public void Internals_are_visible_only_to_each_library_s_own_tests()
    {
        // src/Directory.Build.props grants the project's own tests; nothing else may add a friend.
        var offenders = Repository.FilesUnder("src", "*")
            .Where(f => Path.GetExtension(f) is ".cs" or ".csproj")
            .Where(f => File.ReadAllText(f).Contains("InternalsVisibleTo", StringComparison.Ordinal))
            .Select(Repository.RelativePathOf)
            .ToList();

        Assert.True(offenders.Count == 0, "Only src/Directory.Build.props may grant InternalsVisibleTo:\n" + string.Join('\n', offenders));
    }

    private static List<string> Projects()
    {
        return Repository.FilesUnder("src", "*.csproj").Concat(Repository.FilesUnder("tests", "*.csproj"))
            .Select(Repository.RelativePathOf)
            .Order(StringComparer.Ordinal)
            .ToList();
    }

    private static HashSet<string> SolutionProjects()
    {
        return XDocument.Load(Repository.PathOf("Baseline.slnx"))
            .Descendants("Project")
            .Select(p => ((string)p.Attribute("Path")!).Replace('\\', '/'))
            .ToHashSet(StringComparer.Ordinal);
    }

    private static bool NeedsWindows(string project) => ProjectText(project).Contains("<TargetFramework>net10.0-windows", StringComparison.Ordinal);

    private static bool IsApplication(string project) => ProjectText(project).Contains("<OutputType>Exe</OutputType>", StringComparison.Ordinal);

    private static string ProjectText(string project) => File.ReadAllText(Repository.PathOf(project));
}
