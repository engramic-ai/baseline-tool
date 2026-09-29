using System.Text.RegularExpressions;

namespace Engramic.Baseline.Invariants.Tests;

/// <summary>
/// A banned API may be used only in a file that src/BannedApiExemptions.txt names, only between a
/// commented "#pragma warning disable RS0030" and its restore, and never switched off any other way.
/// </summary>
public sealed partial class BannedApiExemptionTests
{
    private const string Rule = "RS0030";

    [Fact]
    public void Only_the_files_on_the_exemption_list_suppress_the_banned_API_rule()
    {
        var offenders = SourceFiles()
            .Where(f => f.Text.Contains(Rule, StringComparison.Ordinal) && !BannedList.Exemptions.ContainsKey(f.Path))
            .Select(f => f.Path)
            .ToList();

        Assert.True(offenders.Count == 0, $"These files mention {Rule} but src/BannedApiExemptions.txt does not name them:\n" + string.Join('\n', offenders));
    }

    [Fact]
    public void Product_code_never_disables_every_warning_at_once()
    {
        // A bare "#pragma warning disable" would silence the banned-API rule with everything else.
        var offenders = SourceFiles()
            .SelectMany(f => f.Lines.Select((line, i) => (f.Path, Line: i + 1, Text: line)))
            .Where(l => BareDisable().IsMatch(l.Text))
            .Select(l => $"{l.Path}({l.Line})")
            .ToList();

        Assert.True(offenders.Count == 0, "Name the warnings a pragma disables:\n" + string.Join('\n', offenders));
    }

    [Fact]
    public void An_exempt_use_is_a_commented_pragma_that_is_restored()
    {
        var problems = new List<string>();
        foreach (var file in SourceFiles().Where(f => BannedList.Exemptions.ContainsKey(f.Path)))
        {
            var open = 0;
            for (var i = 0; i < file.Lines.Count; i++)
            {
                var line = file.Lines[i];
                if (!line.Contains(Rule, StringComparison.Ordinal))
                {
                    continue;
                }

                var where = $"{file.Path}({i + 1})";
                if (Disable().Match(line) is { Success: true } disable)
                {
                    if (disable.Groups["reason"].Value.Trim().Length == 0)
                    {
                        problems.Add($"{where}: say why after the pragma, as // <reason>");
                    }

                    if (open++ > 0)
                    {
                        problems.Add($"{where}: disabled again before it was restored");
                    }
                }
                else if (Restore().IsMatch(line))
                {
                    if (open-- == 0)
                    {
                        problems.Add($"{where}: restored without being disabled");
                    }
                }
                else
                {
                    problems.Add($"{where}: {Rule} may appear only in a pragma, never in SuppressMessage");
                }
            }

            if (open > 0)
            {
                problems.Add($"{file.Path}: {Rule} is disabled to the end of the file; restore it after the exempt lines");
            }
        }

        Assert.True(problems.Count == 0, string.Join('\n', problems));
    }

    [Fact]
    public void Every_exemption_names_a_file_that_uses_it_and_says_why()
    {
        var problems = new List<string>();
        foreach (var (path, reason) in BannedList.Exemptions)
        {
            var full = Repository.PathOf(path);
            if (!path.StartsWith("src/", StringComparison.Ordinal) || !path.EndsWith(".cs", StringComparison.Ordinal) || !File.Exists(full))
            {
                problems.Add($"{path}: not a C# file under src/");
            }
            else if (!File.ReadAllLines(full).Any(l => Disable().IsMatch(l)))
            {
                problems.Add($"{path}: uses no banned API any more; take it off the list");
            }

            if (reason.Length == 0)
            {
                problems.Add($"{path}: give the reason after a semicolon");
            }
        }

        Assert.True(problems.Count == 0, "src/BannedApiExemptions.txt:\n" + string.Join('\n', problems));
    }

    [Fact]
    public void No_build_setting_turns_the_banned_API_rule_down()
    {
        // The rule is an error in .editorconfig, and Directory.Build.targets fails a product build that
        // lost the analyser or its list. Nothing else may name it: not NoWarn, not another config file.
        var allowed = new Dictionary<string, Func<string, bool>>(StringComparer.Ordinal)
        {
            [".editorconfig"] = line => line.Trim() == $"dotnet_diagnostic.{Rule}.severity = error",
            ["Directory.Build.targets"] = _ => true,
        };

        var offenders = new List<string>();
        foreach (var file in Repository.FilesUnder(".", "*").Where(IsBuildSetting))
        {
            var path = Repository.RelativePathOf(file);
            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
            {
                if (lines[i].Contains(Rule, StringComparison.Ordinal) && !(allowed.TryGetValue(path, out var ok) && ok(lines[i])))
                {
                    offenders.Add($"{path}({i + 1}): {lines[i].Trim()}");
                }
            }
        }

        Assert.True(offenders.Count == 0, $"Only .editorconfig (as an error) and Directory.Build.targets may name {Rule}:\n" + string.Join('\n', offenders));
    }

    [Fact]
    public void Product_projects_keep_the_analysers_and_the_build_rules_that_check_them()
    {
        // Directory.Build.targets fails a product build that skips the analysers or swaps the list, but it
        // cannot see a project that stopped importing it, so the project files are read here instead.
        var offenders = new List<string>();
        foreach (var file in Repository.FilesUnder("src", "*").Where(IsBuildSetting))
        {
            var path = Repository.RelativePathOf(file);
            if (Path.GetExtension(file) != ".csproj" && path != "src/Directory.Build.props")
            {
                offenders.Add($"{path}: product build settings live in src/Directory.Build.props and the project files only");
                continue;
            }

            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
            {
                if (AnalyserSwitch().IsMatch(lines[i]))
                {
                    offenders.Add($"{path}({i + 1}): {lines[i].Trim()}");
                }
            }
        }

        foreach (var file in new[] { "Directory.Build.props", "Directory.Packages.props" })
        {
            var lines = File.ReadAllLines(Repository.PathOf(file));
            for (var i = 0; i < lines.Length; i++)
            {
                if (AnalyserSwitch().IsMatch(lines[i]))
                {
                    offenders.Add($"{file}({i + 1}): {lines[i].Trim()}");
                }
            }
        }

        Assert.True(offenders.Count == 0, "Product code must run the analysers with the shared banned-API list:\n" + string.Join('\n', offenders));
    }

    private static bool IsBuildSetting(string file)
    {
        var name = Path.GetFileName(file);
        return name is ".editorconfig" or ".globalconfig" or "Directory.Build.rsp"
            || Path.GetExtension(file) is ".csproj" or ".props" or ".targets" or ".globalconfig" or ".ruleset" or ".rsp";
    }

    private static IEnumerable<(string Path, string Text, IReadOnlyList<string> Lines)> SourceFiles()
    {
        foreach (var file in Repository.FilesUnder("src", "*.cs"))
        {
            var text = File.ReadAllText(file);
            yield return (Repository.RelativePathOf(file), text, text.ReplaceLineEndings("\n").Split('\n'));
        }
    }

    /// <summary>
    /// A setting that stops the analysers running, stops the shared build rules being imported, or removes
    /// an analyser or an additional file (such as the banned-API list) that src/Directory.Build.props adds.
    /// </summary>
    [GeneratedRegex(@"RunAnalyzers|RunAnalyzersDuringBuild|OptimizeImplicitlyTriggeredBuild|ImportDirectoryBuild(Props|Targets)|ImportDirectoryPackagesProps|<(Analyzer|AdditionalFiles)\s[^>]*\bRemove\s*=")]
    private static partial Regex AnalyserSwitch();

    [GeneratedRegex(@"^\s*#pragma\s+warning\s+disable\s*(//.*)?$")]
    private static partial Regex BareDisable();

    [GeneratedRegex(@"^\s*#pragma\s+warning\s+disable\s+RS0030\s*(//(?<reason>.*))?$")]
    private static partial Regex Disable();

    [GeneratedRegex(@"^\s*#pragma\s+warning\s+restore\s+RS0030\s*(//.*)?$")]
    private static partial Regex Restore();
}
