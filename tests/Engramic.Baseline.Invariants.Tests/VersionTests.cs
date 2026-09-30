using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Engramic.Baseline.Invariants.Tests;

/// <summary>
/// The version is written once, in Directory.Build.props, as VersionPrefix and VersionSuffix. Every assembly and
/// baseline.exe --version take it from there, and tools/Test-ReleaseTag.ps1 holds a release tag to it exactly, so
/// it must be plain text that no condition and no other build file can change.
/// </summary>
public sealed partial class VersionTests
{
    private const string Props = "Directory.Build.props";

    // The properties that set a version in MSBuild, one way or another.
    private static readonly string[] VersionProperties =
        ["Version", "VersionPrefix", "VersionSuffix", "AssemblyVersion", "FileVersion", "InformationalVersion", "PackageVersion"];

    [Fact]
    public void Directory_Build_props_writes_the_version_once_as_plain_text()
    {
        var props = XDocument.Load(Repository.PathOf(Props));
        var prefix = Properties(props, "VersionPrefix");
        var suffix = Properties(props, "VersionSuffix");

        Assert.True(prefix.Count == 1, $"{Props} must set VersionPrefix once, not {prefix.Count} times.");
        Assert.True(suffix.Count <= 1, $"{Props} must set VersionSuffix at most once, not {suffix.Count} times.");
        var conditional = prefix.Concat(suffix)
            .Where(e => e.AncestorsAndSelf().Any(a => a.Attribute("Condition") is not null))
            .Select(e => e.Name.LocalName)
            .ToList();
        Assert.True(conditional.Count == 0, $"{Props} sets these under a condition: {string.Join(", ", conditional)}");
        Assert.Matches(PrefixPattern(), prefix[0].Value.Trim());
        if (suffix.Count == 1)
        {
            Assert.Matches(SuffixPattern(), suffix[0].Value.Trim());
        }
    }

    [Fact]
    public void Nothing_else_sets_a_version()
    {
        var offenders = new List<string>();
        foreach (var file in BuildFiles())
        {
            var document = XDocument.Load(Repository.PathOf(file));
            string[] allowed = file == Props ? ["VersionPrefix", "VersionSuffix"] : [];
            offenders.AddRange(VersionProperties
                .Where(name => !allowed.Contains(name, StringComparer.Ordinal))
                .SelectMany(name => Properties(document, name))
                .Select(e => $"{file}: {e.Name.LocalName}"));
        }

        Assert.True(offenders.Count == 0, $"Only VersionPrefix and VersionSuffix in {Props} may set the version:\n" + string.Join('\n', offenders));
    }

    [Fact]
    public void The_build_files_include_the_one_with_the_version()
    {
        // Guards the test above against finding nothing to look at.
        Assert.Contains(Props, BuildFiles());
        Assert.Contains("src/Engramic.Baseline.Cli/Engramic.Baseline.Cli.csproj", BuildFiles());
    }

    private static List<XElement> Properties(XDocument document, string name)
    {
        return document.Descendants()
            .Where(e => e.Name.LocalName == name && e.Parent?.Name.LocalName == "PropertyGroup")
            .ToList();
    }

    private static List<string> BuildFiles()
    {
        var atRoot = new[] { "*.props", "*.targets" }
            .SelectMany(pattern => Directory.EnumerateFiles(Repository.Root, pattern))
            .Select(Repository.RelativePathOf);
        var below = new[] { "src", "tests" }
            .SelectMany(folder => Repository.FilesUnder(folder, "*"))
            .Where(f => Path.GetExtension(f) is ".csproj" or ".props" or ".targets")
            .Select(Repository.RelativePathOf);
        return atRoot.Concat(below).Order(StringComparer.Ordinal).ToList();
    }

    [GeneratedRegex(@"^\d+\.\d+\.\d+$")]
    private static partial Regex PrefixPattern();

    [GeneratedRegex(@"^[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*$")]
    private static partial Regex SuffixPattern();
}
