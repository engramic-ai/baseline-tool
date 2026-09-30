using System.Text;

namespace Engramic.Baseline.Model.Tests;

/// <summary>
/// The schema an administrator's copy of a config file must meet before it replaces the shipped one: one plain
/// JSON object, in UTF-8, that the file's generated reader accepts.
/// </summary>
public sealed class ConfigSchemaTests
{
    private const string OverridePath = @"C:\ProgramData\EngramicBaseline\config\os-lifecycle.json";
    private const string Valid = """{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }""";

    [Fact]
    public void Every_config_file_the_tool_reads_has_a_schema()
    {
        Assert.Equal(["os-lifecycle.json"], ConfigFile.Names);
    }

    [Fact]
    public void A_copy_its_reader_accepts_passes_with_or_without_a_byte_order_mark()
    {
        Assert.Null(ConfigFile.FindProblem("os-lifecycle.json", OverridePath, Encoding.UTF8.GetBytes(Valid)));
        Assert.Null(ConfigFile.FindProblem("os-lifecycle.json", OverridePath, Utf8Bom.GetBytes(Valid)));
    }

    [Fact]
    public void Members_the_tool_does_not_read_are_allowed_as_the_shipped_files_carry_notes()
    {
        var copy = """
            {
              "lastReviewed": "2026-09-16",
              "reviewWarningDays": 90,
              "upcomingEndWarningDays": 60,
              "notes": "Reviewed by the service desk.",
              "windows11": [ { "build": 28000, "version": "26H1", "homePro": null, "enterprise": null, "notes": "not yet known" } ],
              "serverSource": "https://example.com/lifecycle"
            }
            """;

        Assert.Null(ConfigFile.FindProblem("os-lifecycle.json", OverridePath, Encoding.UTF8.GetBytes(copy)));
    }

    [Fact]
    public void The_same_member_in_different_objects_is_fine()
    {
        var copy = """
            {
              "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60,
              "windows11": [ { "build": 26100, "version": "24H2" }, { "build": 26200, "version": "25H2" } ],
              "windowsServer": [ { "build": 26100, "version": "2025" } ]
            }
            """;

        Assert.Null(ConfigFile.FindProblem("os-lifecycle.json", OverridePath, Encoding.UTF8.GetBytes(copy)));
    }

    [Fact]
    public void The_file_s_name_matches_whatever_its_case_as_Windows_finds_the_file()
    {
        Assert.Null(ConfigFile.FindProblem("OS-Lifecycle.JSON", OverridePath, Encoding.UTF8.GetBytes(Valid)));
    }

    [Theory]
    [InlineData(new byte[] { 0x7B, 0xFF, 0x7D })]
    [InlineData(new byte[] { 0x7B, 0x22, 0xC3, 0x22, 0x3A, 0x31, 0x7D })]
    [InlineData(new byte[] { 0x7B, 0x22, 0xED, 0xA0, 0x80, 0x22, 0x3A, 0x31, 0x7D })]
    [InlineData(new byte[] { 0xEF, 0xBB, 0xBF, 0x7B, 0x22, 0xC0, 0xAF, 0x22, 0x3A, 0x31, 0x7D })]
    public void Text_that_is_not_UTF8_is_refused(byte[] copy)
    {
        Assert.Equal($"{OverridePath} is not UTF-8 text.", ConfigFile.FindProblem("os-lifecycle.json", OverridePath, copy));
    }

    [Fact]
    public void Only_one_byte_order_mark_is_taken_off()
    {
        var copy = Utf8Bom.GetBytes("\uFEFF" + Valid);

        Assert.StartsWith($"{OverridePath} is not valid JSON: ", ConfigFile.FindProblem("os-lifecycle.json", OverridePath, copy), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("[ { \"lastReviewed\": \"2026-09-16\" } ]")]
    [InlineData("null")]
    [InlineData("42")]
    [InlineData("\"os-lifecycle\"")]
    [InlineData("true")]
    public void Anything_but_a_JSON_object_is_refused(string copy)
    {
        Assert.Equal($"{OverridePath} is not a JSON object.", ConfigFile.FindProblem("os-lifecycle.json", OverridePath, Encoding.UTF8.GetBytes(copy)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("""{ "lastReviewed": """)]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60, }""")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60, "windows11": [ { "build": 26100 }, ] }""")]
    [InlineData("""{ /* reviewed */ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }""")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 } // reviewed""")]
    [InlineData("""{ 'lastReviewed': '2026-09-16', 'reviewWarningDays': 90, 'upcomingEndWarningDays': 60 }""")]
    [InlineData("""{ lastReviewed: "2026-09-16", reviewWarningDays: 90, upcomingEndWarningDays: 60 }""")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 } { "lastReviewed": "2020-01-01" }""")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 } x""")]
    public void Text_that_is_not_one_plain_well_formed_JSON_value_is_refused(string copy)
    {
        var problem = ConfigFile.FindProblem("os-lifecycle.json", OverridePath, Encoding.UTF8.GetBytes(copy));

        Assert.StartsWith($"{OverridePath} is not valid JSON: ", problem, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60, "lastReviewed": "2020-01-01" }""", "lastReviewed", 1)]
    [InlineData("{\n  \"LastReviewed\": \"2026-09-16\",\n  \"reviewWarningDays\": 90,\n  \"lastreviewed\": \"2020-01-01\",\n  \"upcomingEndWarningDays\": 60\n}", "lastreviewed", 4)]
    [InlineData("""{ "lastReviewed": "2026-09-16", "\u006castReviewed": "2020-01-01", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }""", "lastReviewed", 1)]
    [InlineData("{ \"lastReviewed\": \"2026-09-16\", \"reviewWarningDays\": 90, \"upcomingEndWarningDays\": 60,\n  \"windows11\": [ { \"build\": 26100, \"homePro\": \"2026-10-13\", \"build\": 22000 } ] }", "build", 2)]
    [InlineData("""{ "notes": "one", "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60, "Notes": "two" }""", "Notes", 1)]
    public void A_member_named_twice_in_one_object_is_refused_whatever_its_case(string copy, string member, int line)
    {
        Assert.Equal(
            $"{OverridePath} names {member} more than once in one object (line {line}), so which value counts is not clear.",
            ConfigFile.FindProblem("os-lifecycle.json", OverridePath, Encoding.UTF8.GetBytes(copy)));
    }

    [Theory]
    [InlineData("""{ "\ud800": 1 }""")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60, "\udc00": 1 }""")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60, "windows11": [ { "build": 26100, "x\ud800y": 1 } ] }""")]
    public void A_member_named_by_an_escaped_lone_surrogate_is_refused_not_thrown(string copy)
    {
        // Plain ASCII, so it is UTF-8, and well formed JSON; but the name is no string, and reading it throws.
        var problem = ConfigFile.FindProblem("os-lifecycle.json", OverridePath, Encoding.UTF8.GetBytes(copy));

        Assert.StartsWith($"{OverridePath} is not valid JSON: ", problem, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{ "lastReviewed": "\ud800", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }""")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60, "windows11": [ { "build": 26100, "version": "24H2\udc00" } ] }""")]
    public void A_value_the_file_s_reader_reads_that_is_an_escaped_lone_surrogate_is_refused_not_thrown(string copy)
    {
        var problem = ConfigFile.FindProblem("os-lifecycle.json", OverridePath, Encoding.UTF8.GetBytes(copy));

        Assert.StartsWith($"{OverridePath} is not a valid os-lifecycle.json: ", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void Nesting_as_deep_as_the_limit_passes_and_any_deeper_is_refused()
    {
        // The file's object is the first level, so a member may hold arrays one fewer deep than the limit.
        static byte[] Nested(int arrays) => Encoding.UTF8.GetBytes(
            """{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60, "notes": """
            + new string('[', arrays) + new string(']', arrays) + " }");

        Assert.Null(ConfigFile.FindProblem("os-lifecycle.json", OverridePath, Nested(ConfigFile.MaxDepth - 1)));
        Assert.StartsWith($"{OverridePath} is not valid JSON: ", ConfigFile.FindProblem("os-lifecycle.json", OverridePath, Nested(ConfigFile.MaxDepth)), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{ "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }""")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": "ninety", "upcomingEndWarningDays": 60 }""")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60, "windows11": { "build": 26100 } }""")]
    [InlineData("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60, "windows11": [ { "build": "24H2" } ] }""")]
    [InlineData("""{ "lastReviewed": 20260916, "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }""")]
    public void A_copy_the_file_s_reader_does_not_accept_is_refused(string copy)
    {
        var problem = ConfigFile.FindProblem("os-lifecycle.json", OverridePath, Encoding.UTF8.GetBytes(copy));

        Assert.StartsWith($"{OverridePath} is not a valid os-lifecycle.json: ", problem, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("thresholds.json")]
    [InlineData("")]
    [InlineData("../config/os-lifecycle.json")]
    public void A_file_the_tool_does_not_read_has_no_schema(string name)
    {
        Assert.Throws<ArgumentException>(() => ConfigFile.FindProblem(name, OverridePath, Encoding.UTF8.GetBytes(Valid)));
    }
}
