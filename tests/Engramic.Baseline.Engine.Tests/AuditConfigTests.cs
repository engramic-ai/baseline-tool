namespace Engramic.Baseline.Engine.Tests;

public sealed class AuditConfigTests
{
    [Fact]
    public void Reads_a_config_file_once_and_keeps_it()
    {
        var files = new CountingFiles("""{ "lastReviewed": "2026-09-16", "reviewWarningDays": 90, "upcomingEndWarningDays": 60 }""");
        var config = new AuditConfig(files);

        Assert.Same(config.OsLifecycle, config.OsLifecycle);
        Assert.Equal("2026-09-16", config.OsLifecycle.LastReviewed);
        Assert.Equal(1, files.Reads);
    }

    [Fact]
    public void A_missing_file_throws_when_it_is_first_read()
    {
        var config = new AuditConfig(new ConfigFiles());

        var error = Assert.Throws<InvalidDataException>(() => config.OsLifecycle);

        Assert.Equal("config/os-lifecycle.json is missing.", error.Message);
    }

    [Fact]
    public void A_file_that_is_not_valid_throws_saying_which()
    {
        var config = new AuditConfig(new ConfigFiles(new() { ["os-lifecycle.json"] = """{ "lastReviewed": "2026-09-16" }""" }));

        var error = Assert.Throws<InvalidDataException>(() => config.OsLifecycle);

        Assert.StartsWith("config/os-lifecycle.json is not valid: ", error.Message, StringComparison.Ordinal);
    }

    private sealed class CountingFiles(string lifecycle) : IConfigFiles
    {
        public int Reads { get; private set; }

        public byte[]? Read(string name)
        {
            Reads++;
            return name == "os-lifecycle.json" ? System.Text.Encoding.UTF8.GetBytes(lifecycle) : null;
        }
    }
}
