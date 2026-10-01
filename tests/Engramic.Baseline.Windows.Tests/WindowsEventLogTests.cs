using Engramic.Baseline.Platform;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// The Application log writer's checks, which need no log. Writing to the real log is left to an elevated
/// test that CI runs, under a source of the tests' own.
/// </summary>
public sealed class WindowsEventLogTests
{
    [Fact]
    public void Writes_under_the_installer_s_event_source_for_the_product()
    {
        Assert.Equal("EngramicBaseline", WindowsEventLog.ProductSource);
        Assert.Equal("EngramicBaseline", new WindowsEventLog(WindowsEventLog.ProductSource).Source);
    }

    [Fact]
    public void Needs_a_source()
    {
        Assert.Throws<ArgumentException>(() => new WindowsEventLog(string.Empty));
        Assert.Throws<ArgumentNullException>(() => new WindowsEventLog(null!));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(65536)]
    public void Refuses_an_event_identifier_Windows_would_not_keep(int eventId)
    {
        var log = new WindowsEventLog("EngramicBaselineTests");

        Assert.Throws<ArgumentOutOfRangeException>(() => log.Write(eventId, EventLogLevel.Warning, "never written"));
    }

    [Fact]
    public void Refuses_a_level_that_is_not_one_and_a_missing_message()
    {
        var log = new WindowsEventLog("EngramicBaselineTests");

        Assert.Throws<ArgumentOutOfRangeException>(() => log.Write(1003, (EventLogLevel)7, "never written"));
        Assert.Throws<ArgumentNullException>(() => log.Write(1003, EventLogLevel.Warning, null!));
    }

    [Fact]
    public void The_machine_options_record_notices_in_the_Application_log_under_that_source()
    {
        var options = SecureStoreOptions.ForMachine(new Testing.FakeRegistry(), TimeProvider.System);

        Assert.Equal(WindowsEventLog.ProductSource, Assert.IsType<WindowsEventLog>(options.EventLog).Source);
    }
}
