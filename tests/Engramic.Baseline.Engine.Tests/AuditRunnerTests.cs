using Engramic.Baseline.Model;
using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Engine.Tests;

public sealed class AuditRunnerTests
{
    [Fact]
    public async Task Turns_each_result_into_a_finding_with_the_check_s_details()
    {
        var info = Samples.Info("SU-01", frameworks: [FrameworkTags.CeV33, FrameworkTags.CePlusTC2], severity: Severity.Critical, autoFail: true);
        var check = FakeCheck.Returning(
            info,
            new CheckResult(FindingStatus.Warn) { Subject = "Lifecycle data", Severity = Severity.Low, Expected = "e", Actual = "a", Recommendation = "r", Evidence = ["one", "two"] },
            new CheckResult(FindingStatus.Pass) { Expected = "Supported Windows version", Actual = "fine" });

        var findings = await Run(Samples.Catalog(check));

        Assert.Equal(2, findings.Count);
        var warn = findings[0];
        Assert.Equal("SU-01:Lifecycle-data", warn.FindingId);
        Assert.Equal("SU-01", warn.CheckId);
        Assert.Equal(info.Title, warn.Title);
        Assert.Equal("Lifecycle data", warn.Subject);
        Assert.Equal(info.Category, warn.Category);
        Assert.Equal(["CE v3.3", "CE+ TC2"], warn.Frameworks);
        Assert.Equal(info.Reference, warn.Reference);
        Assert.Equal(CheckScope.Machine, warn.Scope);
        Assert.Equal(FindingStatus.Warn, warn.Status);
        Assert.Equal(Severity.Low, warn.Severity);
        Assert.False(warn.AutoFail);
        Assert.Equal(("e", "a", "r"), (warn.Expected, warn.Actual, warn.Recommendation));
        Assert.Equal(["one", "two"], warn.Evidence);
        Assert.Null(warn.Remediation);
        Assert.Null(warn.Pack);
        Assert.Equal("SU-01", findings[1].FindingId);
        Assert.Equal(Severity.Info, findings[1].Severity);
    }

    [Theory]
    // A result that passes, does not apply or only informs is Info; anything else keeps its severity.
    [InlineData(FindingStatus.Pass, null, Severity.Info)]
    [InlineData(FindingStatus.NotApplicable, Severity.High, Severity.Info)]
    [InlineData(FindingStatus.Info, null, Severity.Info)]
    [InlineData(FindingStatus.Fail, null, Severity.Critical)]
    [InlineData(FindingStatus.Fail, Severity.Medium, Severity.Medium)]
    [InlineData(FindingStatus.Warn, Severity.High, Severity.High)]
    [InlineData(FindingStatus.Manual, null, Severity.Critical)]
    [InlineData(FindingStatus.Skipped, null, Severity.Critical)]
    [InlineData(FindingStatus.Error, null, Severity.Critical)]
    public async Task The_severity_is_the_result_s_or_the_check_s_and_Info_for_results_that_do_not_fail(FindingStatus status, Severity? own, Severity expected)
    {
        var check = FakeCheck.Returning(Samples.Info("SU-01", severity: Severity.Critical), new CheckResult(status) { Severity = own });

        var finding = Assert.Single(await Run(Samples.Catalog(check)));

        Assert.Equal(expected, finding.Severity);
    }

    [Theory]
    [InlineData(FindingStatus.Fail, true, true)]
    [InlineData(FindingStatus.Error, true, false)]
    [InlineData(FindingStatus.Warn, true, false)]
    [InlineData(FindingStatus.Pass, true, false)]
    [InlineData(FindingStatus.Fail, false, false)]
    public async Task Only_a_failing_result_of_an_auto_fail_check_is_an_auto_fail_finding(FindingStatus status, bool autoFailCheck, bool expected)
    {
        var check = FakeCheck.Returning(Samples.Info("SU-01", autoFail: autoFailCheck), new CheckResult(status));

        Assert.Equal(expected, Assert.Single(await Run(Samples.Catalog(check))).AutoFail);
    }

    [Fact]
    public async Task Skips_an_admin_only_check_when_the_audit_is_not_elevated_with_the_PowerShell_tool_s_words()
    {
        var check = FakeCheck.Returning(Samples.Info("NC-01", severity: Severity.High, requiresAdmin: true), new CheckResult(FindingStatus.Pass));

        var finding = Assert.Single(await Run(Samples.Catalog(check), Samples.Device(elevated: false)));

        Assert.Equal(FindingStatus.Skipped, finding.Status);
        Assert.Equal("Not run: requires an elevated (Run as administrator) PowerShell session.", finding.Actual);
        Assert.Equal("Re-run the audit from an elevated PowerShell prompt.", finding.Recommendation);
        Assert.Equal(string.Empty, finding.Expected);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("NC-01", finding.FindingId);
        Assert.Equal(0, check.Runs);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Runs_an_admin_only_check_when_elevated_or_SYSTEM(bool elevated, bool system)
    {
        var check = FakeCheck.Returning(Samples.Info("NC-01", requiresAdmin: true), new CheckResult(FindingStatus.Pass));

        var finding = Assert.Single(await Run(Samples.Catalog(check), Samples.Device(elevated, system)));

        Assert.Equal(FindingStatus.Pass, finding.Status);
        Assert.Equal(1, check.Runs);
    }

    [Fact]
    public async Task Skipping_comes_before_asking_whether_the_check_applies()
    {
        var check = new FakeCheck(Samples.Info("NC-01", requiresAdmin: true)) { Applies = _ => Applicability.NotApplicable("No.") };

        Assert.Equal(FindingStatus.Skipped, Assert.Single(await Run(Samples.Catalog(check))).Status);
    }

    [Fact]
    public async Task A_check_that_does_not_apply_gives_one_NotApplicable_finding_with_its_reason_and_does_not_run()
    {
        var check = new FakeCheck(Samples.Info("UA-08")) { Applies = _ => Applicability.NotApplicable("Not joined to Entra ID.") };

        var finding = Assert.Single(await Run(Samples.Catalog(check)));

        Assert.Equal(FindingStatus.NotApplicable, finding.Status);
        Assert.Equal("Not joined to Entra ID.", finding.Actual);
        Assert.Equal(Severity.Info, finding.Severity);
        Assert.Equal(0, check.Runs);
    }

    [Fact]
    public async Task Without_a_reason_the_PowerShell_tool_s_default_is_given()
    {
        var check = new FakeCheck(Samples.Info("UA-08")) { Applies = _ => Applicability.NotApplicable() };

        Assert.Equal("Not applicable to this device.", Assert.Single(await Run(Samples.Catalog(check))).Actual);
    }

    [Fact]
    public async Task A_check_whose_applicability_test_throws_does_not_apply()
    {
        var check = new FakeCheck(Samples.Info("UA-08")) { Applies = _ => throw new InvalidOperationException("boom") };

        var finding = Assert.Single(await Run(Samples.Catalog(check)));

        Assert.Equal(FindingStatus.NotApplicable, finding.Status);
        Assert.Equal("Applicability test failed: boom", finding.Actual);
        Assert.Equal(0, check.Runs);
    }

    [Fact]
    public async Task An_exception_becomes_one_Error_finding_and_the_audit_goes_on()
    {
        var failing = new FakeCheck(Samples.Info("FW-01", severity: Severity.Critical), (_, _) => throw new InvalidOperationException("boom"));
        var next = FakeCheck.Returning(Samples.Info("FW-02"), new CheckResult(FindingStatus.Pass));

        var findings = await Run(Samples.Catalog(failing, next));

        Assert.Equal(2, findings.Count);
        var error = findings[0];
        Assert.Equal(FindingStatus.Error, error.Status);
        Assert.Equal("Check failed: boom", error.Actual);
        Assert.Equal("Investigate manually; see Evidence.", error.Recommendation);
        Assert.Equal("System.InvalidOperationException", error.Evidence[0]);
        Assert.Equal(Severity.Critical, error.Severity);
        Assert.Equal("FW-01", error.FindingId);
        Assert.Equal(FindingStatus.Pass, findings[1].Status);
    }

    [Fact]
    public async Task An_exception_from_an_asynchronous_check_is_an_Error_finding_too()
    {
        var failing = new FakeCheck(Samples.Info("FW-01"), async (_, cancel) =>
        {
            await Task.Yield();
            throw new InvalidDataException("config/x.json is missing.");
        });

        var finding = Assert.Single(await Run(Samples.Catalog(failing)));

        Assert.Equal("Check failed: config/x.json is missing.", finding.Actual);
        Assert.Equal("System.IO.InvalidDataException", finding.Evidence[0]);
    }

    [Fact]
    public async Task A_check_that_gives_no_result_is_an_Error()
    {
        var empty = FakeCheck.Returning(Samples.Info("FW-01"));

        var finding = Assert.Single(await Run(Samples.Catalog(empty)));

        Assert.Equal(FindingStatus.Error, finding.Status);
        Assert.Equal("Check returned no result.", finding.Actual);
        Assert.Equal(string.Empty, finding.Recommendation);
    }

    [Fact]
    public async Task A_check_that_runs_out_of_time_is_stopped_and_reported_as_an_Error()
    {
        var time = new FakeTimeProvider(Samples.AuditTime);
        var stopped = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var slow = new FakeCheck(Samples.Info("SU-03"), async (_, cancel) =>
        {
            using var registration = cancel.Register(() => stopped.TrySetResult(true));
            await Task.Delay(Timeout.InfiniteTimeSpan, cancel);
            return [];
        });
        var next = FakeCheck.Returning(Samples.Info("SU-04"), new CheckResult(FindingStatus.Pass));
        var runner = new AuditRunner(Samples.Catalog(slow, next), new AuditRunnerOptions { CheckTimeout = TimeSpan.FromMinutes(10) });

        var run = runner.RunAsync(CheckSelection.All, Samples.Context(time: time), TestContext.Current.CancellationToken);
        time.Advance(TimeSpan.FromMinutes(9));
        Assert.False(run.IsCompleted);
        time.Advance(TimeSpan.FromMinutes(1));
        var findings = await run;

        Assert.Equal(2, findings.Count);
        Assert.Equal(FindingStatus.Error, findings[0].Status);
        Assert.Equal("Check failed: it did not finish within 10 minutes, so it was stopped.", findings[0].Actual);
        Assert.Equal("Run the audit again. If this check keeps running out of time, investigate manually.", findings[0].Recommendation);
        Assert.True(await stopped.Task);
        Assert.Equal(FindingStatus.Pass, findings[1].Status);
    }

    [Fact]
    public async Task A_check_that_ignores_being_stopped_is_left_behind()
    {
        var time = new FakeTimeProvider(Samples.AuditTime);
        var release = new TaskCompletionSource<IReadOnlyList<CheckResult>>(TaskCreationOptions.RunContinuationsAsynchronously);
        var stubborn = new FakeCheck(Samples.Info("SU-03"), (_, _) => new ValueTask<IReadOnlyList<CheckResult>>(release.Task));
        var runner = new AuditRunner(Samples.Catalog(stubborn), new AuditRunnerOptions { CheckTimeout = TimeSpan.FromSeconds(90) });

        var run = runner.RunAsync(CheckSelection.All, Samples.Context(time: time), TestContext.Current.CancellationToken);
        time.Advance(TimeSpan.FromSeconds(90));
        var finding = Assert.Single(await run);
        release.SetResult([new CheckResult(FindingStatus.Pass)]);

        Assert.Equal("Check failed: it did not finish within 90 seconds, so it was stopped.", finding.Actual);
    }

    [Fact]
    public async Task Stopping_the_audit_stops_the_run_instead_of_making_findings()
    {
        using var stop = new CancellationTokenSource();
        var check = new FakeCheck(Samples.Info("SU-03"), async (_, cancel) =>
        {
            await stop.CancelAsync();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancel);
            return [];
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new AuditRunner(Samples.Catalog(check)).RunAsync(CheckSelection.All, Samples.Context(), stop.Token));
    }

    [Fact]
    public async Task Checks_run_in_catalog_order_with_the_same_context()
    {
        var seen = new List<(string Id, CheckContext Context)>();
        Check Recording(string id) => new FakeCheck(Samples.Info(id), (context, _) =>
        {
            seen.Add((id, context));
            return ValueTask.FromResult<IReadOnlyList<CheckResult>>([new CheckResult(FindingStatus.Pass)]);
        });
        var context = Samples.Context();

        var findings = await new AuditRunner(Samples.Catalog(Recording("SU-02"), Recording("FW-01"), Recording("SU-01")))
            .RunAsync(CheckSelection.All, context, TestContext.Current.CancellationToken);

        Assert.Equal(["SU-02", "FW-01", "SU-01"], findings.Select(f => f.CheckId));
        Assert.All(seen, s => Assert.Same(context, s.Context));
    }

    [Fact]
    public void The_time_a_check_may_take_must_be_positive()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuditRunner(Samples.Catalog(), new AuditRunnerOptions { CheckTimeout = TimeSpan.Zero }));
        _ = new AuditRunner(Samples.Catalog(), new AuditRunnerOptions { CheckTimeout = Timeout.InfiniteTimeSpan });
    }

    private static Task<IReadOnlyList<Finding>> Run(CheckCatalog catalog, DeviceContext? device = null)
    {
        return new AuditRunner(catalog).RunAsync(CheckSelection.All, Samples.Context(device), TestContext.Current.CancellationToken);
    }
}
