using Engramic.Baseline.Model;

namespace Engramic.Baseline.Contracts.Tests;

/// <summary>
/// The Intune discovery and detection scripts, unchanged, in 64-bit and 32-bit Windows PowerShell 5.1, on
/// status.json as Baseline writes it: what they report, and that a change to a key, its casing or the byte order
/// mark changes what they report wherever they can see it. Windows only.
/// </summary>
public sealed class IntuneReaderTests
{
    /// <summary>
    /// The reader probe as Baseline writes it now (the scripts measure the audit's age from the clock), and what
    /// the scripts reported for it: shared by the tests, as a run takes a few seconds.
    /// </summary>
    private static readonly Lazy<(byte[] File, IReadOnlyList<ReaderRun> Runs)> Probe = new(() =>
    {
        var file = WrittenNow(ContractSamples.ReaderProbe());
        return (file, IntuneReaders.Run(file));
    });

    public static TheoryData<string> Mutations => [.. StatusMutations.All.Select(m => m.Name)];

    [Fact]
    public void Each_script_runs_in_both_hosts_and_both_hosts_report_the_same()
    {
        SkipUnlessAvailable();

        var runs = Probe.Value.Runs;

        Assert.Equal(["Discover 64-bit", "Discover 32-bit", "Detect 64-bit", "Detect 32-bit"], runs.Select(r => $"{r.Script} {r.Bitness}"));
        Assert.All(runs, run =>
        {
            Assert.Equal(run.Bitness == "64-bit", run.Is64BitProcess);
            Assert.StartsWith("5.1.", run.PSVersion, StringComparison.Ordinal);
            Assert.False(run.TaskStartRequested, $"{run.Script} tried to start the scheduled audit.");
            Assert.Empty(run.Errors);
        });
        foreach (var script in new[] { "Discover", "Detect" })
        {
            var hosts = runs.Where(r => r.Script == script).ToList();
            Assert.Equal(hosts[0].Reported, hosts[1].Reported);
        }
    }

    [Fact]
    public void The_discovery_script_reads_every_value_of_the_probe_as_written()
    {
        SkipUnlessAvailable();

        var discover = Probe.Value.Runs.Single(r => r.Script == "Discover" && r.Bitness == "32-bit");

        Assert.Equal(0, discover.ExitCode);
        // Text beyond ASCII arrives intact: the byte order mark tells Windows PowerShell 5.1 the file is UTF-8.
        Assert.Equal(ContractSamples.ProbeToolVersion, discover.Value("CEToolVersion"));
        Assert.Equal("0", discover.Value("CEAuditAgeHours"));
        Assert.Equal("false", discover.Value("CEAuditError"));
        Assert.Equal("2", discover.Value("CEAutoFailCount"));
        Assert.Equal("3", discover.Value("CEFailCount"));
        Assert.Equal("3", discover.Value("CEReviewCount"));
        Assert.Equal("33", discover.Value("CEv33MetPct"));
        Assert.Equal("67", discover.Value("CENcscMetPct"));
        Assert.Equal("true", discover.Value("CEOSSupported"));
        Assert.Equal("false", discover.Value("CEPatchingOK"));
        Assert.Equal("Likely fail", discover.Value("CEPlusTC2"));
        Assert.Equal("Check", discover.Value("CEPlusTC3"));
        Assert.Equal("Likely pass", discover.Value("CEPlusTC5"));
        Assert.Equal("FW-02, SU-03, SU-05", discover.Value("CEFailing"));
    }

    [Fact]
    public void The_detection_script_reads_every_value_of_the_probe_as_written()
    {
        SkipUnlessAvailable();

        var detect = Probe.Value.Runs.Single(r => r.Script == "Detect" && r.Bitness == "32-bit");

        Assert.Equal(1, detect.ExitCode);
        Assert.Equal("false", detect.Value("LastRunError"));
        Assert.Equal("AUTO-FAIL", detect.Value("State"));
        Assert.Equal("2", detect.Value("AutoFail"));
        Assert.Equal("5", detect.Value("Attention"));
        Assert.Equal("1", detect.Value("Review"));
        Assert.Equal("0", detect.Value("AgeHours"));
        Assert.Equal("TC2=Likely fail TC3=Check TC4=Check TC5=Likely pass", detect.Value("CEPlus"));
        Assert.Equal(ContractSamples.ProbeToolVersion, detect.Value("Version"));
        Assert.Equal("SU-03,SU-05", detect.Value("Failing"));
    }

    [Theory]
    [InlineData("su01-pass", "true", "0", "", "100", "Likely pass", 0, "OK")]
    [InlineData("su01-fail", "false", "1", "SU-01", "0", "Likely fail", 1, "AUTO-FAIL")]
    public void Intune_takes_whether_the_operating_system_is_supported_from_SU_01(
        string sample, string supported, string autoFails, string failing, string metPct, string tc2, int detectExitCode, string state)
    {
        SkipUnlessAvailable();

        var runs = IntuneReaders.Run(WrittenNow(ContractSamples.Named(sample)));

        foreach (var discover in runs.Where(r => r.Script == "Discover"))
        {
            Assert.Equal(supported, discover.Value("CEOSSupported"));
            Assert.Equal(autoFails, discover.Value("CEAutoFailCount"));
            Assert.Equal(failing, discover.Value("CEFailing"));
            Assert.Equal(metPct, discover.Value("CEv33MetPct"));
            Assert.Equal("-1", discover.Value("CENcscMetPct"));
            Assert.Equal(tc2, discover.Value("CEPlusTC2"));
        }

        foreach (var detect in runs.Where(r => r.Script == "Detect"))
        {
            Assert.Equal(detectExitCode, detect.ExitCode);
            Assert.Equal(state, detect.Value("State"));
            Assert.Equal(failing, detect.Value("Failing"));
        }
    }

    [Theory]
    [MemberData(nameof(Mutations))]
    public void A_change_to_a_key_its_casing_or_the_byte_order_mark_changes_what_the_scripts_report_wherever_they_can_see_it(string name)
    {
        SkipUnlessAvailable();
        var mutation = StatusMutations.Named(name);
        var (file, before) = Probe.Value;

        var after = IntuneReaders.Run(mutation.Apply(file));

        Assert.Equal(before.Select(r => $"{r.Script} {r.Bitness}"), after.Select(r => $"{r.Script} {r.Bitness}"));
        var changes = before.Zip(after).Where(p => p.First.Reported != p.Second.Reported).Select(p => p.Second).ToList();
        Assert.All(after, run => Assert.False(run.TaskStartRequested, $"{run.Script} tried to start the scheduled audit."));
        if (mutation.ReadersSee)
        {
            // In each host, so the 32-bit reader is shown to depend on it as much as the 64-bit one.
            foreach (var bitness in new[] { "64-bit", "32-bit" })
            {
                Assert.True(
                    changes.Any(r => r.Bitness == bitness),
                    $"When {mutation.Change}, the scripts in {bitness} Windows PowerShell should report something else ({mutation.Why}), but they reported the same.");
            }
        }
        else
        {
            Assert.True(
                changes.Count == 0,
                $"When {mutation.Change}, the scripts were expected to report the same ({mutation.Why}), but {string.Join("; ", changes.Select(r => $"{r.Script} {r.Bitness} reported {r.Reported}"))}. Mark the change as one the readers see.");
        }
    }

    private static void SkipUnlessAvailable() => Assert.SkipWhen(IntuneReaders.Unavailable is not null, IntuneReaders.Unavailable ?? string.Empty);

    /// <summary>A sample as Baseline writes it, with an audit that ran a moment ago, so the scripts take it as current.</summary>
    private static byte[] WrittenNow(StatusDocument sample) => StatusFile.ToBytes(sample with { AuditTime = DateTimeOffset.UtcNow.AddSeconds(-5) });
}
