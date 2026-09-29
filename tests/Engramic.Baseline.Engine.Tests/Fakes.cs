using System.Threading.Channels;
using Engramic.Baseline.Model;
using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Engine.Tests;

/// <summary>A check whose metadata and behaviour a test sets.</summary>
internal sealed class FakeCheck(CheckInfo info, Func<CheckContext, CancellationToken, ValueTask<IReadOnlyList<CheckResult>>>? run = null) : Check
{
    public override CheckInfo Info { get; } = info;

    public Func<DeviceContext, Applicability>? Applies { get; init; }

    public int Runs { get; private set; }

    public static FakeCheck Returning(CheckInfo info, params CheckResult[] results)
    {
        return new FakeCheck(info, (_, _) => ValueTask.FromResult<IReadOnlyList<CheckResult>>(results));
    }

    public override Applicability AppliesTo(DeviceContext device) => Applies is null ? base.AppliesTo(device) : Applies(device);

    public override ValueTask<IReadOnlyList<CheckResult>> RunAsync(CheckContext context, CancellationToken cancel)
    {
        Runs++;
        return run is null ? ValueTask.FromResult<IReadOnlyList<CheckResult>>([new CheckResult(FindingStatus.Pass)]) : run(context, cancel);
    }
}

/// <summary>
/// A fake clock that tells a test when a timer is started on it, so the test moves the time only once the code
/// under test is waiting for it, whichever threads run what and in whatever order.
/// </summary>
internal sealed class WatchedClock(DateTimeOffset now) : FakeTimeProvider(now)
{
    private readonly Channel<TimeSpan> _started = Channel.CreateUnbounded<TimeSpan>();

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = base.CreateTimer(callback, state, dueTime, period);
        _ = _started.Writer.TryWrite(dueTime);
        return timer;
    }

    /// <summary>Waits for the next timer started on this clock, failing the test if none is started in time.</summary>
    /// <returns>How long after it was started the timer is due.</returns>
    public Task<TimeSpan> NextTimerAsync() => _started.Reader.ReadAsync(TestContext.Current.CancellationToken).AsTask().WithTimeout("a timer to be started on the clock");
}

/// <summary>Config files held in memory, by name.</summary>
internal sealed class ConfigFiles(Dictionary<string, string>? files = null) : IConfigFiles
{
    public byte[]? Read(string name)
    {
        return files is not null && files.TryGetValue(name, out var text) ? System.Text.Encoding.UTF8.GetBytes(text) : null;
    }
}

internal static class Samples
{
    public static readonly DateTimeOffset AuditTime = new(2026, 9, 29, 14, 3, 49, TimeSpan.Zero);

    public static CheckInfo Info(
        string id,
        CheckCategory category = CheckCategory.SecurityUpdateManagement,
        Severity severity = Severity.High,
        IReadOnlyList<string>? frameworks = null,
        CheckScope scope = CheckScope.Machine,
        bool autoFail = false,
        bool requiresAdmin = false)
    {
        return new CheckInfo(id, "Title of " + id, category, severity, frameworks ?? [FrameworkTags.CeV33], "Reference of " + id, scope, autoFail, requiresAdmin);
    }

    public static DeviceContext Device(bool elevated = false, bool system = false) => new()
    {
        ComputerName = "DEVICE01",
        OSFamily = "Windows 11",
        InstallationType = "Client",
        ProductName = "Windows 10 Pro",
        EditionId = "Professional",
        EditionClass = "Pro",
        DisplayVersion = "24H2",
        Build = 26100,
        Ubr = 4946,
        RunningAs = system ? @"NT AUTHORITY\SYSTEM" : @"CONTOSO\alex",
        IsElevated = elevated || system,
        IsSystem = system,
        AuditTime = AuditTime,
    };

    public static CheckContext Context(DeviceContext? device = null, TimeProvider? time = null)
    {
        return new CheckContext(device ?? Device(), new AuditConfig(new ConfigFiles()), time ?? new FakeTimeProvider(AuditTime));
    }

    public static CheckCatalog Catalog(params Check[] checks) => new CheckCatalog.Builder().AddRange(checks).Build();
}
