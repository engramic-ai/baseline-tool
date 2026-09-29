using System.Globalization;
using Engramic.Baseline.Model;

namespace Engramic.Baseline.Engine;

/// <summary>
/// Runs checks and turns their results into findings, as the PowerShell tool's Invoke-CEAuditCore does.
/// </summary>
/// <remarks>
/// Checks run one at a time, in catalog order, and each is isolated: whatever happens to one never stops
/// the others. For each check:
/// <list type="number">
/// <item>An admin-only check is Skipped when the audit is not elevated, with the PowerShell tool's words.</item>
/// <item>A check that does not apply to the device is NotApplicable, with its reason. If deciding that
/// throws, it is NotApplicable too, with the error.</item>
/// <item>Otherwise it runs, on a thread of its own. An exception, no result at all, or running longer
/// than the time allowed (new in this tool), counted from when it starts, whether it yields or blocks,
/// makes an Error finding instead of its results. A check that runs out of time is told to stop through
/// its token, and the audit goes on without waiting for it.</item>
/// </list>
/// Stopping the audit through its cancellation token stops the run, and tells the running check to stop;
/// nothing else stops the run.
/// </remarks>
public sealed class AuditRunner
{
    /// <summary>What a skipped admin-only check found: the PowerShell tool's words, until the wording is reviewed.</summary>
    public const string SkippedActual = "Not run: requires an elevated (Run as administrator) PowerShell session.";

    /// <summary>What to do about a skipped admin-only check: the PowerShell tool's words, until the wording is reviewed.</summary>
    public const string SkippedRecommendation = "Re-run the audit from an elevated PowerShell prompt.";

    /// <summary>The result of a check that gave none.</summary>
    public const string NoResultActual = "Check returned no result.";

    /// <summary>What to do about a check that failed with an exception.</summary>
    public const string FailedRecommendation = "Investigate manually; see Evidence.";

    /// <summary>What to do about a check that ran out of time.</summary>
    public const string TimedOutRecommendation = "Run the audit again. If this check keeps running out of time, investigate manually.";

    private readonly CheckCatalog _catalog;
    private readonly AuditRunnerOptions _options;

    /// <summary>Makes a runner for the checks of a catalog.</summary>
    /// <param name="catalog">The checks the runner can run.</param>
    /// <param name="options">How long a check may take; the defaults when null.</param>
    public AuditRunner(CheckCatalog catalog, AuditRunnerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        options ??= new AuditRunnerOptions();
        if (options.CheckTimeout <= TimeSpan.Zero && options.CheckTimeout != Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.CheckTimeout, "The time a check may take must be positive, or infinite.");
        }

        _catalog = catalog;
        _options = options;
    }

    /// <summary>Runs the checks a selection matches.</summary>
    /// <param name="selection">Which checks to run.</param>
    /// <param name="context">What the checks may use; the same for every check.</param>
    /// <param name="cancel">Stops the audit.</param>
    /// <returns>The findings, check by check in catalog order, each check's in the order it gave them.</returns>
    /// <exception cref="OperationCanceledException"><paramref name="cancel"/> was cancelled.</exception>
    public async Task<IReadOnlyList<Finding>> RunAsync(CheckSelection selection, CheckContext context, CancellationToken cancel = default)
    {
        ArgumentNullException.ThrowIfNull(selection);
        ArgumentNullException.ThrowIfNull(context);
        var findings = new List<Finding>();
        foreach (var check in _catalog.Select(selection))
        {
            cancel.ThrowIfCancellationRequested();
            findings.AddRange(await RunCheckAsync(check, context, cancel).ConfigureAwait(false));
        }

        return findings;
    }

    private static Finding[] One(CheckInfo info, CheckResult result) => [FindingFactory.Create(info, result)];

    private static string Describe(TimeSpan time)
    {
        return time.TotalMinutes >= 1 && time.TotalMinutes == Math.Floor(time.TotalMinutes)
            ? string.Create(CultureInfo.InvariantCulture, $"{time.TotalMinutes:0} minute{(time.TotalMinutes == 1 ? string.Empty : "s")}")
            : string.Create(CultureInfo.InvariantCulture, $"{time.TotalSeconds:0.###} seconds");
    }

    private static IEnumerable<string> EvidenceOf(Exception error)
    {
        yield return error.GetType().FullName ?? error.GetType().Name;
        var where = error.StackTrace?.Split('\n', 2)[0].Trim();
        if (!string.IsNullOrEmpty(where))
        {
            yield return where;
        }
    }

    // Starts a check on a thread of its own rather than a thread pool thread. The time allowed then covers what the
    // check does before it first yields, such as blocking on a registry, CIM or process call, and a check that never
    // returns holds only that thread, leaving the pool to the timers, the callbacks and the checks after it. The check
    // is called even if its time has run out before its thread starts, and its token then tells it to stop.
    private static Task<IReadOnlyList<CheckResult>> Start(Check check, CheckContext context, CancellationToken stop)
    {
        return Task.Factory.StartNew(
            () => check.RunAsync(context, stop).AsTask(),
            CancellationToken.None,
            TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach,
            TaskScheduler.Default).Unwrap();
    }

    // Tells a check to stop without waiting for it: the token is cancelled at once, and the check's callbacks run on
    // the thread pool, as one that blocks must not hold up the audit, and one that throws is not the audit's concern.
    private static void Stop(CancellationTokenSource stop)
    {
        try
        {
            _ = stop.CancelAsync().ContinueWith(
                static stopping => { _ = stopping.Exception; },
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
        catch (ObjectDisposedException)
        {
            // The check finished as its time ran out, and its token went with it: there is nothing to stop.
        }
    }

    private async Task<IReadOnlyList<Finding>> RunCheckAsync(Check check, CheckContext context, CancellationToken cancel)
    {
        var info = check.Info;
        if (info.RequiresAdmin && !context.Device.IsElevated)
        {
            return One(info, new CheckResult(FindingStatus.Skipped) { Actual = SkippedActual, Recommendation = SkippedRecommendation });
        }

        Applicability applies;
        try
        {
            applies = check.AppliesTo(context.Device);
        }
        catch (Exception e)
        {
            applies = Applicability.NotApplicable("Applicability test failed: " + e.Message);
        }

        if (!applies.IsApplicable)
        {
            return One(info, new CheckResult(FindingStatus.NotApplicable) { Actual = applies.Reason });
        }

        // The check's token, cancelled when the audit stops or the check runs out of time. It lasts as long as the
        // check does, which can be longer than the runner waits for it, so the check always hears that it should stop.
        var stop = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        var running = Start(check, context, stop.Token);
        _ = running.ContinueWith(
            static (ran, source) =>
            {
                // Observed here, as a check that was left behind can still fail once nothing is waiting for it.
                _ = ran.Exception;
                ((CancellationTokenSource)source!).Dispose();
            },
            stop,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        try
        {
            var results = await running.WaitAsync(_options.CheckTimeout, context.Time, cancel).ConfigureAwait(false);
            var findings = (results ?? []).Where(r => r is not null).Select(r => FindingFactory.Create(info, r)).ToArray();
            return findings.Length > 0 ? findings : One(info, new CheckResult(FindingStatus.Error) { Actual = NoResultActual });
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested)
        {
            throw;
        }
        catch (TimeoutException timeout) when (running.Exception?.InnerException != timeout)
        {
            // The time ran out, as opposed to the check throwing a TimeoutException of its own. Tell the check to stop
            // and go on: one that ignores its token is left to finish on its own, and its result is not used.
            Stop(stop);
            return One(info, new CheckResult(FindingStatus.Error)
            {
                Actual = $"Check failed: it did not finish within {Describe(_options.CheckTimeout)}, so it was stopped.",
                Recommendation = TimedOutRecommendation,
            });
        }
        catch (Exception e)
        {
            return One(info, new CheckResult(FindingStatus.Error)
            {
                Actual = "Check failed: " + e.Message,
                Recommendation = FailedRecommendation,
                Evidence = [.. EvidenceOf(e)],
            });
        }
    }
}

/// <summary>
/// How the runner runs checks.
/// </summary>
public sealed record AuditRunnerOptions
{
    /// <summary>
    /// Gets how long one check may run before it is stopped and reported as an Error: 10 minutes by default,
    /// longer than the slowest check (the online Windows Update search) takes on a slow connection.
    /// <see cref="Timeout.InfiniteTimeSpan"/> lets checks run as long as they take.
    /// </summary>
    public TimeSpan CheckTimeout { get; init; } = TimeSpan.FromMinutes(10);
}
