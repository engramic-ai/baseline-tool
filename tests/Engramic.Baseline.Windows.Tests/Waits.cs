using Microsoft.Extensions.Time.Testing;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>Runs SecureStore's waits on a fake clock, so that its retries take no real time.</summary>
internal static class Waits
{
    /// <summary>Gives up on something that has not finished after this long, and says so.</summary>
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(10);

    /// <summary>Runs an action on a thread of its own, moving a fake clock on until it finishes.</summary>
    /// <param name="clock">The clock the store waits by.</param>
    /// <param name="action">What to run: what it throws is thrown here.</param>
    public static void AdvanceUntilDone(FakeTimeProvider clock, Action action)
    {
        var done = Task.Factory.StartNew(action, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        var started = Environment.TickCount64;
        while (!done.IsCompleted)
        {
            if (Environment.TickCount64 - started > Limit.TotalMilliseconds)
            {
                throw new TimeoutException($"The store had not finished after {Limit.TotalSeconds} seconds of moving the clock on.");
            }

            clock.Advance(TimeSpan.FromMilliseconds(50));
            Thread.Sleep(1);
        }

        done.GetAwaiter().GetResult();
    }
}
