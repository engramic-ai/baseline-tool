using System.Runtime.CompilerServices;

namespace Engramic.Baseline.Engine.Tests;

/// <summary>
/// Waits that give up: a test waiting on work that runs on other threads fails within seconds, naming what it
/// waited for, instead of hanging the whole test run when that work never finishes.
/// </summary>
internal static class Bounded
{
    /// <summary>
    /// How long a test waits for something that should happen at once: far longer than that takes on a slow, busy
    /// machine, and far shorter than a hung run takes to be noticed.
    /// </summary>
    public static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    /// <summary>Waits for a task, and fails the test if it has not finished in time.</summary>
    /// <param name="task">What to wait for.</param>
    /// <param name="what">What the failure names; the awaited expression by default.</param>
    /// <returns>The task, finished.</returns>
    public static async Task WithTimeout(this Task task, [CallerArgumentExpression(nameof(task))] string what = "")
    {
        try
        {
            await task.WaitAsync(Wait, TestContext.Current.CancellationToken);
        }
        catch (TimeoutException) when (!task.IsCompleted)
        {
            throw new TimeoutException($"Waited {Wait.TotalSeconds:0} seconds for {what}.");
        }
    }

    /// <summary>Waits for a task's result, and fails the test if it has not finished in time.</summary>
    /// <typeparam name="T">The type of the result.</typeparam>
    /// <param name="task">What to wait for.</param>
    /// <param name="what">What the failure names; the awaited expression by default.</param>
    /// <returns>The result.</returns>
    public static async Task<T> WithTimeout<T>(this Task<T> task, [CallerArgumentExpression(nameof(task))] string what = "")
    {
        await ((Task)task).WithTimeout(what);
        return await task;
    }
}
