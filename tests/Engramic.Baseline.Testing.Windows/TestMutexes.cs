using System.Security.AccessControl;

namespace Engramic.Baseline.Testing.Windows;

/// <summary>
/// Mutexes under names of the tests' own, in the global namespace: never the product's
/// Global\EngramicBaselineAudit, which a real audit or install on this machine may hold.
/// </summary>
public static class TestMutexes
{
    /// <summary>Makes a unique name.</summary>
    /// <returns>The name.</returns>
    public static string NewName() => @"Global\Engramic.Baseline.Tests." + Guid.NewGuid().ToString("n");

    /// <summary>Creates, or opens, a mutex that the account running the tests may open again.</summary>
    /// <param name="name">The name.</param>
    /// <returns>The mutex, not held.</returns>
    public static Mutex OpenableByTheTests(string name)
    {
        return Create(name, $"D:P(A;;0x1f0001;;;SY)(A;;0x1f0001;;;BA)(A;;0x1f0001;;;{Elevation.CurrentUser})");
    }

    /// <summary>Creates a mutex with the access list a test gives, as another program could make it first.</summary>
    /// <param name="name">The name.</param>
    /// <param name="sddl">The access list, such as D:P(A;;0x1f0001;;;SY) for SYSTEM alone.</param>
    /// <returns>The mutex, not held; this handle has every right, as its creator's does.</returns>
    public static Mutex Create(string name, string sddl)
    {
        var security = new MutexSecurity();
        security.SetSecurityDescriptorSddlForm(sddl);
        return MutexAcl.Create(initiallyOwned: false, name, out _, security);
    }

    /// <summary>Runs something on a thread of its own, where a mutex held by the calling thread is someone else's.</summary>
    /// <typeparam name="T">What it gives.</typeparam>
    /// <param name="action">What to run.</param>
    /// <returns>What it gave; what it threw is thrown here.</returns>
    public static T OnOtherThread<T>(Func<T> action)
    {
        T? result = default;
        Exception? error = null;
        var thread = new Thread(() =>
        {
            try
            {
                result = action();
            }
            catch (Exception e)
            {
                error = e;
            }
        });
        thread.Start();
        thread.Join();
        return error is null ? result! : throw error;
    }

    /// <summary>Tells whether another thread could take a mutex now, releasing it again if so.</summary>
    /// <param name="mutex">A handle on the mutex.</param>
    /// <returns>True when it is free.</returns>
    public static bool IsFree(Mutex mutex)
    {
        return OnOtherThread(() =>
        {
            bool taken;
            try
            {
                taken = mutex.WaitOne(0);
            }
            catch (AbandonedMutexException)
            {
                taken = true;
            }

            if (taken)
            {
                mutex.ReleaseMutex();
            }

            return taken;
        });
    }
}
