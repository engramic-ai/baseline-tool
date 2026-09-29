using System.Security.AccessControl;
using System.Security.Principal;

namespace Engramic.Baseline.Windows;

/// <summary>
/// The audit mutex, which lets one audit run at a time and makes an install wait for a running audit. The
/// PowerShell tool's scheduled audit and installer take the same one, Global\EngramicBaselineAudit.
/// </summary>
/// <remarks>
/// <para>
/// It is created with an access list that grants SYSTEM and Administrators alone, protected from
/// inheritance, set in the call that creates it (MutexAcl), never afterwards. When it already exists it is
/// opened for the full rights MutexAcl asks for; if its access list does not grant them, as when a
/// standard user made it first to block audits, opening it fails as access denied, which the scheduled
/// audit counts as a failed run rather than running unguarded.
/// </para>
/// <para>
/// A mutex belongs to the thread that took it: dispose of this object on that thread.
/// </para>
/// </remarks>
public sealed class AuditMutex : IDisposable
{
    /// <summary>The name of the product's audit mutex, in the global namespace every session shares.</summary>
    public const string MachineName = @"Global\EngramicBaselineAudit";

    /// <summary>MUTEX_ALL_ACCESS, which MutexAcl asks for: what the access list grants SYSTEM and Administrators.</summary>
    private const MutexRights AllAccess = MutexRights.FullControl;

    private readonly Mutex _mutex;
    private bool _released;

    private AuditMutex(Mutex mutex) => _mutex = mutex;

    /// <summary>Takes the mutex, creating it if need be, waiting until it is free or the time runs out.</summary>
    /// <param name="name">The mutex's name: <see cref="MachineName"/> for the product, another for a test.</param>
    /// <param name="timeout">How long to wait while another holder has it.</param>
    /// <returns>The mutex, held until disposed; or null when another holder kept it for the whole time.</returns>
    /// <exception cref="UnauthorizedAccessException">The mutex exists, and its access list does not let this account use it.</exception>
    /// <exception cref="WaitHandleCannotBeOpenedException">Something other than a mutex has that name.</exception>
    /// <exception cref="IOException">Windows refused to create or open it for another reason.</exception>
    public static AuditMutex? TryAcquire(string name, TimeSpan timeout)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        var mutex = MutexAcl.Create(initiallyOwned: false, name, out _, Security());
        var held = false;
        try
        {
            try
            {
                held = mutex.WaitOne(timeout);
            }
            catch (AbandonedMutexException)
            {
                // The last holder ended without releasing it, and this thread now holds it, as the PowerShell tool takes it.
                held = true;
            }

            return held ? new AuditMutex(mutex) : null;
        }
        finally
        {
            if (!held)
            {
                mutex.Dispose();
            }
        }
    }

    /// <summary>Releases the mutex and closes it. Call it on the thread that took it.</summary>
    public void Dispose()
    {
        if (_released)
        {
            return;
        }

        _released = true;
        try
        {
            _mutex.ReleaseMutex();
        }
        finally
        {
            _mutex.Dispose();
        }
    }

    /// <summary>The access list the mutex is created with: SYSTEM and Administrators, all access, nothing inherited.</summary>
    /// <returns>The security descriptor, without an owner, which Windows takes from the creator.</returns>
    internal static MutexSecurity Security()
    {
        var security = new MutexSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), AllAccess, AccessControlType.Allow));
        security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), AllAccess, AccessControlType.Allow));
        return security;
    }
}
