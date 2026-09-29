using System.Globalization;
using Engramic.Baseline.Controls;
using Engramic.Baseline.Engine;
using Engramic.Baseline.Model;
using Engramic.Baseline.Platform;
using Engramic.Baseline.Windows;

namespace Engramic.Baseline.Cli;

/// <summary>
/// The unattended audit that the scheduled task runs as SYSTEM, as the PowerShell tool's
/// Invoke-CEScheduledAudit.ps1 does, with what has been ported so far.
/// </summary>
/// <remarks>
/// <para>
/// In order: refuse unless running as SYSTEM; take the audit mutex, waiting up to 30 minutes for another
/// audit or an install; open the data folder through SecureStore, which checks it and holds it; run the
/// machine checks; and write status.json into it atomically, UTF-8 with a byte order mark. A failed run
/// leaves status.json as it was, so its age keeps growing and Intune stops trusting it.
/// </para>
/// <para>
/// The exit codes are the module's: <see cref="Succeeded"/>, <see cref="Failed"/> (also for a refusal to
/// run, and for a mutex this account may not open, which another program may have made to stop audits)
/// and <see cref="AlreadyRunning"/>.
/// </para>
/// <para>
/// Not ported yet: counting failed runs in last-error.json, the report folder and its retention, the log,
/// events 1000 to 1003, and excludeCheckIds from an administrator's config. Every failure ends in
/// <see cref="Fail"/> and every success in <see cref="Succeed"/>, where those join, and the checks are
/// chosen in <see cref="Selection"/>.
/// </para>
/// </remarks>
internal static class ScheduledAudit
{
    /// <summary>The audit ran and status.json was written.</summary>
    public const int Succeeded = 0;

    /// <summary>The audit did not run, or status.json could not be written.</summary>
    public const int Failed = 1;

    /// <summary>Another audit, or an install, held the mutex for the whole wait.</summary>
    public const int AlreadyRunning = 2;

    /// <summary>Runs the scheduled audit. Call it on one thread: the mutex belongs to the thread that takes it.</summary>
    /// <param name="settings">This device's, or a test's.</param>
    /// <param name="output">Where progress goes.</param>
    /// <param name="error">Where failures go.</param>
    /// <returns>The exit code.</returns>
    public static int Run(ScheduledAuditSettings settings, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        if (!settings.Account.IsLocalSystem)
        {
            error.WriteLine($"baseline scheduled-audit runs only as SYSTEM, as the scheduled audit task runs it; this process runs as {settings.Account.Name}. To audit this device now, run baseline audit.");
            return Failed;
        }

        AuditMutex? mutex;
        try
        {
            mutex = AuditMutex.TryAcquire(settings.MutexName, settings.MutexWait);
        }
        catch (Exception e) when (e is UnauthorizedAccessException or WaitHandleCannotBeOpenedException or IOException)
        {
            return Fail(error, $"the audit mutex {settings.MutexName} could not be taken, so another program may be holding its name to stop audits. {e.Message}", dataFolder: null);
        }

        if (mutex is null)
        {
            error.WriteLine("Another audit is still running; giving up.");
            return AlreadyRunning;
        }

        using (mutex)
        {
            ISecureStore store;
            try
            {
                store = settings.OpenStore();
            }
            catch (SecureStoreException e)
            {
                // Nothing is written anywhere: the data folder is exactly what cannot be trusted.
                return Fail(error, e.Message, dataFolder: null);
            }

            using (store)
            {
                try
                {
                    return Audit(settings, store, output);
                }
                catch (Exception e) when (e is not OutOfMemoryException)
                {
                    return Fail(error, e.Message, store);
                }
            }
        }
    }

    /// <summary>The checks the scheduled audit runs: the machine's. Shadow AI and WSL are the user probe's.</summary>
    /// <returns>The selection.</returns>
    internal static CheckSelection Selection() => new() { Scopes = [CheckScope.Machine] };

    private static int Audit(ScheduledAuditSettings settings, ISecureStore store, TextWriter output)
    {
        var device = DeviceContextReader.Read(settings.Registry, settings.ComputerName, settings.Account, settings.Time.GetUtcNow());
        output.WriteLine($"Audit started on {device.ComputerName} as {device.RunningAs} (tool {settings.ToolVersion})");
        var context = new CheckContext(device, new AuditConfig(settings.Config), settings.Time);

        // Synchronously, on this thread, which holds the mutex; the checks themselves run on the thread pool.
        var findings = new AuditRunner(settings.Catalog).RunAsync(Selection(), context).GetAwaiter().GetResult();
        var status = StatusBuilder.Build(findings, settings.Catalog, device, settings.ToolVersion);
        store.WriteFile(StatusFile.FileName, StatusFile.ToBytes(status));
        return Succeed(output, status, store.RootPath + @"\" + StatusFile.FileName);
    }

    /// <summary>
    /// Where every successful run ends. Removing last-error.json, the event and the report's retention will
    /// join here.
    /// </summary>
    private static int Succeed(TextWriter output, StatusDocument status, string statusPath)
    {
        var culture = CultureInfo.InvariantCulture;
        var rollups = new (string Key, FrameworkRollup? Rollup)[] { ("ce-v3.3", status.Frameworks.CeV33), ("ncsc", status.Frameworks.Ncsc) };
        output.WriteLine(string.Create(culture, $"Checks: {status.Checks.Count}  Auto-fail failing: {status.AutoFailCount}"));
        output.WriteLine("Frameworks: " + string.Join("  ", rollups.Where(r => r.Rollup is not null).Select(r => string.Create(culture, $"{r.Key}={r.Rollup!.MetPct}%"))));
        output.WriteLine("Status: " + statusPath);
        return Succeeded;
    }

    /// <summary>
    /// Where every failed run ends. Counting it in last-error.json, and the event, will join here: only when
    /// the data folder was opened and checked (<paramref name="dataFolder"/> is not null), as the module
    /// records a failure only in a data folder it set up and trusts.
    /// </summary>
    private static int Fail(TextWriter error, string message, ISecureStore? dataFolder)
    {
        error.WriteLine("Audit failed: " + message);
        return Failed;
    }
}
