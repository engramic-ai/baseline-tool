using System.CommandLine;

namespace Engramic.Baseline.Cli;

/// <summary>
/// baseline scheduled-audit: the unattended audit for the scheduled task, run as SYSTEM, which writes
/// status.json into the data folder (<see cref="ScheduledAudit"/>).
/// </summary>
internal static class ScheduledAuditCommand
{
    /// <summary>Makes the command.</summary>
    /// <returns>The command.</returns>
    public static Command Create()
    {
        var command = new Command(
            "scheduled-audit",
            "Run the unattended audit and write status.json to the data folder, for the scheduled task. Runs only as SYSTEM; to audit this device yourself, use audit. Exit codes: 0 done, 1 failed, 2 another audit is still running.");

        // Synchronous, so the whole run stays on the thread that takes the audit mutex.
        command.SetAction(_ => ScheduledAudit.Run(ScheduledAuditSettings.ForThisDevice(), Console.Out, Console.Error));
        return command;
    }
}
