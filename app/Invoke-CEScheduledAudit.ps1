#Requires -Version 5.1
<#
.SYNOPSIS
    Unattended audit for scheduled tasks and Intune. Read-only.

.DESCRIPTION
    Runs every check, then writes to the machine data folder
    (%ProgramData%\EngramicBaseline by default):

      status.json         Compact result read by the Intune compliance and
                          Remediations scripts
      reports\<time>\     Full HTML / Markdown / JSON report and changeset
      logs\               Transcript of each run
      last-error.json     Only if the last run failed: the error, and the number
                          of failed runs in a row with the time of the first
                          (Write-CEAuditFailure)

    It also writes an Application event log entry (source
    EngramicBaseline, IDs 1000-1002, and 1003 when an untrusted data folder
    is moved aside) when the installer has registered the source.

    If a run fails, status.json is left alone so the audit age keeps growing
    and the device eventually reports as non-compliant for having no recent
    audit, rather than falsely passing. last-error.json counts the failed runs
    since the last success, so Intune can also flag a device whose audit keeps
    failing (3 in a row, or failing for 72 hours) before its result goes stale;
    one failed run on its own changes nothing. A successful run removes it.

.PARAMETER DataRoot
    Machine data folder. Default: %ProgramData%\EngramicBaseline

.PARAMETER KeepReports
    Number of report folders to keep. Default 14.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-CEScheduledAudit.ps1
#>
[CmdletBinding()]
param(
    [string]$DataRoot,
    [ValidateRange(1, 365)][int]$KeepReports = 14
)

$ErrorActionPreference = 'Stop'
# Passed to the module directly: it ignores the CE_CHECKER_DATA environment variable when elevated.
Import-Module (Join-Path $PSScriptRoot '..\src\CEAudit\CEAudit.psd1') -Force -ArgumentList $DataRoot
$DataRoot = Get-CEDataRoot

$reportRoot = Join-Path $DataRoot 'reports'
$logRoot = Join-Path $DataRoot 'logs'

# Only one audit at a time, and take the mutex before touching the data folder. The installer takes
# the same mutex before it sets the folders up, so an upgrade never runs underneath this audit and
# this audit never creates the root while the installer is moving it aside.
$mutex = New-Object System.Threading.Mutex($false, 'Global\EngramicBaselineAudit')
$haveMutex = $false
try { $haveMutex = $mutex.WaitOne([TimeSpan]::FromMinutes(30)) }
catch [System.Threading.AbandonedMutexException] { $haveMutex = $true }
if (-not $haveMutex) {
    Write-Warning 'Another audit is still running; giving up.'
    $mutex.Dispose()
    exit 2
}

$exitCode = 0
$transcribing = $false
# Whether all three data folders were set up and are trusted. Until this is true, $DataRoot, $reportRoot
# and $logRoot may be untrusted (a folder or junction a standard user controls), so the catch and finally
# must not write into them or delete through them.
$foldersReady = $false
try {
    # Create the data root and its folders the locked way the installer does, INSIDE the error
    # handling: a root this audit makes before the installer runs (an elevated first run) is never
    # briefly writable by a standard user, and a failure here (e.g. a tampered root that has to be
    # moved aside) is recorded in last-error.json instead of crashing the task silently. Capture any
    # move-aside warning so it can be written into the transcript below (Initialize runs before it).
    $setupNotices = @()
    foreach ($d in @($DataRoot, $reportRoot, $logRoot)) { Initialize-CEDataFolder -Path $d -WarningVariable +setupNotices -WarningAction SilentlyContinue | Out-Null }
    $foldersReady = $true

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $transcript = Join-Path $logRoot "audit-$stamp.log"
    Start-Transcript -LiteralPath $transcript | Out-Null
    $transcribing = $true
    # An untrusted folder moved aside is real (possible) data loss, so record it in the transcript, not
    # only as a warning before logging started.
    foreach ($n in @($setupNotices)) { if ("$n") { Write-Warning "Data folder set-up: $n" } }

    $ctx = Get-CEDeviceContext
    Write-Host "Audit started on $($ctx.ComputerName) as $($ctx.RunningAs) (tool $(Get-CEToolVersion))"
    $exclude = @()
    $opts = (Get-CEConfig).'scheduled-audit'
    if ($opts -and $opts.excludeCheckIds) { $exclude = @($opts.excludeCheckIds) }
    if ($exclude.Count) { Write-Host "Skipping checks by configuration: $($exclude -join ', ')" }
    # SYSTEM only assesses the device. Shadow-AI and WSL are per-user and are
    # collected by Invoke-CEUserProbe.ps1 in each user's own session.
    $findings = @(Invoke-CEAuditCore -Scope 'Machine' -ExcludeId $exclude)
    $folder = Join-Path $reportRoot "$($ctx.ComputerName)-$stamp"
    $report = Export-CEReport -Findings $findings -Context $ctx -OutputPath $folder
    $status = ConvertTo-CEStatus -Findings $findings -Summary $report.Summary -Context $ctx -ReportFolder $folder
    $statusPath = Write-CEStatus -Status $status -Path (Join-Path $DataRoot 'status.json')
    # This run succeeded, so the count of failed runs starts again.
    try { Clear-CEAuditFailure -DataRoot $DataRoot }
    catch { Write-Warning "Could not remove last-error.json after a successful audit: $($_.Exception.Message)" }
    try { Write-CEEventLog -Status $status } catch { Write-Warning "Could not write event log: $_" }

    $fwLine = @($status.frameworks.Keys | ForEach-Object { $v = $status.frameworks[$_]; if ($null -ne $v.metPct) { "$_=$($v.metPct)%" } })
    Write-Host "Checks: $(@($status.checks.Keys).Count)  Auto-fail failing: $($status.autoFailCount)"
    Write-Host "Frameworks: $($fwLine -join '  ')"
    Write-Host "Status: $statusPath"
    Write-Host "Report: $folder"
}
catch {
    $exitCode = 1
    $failure = $_
    Write-Warning "Audit failed: $($failure.Exception.Message)"
    # Record the failure ONLY into a data root that was set up and is trusted. If Initialize-CEDataFolder
    # itself failed - which is exactly when $DataRoot may be a folder or junction a standard user controls
    # - do not write last-error.json (a SYSTEM write could land through the user's junction). The task's
    # non-zero exit and the stale status.json are the signal instead.
    if ($foldersReady) {
        try {
            $record = Write-CEAuditFailure -DataRoot $DataRoot -Message $failure.Exception.Message -Where ([string]$failure.InvocationInfo.PositionMessage)
            Write-Warning "Failed runs in a row: $($record.FailedRuns), the first at $($record.FirstFailure) (UTC)."
        }
        catch { Write-Warning "Could not record the failure: $($_.Exception.Message)" }
    }
}
finally {
    if ($transcribing) { Stop-Transcript | Out-Null }
    # Housekeeping: keep the newest reports and logs. Only when the folders were set up and are trusted
    # - otherwise $reportRoot / $logRoot may be a junction a standard user controls, and following it
    # would delete through it. Delete old report folders with a recursive delete that never follows a
    # link (Remove-Item -Recurse follows junctions on 5.1) and never lists a folder it does not trust;
    # this runs as SYSTEM under the data folder.
    if ($foldersReady) {
        Get-ChildItem -LiteralPath $reportRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -Skip $KeepReports |
            ForEach-Object { try { Remove-CEDataTree -Path $_.FullName | Out-Null } catch { Write-Warning "Could not remove old report folder $($_.FullName): $_" } }
        Get-ChildItem -LiteralPath $logRoot -Filter 'audit-*.log' -File -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -Skip ($KeepReports * 2) |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    if ($haveMutex) { try { $mutex.ReleaseMutex() } catch { $null = $_ } }
    $mutex.Dispose()
}
exit $exitCode
