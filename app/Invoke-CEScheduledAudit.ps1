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
      last-error.json     Only if the last run failed

    It also writes an Application event log entry (source
    EngramicBaseline, IDs 1000-1003) when the installer has registered
    the source.

    If a run fails, status.json is left alone so the audit age keeps growing
    and the device eventually reports as non-compliant for having no recent
    audit, rather than falsely passing.

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
foreach ($d in @($DataRoot, $reportRoot, $logRoot)) {
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# Only one audit at a time (scheduled task, Intune remediation and a manual run can overlap).
$mutex = New-Object System.Threading.Mutex($false, 'Global\EngramicBaselineAudit')
if (-not $mutex.WaitOne([TimeSpan]::FromMinutes(30))) {
    Write-Warning 'Another audit is still running; giving up.'
    exit 2
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transcript = Join-Path $logRoot "audit-$stamp.log"
Start-Transcript -LiteralPath $transcript | Out-Null
$exitCode = 0
try {
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
    Remove-Item -LiteralPath (Join-Path $DataRoot 'last-error.json') -ErrorAction SilentlyContinue
    try { Write-CEEventLog -Status $status } catch { Write-Warning "Could not write event log: $_" }

    $fwLine = @($status.frameworks.Keys | ForEach-Object { $v = $status.frameworks[$_]; if ($null -ne $v.metPct) { "$_=$($v.metPct)%" } })
    Write-Host "Checks: $(@($status.checks.Keys).Count)  Auto-fail failing: $($status.autoFailCount)"
    Write-Host "Frameworks: $($fwLine -join '  ')"
    Write-Host "Status: $statusPath"
    Write-Host "Report: $folder"
}
catch {
    $exitCode = 1
    Write-Warning "Audit failed: $($_.Exception.Message)"
    [pscustomobject]@{
        Time    = (Get-Date).ToUniversalTime().ToString('o')
        Message = $_.Exception.Message
        Where   = [string]$_.InvocationInfo.PositionMessage
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $DataRoot 'last-error.json') -Encoding UTF8
}
finally {
    Stop-Transcript | Out-Null
    # Housekeeping: keep the newest reports and logs.
    Get-ChildItem -LiteralPath $reportRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -Skip $KeepReports |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $logRoot -Filter 'audit-*.log' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -Skip ($KeepReports * 2) |
        Remove-Item -Force -ErrorAction SilentlyContinue
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
exit $exitCode
