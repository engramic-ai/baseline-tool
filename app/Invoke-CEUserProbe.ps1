#Requires -Version 5.1
<#
.SYNOPSIS
    Per-user probe for shadow AI and other user-scope controls. Read-only, no admin.

.DESCRIPTION
    Shadow AI is a per-user problem: the agents, WSL distributions and MCP servers
    a person uses live in their own profile and their own WSL VM, which SYSTEM
    cannot see. This script runs the User-scope checks (Register-CECheck -Scope User)
    in the signed-in user's own session and writes to the per-user data folder
    (%LOCALAPPDATA%\EngramicBaseline by default):

      user-status.json    Compact per-user result (agents found, WSL, containment)
      logs\               Transcript of each run

    A sysadmin runs it for every user by registering it as a scheduled task with a
    Users-group principal (Install-CEChecker.ps1 does this), or as an Intune
    user-context script / proactive remediation. The machine audit
    (Invoke-CEScheduledAudit.ps1) covers the device; this covers the person.

.PARAMETER DataRoot
    Per-user data folder. Default: %LOCALAPPDATA%\EngramicBaseline

.PARAMETER KeepReports
    Retention factor for run logs (keeps KeepReports x 2 transcripts). Default 8.

.PARAMETER Quiet
    Suppress the per-finding console output (still writes user-status.json).

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-CEUserProbe.ps1
#>
[CmdletBinding()]
param(
    [string]$DataRoot,
    [ValidateRange(1, 365)][int]$KeepReports = 8,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\CEAudit\CEAudit.psd1') -Force

if (-not $DataRoot) {
    $base = $env:LOCALAPPDATA
    if (-not $base) { $base = [IO.Path]::GetTempPath() }
    $DataRoot = Join-Path $base 'EngramicBaseline'
}
$logRoot = Join-Path $DataRoot 'logs'
foreach ($d in @($DataRoot, $logRoot)) {
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# Per-session (not Global\): different users must not block each other.
$mutex = New-Object System.Threading.Mutex($false, 'EngramicBaselineUserProbe')
if (-not $mutex.WaitOne([TimeSpan]::FromMinutes(10))) {
    Write-Warning 'Another user probe is still running in this session; giving up.'
    exit 2
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transcript = Join-Path $logRoot "userprobe-$stamp.log"
Start-Transcript -LiteralPath $transcript | Out-Null
$exitCode = 0
try {
    $ctx = Get-CEDeviceContext
    Write-Host "User probe started on $($ctx.ComputerName) as $($ctx.RunningAs) (tool $(Get-CEToolVersion))"
    if ($ctx.IsSystem) {
        throw 'The user probe must run in a user session, not as SYSTEM. Deploy it with a Users-group scheduled task or an Intune user-context script.'
    }

    $userChecks = @(Get-CECheck -Scope 'User')
    if ($userChecks.Count -eq 0) {
        Write-Warning 'No User-scope checks are registered; nothing to probe.'
    }
    $findings = @(Invoke-CEAuditCore -Scope 'User')

    # Same contract as the device status.json: checks are the source of truth,
    # frameworks are derived (user-scope only, so no CE+ summary), plus the AI
    # inventory block that only a user session can gather.
    $checkMap = Get-CEStatusCheckMap -Findings $findings
    $frameworks = Get-CEFrameworkRollup -CheckMap $checkMap
    $ai = Get-CEAiPosture -Context $ctx

    $counts = [ordered]@{}
    foreach ($s in @('Pass', 'Fail', 'Warn', 'Manual', 'Info', 'NotApplicable', 'Skipped', 'Error')) {
        $counts[$s] = @($findings | Where-Object { $_.Status -eq $s }).Count
    }
    $status = [pscustomobject]@{
        schemaVersion = 1
        scope         = 'User'
        toolVersion   = [string](Get-CEToolVersion)
        computerName  = [string]$ctx.ComputerName
        user          = [string]$ctx.RunningAs
        ranAt         = (Get-Date).ToUniversalTime().ToString('o')
        elevated      = [bool]$ctx.IsElevated
        counts        = $counts
        checks        = $checkMap
        frameworks    = $frameworks
        ai            = $ai
    }
    $statusPath = Join-Path $DataRoot 'user-status.json'
    $status | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statusPath -Encoding UTF8
    Remove-Item -LiteralPath (Join-Path $DataRoot 'last-error.json') -ErrorAction SilentlyContinue

    if (-not $Quiet) {
        foreach ($f in $findings) {
            $subject = if ($f.Subject) { " ($($f.Subject))" } else { '' }
            Write-Host ('  {0,-8} {1,-7} {2}{3}' -f $f.CheckId, $f.Status, $f.Title, $subject)
        }
    }
    Write-Host "AI agents: $($ai.agentsFound)  contained: $($ai.contained)  deviations: $($ai.deviations)"
    Write-Host "User-scope checks: $($userChecks.Count)  ($(($counts.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '  '))"
    Write-Host "Status: $statusPath"
}
catch {
    $exitCode = 1
    Write-Warning "User probe failed: $($_.Exception.Message)"
    [pscustomobject]@{
        Time    = (Get-Date).ToUniversalTime().ToString('o')
        Message = $_.Exception.Message
        Where   = [string]$_.InvocationInfo.PositionMessage
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $DataRoot 'last-error.json') -Encoding UTF8
}
finally {
    Stop-Transcript | Out-Null
    Get-ChildItem -LiteralPath $logRoot -Filter 'userprobe-*.log' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -Skip ($KeepReports * 2) |
        Remove-Item -Force -ErrorAction SilentlyContinue
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
exit $exitCode
