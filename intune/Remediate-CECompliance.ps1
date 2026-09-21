# Engramic Baseline - Intune Remediations REMEDIATION script.
#
# Pair with Detect-CECompliance.ps1. Runs as SYSTEM.
#   1. Runs a fresh audit (updates status.json, report, event log).
#   2. If config/auto-remediation.json is enabled, applies the listed fixes
#      (never High risk), then audits again so status.json reflects the result.
# With the default config it only refreshes the audit, so it is safe to deploy
# as-is. Prints one summary line for the "Post-remediation" column.

$ErrorActionPreference = 'Stop'

# Intune may start us in a 32-bit host; the audit must run 64-bit.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    exit $LASTEXITCODE
}

try {
    $installPath = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\EngramicBaseline' -ErrorAction Stop).InstallPath
}
catch {
    Write-Output 'NOT_INSTALLED: deploy the Engramic Baseline Win32 app first'
    exit 1
}
$ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$auditScript = Join-Path $installPath 'app\Invoke-CEScheduledAudit.ps1'

function Invoke-Audit {
    $null = & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $auditScript 2>&1
    return $LASTEXITCODE
}

$code = Invoke-Audit
if ($code -ne 0) {
    Write-Output "AUDIT_FAILED: exit $code (see %ProgramData%\EngramicBaseline\logs)"
    exit 1
}

$applied = 0
$failed = 0
try {
    Import-Module (Join-Path $installPath 'src\CEAudit\CEAudit.psd1') -Force
    $cfg = (Get-CEConfig).'auto-remediation'
    if ($cfg -and $cfg.enabled -and @($cfg.remediationIds).Count) {
        $status = Get-Content -LiteralPath (Join-Path (Get-CEDataRoot) 'status.json') -Raw | ConvertFrom-Json
        $csPath = Join-Path $status.ReportFolder 'changeset.json'
        $cs = Get-Content -LiteralPath $csPath -Raw | ConvertFrom-Json
        $allowed = @($cfg.remediationIds)
        $items = @($cs.Items | Where-Object { $allowed -contains $_.RemediationId -and $_.Risk -ne 'High' })
        if ($items.Count) {
            $outcome = Invoke-CEChangeset -Items $items -ChangesetPath $csPath 6>$null
            $applied = $outcome.Applied
            $failed = $outcome.Failed
            $null = Invoke-Audit
        }
    }
}
catch {
    Write-Output "REMEDIATION_ERROR: $($_.Exception.Message)"
    exit 1
}

$s = Get-Content -LiteralPath (Join-Path $env:ProgramData 'EngramicBaseline\status.json') -Raw | ConvertFrom-Json
$props = @($s.checks.PSObject.Properties)
$attention = @($props | Where-Object { @('Fail', 'Warn', 'Error') -contains [string]$_.Value.status }).Count
$review = @($props | Where-Object { [string]$_.Value.status -eq 'Manual' }).Count
Write-Output ("autofail={0} attention={1} review={2} | fixes applied={3} failed={4}" -f [int]$s.autoFailCount, $attention, $review, $applied, $failed)
exit 0
