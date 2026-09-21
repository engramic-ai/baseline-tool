# Engramic Baseline - Intune Remediations DETECTION script.
#
# Upload in Intune: Devices > Scripts and remediations > Remediations > Create.
#   Detection script: this file. Remediation script: Remediate-CECompliance.ps1
#   Run this script using the logged-on credentials: No
#   Run script in 64-bit PowerShell: Yes
#   Schedule: daily
#
# Prints one line that Intune shows in the "Pre-remediation detection output"
# column, so the Remediations report gives a tenant-wide view of every device's
# Cyber Essentials state and which checks are failing.
# Exit 0 = ready (no remediation). Exit 1 = not ready or no recent audit.

$maxAgeHours = 72
$dataRoot = Join-Path $env:ProgramData 'EngramicBaseline'
$statusPath = Join-Path $dataRoot 'status.json'

if (-not (Test-Path -LiteralPath $statusPath)) {
    Write-Output 'NO_DATA: no audit has completed on this device yet (is the Win32 app installed?)'
    exit 1
}
try {
    $s = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
}
catch {
    Write-Output "NO_DATA: status.json unreadable: $($_.Exception.Message)"
    exit 1
}

$auditTime = [datetime]::MinValue
if ($s.auditTime -is [datetime]) { $auditTime = $s.auditTime.ToUniversalTime() }
else { [void][datetime]::TryParse([string]$s.auditTime, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$auditTime) }
$age = [int][math]::Floor(([datetime]::UtcNow - $auditTime.ToUniversalTime()).TotalHours)

# Count from checks (the source of truth) so frameworks that share a check aren't double counted.
$props = @($s.checks.PSObject.Properties)
$attention = @($props | Where-Object { @('Fail', 'Warn', 'Error') -contains [string]$_.Value.status }).Count
$review = @($props | Where-Object { [string]$_.Value.status -eq 'Manual' }).Count
$autoFail = [int]$s.autoFailCount

$failing = (@($s.autoFails) | Where-Object { $_ } | Select-Object -Unique) -join ','
$tcs = if ($s.frameworks -and $s.frameworks.'ce-plus') { $s.frameworks.'ce-plus'.tcs } else { $null }
$plus = (@('TC2', 'TC3', 'TC4', 'TC5') | ForEach-Object { "$_=$(if ($tcs) { $tcs.$_ })" }) -join ' '

$state = if ($age -gt $maxAgeHours) { 'STALE' }
elseif ($autoFail -gt 0) { 'AUTO-FAIL' }
elseif ($attention -gt 0) { 'ATTENTION' }
elseif ($review -gt 0) { 'REVIEW' }
else { 'OK' }

$line = "{0} | autofail={1} attention={2} review={3} | age={4}h | {5} | v{6} | {7}" -f $state, $autoFail, $attention, $review, $age, $plus, $s.toolVersion, $failing
if (Test-Path -LiteralPath (Join-Path $dataRoot 'last-error.json')) { $line = "LAST_RUN_ERROR | $line" }
if ($line.Length -gt 2000) { $line = $line.Substring(0, 1997) + '...' }
Write-Output $line

if ($state -eq 'OK') { exit 0 }
exit 1
