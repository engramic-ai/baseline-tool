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

function Get-CEStatusTrustProblem {
    <#
        Why status.json can't be trusted, or '' when it can: the data folder or the file is a link
        (junction or symbolic link), or is owned by someone other than SYSTEM, Administrators or
        TrustedInstaller. Only the SYSTEM audit should write it, and a standard user who owned
        either could make the device look compliant. The same function is in
        Detect-CECompliance.ps1 and Discover-CECompliance.ps1 (each is uploaded on its own).
    #>
    param([string]$DataRoot)
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    foreach ($path in @($DataRoot, (Join-Path $DataRoot 'status.json'))) {
        $attributes = $null
        try { $attributes = [IO.File]::GetAttributes($path) } catch { continue }
        if ($attributes -band [IO.FileAttributes]::ReparsePoint) { return "$path is a link (junction or symbolic link)" }
        $owner = ''
        try { $owner = (Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { return "the owner of $path could not be read" }
        if ($trusted -notcontains $owner) { return "$path is owned by $owner, not an administrator" }
    }
    return ''
}

$maxAgeHours = 72
$dataRoot = Join-Path $env:ProgramData 'EngramicBaseline'
$statusPath = Join-Path $dataRoot 'status.json'

# Intune runs this as SYSTEM. A standard user running it can only mislead themselves.
$elevated = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($elevated) {
    $problem = Get-CEStatusTrustProblem -DataRoot $dataRoot
    if ($problem) {
        Write-Output "UNTRUSTED: $problem, so status.json may be forged. Reinstall the Win32 app to take the folder back."
        exit 1
    }
}

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
