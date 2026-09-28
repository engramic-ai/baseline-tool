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
        (junction or symbolic link), is owned by someone other than SYSTEM, Administrators or
        TrustedInstaller, or has permissions that let anyone else change it. Only the SYSTEM audit
        should write it, and a standard user who could change either could make the device look
        compliant. The owner alone is not enough: a hard link to a file the user can write, such as
        their ntuser.ini, keeps that file's administrator owner. The same function is in
        Detect-CECompliance.ps1 and Discover-CECompliance.ps1 (each is uploaded on its own).
    #>
    param([string]$DataRoot)
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    # Rights that let someone change, delete or re-permission it, including GENERIC_WRITE and GENERIC_ALL.
    $writeRights = 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288 -bor 0x40000000 -bor 0x10000000
    foreach ($path in @($DataRoot, (Join-Path $DataRoot 'status.json'))) {
        $attributes = $null
        try { $attributes = [IO.File]::GetAttributes($path) } catch { continue }
        if ($attributes -band [IO.FileAttributes]::ReparsePoint) { return "$path is a link (junction or symbolic link)" }
        $acl = $null
        try { $acl = Get-Acl -LiteralPath $path } catch { return "the permissions of $path could not be read" }
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($trusted -notcontains $owner) { return "$path is owned by $owner, not an administrator" }
        foreach ($rule in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
            $sid = "$($rule.IdentityReference)"
            if ("$($rule.AccessControlType)" -ne 'Allow') {
                # A deny entry against SYSTEM, Administrators or TrustedInstaller could stop the audit
                # replacing status.json, freezing a forged one in place, so treat it as tampering.
                if ($trusted -contains $sid) { return "$path denies $sid, so the audit may be unable to replace it" }
                continue
            }
            # CREATOR OWNER only applies to new items, which only administrators can create in a locked folder.
            if ($trusted -contains $sid -or $sid -eq 'S-1-3-0') { continue }
            $rights = [long]0
            try { $rights = [long]$rule.FileSystemRights } catch { $rights = [long]::MaxValue }
            if ($rights -band $writeRights) { return "$path can be changed by $sid, not only administrators" }
        }
    }
    return ''
}

$maxAgeHours = 72
$dataRoot = Join-Path $env:ProgramData 'EngramicBaseline'
$statusPath = Join-Path $dataRoot 'status.json'

# Intune runs this as SYSTEM. A standard user running it can only mislead themselves. Exit 1 on an
# untrusted status.json runs the remediation script, whose SYSTEM audit moves an untrusted data folder
# aside and makes a fresh, locked one (or replaces an untrusted status.json); nothing needs reinstalling.
$elevated = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($elevated) {
    $problem = Get-CEStatusTrustProblem -DataRoot $dataRoot
    if ($problem) {
        Write-Output "UNTRUSTED: $problem, so status.json may be forged. The next SYSTEM audit (the remediation script runs one) moves an untrusted data folder aside to %ProgramData%\EngramicBaseline.untrusted-<id> and writes a fresh status.json; check that folder, then delete it."
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
# A run that failed after status.json was written means status.json is not the device's current
# state, however recent it looks: exit 1 so the remediation script runs a fresh audit.
$lastErrorPath = Join-Path $dataRoot 'last-error.json'
$failedSince = $false
if (Test-Path -LiteralPath $lastErrorPath) {
    $line = "LAST_RUN_ERROR | $line"
    $failedSince = (Get-Item -LiteralPath $lastErrorPath).LastWriteTimeUtc -gt (Get-Item -LiteralPath $statusPath).LastWriteTimeUtc
}
if ($line.Length -gt 2000) { $line = $line.Substring(0, 1997) + '...' }
Write-Output $line

if ($state -eq 'OK' -and -not $failedSince) { exit 0 }
exit 1
