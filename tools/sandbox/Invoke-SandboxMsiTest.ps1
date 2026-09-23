#Requires -Version 5.1
<#
.SYNOPSIS
    Runs inside Windows Sandbox: installs the desktop MSI, checks it, uninstalls, checks again.
.DESCRIPTION
    An installer can only be trusted once it has been installed somewhere disposable. This checks
    what a person actually gets: the files, a Start menu entry that launches the app, an entry in
    Installed apps naming the publisher, signatures that survived packaging, and an uninstall that
    leaves nothing behind.

    Deliberately also checks what the MSI does NOT do. It must not register the scheduled audit
    tasks: those belong to the fleet deployment, and a daily SYSTEM task on a personal machine is a
    surprise rather than a feature.
#>
[CmdletBinding()]
param([string]$MsiPath)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:USERNAME -ne 'WDAGUtilityAccount') {
    throw 'This installs and uninstalls software. Run it with tools\sandbox\New-SandboxRun.ps1 -Environment msi-test.'
}
$results = if ($env:SANDBOX_RESULTS) { $env:SANDBOX_RESULTS } else { Join-Path 'C:\results' (Get-Date -Format 'yyyyMMdd-HHmmss') }
New-Item -ItemType Directory -Path $results -Force | Out-Null

$checks = New-Object System.Collections.ArrayList
function Add-Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    [void]$checks.Add([pscustomobject]@{ Check = $Name; Ok = $Ok; Detail = $Detail })
    Write-Host ("  [{0}] {1}{2}" -f $(if ($Ok) { '+' } else { '-' }), $Name, $(if ($Detail) { " - $Detail" })) -ForegroundColor $(if ($Ok) { 'Green' } else { 'Red' })
}

if (-not $MsiPath) {
    $found = @(Get-ChildItem -LiteralPath 'C:\baseline-tool\build' -Recurse -Filter '*.msi' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending)
    if (-not $found.Count) { throw 'No .msi found under C:\baseline-tool\build. Build one with installer\Build-Msi.ps1 first.' }
    $MsiPath = $found[0].FullName
}
Write-Host "==> Installing $(Split-Path -Leaf $MsiPath)" -ForegroundColor Cyan

$installRoot = Join-Path $env:ProgramFiles 'EngramicBaseline'
$shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Engramic Baseline.lnk'
$log = Join-Path $results 'msi-install.log'

$p = Start-Process msiexec.exe -ArgumentList @('/i', "`"$MsiPath`"", '/qn', '/norestart', '/l*v', "`"$log`"") -Wait -PassThru
Add-Check 'installs without prompting' ($p.ExitCode -eq 0) "msiexec exit $($p.ExitCode)"

# --- what the user got ----------------------------------------------------------------------------
Write-Host '==> What landed on the machine' -ForegroundColor Cyan
# Compare against the payload the MSI was built from, not a list of paths someone remembered to
# write down. Checking only that expected files arrived proves nothing was lost; it says nothing
# about what else came along. WiX is a build tool we pin by hash alone, so what it ADDS matters.
$payloadDir = Join-Path (Split-Path -Parent $MsiPath) 'payload'
if (-not (Test-Path -LiteralPath $payloadDir)) { throw "Cannot find the payload the installer was built from: $payloadDir" }
function Get-RelativeFileSet {
    param([string]$Root)
    $full = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\')
    $set = @(Get-ChildItem -LiteralPath $full -Recurse -File -ErrorAction SilentlyContinue |
            ForEach-Object { $_.FullName.Substring($full.Length + 1) })
    return , @($set | Sort-Object)
}
$wanted = Get-RelativeFileSet -Root $payloadDir
$got = Get-RelativeFileSet -Root $installRoot
$absent = @($wanted | Where-Object { $got -notcontains $_ })
$extra = @($got | Where-Object { $wanted -notcontains $_ })
Add-Check 'every payload file was installed' ($absent.Count -eq 0) $(if ($absent.Count) { "missing: $(($absent | Select-Object -First 5) -join ', ')" } else { "$($wanted.Count) file(s)" })
Add-Check 'the installer added nothing of its own' ($extra.Count -eq 0) $(if ($extra.Count) { "unexpected: $(($extra | Select-Object -First 5) -join ', ')" } else { 'no extra files' })

Add-Check 'a Start menu entry exists' (Test-Path -LiteralPath $shortcut)
if (Test-Path -LiteralPath $shortcut) {
    $sh = New-Object -ComObject WScript.Shell
    $lnk = $sh.CreateShortcut($shortcut)
    $pointsAtApp = ($lnk.TargetPath -match 'powershell\.exe$') -and ($lnk.Arguments -match 'Start-CEAuditGui\.ps1')
    Add-Check 'the Start menu entry launches the app' $pointsAtApp $lnk.Arguments
    # The shortcut runs powershell.exe, so without an icon of our own a user would see PowerShell's
    # blue console tile in their Start menu rather than anything of ours.
    $ownIcon = $lnk.IconLocation -and ($lnk.IconLocation -notmatch 'powershell\.exe')
    Add-Check 'the Start menu entry shows our icon, not PowerShell blue' $ownIcon $lnk.IconLocation
}

# An MSI can run arbitrary code at install time through custom actions. This one has none, and that
# is worth asserting rather than assuming: it is the main thing a compromised build tool could add.
$customActions = 0
try {
    $wi = New-Object -ComObject WindowsInstaller.Installer
    $db = $wi.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $wi, @($MsiPath, 0))
    try {
        $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @('SELECT Action FROM CustomAction'))
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
        while ($view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)) { $customActions++ }
    }
    catch { $customActions = 0 }  # no CustomAction table at all is the strongest possible answer
    Add-Check 'the installer runs no code of its own' ($customActions -eq 0) "$customActions custom action(s)"
}
catch { Add-Check 'the installer runs no code of its own' $false "could not read the MSI: $($_.Exception.Message)" }

$arp = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
        Where-Object { $_.DisplayName -eq 'Engramic Baseline' })
Add-Check 'it appears in Installed apps' ($arp.Count -eq 1) $(if ($arp.Count) { "$($arp[0].DisplayName) $($arp[0].DisplayVersion)" })
if ($arp.Count) {
    Add-Check 'Installed apps names the publisher' ($arp[0].Publisher -eq 'Engramic Ltd') $arp[0].Publisher
}

# --- the signatures survived being packaged ---------------------------------------------------------
Write-Host '==> Signatures after installation' -ForegroundColor Cyan
$installed = @(Get-ChildItem -LiteralPath $installRoot -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1' })
$sigs = @($installed | ForEach-Object { Get-AuthenticodeSignature -LiteralPath $_.FullName })
$unsigned = @($sigs | Where-Object { $_.Status -eq 'NotSigned' }).Count
$stamped = @($sigs | Where-Object { $_.TimeStamperCertificate }).Count
Add-Check 'no installed script lost its signature' ($unsigned -eq 0 -and $installed.Count -gt 0) "$($installed.Count) file(s), $unsigned unsigned"
Add-Check 'installed signatures are timestamped' ($stamped -eq $installed.Count -and $installed.Count -gt 0) "$stamped of $($installed.Count)"

# --- what it must NOT have done -----------------------------------------------------------------------
Write-Host '==> What it deliberately did not do' -ForegroundColor Cyan
$tasks = @(Get-ScheduledTask -TaskPath '\EngramicBaseline\*' -ErrorAction SilentlyContinue)
Add-Check 'no scheduled task was registered' ($tasks.Count -eq 0) "$($tasks.Count) task(s)"

# --- it actually runs from where it was installed --------------------------------------------------------
Write-Host '==> The installed copy runs' -ForegroundColor Cyan
$ran = $false
$detail = ''
try {
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Import-Module '$installRoot\src\CEAudit\CEAudit.psd1' -ErrorAction Stop; (Get-Command -Module CEAudit).Count" 2>&1
    $count = 0
    if ([int]::TryParse(([string]@($out)[-1]).Trim(), [ref]$count)) { $ran = ($count -gt 0); $detail = "$count exported commands" }
    else { $detail = (@($out) -join ' ') }
}
catch { $detail = $_.Exception.Message }
Add-Check 'the installed module imports' $ran $detail

# --- uninstall --------------------------------------------------------------------------------------------
Write-Host '==> Uninstalling' -ForegroundColor Cyan
$uninstallLog = Join-Path $results 'msi-uninstall.log'
$p = Start-Process msiexec.exe -ArgumentList @('/x', "`"$MsiPath`"", '/qn', '/norestart', '/l*v', "`"$uninstallLog`"") -Wait -PassThru
Add-Check 'uninstalls without prompting' ($p.ExitCode -eq 0) "msiexec exit $($p.ExitCode)"

$leftovers = New-Object System.Collections.ArrayList
if (Test-Path -LiteralPath $installRoot) {
    $rest = @(Get-ChildItem -LiteralPath $installRoot -Recurse -File -ErrorAction SilentlyContinue)
    if ($rest.Count) { [void]$leftovers.Add("$($rest.Count) file(s) in Program Files") }
}
if (Test-Path -LiteralPath $shortcut) { [void]$leftovers.Add('Start menu entry') }
$arpAfter = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
        Where-Object { $_.DisplayName -eq 'Engramic Baseline' })
if ($arpAfter.Count) { [void]$leftovers.Add('Installed apps entry') }
Add-Check 'uninstall left nothing behind' ($leftovers.Count -eq 0) ($leftovers -join '; ')

# --- report ----------------------------------------------------------------------------------------------
$fail = @($checks | Where-Object { -not $_.Ok }).Count
$lines = @("# Desktop installer test $(Split-Path -Leaf $results)", '',
    "Verdict: **$(if ($fail) { 'FAILED' } else { 'PASSED' })**", '',
    "Installer: $(Split-Path -Leaf $MsiPath)", '',
    '| Check | Result | Detail |', '|---|---|---|')
foreach ($c in $checks) { $lines += "| $($c.Check) | $(if ($c.Ok) { 'pass' } else { '**fail**' }) | $($c.Detail) |" }
Set-Content -LiteralPath (Join-Path $results 'msi-test.md') -Value ($lines -join "`r`n") -Encoding ASCII

Write-Host ''
$checks | Format-Table -AutoSize | Out-String | Write-Host
Write-Host "Desktop installer: $(if ($fail) { "FAILED ($fail check(s))" } else { 'PASSED' })" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
Write-Host "Results on the host under build\sandbox\results\msi-test. Close this window to destroy the sandbox." -ForegroundColor Cyan
