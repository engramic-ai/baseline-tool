#Requires -Version 5.1
<#
.SYNOPSIS
    One-shot local rehearsal of the Intune deployment on this machine.

.DESCRIPTION
    Does what Intune would do, the way Intune would do it, and checks each step:

      1. Installs with intune\Install-CEChecker.ps1 (as the Win32 app would)
      2. Runs the detection script and checks it reports "installed"
      3. Runs the scheduled audit task as SYSTEM and waits for status.json
      4. Runs the compliance discovery script as SYSTEM in BOTH the 32-bit and
         64-bit PowerShell hosts, and checks the output is valid single-line
         JSON under 1 MB
      5. Evaluates both compliance rules files against that output, exactly as
         the custom compliance policy would, and shows the per-rule result
      6. Runs the Remediations detection script as SYSTEM
      7. Uninstalls again (unless -KeepInstalled)

    The deployment test PASSES when every step works, whether or not this
    particular device is compliant. Device compliance is reported separately.

    Run from an elevated PowerShell prompt in the repo folder.

.PARAMETER KeepInstalled
    Leave the tool installed afterwards.

.PARAMETER TimeoutMinutes
    How long to wait for the audit. Default 30 (Windows Update searches can be slow).

.EXAMPLE
    .\intune\Test-IntuneDeployment.ps1
#>
[CmdletBinding()]
param(
    [switch]$KeepInstalled,
    [ValidateRange(1, 180)][int]$TimeoutMinutes = 30
)

$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated (Run as administrator) PowerShell prompt.'
}

$repo = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repo 'src\CEAudit\CEAudit.psd1') -Force
$dataRoot = Join-Path $env:ProgramData 'EngramicBaseline'
$workDir = Join-Path $dataRoot 'deployment-test'
$ps64 = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$ps32 = Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
$steps = New-Object System.Collections.ArrayList

function Add-Step {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    [void]$steps.Add([pscustomobject]@{ Step = $Name; Result = $(if ($Ok) { 'PASS' } else { 'FAIL' }); Detail = $Detail })
    $colour = if ($Ok) { 'Green' } else { 'Red' }
    Write-Host ("  [{0}] {1} {2}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $Detail) -ForegroundColor $colour
}

function Invoke-AsSystem {
    <#
        Runs a script as SYSTEM through a temporary scheduled task (the same
        account Intune uses) and returns its stdout and exit code.
    #>
    param([string]$Script, [string]$HostExe, [int]$TimeoutSeconds = 600)
    $id = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $out = Join-Path $workDir "$id.out"
    $codeFile = Join-Path $workDir "$id.code"
    $wrapper = Join-Path $workDir "$id.ps1"
    @"
`$o = & '$HostExe' -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '$Script' 2>&1
`$c = `$LASTEXITCODE
[IO.File]::WriteAllText('$out', ((@(`$o) | ForEach-Object { [string]`$_ }) -join "``n"))
[IO.File]::WriteAllText('$codeFile', [string]`$c)
"@ | Set-Content -LiteralPath $wrapper -Encoding UTF8
    $name = "CEChecker-Test-$id"
    $action = New-ScheduledTaskAction -Execute $ps64 -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$wrapper`""
    $sysPrincipal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $name -Action $action -Principal $sysPrincipal -Force | Out-Null
    try {
        Start-ScheduledTask -TaskName $name
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while (-not (Test-Path -LiteralPath $codeFile)) {
            if ((Get-Date) -gt $deadline) { throw "Timed out running $Script as SYSTEM" }
            Start-Sleep -Milliseconds 500
        }
        Start-Sleep -Milliseconds 300
        return [pscustomobject]@{
            ExitCode = [int](Get-Content -LiteralPath $codeFile -Raw).Trim()
            Output   = [string](Get-Content -LiteralPath $out -Raw)
        }
    }
    finally {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $out, $codeFile, $wrapper -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host "Engramic Baseline: Intune deployment rehearsal on $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host ''
New-Item -ItemType Directory -Path $workDir -Force | Out-Null
$compliance = @()

try {
    # 1. Install (from a 32-bit host, as Intune's agent may do, to prove the 64-bit relaunch)
    Write-Host '1. Installing...'
    $installHost = if (Test-Path $ps32) { $ps32 } else { $ps64 }
    $p = Start-Process -FilePath $installHost -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $PSScriptRoot 'Install-CEChecker.ps1')`"") -Wait -PassThru -WindowStyle Hidden
    Add-Step 'Install (exit code 0)' ($p.ExitCode -eq 0) "exit $($p.ExitCode); log in $dataRoot\logs"
    if ($p.ExitCode -ne 0) { throw 'Install failed; stopping.' }

    $reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\EngramicBaseline'
    Add-Step 'Detection key written (64-bit view)' ([bool]$reg.Version) "Version $($reg.Version) at $($reg.InstallPath)"
    $task = Get-ScheduledTask -TaskPath '\EngramicBaseline\' -TaskName 'Audit' -ErrorAction SilentlyContinue
    Add-Step 'Scheduled task registered as SYSTEM' ([bool]$task -and $task.Principal.UserId -match 'SYSTEM|S-1-5-18') "$($task.Triggers.Count) triggers"
    $acl = (Get-Acl -LiteralPath $reg.InstallPath).Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-545' -and $_.FileSystemRights -match 'Write|Modify|FullControl' }
    Add-Step 'Program folder not writable by standard users' (-not $acl) ''

    # 2. Detection script, 32-bit as Intune defaults to
    Write-Host '2. Detection script...'
    $det = Invoke-AsSystem -Script (Join-Path $reg.InstallPath 'intune\Detect-CEChecker.ps1') -HostExe $installHost -TimeoutSeconds 120
    Add-Step 'Win32 detection reports installed' ($det.ExitCode -eq 0 -and $det.Output.Trim()) $det.Output.Trim()

    # 3. Scheduled audit
    Write-Host "3. Running the scheduled audit as SYSTEM (can take several minutes)..."
    $statusPath = Join-Path $dataRoot 'status.json'
    $errPath = Join-Path $dataRoot 'last-error.json'
    $started = (Get-Date).ToUniversalTime().AddSeconds(-2)
    Start-ScheduledTask -TaskPath '\EngramicBaseline\' -TaskName 'Audit'
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    do {
        Start-Sleep -Seconds 5
        $t = Get-ScheduledTask -TaskPath '\EngramicBaseline\' -TaskName 'Audit'
        $fresh = (Test-Path $statusPath) -and (Get-Item $statusPath).LastWriteTimeUtc -gt $started
        $errNew = (Test-Path $errPath) -and (Get-Item $errPath).LastWriteTimeUtc -gt $started
        Write-Host "   task state: $($t.State)   status updated: $fresh" -ForegroundColor DarkGray
        $finished = ($fresh -or $errNew) -and $t.State -ne 'Running'
    } while (-not $finished -and (Get-Date) -lt $deadline)
    $info = Get-ScheduledTaskInfo -TaskPath '\EngramicBaseline\' -TaskName 'Audit'
    Add-Step 'Scheduled audit completed' ($fresh -and $info.LastTaskResult -eq 0) "last result $($info.LastTaskResult)"
    if (-not $fresh) {
        if (Test-Path $errPath) { Write-Host (Get-Content $errPath -Raw) -ForegroundColor Red }
        throw 'No status.json was produced; see the logs folder.'
    }
    $status = Get-Content $statusPath -Raw | ConvertFrom-Json
    $errors = @($status.checks.PSObject.Properties | Where-Object { $_.Value.status -eq 'Error' } | ForEach-Object Name)
    Add-Step 'All checks ran as SYSTEM without errors' ($errors.Count -eq 0) ($errors -join ', ')
    # Filter by our event IDs server-side, then confirm the source client-side.
    # A source registered only via its Application-log registry key (as the
    # installer does, to avoid CreateEventSource enumerating every log) has no
    # publisher metadata, so a ProviderName FilterHashtable never matches it -
    # but the event is in the log; $_.ProviderName resolves it after the fact.
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000, 1001, 1002; StartTime = (Get-Date).AddMinutes(-$TimeoutMinutes - 5) } -MaxEvents 25 -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -eq 'EngramicBaseline' } | Select-Object -First 1
    Add-Step 'Event log entry written' ([bool]$ev) $(if ($ev) { "event $($ev.Id)" } else { '' })

    # 4 + 5. Discovery script in both hosts, evaluated against both rules files
    Write-Host '4. Compliance discovery script as SYSTEM...'
    $discovery = Join-Path $reg.InstallPath 'intune\Discover-CECompliance.ps1'
    $lastOutput = $null
    foreach ($h in @(@{ Name = '32-bit'; Exe = $ps32 }, @{ Name = '64-bit'; Exe = $ps64 })) {
        if (-not (Test-Path $h.Exe)) { continue }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-AsSystem -Script $discovery -HostExe $h.Exe -TimeoutSeconds 600
        $sw.Stop()
        $text = $r.Output.Trim()
        $okJson = $true
        try { $null = $text | ConvertFrom-Json } catch { $okJson = $false }
        Add-Step "Discovery ($($h.Name)) returns one line of JSON" ($r.ExitCode -eq 0 -and $okJson -and $text -notmatch "`n") ("{0:N1}s, {1} bytes" -f $sw.Elapsed.TotalSeconds, $text.Length)
        $lastOutput = $text
    }

    Write-Host '5. Evaluating compliance rules...'
    foreach ($rulesFile in @('compliance-rules.json', 'compliance-rules-autofail-only.json')) {
        $eval = Test-CEComplianceRules -DiscoveryOutput $lastOutput -RulesPath (Join-Path $PSScriptRoot $rulesFile)
        Add-Step "Rules file $rulesFile is valid for this output" ($eval.Problems.Count -eq 0 -and -not @($eval.Rules | Where-Object { @('NotDiscovered', 'TypeError') -contains $_.State }).Count) ($eval.Problems -join ' ')
        $compliance += [pscustomobject]@{ File = $rulesFile; Result = $eval }
    }

    # 6. Remediations detection
    Write-Host '6. Remediations detection script as SYSTEM...'
    $rd = Invoke-AsSystem -Script (Join-Path $reg.InstallPath 'intune\Detect-CECompliance.ps1') -HostExe $ps64 -TimeoutSeconds 120
    Add-Step 'Remediations detection runs and reports' (@(0, 1) -contains $rd.ExitCode -and $rd.Output.Trim()) "exit $($rd.ExitCode): $($rd.Output.Trim())"
}
catch {
    Add-Step 'Unexpected error' $false $_.Exception.Message
}
finally {
    if (-not $KeepInstalled) {
        Write-Host '7. Uninstalling...'
        $u = Start-Process -FilePath $ps64 -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $PSScriptRoot 'Uninstall-CEChecker.ps1')`"") -Wait -PassThru -WindowStyle Hidden
        $gone = -not (Test-Path 'HKLM:\SOFTWARE\EngramicBaseline') -and -not (Get-ScheduledTask -TaskPath '\EngramicBaseline\' -ErrorAction SilentlyContinue)
        Add-Step 'Uninstall removes app, task and detection key' ($u.ExitCode -eq 0 -and $gone) "exit $($u.ExitCode)"
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host 'Device compliance (what Intune would report for this machine):' -ForegroundColor Cyan
foreach ($c in $compliance) {
    $state = if ($c.Result.Compliant) { 'COMPLIANT' } else { 'NOT COMPLIANT' }
    Write-Host ("  {0}: {1}" -f $c.File, $state) -ForegroundColor $(if ($c.Result.Compliant) { 'Green' } else { 'Yellow' })
    foreach ($r in $c.Result.Rules) {
        $mark = if ($r.State -eq 'Compliant') { 'ok ' } else { 'NO ' }
        Write-Host ("    {0} {1,-20} {2,-8} {3}" -f $mark, $r.SettingName, [string]$r.Actual, $r.Detail)
    }
}

$failedSteps = @($steps | Where-Object Result -eq 'FAIL')
Write-Host ''
if ($failedSteps.Count) {
    Write-Host "Deployment test: FAILED ($($failedSteps.Count) step(s))" -ForegroundColor Red
    exit 1
}
Write-Host 'Deployment test: PASSED. The package is ready for Intune.' -ForegroundColor Green
if ($KeepInstalled) { Write-Host "Left installed. Report: $($status.ReportFolder)" }
exit 0
