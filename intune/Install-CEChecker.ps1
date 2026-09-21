#Requires -Version 5.1
<#
.SYNOPSIS
    Installs Engramic Baseline machine-wide. Built to run as the
    install command of an Intune Win32 app, and also runnable by hand.

.DESCRIPTION
    - Copies the tool to Program Files, locked down so only administrators and
      SYSTEM can change it (the scheduled task runs these scripts as SYSTEM)
    - Creates %ProgramData%\EngramicBaseline for status, reports and logs
    - Registers the Application event log source EngramicBaseline
    - Registers the scheduled task \EngramicBaseline\Audit (SYSTEM,
      daily with a random delay, plus shortly after start-up)
    - Adds a Start menu shortcut for the desktop app
    - Writes HKLM\SOFTWARE\EngramicBaseline (Version, InstallPath) for
      Intune detection

    Safe to run again: re-running upgrades in place. Relaunches itself in
    64-bit PowerShell if started from a 32-bit host (as Intune may do).

    Exit codes: 0 success, 1 failure.

.PARAMETER InstallPath
    Default: %ProgramFiles%\EngramicBaseline

.PARAMETER DailyAt
    Time of the daily audit, HH:mm, local time. Default 11:00 (when laptops
    are usually on).

.PARAMETER RandomDelayMinutes
    Spreads audits across the fleet. Default 120.

.PARAMETER RunNow
    Start the first audit straight after installing.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\intune\Install-CEChecker.ps1 -RunNow
#>
[CmdletBinding()]
param(
    [string]$InstallPath,
    [ValidatePattern('^\d{2}:\d{2}$')][string]$DailyAt = '11:00',
    [ValidateRange(0, 720)][int]$RandomDelayMinutes = 120,
    [switch]$NoScheduledTask,
    [switch]$NoUserProbeTask,
    [switch]$NoShortcut,
    [switch]$RunNow
)

$ErrorActionPreference = 'Stop'

# --- 64-bit relaunch --------------------------------------------------------
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v) { $argList += "-$k" } }
        else { $argList += @("-$k", "`"$v`"") }
    }
    $p = Start-Process -FilePath $ps64 -ArgumentList $argList -Wait -PassThru -NoNewWindow
    exit $p.ExitCode
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this as an administrator (Intune runs it as SYSTEM).'
    exit 1
}

$packageRoot = Split-Path -Parent $PSScriptRoot
if (-not $InstallPath) { $InstallPath = Join-Path $env:ProgramFiles 'EngramicBaseline' }
$dataRoot = Join-Path $env:ProgramData 'EngramicBaseline'
$regPath = 'HKLM:\SOFTWARE\EngramicBaseline'
$taskPath = '\EngramicBaseline\'
$taskName = 'Audit'
$userTaskName = 'User probe'

foreach ($d in @($dataRoot, (Join-Path $dataRoot 'logs'), (Join-Path $dataRoot 'reports'), (Join-Path $dataRoot 'config'))) {
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
$log = Join-Path $dataRoot ("logs\install-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Start-Transcript -LiteralPath $log | Out-Null

function Set-CELockedAcl {
    <# SYSTEM and Administrators: full control. Users: read (optional). SIDs keep this locale independent. #>
    param([string]$Path, [switch]$UsersRead)
    $grants = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    if ($UsersRead) { $grants += '*S-1-5-32-545:(OI)(CI)RX' }
    $icaclsArgs = @($Path, '/inheritance:r', '/grant:r') + $grants + @('/Q')
    & icacls.exe @icaclsArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path (exit $LASTEXITCODE)" }
}

try {
    $manifest = Import-PowerShellDataFile -Path (Join-Path $packageRoot 'src\CEAudit\CEAudit.psd1')
    $version = [string]$manifest.ModuleVersion
    Write-Host "Installing Engramic Baseline $version to $InstallPath"

    # --- Copy payload into a staging folder, then swap -----------------------
    $payload = @('src', 'config', 'intune', 'docs', 'app', 'README.md')
    $staging = "$InstallPath.staging"
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    foreach ($item in $payload) {
        $src = Join-Path $packageRoot $item
        if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $staging -Recurse -Force }
        elseif ($item -ne 'docs') { throw "Package is missing $item" }
    }
    Get-ChildItem -LiteralPath $staging -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

    # Don't upgrade underneath a running audit.
    $running = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
    if ($running -and $running.State -eq 'Running') { $running | Stop-ScheduledTask -ErrorAction SilentlyContinue }

    $swapped = $false
    if (Test-Path -LiteralPath $InstallPath) {
        try {
            Remove-Item -LiteralPath $InstallPath -Recurse -Force
        }
        catch {
            # Something (e.g. an open desktop app) is holding the folder: update it in place instead.
            Write-Warning "Could not replace $InstallPath ($($_.Exception.Message)); updating files in place."
            Get-ChildItem -LiteralPath $staging | Copy-Item -Destination $InstallPath -Recurse -Force
            Remove-Item -LiteralPath $staging -Recurse -Force
            $swapped = $true
        }
    }
    if (-not $swapped) { Move-Item -LiteralPath $staging -Destination $InstallPath }
    Set-CELockedAcl -Path $InstallPath -UsersRead
    Set-CELockedAcl -Path $dataRoot
    # Users may read config overrides (the desktop app uses them); status and reports stay admin-only.
    & icacls.exe (Join-Path $dataRoot 'config') /grant '*S-1-5-32-545:(OI)(CI)RX' /Q | Out-Null

    # --- Event log source ----------------------------------------------------
    # Register the source by writing its registry key directly. The managed
    # [Diagnostics.EventLog]::CreateEventSource calls SourceExists, which
    # enumerates every event log and throws when Security/State are inaccessible
    # (hosted CI runners, restricted images) - so the source was never created
    # and the audit's event was silently dropped. Creating the key is all that
    # RegisterEventSource (used by the audit) needs; the full message text still
    # shows in Event Viewer as the event's insertion string.
    $sourceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\EngramicBaseline'
    if (-not (Test-Path -LiteralPath $sourceKey)) {
        New-Item -Path $sourceKey -Force | Out-Null
        New-ItemProperty -Path $sourceKey -Name 'EventMessageFile' -PropertyType ExpandString -Value '%SystemRoot%\System32\EventCreate.exe' -Force | Out-Null
        New-ItemProperty -Path $sourceKey -Name 'TypesSupported' -PropertyType DWord -Value 7 -Force | Out-Null
        Write-Host 'Registered event log source EngramicBaseline'
    }

    # --- Scheduled task ------------------------------------------------------
    if (-not $NoScheduledTask) {
        $ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $script = Join-Path $InstallPath 'app\Invoke-CEScheduledAudit.ps1'
        $action = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`"" -WorkingDirectory $dataRoot
        $daily = New-ScheduledTaskTrigger -Daily -At $DailyAt
        if ($RandomDelayMinutes -gt 0) { $daily.RandomDelay = "PT$($RandomDelayMinutes)M" }
        $startup = New-ScheduledTaskTrigger -AtStartup
        $startup.Delay = 'PT15M'
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew `
            -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 30)
        Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger @($daily, $startup) `
            -Principal $taskPrincipal -Settings $settings `
            -Description 'Engramic Baseline: read-only daily audit. Writes %ProgramData%\EngramicBaseline\status.json for Intune compliance.' `
            -Force | Out-Null
        Write-Host "Registered scheduled task $taskPath$taskName (daily at $DailyAt + up to $RandomDelayMinutes min, and 15 min after start-up)"
    }

    # --- Per-user probe task (shadow AI / WSL, runs as each signed-in user) ---
    if (-not $NoUserProbeTask) {
        $ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $probe = Join-Path $InstallPath 'app\Invoke-CEUserProbe.ps1'
        $uAction = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$probe`""
        $uLogon = New-ScheduledTaskTrigger -AtLogOn
        $uLogon.Delay = 'PT2M'
        $uDaily = New-ScheduledTaskTrigger -Daily -At $DailyAt
        if ($RandomDelayMinutes -gt 0) { $uDaily.RandomDelay = "PT$($RandomDelayMinutes)M" }
        # BUILTIN\Users, non-elevated: each signed-in user runs their own instance in
        # their own session, so the probe sees their agents and their WSL VM. SYSTEM
        # cannot, which is why shadow-AI checks are User-scope.
        $uPrincipal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
        $uSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $userTaskName -TaskPath $taskPath -Action $uAction -Trigger @($uLogon, $uDaily) `
            -Principal $uPrincipal -Settings $uSettings `
            -Description 'Engramic Baseline: per-user shadow-AI and WSL probe. Runs as each signed-in user; writes %LOCALAPPDATA%\EngramicBaseline\user-status.json.' `
            -Force | Out-Null
        Write-Host "Registered scheduled task $taskPath$userTaskName (per signed-in user, at logon + daily at $DailyAt)"
    }

    # --- Start menu shortcut -------------------------------------------------
    $lnk = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Engramic Baseline.lnk'
    if (-not $NoShortcut) {
        $shell = New-Object -ComObject WScript.Shell
        $sc = $shell.CreateShortcut($lnk)
        $sc.TargetPath = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $sc.Arguments = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$(Join-Path $InstallPath 'app\Start-CEAuditGui.ps1')`""
        # Not the install folder, so an open app never blocks an upgrade.
        $sc.WorkingDirectory = '%USERPROFILE%'
        $sc.IconLocation = "$env:WINDIR\System32\shell32.dll,47"
        $sc.Description = 'Check this device against Cyber Essentials'
        $sc.Save()
        Write-Host "Created Start menu shortcut"
    }
    elseif (Test-Path -LiteralPath $lnk) {
        Remove-Item -LiteralPath $lnk -Force
    }

    # --- Detection key -------------------------------------------------------
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    New-ItemProperty -Path $regPath -Name 'Version' -Value $version -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name 'InstallPath' -Value $InstallPath -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name 'DataRoot' -Value $dataRoot -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name 'InstalledAt' -Value ((Get-Date).ToUniversalTime().ToString('o')) -PropertyType String -Force | Out-Null

    if ($RunNow -and -not $NoScheduledTask) {
        Start-ScheduledTask -TaskPath $taskPath -TaskName $taskName
        Write-Host 'First audit started in the background.'
    }
    Write-Host "Installed $version."
    $exit = 0
}
catch {
    Write-Error "Install failed: $($_.Exception.Message)" -ErrorAction Continue
    $exit = 1
}
finally {
    Stop-Transcript | Out-Null
}
exit $exit
