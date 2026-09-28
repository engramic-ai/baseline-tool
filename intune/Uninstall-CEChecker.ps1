#Requires -Version 5.1
<#
.SYNOPSIS
    Removes Engramic Baseline. Intune Win32 app uninstall command.

.DESCRIPTION
    Removes the scheduled task, Start menu shortcut, program folder, event log
    source and detection key. Audit history in %ProgramData% is kept unless
    -RemoveData is given, so evidence isn't lost by accident.

    Exit codes: 0 success, 1 failure.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\intune\Uninstall-CEChecker.ps1
#>
[CmdletBinding()]
param(
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'

if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($RemoveData) { $argList += '-RemoveData' }
    $p = Start-Process -FilePath $ps64 -ArgumentList $argList -Wait -PassThru -NoNewWindow
    exit $p.ExitCode
}

function Remove-CETreeNoFollow {
    <#
        Deletes a folder and everything in it without ever following a junction or symbolic link (each
        link is removed as a link). This runs as SYSTEM under the data folder, and Remove-Item -Recurse
        follows links on Windows PowerShell 5.1, which could empty a folder a link points at.
    #>
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $attrs = [IO.File]::GetAttributes($Path)
    if ($attrs -band [IO.FileAttributes]::ReparsePoint) {
        if ($attrs -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete($Path, $false) } else { [IO.File]::Delete($Path) }
        return
    }
    if (-not ($attrs -band [IO.FileAttributes]::Directory)) { [IO.File]::Delete($Path); return }
    foreach ($child in @([IO.Directory]::GetFileSystemEntries($Path))) {
        $ca = $null
        try { $ca = [IO.File]::GetAttributes($child) } catch { continue }
        if ($ca -band [IO.FileAttributes]::ReparsePoint) {
            if ($ca -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete($child, $false) } else { [IO.File]::Delete($child) }
        }
        elseif ($ca -band [IO.FileAttributes]::Directory) { Remove-CETreeNoFollow -Path $child }
        else { [IO.File]::Delete($child) }
    }
    [IO.Directory]::Delete($Path, $false)
}

$regPath = 'HKLM:\SOFTWARE\EngramicBaseline'
$dataRoot = Join-Path $env:ProgramData 'EngramicBaseline'
$installPath = Join-Path $env:ProgramFiles 'EngramicBaseline'
if (Test-Path $regPath) {
    $saved = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).InstallPath
    if ($saved) { $installPath = $saved }
}

$exit = 0
try {
    $task = Get-ScheduledTask -TaskPath '\EngramicBaseline\' -ErrorAction SilentlyContinue
    if ($task) {
        $task | Stop-ScheduledTask -ErrorAction SilentlyContinue
        $task | Unregister-ScheduledTask -Confirm:$false
        Write-Host 'Removed scheduled task'
    }
    try {
        $svc = New-Object -ComObject 'Schedule.Service'
        $svc.Connect()
        $svc.GetFolder('\').DeleteFolder('EngramicBaseline', 0)
    }
    catch {
        Write-Verbose "Task folder not removed: $_"
    }

    $lnk = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Engramic Baseline.lnk'
    Remove-Item -LiteralPath $lnk -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $installPath) {
        Remove-Item -LiteralPath $installPath -Recurse -Force
        Write-Host "Removed $installPath"
    }
    Remove-Item -LiteralPath "$installPath.staging" -Recurse -Force -ErrorAction SilentlyContinue

    # Remove the source by deleting its registry key directly.
    # [Diagnostics.EventLog]::DeleteEventSource calls SourceExists, which
    # enumerates every event log and throws when Security/State are inaccessible
    # (hosted CI runners, restricted images); the install registers it the same
    # registry-only way.
    Remove-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\EngramicBaseline' -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue

    if ($RemoveData -and (Test-Path -LiteralPath $dataRoot)) {
        Remove-CETreeNoFollow -Path $dataRoot
        Write-Host "Removed $dataRoot"
    }
    Write-Host 'Uninstalled.'
}
catch {
    Write-Error "Uninstall failed: $($_.Exception.Message)" -ErrorAction Continue
    $exit = 1
}
exit $exit
