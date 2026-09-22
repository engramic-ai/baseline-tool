#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Win32 app detection script for Engramic Baseline.

.DESCRIPTION
    Detected (exit 0 with output) when the installed version is at least the
    version this script ships with and the scheduled task exists. Intune treats
    "exit 0 and something written to STDOUT" as installed.
    Reads the 64-bit registry view, so it works whether Intune runs it as a
    32-bit or 64-bit process.
#>
$required = [version]'0.3.0'

try {
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $hklm.OpenSubKey('SOFTWARE\EngramicBaseline')
    if (-not $key) { exit 1 }
    $version = [version][string]$key.GetValue('Version')
    $installPath = [string]$key.GetValue('InstallPath')
    $key.Close()
    if ($version -lt $required) { exit 1 }
    if (-not (Test-Path -LiteralPath (Join-Path $installPath 'app\Invoke-CEScheduledAudit.ps1'))) { exit 1 }
    if (-not (Get-ScheduledTask -TaskPath '\EngramicBaseline\' -TaskName 'Audit' -ErrorAction SilentlyContinue)) { exit 1 }
    Write-Output "Engramic Baseline $version installed at $installPath"
    exit 0
}
catch {
    exit 1
}
