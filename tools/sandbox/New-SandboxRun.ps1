#Requires -Version 5.1
<#
.SYNOPSIS
    Runs a real audit -> apply -> verify -> roll back cycle inside Windows Sandbox.
.DESCRIPTION
    The Pester suite mocks every write, so it can never tell you that a fix really
    took on a live Windows and really came back off again. Windows Sandbox can: a
    disposable Windows that starts in seconds and is destroyed when its window
    closes. Nothing this run does reaches the host.

    This script writes a .wsb configuration under build\sandbox\ (git-ignored,
    because it holds absolute paths from this machine) and launches it. Inside,
    tools\sandbox\Invoke-SandboxTest.ps1 runs as the sandbox's built-in
    administrator: audit, apply the selected low/medium-risk fixes, audit again,
    roll everything back, audit a third time, and compare. Results land in
    build\sandbox\results\<timestamp>\ on the host.

    The repository is mapped read-only and copied inside the sandbox before
    anything runs. Networking is off unless -Networking is given, so fixes that
    need the internet (winget updates) are left out of the apply step.

    Requires Windows 10/11 Pro, Enterprise or Education with the Windows Sandbox
    feature enabled (Settings > Optional features > More Windows features).
.PARAMETER PesterPath
    A folder containing Pester (and optionally PSScriptAnalyzer) modules, e.g. the
    parent of Pester\5.9.1. When given, the sandbox also runs the full test suite
    elevated - the one place CE_TESTS_ALLOW_ELEVATED=1 is meant to be used.
.PARAMETER Networking
    Give the sandbox network access. Off by default so the run is fully isolated.
.PARAMETER NoLaunch
    Write the .wsb file and print its path without starting the sandbox.
.EXAMPLE
    .\tools\sandbox\New-SandboxRun.ps1
.EXAMPLE
    .\tools\sandbox\New-SandboxRun.ps1 -PesterPath C:\tools\ps-modules
#>
[CmdletBinding()]
param(
    [string]$PesterPath,
    [switch]$Networking,
    [switch]$NoLaunch
)
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$sandboxExe = Join-Path $env:windir 'System32\WindowsSandbox.exe'
$sandboxMissing = 'Windows Sandbox is not installed. Enable "Windows Sandbox" under Settings > Optional features > More Windows features (Pro, Enterprise or Education), restart, and run this again.'
if (-not $NoLaunch -and -not (Test-Path -LiteralPath $sandboxExe)) { throw $sandboxMissing }

$buildDir = Join-Path $repo 'build\sandbox'
$results = Join-Path $buildDir 'results'
New-Item -ItemType Directory -Path $results -Force | Out-Null
# Options the inner script cannot receive as arguments (the .wsb LogonCommand is fixed).
@{ networking = [bool]$Networking; pester = [bool]$PesterPath } | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $results 'run.json') -Encoding ASCII

$e = { param($s) [System.Security.SecurityElement]::Escape([string]$s) }
$folders = @"
    <MappedFolder>
      <HostFolder>$(& $e $repo)</HostFolder>
      <SandboxFolder>C:\baseline-tool</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$(& $e $results)</HostFolder>
      <SandboxFolder>C:\results</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
"@
if ($PesterPath) {
    $PesterPath = (Resolve-Path -LiteralPath $PesterPath).Path
    if (-not (Get-ChildItem -LiteralPath $PesterPath -Directory -Filter 'Pester' -ErrorAction SilentlyContinue)) {
        throw "No Pester folder under '$PesterPath'. Point -PesterPath at the folder that contains Pester\<version>."
    }
    $folders += @"

    <MappedFolder>
      <HostFolder>$(& $e $PesterPath)</HostFolder>
      <SandboxFolder>C:\ps-modules</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
"@
}

$wsb = @"
<Configuration>
  <Networking>$(if ($Networking) { 'Enable' } else { 'Disable' })</Networking>
  <ClipboardRedirection>false</ClipboardRedirection>
  <PrinterRedirection>false</PrinterRedirection>
  <AudioInput>false</AudioInput>
  <VideoInput>false</VideoInput>
  <MappedFolders>
$folders
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /c start "Engramic Baseline - sandbox run" powershell.exe -NoExit -ExecutionPolicy Bypass -File C:\baseline-tool\tools\sandbox\Invoke-SandboxTest.ps1</Command>
  </LogonCommand>
</Configuration>
"@
$wsbPath = Join-Path $buildDir 'baseline.wsb'
Set-Content -LiteralPath $wsbPath -Value $wsb -Encoding ASCII

Write-Host "Sandbox config : $wsbPath"
Write-Host "Repository     : $repo (read-only inside the sandbox)"
Write-Host "Results        : $results"
Write-Host "Networking     : $(if ($Networking) { 'on' } else { 'off' })"
if ($PesterPath) { Write-Host "Test suite     : yes, from $PesterPath" } else { Write-Host 'Test suite     : no (pass -PesterPath to include it)' }
if ($NoLaunch) {
    if (-not (Test-Path -LiteralPath $sandboxExe)) { Write-Warning $sandboxMissing }
    return
}

Write-Host ''
Write-Host 'Starting Windows Sandbox. The first launch can take a few minutes to build the image; a console titled "Engramic Baseline - sandbox run" then appears inside it and stays open with the verdict.'
Write-Host 'Closing the window destroys the sandbox. Results are already on the host.'
Start-Process -FilePath $sandboxExe -ArgumentList "`"$wsbPath`""
