#Requires -Version 5.1
<#
.SYNOPSIS
    Builds and launches a disposable Windows Sandbox from an environment definition.
.DESCRIPTION
    An environment is a small JSON file:

      {
        "name": "ai-lab",
        "description": "what this environment is for",
        "networking": true,
        "mappedFolders": [ { "host": "{root}", "sandbox": "C:\\baseline-tool", "readOnly": true } ],
        "tools": [ "vscode" ],                       # ids from tools.json, installed before run
        "vars": { "CE_LAB_TOOLS": "claude-desktop" },# environment variables set before run
        "run": { "script": "C:\\baseline-tool\\tests\\lab\\Invoke-Lab.ps1", "args": [] }
      }

    Tokens: {root} is -Root (default: the parent of this sandbox folder), {results} the
    results folder on the host, {sandbox} this folder. This folder is always mapped read-only
    at C:\sandbox and the results folder read-write at C:\results, where the resolved
    environment is copied as env.json for Invoke-SandboxBootstrap.ps1 to read.

    The .wsb is written under -BuildDir (default <root>\build\sandbox) because it holds
    absolute paths from this machine. Nothing in the sandbox can change the host except
    through the results folder.
.PARAMETER Environment
    Path to the environment JSON.
.PARAMETER Root
    Folder that {root} resolves to. Default: the parent of the sandbox folder.
.PARAMETER MappedFolder
    Extra folders to map: hashtables with host, sandbox and optional readOnly (default true).
.PARAMETER Var
    Extra environment variables for the run, merged over the environment's vars.
.PARAMETER Networking
    Force networking on regardless of the environment file.
.PARAMETER NoLaunch
    Write the .wsb and env.json without starting the sandbox.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Environment,
    [string]$Root,
    [hashtable[]]$MappedFolder = @(),
    [hashtable]$Var = @{},
    [switch]$Networking,
    [switch]$NoLaunch,
    [string]$BuildDir
)
$ErrorActionPreference = 'Stop'

$sandboxDir = $PSScriptRoot
if (-not $Root) { $Root = Split-Path -Parent $sandboxDir }
$Root = (Resolve-Path -LiteralPath $Root).Path
if (-not $BuildDir) { $BuildDir = Join-Path $Root 'build\sandbox' }
$env = Get-Content -LiteralPath (Resolve-Path -LiteralPath $Environment).Path -Raw | ConvertFrom-Json
$name = [string]$env.name
if (-not $name) { throw "Environment file has no 'name'." }

$results = Join-Path $BuildDir "results\$name"
New-Item -ItemType Directory -Path $results -Force | Out-Null
$resolve = { param($s) ([string]$s).Replace('{root}', $Root).Replace('{results}', $results).Replace('{sandbox}', $sandboxDir) }
$field = { param($o, $n, $d) $p = $o.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { $p.Value } else { $d } }

$net = $Networking -or [bool](& $field $env 'networking' $false)
$folders = @(
    @{ host = $sandboxDir; sandbox = 'C:\sandbox'; readOnly = $true }
    @{ host = $results; sandbox = 'C:\results'; readOnly = $false }
)
foreach ($m in @(& $field $env 'mappedFolders' @())) { $folders += @{ host = (& $resolve $m.host); sandbox = [string]$m.sandbox; readOnly = [bool](& $field $m 'readOnly' $true) } }
foreach ($m in $MappedFolder) { $folders += @{ host = [string]$m.host; sandbox = [string]$m.sandbox; readOnly = $(if ($m.ContainsKey('readOnly')) { [bool]$m.readOnly } else { $true }) } }
foreach ($f in $folders) {
    if (-not (Test-Path -LiteralPath $f.host)) { throw "Mapped folder does not exist on the host: $($f.host)" }
    $f.host = (Resolve-Path -LiteralPath $f.host).Path
}

$vars = @{}
foreach ($p in @((& $field $env 'vars' ([pscustomobject]@{})).PSObject.Properties)) { $vars[$p.Name] = [string]$p.Value }
foreach ($k in $Var.Keys) { $vars[$k] = [string]$Var[$k] }

$run = & $field $env 'run' $null
$resolved = [ordered]@{
    name          = $name
    description   = [string](& $field $env 'description' '')
    networking    = $net
    tools         = @(& $field $env 'tools' @())
    vars          = $vars
    run           = $(if ($run) { [ordered]@{ script = (& $resolve $run.script); args = @(& $field $run 'args' @()) } } else { $null })
    mappedFolders = @($folders | ForEach-Object { [ordered]@{ host = $_.host; sandbox = $_.sandbox; readOnly = $_.readOnly } })
    createdAt     = (Get-Date).ToString('o')
}
$resolved | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $results 'env.json') -Encoding UTF8

$e = { param($s) [System.Security.SecurityElement]::Escape([string]$s) }
$xmlFolders = ($folders | ForEach-Object {
    "    <MappedFolder>`r`n      <HostFolder>$(& $e $_.host)</HostFolder>`r`n      <SandboxFolder>$(& $e $_.sandbox)</SandboxFolder>`r`n      <ReadOnly>$(if ($_.readOnly) { 'true' } else { 'false' })</ReadOnly>`r`n    </MappedFolder>"
}) -join "`r`n"
$wsb = @"
<Configuration>
  <Networking>$(if ($net) { 'Enable' } else { 'Disable' })</Networking>
  <ClipboardRedirection>false</ClipboardRedirection>
  <PrinterRedirection>false</PrinterRedirection>
  <AudioInput>false</AudioInput>
  <VideoInput>false</VideoInput>
  <MappedFolders>
$xmlFolders
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /c reg add HKCU\Console /v QuickEdit /t REG_DWORD /d 0 /f &amp; start "$(& $e $name)" powershell.exe -NoExit -ExecutionPolicy Bypass -File C:\sandbox\Invoke-SandboxBootstrap.ps1</Command>
  </LogonCommand>
</Configuration>
"@
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
$wsbPath = Join-Path $BuildDir "$name.wsb"
Set-Content -LiteralPath $wsbPath -Value $wsb -Encoding ASCII

Write-Host "Environment : $name$(if ($resolved.description) { " - $($resolved.description)" })"
Write-Host "Sandbox file: $wsbPath"
Write-Host "Results     : $results"
Write-Host "Networking  : $(if ($net) { 'on' } else { 'off' })"
Write-Host "Tools       : $(if ($resolved.tools.Count) { $resolved.tools -join ', ' } else { '(none pre-installed)' })"
foreach ($f in $folders) { Write-Host ("Map         : {0} -> {1}{2}" -f $f.host, $f.sandbox, $(if ($f.readOnly) { ' (read-only)' } else { '' })) }

$sandboxExe = Join-Path $env:windir 'System32\WindowsSandbox.exe'
$missing = 'Windows Sandbox is not installed. Enable "Windows Sandbox" under Settings > Optional features > More Windows features (Pro, Enterprise or Education), restart, and run this again.'
if ($NoLaunch) { if (-not (Test-Path -LiteralPath $sandboxExe)) { Write-Warning $missing }; return }
if (-not (Test-Path -LiteralPath $sandboxExe)) { throw $missing }
Write-Host ''
Write-Host "Starting Windows Sandbox. A console titled `"$name`" appears inside it once the image is up (the first launch takes a few minutes)."
Start-Process -FilePath $sandboxExe -ArgumentList "`"$wsbPath`""
