#Requires -Version 5.1
<#
.SYNOPSIS
    Runs one of Engramic Baseline's sandbox environments in a disposable Windows Sandbox.
.DESCRIPTION
    Thin wrapper over sandbox\New-Sandbox.ps1 (which has no dependency on Baseline) that picks an
    environment from tools\sandbox\environments\:

      apply-rollback  audit, apply the selected low/medium-risk fixes for real, audit again, roll
                      back from the undo log, audit a third time and compare. Networking off.
      ai-lab          install real AI tools one at a time and check Baseline detects each of them:
                      installed, running (and flagged elevated), and a seeded MCP config with a
                      plaintext credential. Networking on. Runs tests\lab\ as a Pester suite.
      ci              the same jobs as .github/workflows/ci.yml on a throwaway Windows: lint and
                      the unit tests on Windows PowerShell 5.1 and pwsh 7, the desktop app layout,
                      and the Intune deployment rehearsal (install, audit as SYSTEM, uninstall).
                      Networking on (pwsh and the Intune packaging tool are downloaded).
      showcase        install representative AI tools, seed an MCP configuration, run a real audit
                      and keep the report - anonymous, current marketing screenshots on demand.
                      Networking on.

    Results land in build\sandbox\results\<environment>\<timestamp>\ on the host. The
    repository is mapped read-only; the sandbox is destroyed when its window closes.
.PARAMETER Environment
    apply-rollback (default), ai-lab, ci or showcase, or a path to your own environment JSON.
.PARAMETER Tools
    ai-lab only: which catalogue tools to install and test (ids from sandbox\tools.json).
    Default is the environment's own list.
.PARAMETER PesterPath
    A folder containing Pester and PSScriptAnalyzer (the parent of Pester\<version>). Recommended
    for ai-lab and ci; for apply-rollback it additionally runs the whole unit-test suite elevated.
.PARAMETER Networking
    Force networking on.
.PARAMETER NoLaunch
    Write the sandbox files without starting the sandbox.
.EXAMPLE
    .\tools\sandbox\New-SandboxRun.ps1
.EXAMPLE
    .\tools\sandbox\New-SandboxRun.ps1 -Environment ai-lab -PesterPath C:\tools\ps-modules -Tools claude-desktop,cursor
#>
[CmdletBinding()]
param(
    [string]$Environment = 'apply-rollback',
    [string[]]$Tools,
    [string]$PesterPath,
    [switch]$Networking,
    [switch]$NoLaunch
)
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$envPath = if (Test-Path -LiteralPath $Environment) { $Environment } else { Join-Path $PSScriptRoot "environments\$Environment.json" }
if (-not (Test-Path -LiteralPath $envPath)) { throw "No environment '$Environment'. Use apply-rollback, ai-lab, ci, showcase, or a path to an environment JSON." }

$maps = @()
$vars = @{}
if ($PesterPath) {
    $PesterPath = (Resolve-Path -LiteralPath $PesterPath).Path
    if (-not (Get-ChildItem -LiteralPath $PesterPath -Directory -Filter 'Pester' -ErrorAction SilentlyContinue)) {
        throw "No Pester folder under '$PesterPath'. Point -PesterPath at the folder that contains Pester\<version>."
    }
    $maps += @{ host = $PesterPath; sandbox = 'C:\ps-modules'; readOnly = $true }
}
elseif ((Split-Path -Leaf $envPath) -in @('ai-lab.json', 'ci.json')) {
    Write-Warning "$([IO.Path]::GetFileNameWithoutExtension($envPath)) runs Pester; without -PesterPath it will try to install Pester from the gallery inside the sandbox."
}
if ($Tools) { $vars['CE_LAB_TOOLS'] = ($Tools -join ',') }

& (Join-Path $repo 'sandbox\New-Sandbox.ps1') -Environment $envPath -Root $repo -MappedFolder $maps -Var $vars -Networking:$Networking -NoLaunch:$NoLaunch
