#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the AI-tool detection lab inside Windows Sandbox. Started by the ai-lab environment, not directly.
.DESCRIPTION
    Sets the lab switches, runs tests\lab\*.Lab.Tests.ps1 with Pester, and writes lab-summary.md
    (one row per tool: install, detected, signal, running, elevated flag, MCP config) plus
    pester-lab.xml to the run's results folder on the host.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or -not (Test-Path 'C:\baseline-tool\src\CEAudit\CEAudit.psd1')) {
    throw 'The lab installs software and runs elevated. It only runs inside a Windows Sandbox started by tools\sandbox\New-SandboxRun.ps1 -Environment ai-lab.'
}
$results = if ($env:SANDBOX_RESULTS) { $env:SANDBOX_RESULTS } else { Join-Path 'C:\results' (Get-Date -Format 'yyyyMMdd-HHmmss') }
New-Item -ItemType Directory -Path $results -Force | Out-Null

$env:CE_LAB = '1'
$env:CE_TESTS_ALLOW_ELEVATED = '1'
if (Test-Path 'C:\ps-modules\Pester') { $env:PSModulePath = 'C:\ps-modules;' + $env:PSModulePath }
if (-not (Get-Module -ListAvailable Pester | Where-Object { $_.Version -ge [version]'5.5' })) {
    Write-Host 'Installing Pester from the PowerShell Gallery...'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -Confirm:$false | Out-Null
    Import-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue | Out-Null
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    Install-Module Pester -MinimumVersion 5.5 -Force -Scope CurrentUser -SkipPublisherCheck -Confirm:$false
}
Import-Module Pester -MinimumVersion 5.5

$global:LabMatrix = New-Object System.Collections.ArrayList
$c = New-PesterConfiguration
$c.Run.Path = 'C:\baseline-tool\tests\lab'
$c.Run.PassThru = $true
$c.Output.Verbosity = 'Detailed'
$c.Output.RenderMode = 'Plaintext'   # no ANSI: sandbox consoles cope badly with colour redraws
$c.TestResult.Enabled = $true
$c.TestResult.OutputPath = Join-Path $results 'pester-lab.xml'
$r = Invoke-Pester -Configuration $c

$lines = @(
    "# AI-tool detection lab $(Split-Path -Leaf $results)"
    ''
    "Pester: passed $($r.PassedCount), failed $($r.FailedCount), skipped $($r.SkippedCount)"
    ''
    '| Tool | Install | Detected after install | Signal | Running | Elevated flagged | MCP config | Note |'
    '|---|---|---|---|---|---|---|---|'
)
foreach ($row in $global:LabMatrix) {
    $lines += "| $($row.Tool) | $($row.Install) | $($row.Detected) | $($row.Signal) | $($row.Running) | $($row.Elevated) | $($row.Mcp) | $($row.Note) |"
}
$lines += ''
$lines += 'Install = how the tool got onto the machine (winget / script / npm / vscode) or why it could not. Signal = the first detection rule that fired. Elevated flagged = UA-10 reported the running agent as administrator (the sandbox user is one).'
Set-Content -LiteralPath (Join-Path $results 'lab-summary.md') -Value ($lines -join "`r`n") -Encoding UTF8
$global:LabMatrix | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $results 'lab-summary.json') -Encoding UTF8

Write-Host ''
$global:LabMatrix | Format-Table Tool, Install, Detected, Signal, Running, Elevated, Mcp -AutoSize | Out-String | Write-Host
Write-Host "Lab: passed $($r.PassedCount), failed $($r.FailedCount), skipped $($r.SkippedCount)" -ForegroundColor $(if ($r.FailedCount) { 'Red' } else { 'Green' })
Write-Host "Results are on the host under build\sandbox\results\ai-lab\$(Split-Path -Leaf $results). Close this window to destroy the sandbox." -ForegroundColor Cyan
