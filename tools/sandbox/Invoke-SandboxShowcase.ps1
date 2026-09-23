#Requires -Version 5.1
<#
.SYNOPSIS
    Runs inside Windows Sandbox: builds a representative device and keeps its audit report.
.DESCRIPTION
    Started by the showcase environment. Installs the AI tools named in CE_SHOWCASE_TOOLS,
    launches them so they are seen running, writes a realistic MCP server configuration for
    Claude Desktop, then runs a full audit and copies the report to the results folder.

    The point is honest marketing material: a real audit of a real (if deliberately
    representative) device, on a throwaway machine whose name is a random GUID and whose only
    account is WDAGUtilityAccount - so nothing identifying can leak into a published screenshot.
    The MCP configuration is seeded rather than fabricated in the report: the tool genuinely
    discovers and classifies it, which is the behaviour the screenshot is meant to show.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:USERNAME -ne 'WDAGUtilityAccount' -or -not (Test-Path 'C:\baseline-tool\src\CEAudit\CEAudit.psd1')) {
    throw 'This installs software. It only runs inside a Windows Sandbox started by tools\sandbox\New-SandboxRun.ps1 -Environment showcase.'
}
$results = if ($env:SANDBOX_RESULTS) { $env:SANDBOX_RESULTS } else { Join-Path 'C:\results' (Get-Date -Format 'yyyyMMdd-HHmmss') }
New-Item -ItemType Directory -Path $results -Force | Out-Null
Import-Module 'C:\sandbox\SandboxLab.psm1' -Force

$work = 'C:\work\baseline-tool'
New-Item -ItemType Directory -Path $work -Force | Out-Null
& robocopy.exe 'C:\baseline-tool' $work /E /NFL /NDL /NJH /NJS /XD .git output build .playwright-mcp | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed with exit code $LASTEXITCODE" }

$tools = @(($env:CE_SHOWCASE_TOOLS -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
Write-Host "==> Installing $($tools.Count) AI tool(s): $($tools -join ', ')" -ForegroundColor Cyan
foreach ($t in $tools) {
    $r = Install-SandboxTool -Id $t
    Write-Host ("    {0}: {1}{2} ({3}s)" -f $t, $(if ($r.Installed) { 'installed' } else { 'FAILED' }), $(if ($r.Message) { " - $($r.Message)" }), $r.Seconds) -ForegroundColor $(if ($r.Installed) { 'Green' } else { 'Red' })
    if ($r.Installed) { $null = Start-SandboxTool -Id $t -SettleSeconds 6 }
}

Write-Host '==> Writing a representative MCP server configuration' -ForegroundColor Cyan
# Two servers wired to Claude Desktop: one holding its token in plaintext, one referencing an
# environment variable. This is an ordinary way for these files to end up on a developer's machine,
# and it is what SC-13 is designed to find.
$cfgPath = Join-Path $env:APPDATA 'Claude\claude_desktop_config.json'
New-Item -ItemType Directory -Path (Split-Path -Parent $cfgPath) -Force | Out-Null
@'
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_SHOWCASEonlyNOTaREALtoken0123456789" }
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\WDAGUtilityAccount\\Documents"],
      "env": { "OPENAI_API_KEY": "${env:OPENAI_API_KEY}" }
    }
  }
}
'@ | Set-Content -LiteralPath $cfgPath -Encoding UTF8

Write-Host '==> Running the audit' -ForegroundColor Cyan
$out = Join-Path $results 'audit'
& (Join-Path $work 'app\Invoke-CEAudit.ps1') -OutputPath $out -NoOpen
foreach ($n in 'report.html', 'report.md', 'findings.json', 'changeset.json') {
    $p = Join-Path $out $n
    if (Test-Path -LiteralPath $p) { Copy-Item -LiteralPath $p -Destination (Join-Path $results $n) -Force }
}

Write-Host ''
Write-Host "Report is on the host under build\sandbox\results\showcase\$(Split-Path -Leaf $results)\report.html" -ForegroundColor Cyan
Write-Host 'Machine name and account are the sandbox defaults, so nothing identifying is in it.' -ForegroundColor Cyan
Write-Host 'Close this window to destroy the sandbox.' -ForegroundColor Cyan
