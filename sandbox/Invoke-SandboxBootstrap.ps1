#Requires -Version 5.1
<#
.SYNOPSIS
    Runs inside Windows Sandbox: applies the environment in C:\results\env.json, then runs its script.
.DESCRIPTION
    Started by the .wsb LogonCommand that New-Sandbox.ps1 writes. Sets the environment's
    variables, bootstraps winget if any tool needs it, installs the listed tools, then runs
    the environment's script in this console. Everything it prints is also transcribed to
    the run's results folder, whose path is exported as SANDBOX_RESULTS.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # progress bars redraw the console constantly; the transcript is the record

if ($env:USERNAME -ne 'WDAGUtilityAccount' -or -not (Test-Path 'C:\results\env.json')) {
    throw 'This script only runs inside a Windows Sandbox started by New-Sandbox.ps1.'
}
$config = Get-Content -LiteralPath 'C:\results\env.json' -Raw | ConvertFrom-Json
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$run = Join-Path 'C:\results' $stamp
New-Item -ItemType Directory -Path $run -Force | Out-Null
$env:SANDBOX_RESULTS = $run
$env:SANDBOX_NAME = [string]$config.name
Start-Transcript -Path (Join-Path $run 'bootstrap.txt') | Out-Null
$Host.UI.RawUI.WindowTitle = "$($config.name) - sandbox"

try {
    Import-Module 'C:\sandbox\SandboxLab.psm1' -Force
    Write-Host "Environment: $($config.name)" -ForegroundColor Cyan
    if ($config.description) { Write-Host "  $($config.description)" }
    Write-Host "  networking: $(if ($config.networking) { 'on' } else { 'off' })   results: $run"

    foreach ($p in @($config.vars.PSObject.Properties)) { Set-Item -Path "Env:\$($p.Name)" -Value ([string]$p.Value) }

    if ($config.networking) {
        # The host's ICS DNS proxy is unreliable from a sandbox, so do not wait to find out: point the
        # sandbox at public resolvers first (it is a throwaway VM), then check that names resolve.
        foreach ($a in (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' })) {
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses @('1.1.1.1', '8.8.8.8') -ErrorAction SilentlyContinue
        }
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        $resolves = { try { [void][Net.Dns]::GetHostAddresses('www.microsoft.com'); $true } catch { $false } }
        $online = $false
        for ($i = 0; $i -lt 8 -and -not $online; $i++) { $online = & $resolves; if (-not $online) { Start-Sleep -Seconds 2 } }
        if ($online) { Write-Host 'Network is up (DNS 1.1.1.1 / 8.8.8.8).' -ForegroundColor Green; $env:SANDBOX_ONLINE = '1' }
        else {
            $probe = '1.1.1.1'
            $raw = Test-Connection -ComputerName $probe -Count 1 -Quiet -ErrorAction SilentlyContinue
            Write-Warning "No network: name resolution fails$(if ($raw) { ' although raw IP works' } else { ' and raw IP fails too' }). Installs will fail. On the host, check for a VPN or firewall rule blocking the sandbox's virtual adapter, or restart Internet Connection Sharing (Restart-Service SharedAccess)."
            $env:SANDBOX_ONLINE = '0'
        }
    }

    $tools = @($config.tools)
    if ($tools.Count) {
        if (-not $config.networking) { throw "Environment lists tools to install but networking is off." }
        Install-Winget | Out-Null
        $installed = foreach ($t in $tools) {
            Write-Host "Installing $t..." -ForegroundColor Cyan
            $r = Install-SandboxTool -Id $t
            Write-Host ("  {0}: {1}{2} ({3}s)" -f $t, $(if ($r.Installed) { 'installed' } else { 'FAILED' }), $(if ($r.Message) { " - $($r.Message)" }), $r.Seconds) -ForegroundColor $(if ($r.Installed) { 'Green' } else { 'Red' })
            $r
        }
        $installed | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $run 'tools-installed.json') -Encoding UTF8
    }

    if ($config.run -and $config.run.script) {
        $script = [string]$config.run.script
        if (-not (Test-Path -LiteralPath $script)) { throw "Run script not found in the sandbox: $script" }
        Write-Host ''
        Write-Host "==> $script" -ForegroundColor Cyan
        $runArgs = @($config.run.args)
        & $script @runArgs
    }
    else {
        Write-Host ''
        Write-Host 'No run script: the environment is ready. Close this window to destroy the sandbox.' -ForegroundColor Cyan
    }
}
catch {
    Write-Host ''
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
}
finally {
    Stop-Transcript | Out-Null
}
