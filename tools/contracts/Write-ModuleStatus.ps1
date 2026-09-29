#Requires -Version 5.1
<#
.SYNOPSIS
    Has the PowerShell module audit the given checks and write status.json for them, as its scheduled audit
    writes the file.

.DESCRIPTION
    Imports the module, runs Invoke-CEAuditCore for -Id, then Get-CESummary, ConvertTo-CEStatus (with no report
    folder, as baseline.exe has none yet) and Write-CEStatus, which writes status.json atomically, UTF-8 with a
    byte order mark. This is the module's side of the comparison with baseline.exe: the same checks, on the same
    device, as the same account.

    Without -Path the file goes into the module's data folder, %ProgramData%\EngramicBaseline, as the scheduled
    audit writes it. The Contracts job does that as SYSTEM on its runner, after baseline.exe scheduled-audit has
    written the file there. With -Path it goes where you say, which is how to make one without changing the
    data folder.

    It runs in Windows PowerShell 5.1, as the scheduled audit does: PowerShell 7 would write the file without
    its byte order mark.

.PARAMETER Id
    The checks to run. Default: SU-01.

.PARAMETER Path
    Where to write status.json. Default: the module's data folder.

.PARAMETER ModulePath
    The module to import. Default: src\CEAudit\CEAudit.psd1 in this repository.

.PARAMETER DataRoot
    The module's data folder, where it reads administrators' config overrides and packs and, without -Path,
    writes status.json. Default: %ProgramData%\EngramicBaseline, as the scheduled audit uses. Give an empty
    folder to keep the device's own data folder out of the comparison.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\contracts\Write-ModuleStatus.ps1 -Id SU-01 -Path .\module\status.json -DataRoot .\module-data
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z]{2}-\d{2}$')][string[]]$Id = @('SU-01'),
    [string]$Path,
    [string]$ModulePath,
    [string]$DataRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Run this in Windows PowerShell 5.1, as the scheduled audit runs: PowerShell 7 would write status.json without its byte order mark.'
}
if (-not $ModulePath) { $ModulePath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src\CEAudit\CEAudit.psd1' }

# As the parity harness does: an import argument moves the data folder even when elevated, unlike the
# development environment variable.
if ($DataRoot) { Import-Module $ModulePath -Force -ArgumentList $DataRoot } else { Import-Module $ModulePath -Force }
$findings = @(Invoke-CEAuditCore -Id $Id)
$context = Get-CEDeviceContext
$summary = Get-CESummary -Findings $findings
$status = ConvertTo-CEStatus -Findings $findings -Summary $summary -Context $context -ReportFolder ''
$written = if ($Path) { Write-CEStatus -Status $status -Path $Path } else { Write-CEStatus -Status $status }
Write-Host "The module ($(Get-CEToolVersion)) wrote $written for $($Id -join ', ') as $($context.RunningAs)."
