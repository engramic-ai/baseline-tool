#Requires -Version 5.1
<#
.SYNOPSIS
    Compares what the Intune scripts reported for a status.json the PowerShell module wrote with what they
    reported for one baseline.exe wrote.

.DESCRIPTION
    Reads two result files of tools\contracts\Invoke-IntuneReaders.ps1, one for each tool's status.json, both
    written for the same checks on the same device and read as the same account. First it checks each file:
    a run of each script in each host, each host the Windows PowerShell 5.1 of the bitness it was meant to be,
    the same account throughout, and no attempt to start the scheduled audit. Then it compares every value
    each script reported in each host.

    Values may differ only where the ledger, tests\parity\divergences.json, ignores or explains them for that
    account and those checks: the tool version, which each tool writes as its own. Anything else that differs
    is unexplained, and the script exits 1; otherwise 0.

.PARAMETER ModuleResultPath
    The result file for the module's status.json.

.PARAMETER BaselineResultPath
    The result file for baseline.exe's status.json.

.PARAMETER CheckId
    The checks both status files hold, for the ledger's scope. Default: SU-01.

.PARAMETER LedgerPath
    The ledger. Default: tests\parity\divergences.json.

.PARAMETER ResultPath
    Also write the comparison as JSON.

.EXAMPLE
    .\tools\contracts\Compare-IntuneReaders.ps1 -ModuleResultPath .\readers-module.json -BaselineResultPath .\readers-baseline.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ModuleResultPath,
    [Parameter(Mandatory = $true)][string]$BaselineResultPath,
    [ValidatePattern('^[A-Za-z]{2}-\d{2}$')][string[]]$CheckId = @('SU-01'),
    [string]$LedgerPath,
    [string]$ResultPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $repo 'tools\parity\Parity.psm1') -Force
if (-not $LedgerPath) { $LedgerPath = Join-Path $repo 'tests\parity\divergences.json' }

function Read-ReaderResult {
    <# A result file, checked: each script in each host once, each host what it was meant to be, one account, no audit started. #>
    param([string]$Path)
    # Windows PowerShell 5.1 passes a top-level JSON array on as one object, so the runs are taken out of it.
    $parsed = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    $runs = @($parsed | ForEach-Object { $_ })
    $problems = New-Object System.Collections.ArrayList
    foreach ($reader in 'Discover', 'Detect') {
        foreach ($bitness in '64-bit', '32-bit') {
            $matching = @($runs | Where-Object { $_.Script -eq $reader -and $_.Bitness -eq $bitness })
            if ($matching.Count -ne 1) { [void]$problems.Add("$reader in $bitness Windows PowerShell ran $($matching.Count) times, not once") }
        }
    }
    foreach ($run in $runs) {
        $name = "$($run.Script) in $($run.Bitness) Windows PowerShell"
        if ([bool]$run.Is64BitProcess -ne ($run.Bitness -eq '64-bit')) { [void]$problems.Add("$name ran in a host that said it was $(if ($run.Is64BitProcess) { '64-bit' } else { '32-bit' })") }
        if (-not ([string]$run.PSVersion).StartsWith('5.1.', [StringComparison]::Ordinal)) { [void]$problems.Add("$name ran in PowerShell $($run.PSVersion), not 5.1") }
        if ([bool]$run.TaskStartRequested) { [void]$problems.Add("$name tried to start the scheduled audit, so it did not take status.json as current") }
    }
    $contexts = @($runs | ForEach-Object { [string]$_.Context } | Select-Object -Unique)
    if ($contexts.Count -ne 1) { [void]$problems.Add("the scripts ran as more than one account: $($contexts -join ', ')") }
    if ($problems.Count) { throw "${Path}: $($problems -join '; ')." }
    return [pscustomobject]@{ Runs = $runs; Context = $contexts[0] }
}

$module = Read-ReaderResult -Path $ModuleResultPath
$baseline = Read-ReaderResult -Path $BaselineResultPath
if ($module.Context -ne $baseline.Context) { throw "The scripts read the module's file as $($module.Context) and baseline.exe's as $($baseline.Context); compare runs as the same account." }
$context = $module.Context
$ledger = Read-ParityLedger -Path $LedgerPath
$entries = Select-ParityLedgerEntry -Ledger $ledger -Context $context -CheckId $CheckId

$moduleValues = New-Object System.Collections.Specialized.OrderedDictionary
Add-ParityReaderValue -Result $module.Runs -Into $moduleValues
$baselineValues = New-Object System.Collections.Specialized.OrderedDictionary
Add-ParityReaderValue -Result $baseline.Runs -Into $baselineValues
$rows = @(Compare-ParityValue -Module $moduleValues -Baseline $baselineValues -Entry $entries)

Write-Host "What the unchanged Intune scripts reported, read as $context, for the module's status.json and for baseline.exe's ($($CheckId -join ', ')):"
Write-ParityComparison -Row $rows
$verdict = Get-ParityVerdict -Row $rows -Entry $entries
Write-Host ('{0} values compared: {1} match, {2} ignored, {3} explained, {4} different' -f $verdict.Compared, $verdict.Match, $verdict.Ignored, $verdict.Explained, $verdict.Unexplained)
if ($ResultPath) {
    $record = [pscustomobject][ordered]@{ Checks = $CheckId; Context = $context; Ledger = $LedgerPath; Verdict = $verdict; Values = ConvertTo-ParityRecord -Row $rows }
    [IO.File]::WriteAllText($ResultPath, (ConvertTo-Json -InputObject $record -Depth 6), (New-Object System.Text.UTF8Encoding($true)))
}
if (-not $verdict.Passed) {
    Write-Host 'Result: DIFFERENT. The scripts report something else for baseline.exe''s status.json where the ledger does not explain it.'
    exit 1
}
Write-Host 'Result: the scripts report the same for both, apart from what the ledger ignores.'
exit 0
