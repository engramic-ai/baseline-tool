#Requires -Version 5.1
<#
.SYNOPSIS
    Runs checks in the PowerShell module and in baseline.exe on this device, as this account, and compares what
    they find.

.DESCRIPTION
    The parity harness. For the checks named by -Id (SU-01 by default) it:

      1. runs the untouched module out of process in Windows PowerShell 5.1: Invoke-CEAuditCore, then
         Get-CESummary and ConvertTo-CEStatus, and writes findings.json and status.json as the module does
         (Write-CEStatus);
      2. runs baseline.exe audit --shipped-config --json findings and --json status, keeping the exact bytes
         each writes;
      3. runs the unchanged Intune discovery and detection scripts on both status files, in 64-bit and 32-bit
         Windows PowerShell 5.1 (tools\contracts\Invoke-IntuneReaders.ps1);
      4. compares them: first the device context each tool saw (computer, account, elevation, Windows), since
         one difference there explains many after it; then every field of every finding, matched by FindingId,
         and their order; every value of status.json by its path, and its byte order mark; and every value
         each Intune script reported in each host.

    Every accepted difference is in the ledger, tests\parity\divergences.json: the path, whether the value is
    ignored (it differs by design) or explained (an accepted difference, until more is ported), the reason, and
    the scope, which contexts and checks it applies to. Anything else that differs is unexplained, and the gate
    is zero unexplained differences: the script exits 1 if there is any, and 0 otherwise. An explained entry in
    scope that explained nothing is listed, so it can come off the ledger once nothing needs it.

    Run it as the account whose audit you want to compare: a standard user, an elevated administrator or
    SYSTEM. The context is found from the process and applied to the ledger. Both tools run hidden and read
    the device only. The module is given an empty data folder under -OutputPath, so no administrator's config
    overrides or packs apply to it; baseline.exe is given --shipped-config, so that elevated it does not read
    the overrides in this device's data folder either, and both read the config that ships. Nothing outside
    -OutputPath is written.

.PARAMETER Id
    The checks to run. Default: SU-01.

.PARAMETER BaselineExe
    baseline.exe to compare. Default: the Release build under artifacts\bin, then the Debug one.

.PARAMETER OutputPath
    Folder for both tools' files. Default: artifacts\parity\<yyyyMMdd-HHmmss>.

.PARAMETER LedgerPath
    The ledger of accepted differences. Default: tests\parity\divergences.json.

.PARAMETER ResultPath
    Also write the comparison as JSON: the context, every value compared with its result and ledger entry,
    the counts and the verdict.

.PARAMETER TimeoutMinutes
    How long each tool may run. Default: 10.

.EXAMPLE
    dotnet build Baseline.slnx -c Release
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\parity\Compare-Parity.ps1 -Id SU-01
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z]{2}-\d{2}$')][string[]]$Id = @('SU-01'),
    [string]$BaselineExe,
    [string]$OutputPath,
    [string]$LedgerPath,
    [string]$ResultPath,
    [ValidateRange(1, 120)][int]$TimeoutMinutes = 10
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $PSScriptRoot 'Parity.psm1') -Force
if (-not $LedgerPath) { $LedgerPath = Join-Path $repo 'tests\parity\divergences.json' }

# The values that say which device and account each tool audited: compared first.
$ContextPaths = @('status.computerName', 'status.runAs', 'status.elevated', 'status.os')

function Resolve-BaselineExe {
    param([string]$Path)
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "baseline.exe not found at $Path" }
        return (Resolve-Path -LiteralPath $Path).ProviderPath
    }
    foreach ($configuration in 'release', 'debug') {
        $candidate = Join-Path $repo "artifacts\bin\Engramic.Baseline.Cli\$configuration\baseline.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    throw 'baseline.exe was not found under artifacts\bin. Build it first (dotnet build Baseline.slnx -c Release) or pass -BaselineExe.'
}

function Invoke-HiddenProcess {
    <# Runs a program without a window and returns its exit code, the exact bytes of its output and its error text. #>
    param([string]$FilePath, [string]$Arguments, [int]$TimeoutMinutes)
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $FilePath
    $start.Arguments = $Arguments
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    # Windows PowerShell finds its own modules; a PSModulePath inherited from PowerShell 7 would point it at 7's.
    [void]$start.EnvironmentVariables.Remove('PSModulePath')
    $process = [System.Diagnostics.Process]::Start($start)
    try {
        $errors = $process.StandardError.ReadToEndAsync()
        $output = New-Object System.IO.MemoryStream
        $copy = $process.StandardOutput.BaseStream.CopyToAsync($output)
        if (-not $process.WaitForExit($TimeoutMinutes * 60000)) {
            $process.Kill()
            throw "$FilePath did not finish within $TimeoutMinutes minutes."
        }
        $copy.Wait()
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $output.ToArray(); Errors = $errors.Result }
    }
    finally {
        $process.Dispose()
    }
}

function ConvertTo-Literal {
    <# A PowerShell single-quoted string literal. #>
    param([string]$Text)
    return "'" + $Text.Replace("'", "''") + "'"
}

function Invoke-Module {
    <# Runs the module in Windows PowerShell 5.1 and writes its findings.json and status.json to $Folder. #>
    param([string[]]$Ids, [string]$Folder, [string]$DataRoot)
    $idList = '@(' + (($Ids | ForEach-Object { ConvertTo-Literal $_ }) -join ', ') + ')'
    $command = @"
`$ErrorActionPreference = 'Stop'
Import-Module $(ConvertTo-Literal (Join-Path $repo 'src\CEAudit\CEAudit.psd1')) -Force -ArgumentList $(ConvertTo-Literal $DataRoot)
`$findings = @(Invoke-CEAuditCore -Id $idList)
`$context = Get-CEDeviceContext
`$summary = Get-CESummary -Findings `$findings
`$status = ConvertTo-CEStatus -Findings `$findings -Summary `$summary -Context `$context -ReportFolder ''
[void](Write-CEStatus -Status `$status -Path $(ConvertTo-Literal (Join-Path $Folder 'status.json')))
[pscustomobject]@{ Findings = `$findings } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $(ConvertTo-Literal (Join-Path $Folder 'findings.json')) -Encoding UTF8
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $shell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $run = Invoke-HiddenProcess -FilePath $shell -Arguments "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded" -TimeoutMinutes $TimeoutMinutes
    if ($run.ExitCode -ne 0) { throw "The module run failed ($($run.ExitCode)): $($run.Errors)" }
}

function Invoke-Baseline {
    <#
        Runs baseline.exe audit and saves what it writes for --json findings and --json status. --shipped-config
        keeps it to the shipped config, as the module's empty data folder keeps the module.
    #>
    param([string]$Exe, [string[]]$Ids, [string]$Folder)
    New-Item -ItemType Directory -Path $Folder -Force | Out-Null
    foreach ($document in 'findings', 'status') {
        $run = Invoke-HiddenProcess -FilePath $Exe -Arguments "audit --id $($Ids -join ',') --json $document --shipped-config" -TimeoutMinutes $TimeoutMinutes
        if ($run.ExitCode -ne 0) { throw "baseline.exe audit --json $document failed ($($run.ExitCode)): $($run.Errors)" }
        [IO.File]::WriteAllBytes((Join-Path $Folder "$document.json"), $run.Output)
    }
}

function Invoke-Reader {
    <# What the unchanged Intune scripts report for the status.json in $Folder, in both hosts, kept beside it as readers.json. #>
    param([string]$Folder)
    $readers = Join-Path $repo 'tools\contracts\Invoke-IntuneReaders.ps1'
    return @(& $readers -StatusPath (Join-Path $Folder 'status.json') -WorkPath $Folder -ResultPath (Join-Path $Folder 'readers.json') -TimeoutSeconds ($TimeoutMinutes * 60))
}

function Read-JsonFile {
    <# A JSON file as PowerShell reads it, and whether it starts with a UTF-8 byte order mark. #>
    param([string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    return [pscustomobject]@{ Value = (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json); Bom = $bom }
}

function Get-Flat {
    <# A value flattened to paths and text (ConvertTo-ParityFlatValue). #>
    param($Value, [string]$Path)
    $flat = New-Object System.Collections.Specialized.OrderedDictionary
    ConvertTo-ParityFlatValue -Value $Value -Path $Path -Into $flat
    return , $flat
}

$exe = Resolve-BaselineExe -Path $BaselineExe
# TEMPORARY, for spike 2 of the .NET port, reverted before review: the SHA-256 of every file CI published, for
# tools/spikes/Measure-RuntimeSpike.ps1 -Phase Determinism -ReferenceManifest to compare a rebuild of the same commit.
if ($env:GITHUB_ACTIONS -eq 'true') {
    $spikeRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $exe)).ProviderPath.TrimEnd('\')
    Write-Host "SPIKE2-ROOT $spikeRoot"
    foreach ($spikeFile in @(Get-ChildItem -LiteralPath $spikeRoot -Recurse -File -Force | Sort-Object FullName)) {
        Write-Host ('SPIKE2-SHA256 {0}  {1}' -f (Get-FileHash -LiteralPath $spikeFile.FullName -Algorithm SHA256).Hash, $spikeFile.FullName.Substring($spikeRoot.Length + 1))
    }
}
$context = Get-ParityContext
$ledger = Read-ParityLedger -Path $LedgerPath
$Id = @($Id | ForEach-Object { $_.ToUpperInvariant() })
$entries = Select-ParityLedgerEntry -Ledger $ledger -Context $context -CheckId $Id
if (-not $OutputPath) { $OutputPath = Join-Path $repo ('artifacts\parity\' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
$moduleFolder = Join-Path $OutputPath 'module'
$baselineFolder = Join-Path $OutputPath 'baseline'
New-Item -ItemType Directory -Path $moduleFolder -Force | Out-Null

Write-Host "Comparing $($Id -join ', ') on $([Environment]::MachineName) as $([Security.Principal.WindowsIdentity]::GetCurrent().Name) ($context)"
Write-Host "  module       : $(Join-Path $repo 'src\CEAudit') in Windows PowerShell 5.1"
Write-Host "  baseline.exe : $exe"
Write-Host "  ledger       : $LedgerPath ($(@($entries).Count) of $(@($ledger).Count) entries apply)"
Write-Host "  output       : $OutputPath"
Invoke-Module -Ids $Id -Folder $moduleFolder -DataRoot (Join-Path $OutputPath 'module-data')
Invoke-Baseline -Exe $exe -Ids $Id -Folder $baselineFolder

$moduleFindings = @((Read-JsonFile (Join-Path $moduleFolder 'findings.json')).Value.Findings)
$baselineFindings = @((Read-JsonFile (Join-Path $baselineFolder 'findings.json')).Value.Findings)
$moduleStatus = Read-JsonFile (Join-Path $moduleFolder 'status.json')
$baselineStatus = Read-JsonFile (Join-Path $baselineFolder 'status.json')

$statusRows = @(Compare-ParityValue -Module (Get-Flat $moduleStatus.Value 'status') -Baseline (Get-Flat $baselineStatus.Value 'status') -Entry $entries)
$rows = New-Object System.Collections.ArrayList
foreach ($row in $statusRows) { if ($ContextPaths -contains $row.Path) { [void]$rows.Add($row) } }
$findingIds = New-Object System.Collections.ArrayList
foreach ($f in $moduleFindings + $baselineFindings) { if (-not $findingIds.Contains([string]$f.FindingId)) { [void]$findingIds.Add([string]$f.FindingId) } }
foreach ($findingId in $findingIds) {
    $a = @($moduleFindings | Where-Object { $_.FindingId -ceq $findingId }) | Select-Object -First 1
    $b = @($baselineFindings | Where-Object { $_.FindingId -ceq $findingId }) | Select-Object -First 1
    foreach ($row in Compare-ParityValue -Module (Get-Flat $a "finding[$findingId]") -Baseline (Get-Flat $b "finding[$findingId]") -Entry $entries) { [void]$rows.Add($row) }
}
$moduleOrder = Get-Flat @($moduleFindings | ForEach-Object { $_.FindingId }) 'findingOrder'
$baselineOrder = Get-Flat @($baselineFindings | ForEach-Object { $_.FindingId }) 'findingOrder'
foreach ($row in Compare-ParityValue -Module $moduleOrder -Baseline $baselineOrder -Entry $entries) { [void]$rows.Add($row) }
foreach ($row in $statusRows) { if ($ContextPaths -notcontains $row.Path) { [void]$rows.Add($row) } }
$moduleBom = Get-Flat $moduleStatus.Bom 'status.json byte order mark'
$baselineBom = Get-Flat $baselineStatus.Bom 'status.json byte order mark'
foreach ($row in Compare-ParityValue -Module $moduleBom -Baseline $baselineBom -Entry $entries) { [void]$rows.Add($row) }

Write-Host '  Intune scripts: discovery and detection in 64-bit and 32-bit Windows PowerShell 5.1, on each status.json'
$moduleReaders = New-Object System.Collections.Specialized.OrderedDictionary
Add-ParityReaderValue -Result (Invoke-Reader -Folder $moduleFolder) -Into $moduleReaders
$baselineReaders = New-Object System.Collections.Specialized.OrderedDictionary
Add-ParityReaderValue -Result (Invoke-Reader -Folder $baselineFolder) -Into $baselineReaders
foreach ($row in Compare-ParityValue -Module $moduleReaders -Baseline $baselineReaders -Entry $entries) { [void]$rows.Add($row) }

Write-Host ''
Write-Host 'Device context:'
Write-ParityComparison -Row @($rows | Where-Object { $ContextPaths -contains $_.Path })
Write-Host 'Findings, status.json and the Intune scripts:'
Write-ParityComparison -Row @($rows | Where-Object { $ContextPaths -notcontains $_.Path })
Write-Host ''

$verdict = Get-ParityVerdict -Row $rows -Entry $entries
foreach ($path in $verdict.Unused) { Write-Host "Ledger entry that explained nothing here (take it off once no context or check needs it): $path" }
Write-Host ('{0} values compared: {1} match, {2} ignored, {3} explained, {4} different' -f $verdict.Compared, $verdict.Match, $verdict.Ignored, $verdict.Explained, $verdict.Unexplained)
if (@($rows | Where-Object { $ContextPaths -contains $_.Path -and $_.Result -eq 'DIFFERENT' }).Count) {
    Write-Host 'The tools saw a different device context, which may explain the differences after it.'
}
if ($ResultPath) {
    $record = [pscustomobject][ordered]@{
        Checks      = $Id
        Context     = $context
        Account     = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        BaselineExe = $exe
        Ledger      = $LedgerPath
        Verdict     = $verdict
        Values      = ConvertTo-ParityRecord -Row $rows
    }
    [IO.File]::WriteAllText($ResultPath, (ConvertTo-Json -InputObject $record -Depth 6), (New-Object System.Text.UTF8Encoding($true)))
}
if (-not $verdict.Passed) {
    Write-Host 'Result: DIFFERENT. The tools disagree where the ledger does not explain it; see the rows marked DIFFERENT.'
    exit 1
}
Write-Host 'Result: no unexplained differences.'
exit 0
