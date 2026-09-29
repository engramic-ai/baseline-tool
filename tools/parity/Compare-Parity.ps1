#Requires -Version 5.1
<#
.SYNOPSIS
    Runs checks in the PowerShell module and in baseline.exe on this device and compares what they find.

.DESCRIPTION
    The start of the parity harness. For the checks named by -Id (SU-01 by default) it:

      1. runs the untouched module out of process in Windows PowerShell 5.1: Invoke-CEAuditCore, then
         Get-CESummary and ConvertTo-CEStatus, and writes findings.json and status.json as the module does
         (Write-CEStatus);
      2. runs baseline.exe audit --json findings and --json status, keeping the exact bytes each writes;
      3. compares the two: every field of every finding, matched by FindingId, and every value of
         status.json by its path, and runs the Intune discovery script's Get-CEComplianceData on both
         status files;

    then prints each value with its result and exits 1 if anything differs that is not ignored or
    explained below. What is ignored differs by design: the tool version, the audit time and the report
    folder. What is explained differs until more of the tool is ported (see $ExplainedPaths).

    Both tools run hidden, as the account that runs this script, and read the device only. The module is
    given an empty data folder under -OutputPath, so no administrator's config overrides or packs apply
    to it; baseline.exe reads only the config it ships with. Nothing outside -OutputPath is written.

    Run it the same way as the audit to compare: as a standard user, elevated, or as SYSTEM.

.PARAMETER Id
    The checks to run. Default: SU-01.

.PARAMETER BaselineExe
    baseline.exe to compare. Default: the Release build under artifacts\bin, then the Debug one.

.PARAMETER OutputPath
    Folder for both tools' files. Default: artifacts\parity\<yyyyMMdd-HHmmss>.

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
    [ValidateRange(1, 120)][int]$TimeoutMinutes = 10
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# Values that differ by design: skipped.
$IgnoredPaths = @(
    @{ Path = 'status.toolVersion'; Reason = 'the version of each tool' }
    @{ Path = 'status.auditTime'; Reason = 'when each audit ran' }
    @{ Path = 'status.reportFolder'; Reason = 'where each tool writes its report' }
    @{ Path = 'discovery.CEToolVersion'; Reason = 'the version of each tool' }
)

# Differences that are expected until more is ported, each with its reason. Every accepted difference
# needs one; an entry here that no longer matches anything is reported, so it can be removed.
$ExplainedPaths = @(
    @{ Path = 'status.hardware'; Reason = 'baseline.exe writes null until the hardware inventory is ported with the hardware checks' }
)

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
    <# Runs baseline.exe audit and saves what it writes for --json findings and --json status. #>
    param([string]$Exe, [string[]]$Ids, [string]$Folder)
    New-Item -ItemType Directory -Path $Folder -Force | Out-Null
    foreach ($document in 'findings', 'status') {
        $run = Invoke-HiddenProcess -FilePath $Exe -Arguments "audit --id $($Ids -join ',') --json $document" -TimeoutMinutes $TimeoutMinutes
        if ($run.ExitCode -ne 0) { throw "baseline.exe audit --json $document failed ($($run.ExitCode)): $($run.Errors)" }
        [IO.File]::WriteAllBytes((Join-Path $Folder "$document.json"), $run.Output)
    }
}

function Read-JsonFile {
    <# A JSON file as PowerShell reads it, and whether it starts with a UTF-8 byte order mark. #>
    param([string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    return [pscustomobject]@{ Value = (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json); Bom = $bom }
}

function ConvertTo-FlatValue {
    <# Every value under $Value as an ordered map of path to text, such as checks.SU-01.frameworks[1] = "CE+ TC2". #>
    param($Value, [string]$Path, [System.Collections.Specialized.OrderedDictionary]$Into)
    if ($null -eq $Value) { $Into[$Path] = 'null'; return }
    if ($Value -is [string]) { $Into[$Path] = '"' + $Value + '"'; return }
    if ($Value -is [bool]) { $Into[$Path] = $Value.ToString().ToLowerInvariant(); return }
    if ($Value -is [datetime]) { $Into[$Path] = '"' + $Value.ToString('o', [Globalization.CultureInfo]::InvariantCulture) + '"'; return }
    if ($Value -is [System.Collections.IDictionary]) {
        if ($Value.Count -eq 0) { $Into[$Path] = '{}'; return }
        foreach ($key in $Value.Keys) { ConvertTo-FlatValue -Value $Value[$key] -Path "$Path.$key" -Into $Into }
        return
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $properties = @($Value.PSObject.Properties)
        if ($properties.Count -eq 0) { $Into[$Path] = '{}'; return }
        foreach ($property in $properties) { ConvertTo-FlatValue -Value $property.Value -Path "$Path.$($property.Name)" -Into $Into }
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @($Value)
        if ($items.Count -eq 0) { $Into[$Path] = '[]'; return }
        for ($i = 0; $i -lt $items.Count; $i++) { ConvertTo-FlatValue -Value $items[$i] -Path "$Path[$i]" -Into $Into }
        return
    }
    $Into[$Path] = [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
}

function Get-Rule {
    <# The ignore or explain rule that covers a path (the path itself or anything under it), or $null. #>
    param([string]$Path, [object[]]$Rules)
    foreach ($rule in $Rules) {
        if ($Path -eq $rule.Path -or $Path.StartsWith($rule.Path + '.', [StringComparison]::Ordinal) -or $Path.StartsWith($rule.Path + '[', [StringComparison]::Ordinal)) { return $rule }
    }
    return $null
}

function Compare-Flat {
    <#
        One row per path in either document, in document order: both values, and whether they match, are
        ignored, are explained or differ, with the rule that ignores or explains them.
    #>
    param($Module, $Baseline, [string]$Path)
    $left = New-Object System.Collections.Specialized.OrderedDictionary
    $right = New-Object System.Collections.Specialized.OrderedDictionary
    ConvertTo-FlatValue -Value $Module -Path $Path -Into $left
    ConvertTo-FlatValue -Value $Baseline -Path $Path -Into $right
    # The module's paths in order, each path only baseline.exe has placed after the one before it in its own order.
    $paths = New-Object System.Collections.ArrayList
    foreach ($key in $left.Keys) { [void]$paths.Add($key) }
    $after = -1
    foreach ($key in $right.Keys) {
        $at = $paths.IndexOf($key)
        if ($at -lt 0) { $at = $after + 1; $paths.Insert($at, $key) }
        $after = $at
    }
    foreach ($key in $paths) {
        $a = if ($left.Contains($key)) { [string]$left[$key] } else { '(missing)' }
        $b = if ($right.Contains($key)) { [string]$right[$key] } else { '(missing)' }
        $ignoreRule = Get-Rule -Path $key -Rules $IgnoredPaths
        $explainRule = Get-Rule -Path $key -Rules $ExplainedPaths
        $rule = $null
        if ($ignoreRule) { $result = 'ignored'; $rule = $ignoreRule }
        elseif ([string]::Equals($a, $b, [StringComparison]::Ordinal)) { $result = 'match' }
        elseif ($explainRule) { $result = 'explained'; $rule = $explainRule; $explainRule.Used = $true }
        else { $result = 'DIFFERENT' }
        [pscustomobject]@{ Path = $key; Module = $a; Baseline = $b; Result = $result; Rule = $rule }
    }
}

function Write-Comparison {
    <#
        Prints the rows: a match with its value, a difference with both values, and each ignore or explain
        rule once, with how many values it covered and why.
    #>
    param([object[]]$Rows)
    $shown = @{}
    foreach ($row in $Rows) {
        switch ($row.Result) {
            'match' { Write-Host ('  match      {0} = {1}' -f $row.Path, $row.Module) }
            'DIFFERENT' { Write-Host ('  DIFFERENT  {0}: module {1}, baseline.exe {2}' -f $row.Path, $row.Module, $row.Baseline) }
            default {
                $key = $row.Result + '|' + $row.Rule.Path
                if ($shown.ContainsKey($key)) { continue }
                $shown[$key] = $true
                $covered = @($Rows | Where-Object { $_.Result -eq $row.Result -and $null -ne $_.Rule -and $_.Rule.Path -eq $row.Rule.Path })
                $values = if ($covered.Count -eq 1) { ': module {0}, baseline.exe {1}' -f $row.Module, $row.Baseline } else { " ($($covered.Count) values)" }
                Write-Host ('  {0,-10} {1}{2}; {3}' -f $row.Result, $row.Rule.Path, $values, $row.Rule.Reason)
            }
        }
    }
}

function Get-DiscoveryOutput {
    <# What the unchanged Intune discovery script reports for a status.json in $Folder, read as a standard user reads it. #>
    param([string]$Folder)
    # Intune runs the script without strict mode, and it reads checks that may not have run.
    Set-StrictMode -Off
    . (Join-Path $repo 'intune\Discover-CECompliance.ps1')
    return Get-CEComplianceData -DataRoot $Folder -Installed $true -Elevated $false -NoKick
}

$exe = Resolve-BaselineExe -Path $BaselineExe
if (-not $OutputPath) { $OutputPath = Join-Path $repo ('artifacts\parity\' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
$moduleFolder = Join-Path $OutputPath 'module'
$baselineFolder = Join-Path $OutputPath 'baseline'
New-Item -ItemType Directory -Path $moduleFolder -Force | Out-Null
$Id = @($Id | ForEach-Object { $_.ToUpperInvariant() })

Write-Host "Comparing $($Id -join ', ') on $([Environment]::MachineName)"
Write-Host "  module       : $(Join-Path $repo 'src\CEAudit') in Windows PowerShell 5.1"
Write-Host "  baseline.exe : $exe"
Write-Host "  output       : $OutputPath"
Invoke-Module -Ids $Id -Folder $moduleFolder -DataRoot (Join-Path $OutputPath 'module-data')
Invoke-Baseline -Exe $exe -Ids $Id -Folder $baselineFolder

$rows = New-Object System.Collections.ArrayList

$moduleFindings = @((Read-JsonFile (Join-Path $moduleFolder 'findings.json')).Value.Findings)
$baselineFindings = @((Read-JsonFile (Join-Path $baselineFolder 'findings.json')).Value.Findings)
$findingIds = New-Object System.Collections.ArrayList
foreach ($f in $moduleFindings + $baselineFindings) { if (-not $findingIds.Contains([string]$f.FindingId)) { [void]$findingIds.Add([string]$f.FindingId) } }
foreach ($findingId in $findingIds) {
    $a = @($moduleFindings | Where-Object { $_.FindingId -ceq $findingId }) | Select-Object -First 1
    $b = @($baselineFindings | Where-Object { $_.FindingId -ceq $findingId }) | Select-Object -First 1
    foreach ($row in Compare-Flat -Module $a -Baseline $b -Path "finding[$findingId]") { [void]$rows.Add($row) }
}
foreach ($row in Compare-Flat -Module @($moduleFindings | ForEach-Object { $_.FindingId }) -Baseline @($baselineFindings | ForEach-Object { $_.FindingId }) -Path 'findingOrder') { [void]$rows.Add($row) }

$moduleStatus = Read-JsonFile (Join-Path $moduleFolder 'status.json')
$baselineStatus = Read-JsonFile (Join-Path $baselineFolder 'status.json')
foreach ($row in Compare-Flat -Module $moduleStatus.Value -Baseline $baselineStatus.Value -Path 'status') { [void]$rows.Add($row) }
foreach ($row in Compare-Flat -Module $moduleStatus.Bom -Baseline $baselineStatus.Bom -Path 'status.json byte order mark') { [void]$rows.Add($row) }
foreach ($row in Compare-Flat -Module (Get-DiscoveryOutput -Folder $moduleFolder) -Baseline (Get-DiscoveryOutput -Folder $baselineFolder) -Path 'discovery') { [void]$rows.Add($row) }

Write-Host ''
Write-Comparison -Rows $rows
Write-Host ''

foreach ($rule in $ExplainedPaths) {
    if (-not $rule.ContainsKey('Used')) { Write-Host "Explained difference no longer seen, so it can be removed: $($rule.Path)" }
}
$different = @($rows | Where-Object { $_.Result -eq 'DIFFERENT' })
$counts = '{0} values compared: {1} match, {2} ignored, {3} explained, {4} different' -f $rows.Count, @($rows | Where-Object { $_.Result -eq 'match' }).Count,
    @($rows | Where-Object { $_.Result -eq 'ignored' }).Count, @($rows | Where-Object { $_.Result -eq 'explained' }).Count, $different.Count
Write-Host $counts
if ($different.Count) {
    Write-Host 'Result: DIFFERENT. The tools disagree where they should not; see the rows marked DIFFERENT.'
    exit 1
}
Write-Host 'Result: no unexplained differences.'
exit 0
