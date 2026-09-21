#Requires -Version 5.1
<#
.SYNOPSIS
    Audits this Windows device against Cyber Essentials v3.3 (Danzell),
    the Cyber Essentials Plus test cases and NCSC Windows device guidance.

.DESCRIPTION
    Read-only. Runs every check, then writes to .\output\<COMPUTER>-<timestamp>\:
      report.html     Interactive report
      report.md       Markdown report (good for tickets / evidence packs)
      findings.json   Full machine-readable results
      changeset.json  Proposed remediations for Apply-CEChangeset.ps1

    Run it twice for the most complete picture:
      1. Un-elevated, as the everyday user (tests account separation, winget, per-user settings)
      2. Elevated ("Run as administrator") for BitLocker, audit policy, Defender exclusions etc.

.PARAMETER OutputPath
    Folder for results. Default: .\output\<COMPUTERNAME>-<yyyyMMdd-HHmmss>

.PARAMETER Category
    Limit to one or more themes: Firewalls, SecureConfiguration, SecurityUpdateManagement,
    UserAccessControl, MalwareProtection, NCSCHardening, plus any added by installed packs.
    -ListChecks shows them all.

.PARAMETER Id
    Run only specific check IDs (e.g. SU-03, UA-01).

.PARAMETER ExcludeId
    Skip specific check IDs.

.PARAMETER CEOnly
    Only run checks that map to Cyber Essentials / CE+ (skip NCSC-only hardening).

.PARAMETER ListChecks
    List the available checks and exit.

.PARAMETER NoOpen
    Don't open the HTML report when finished.

.PARAMETER PassThru
    Return the findings objects.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-CEAudit.ps1

.EXAMPLE
    .\Invoke-CEAudit.ps1 -CEOnly -Category SecurityUpdateManagement,MalwareProtection
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string[]]$Category,
    [string[]]$Id,
    [string[]]$ExcludeId,
    [switch]$CEOnly,
    [switch]$ListChecks,
    [switch]$NoOpen,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\CEAudit\CEAudit.psd1') -Force

# Categories are checked after import because packs can add their own.
$unknownCategory = @($Category | Where-Object { $_ -and @(Get-CECategory).Id -notcontains $_ })
if ($unknownCategory.Count) { throw "Unknown category: $($unknownCategory -join ', '). Valid categories: $((@(Get-CECategory).Id) -join ', ')" }

if ($ListChecks) {
    Get-CECheck | Sort-Object Id | Format-Table -AutoSize -Wrap Id, Category, Severity, AutoFail, RequiresAdmin, Title, @{ n = 'Frameworks'; e = { $_.Frameworks -join ', ' } }
    foreach ($pack in @(Get-CEPack)) {
        Write-Host ("Pack {0} {1}: {2}{3}" -f $pack.Id, $pack.Version, $pack.Status, $(if ($pack.Reason) { " ($($pack.Reason))" })) -ForegroundColor $(if ($pack.Status -eq 'Loaded') { 'Green' } else { 'Yellow' })
    }
    return
}

$isWin = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
if (-not $isWin) { throw 'This audit must be run on Windows.' }

$ctx = Get-CEDeviceContext
if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot ("..\output\{0}-{1}" -f $ctx.ComputerName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

Write-Host ''
Write-Host 'Cyber Essentials v3.3 / CE+ / NCSC device audit' -ForegroundColor Cyan
Write-Host ("  Device : {0}  ({1} {2} {3}, build {4})" -f $ctx.ComputerName, $ctx.OSFamily, $ctx.DisplayVersion, $ctx.EditionID, $ctx.FullBuild)
Write-Host ("  User   : {0}{1}" -f $ctx.RunningAs, $(if ($ctx.IsElevated) { '  [elevated]' } else { '  [not elevated]' }))
Write-Host ("  Joined : domain={0} entra={1} mdm={2}" -f $ctx.DomainJoined, $ctx.EntraJoined, $ctx.MdmEnrolled)
if (-not $ctx.IsElevated) {
    Write-Host '  Note   : not elevated, so admin-only checks will be marked Skipped. Re-run as administrator for full coverage.' -ForegroundColor Yellow
}
Write-Host ''

$framework = $null
if ($CEOnly) { $framework = @('CE') }
# The engine records how many checks it selected in Done, including any that left no finding.
$progress = @{}
$findings = @(Invoke-CEAuditCore -Id $Id -Category $Category -Framework $framework -ExcludeId $ExcludeId -ProgressState $progress)

$colour = @{ Pass = 'Green'; Fail = 'Red'; Warn = 'Yellow'; Manual = 'Cyan'; Info = 'Gray'; NotApplicable = 'DarkGray'; Skipped = 'DarkGray'; Error = 'Magenta' }
foreach ($f in $findings) {
    $label = if ($f.Subject) { "$($f.Title) ($($f.Subject))" } else { $f.Title }
    $af = if ($f.AutoFail) { ' [AUTO-FAIL]' } else { '' }
    Write-Host ('  {0,-8} {1,-7} {2}{3}' -f $f.CheckId, $f.Status, $label, $af) -ForegroundColor $colour[$f.Status]
}

# -CEOnly still runs every Cyber Essentials check, so it keeps a real verdict.
$partial = [bool]($Id -or $Category -or $ExcludeId)
$result = Export-CEReport -Findings $findings -Context $ctx -OutputPath $OutputPath -PartialRun:$partial -ChecksRun ([int]$progress.Done)

Write-Host ''
Write-Host "Verdict: $($result.Summary.Verdict)" -ForegroundColor $(if ($result.Summary.Verdict -like 'READY*') { 'Green' } elseif ($result.Summary.Verdict -like 'NEEDS*' -or $result.Summary.Verdict -like 'PARTIAL*') { 'Yellow' } else { 'Red' })
Write-Host ('  ' + (($result.Summary.ByStatus.Keys | ForEach-Object { "$_=$($result.Summary.ByStatus[$_])" }) -join '  '))
Write-Host ''
Write-Host 'CE+ device test estimate:'
foreach ($t in $result.Summary.CEPlus) { Write-Host ("  {0} {1,-38} {2}" -f $t.TestCase, $t.Name, $t.State) }
$malwareTest = @($findings | Where-Object { $_.CheckId -eq 'MP-11' }) | Select-Object -First 1
if ($malwareTest -and $malwareTest.Status -ne 'Pass') {
    Write-Host '  For a full TC3 check, open the HTML report and run the malware download test (section "Malware download test").' -ForegroundColor Cyan
}
Write-Host ''
$selected = @($result.Changeset.Items | Where-Object Selected).Count
Write-Host ("Changeset: {0} automated fix(es) ({1} pre-selected), {2} manual action(s)" -f @($result.Changeset.Items).Count, $selected, @($result.Changeset.ManualActions).Count)
Write-Host "  Report    : $($result.Paths.Html)"
Write-Host "  Changeset : $($result.Paths.Changeset)"
Write-Host ''
Write-Host 'Next: review the changeset, then preview it with:' -ForegroundColor Cyan
Write-Host "  .\app\Apply-CEChangeset.ps1 -Path '$($result.Paths.Changeset)' -WhatIf"
Write-Host ''

if (-not $NoOpen -and [Environment]::UserInteractive) {
    try { Start-Process $result.Paths.Html } catch { Write-Verbose "Could not open report: $_" }
}
if ($PassThru) { return $findings }
