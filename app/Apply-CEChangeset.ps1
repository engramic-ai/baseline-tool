#Requires -Version 5.1
<#
.SYNOPSIS
    Applies a changeset produced by Invoke-CEAudit.ps1, with backup and rollback.

.DESCRIPTION
    - Only remediations from the built-in library can run; parameters are re-validated.
    - By default only items marked Selected (Low/Medium risk) are applied.
      Edit "Selected" in changeset.json, or use -ItemId / -IncludeUnselected.
    - Every change is recorded in undo-<timestamp>.json next to the changeset.
      Roll back with Restore-CEChangeset.ps1.
    - Supports -WhatIf (preview) and -Confirm (prompt per item).
    - Re-runs the related checks afterwards and shows before/after.

.PARAMETER Path
    Path to changeset.json.

.PARAMETER ItemId
    Apply only these items (e.g. C001,C004), regardless of their Selected flag.

.PARAMETER IncludeUnselected
    Apply all items, including those not pre-selected (High risk still needs -IncludeHighRisk).

.PARAMETER IncludeHighRisk
    Allow High risk items to run when they are selected or named with -ItemId.

.PARAMETER AllowDifferentDevice
    Apply a changeset generated on another computer (e.g. a standard build). Use with care.

.PARAMETER Force
    Don't ask for confirmation before starting.

.EXAMPLE
    .\Apply-CEChangeset.ps1 -Path .\output\PC01-20260916-101500\changeset.json -WhatIf

.EXAMPLE
    .\Apply-CEChangeset.ps1 -Path .\output\PC01-20260916-101500\changeset.json -ItemId C001,C002
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)][string]$Path,
    [string[]]$ItemId,
    [switch]$IncludeUnselected,
    [switch]$IncludeHighRisk,
    [switch]$AllowDifferentDevice,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\CEAudit\CEAudit.psd1') -Force

$Path = (Resolve-Path -LiteralPath $Path).Path
$changeset = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
if ($changeset.SchemaVersion -ne 1) { throw "Unsupported changeset schema version '$($changeset.SchemaVersion)'." }
if ($changeset.ComputerName -ne $env:COMPUTERNAME -and -not $AllowDifferentDevice) {
    throw "This changeset was generated on '$($changeset.ComputerName)', not '$($env:COMPUTERNAME)'. Re-run the audit here, or pass -AllowDifferentDevice."
}

$ctx = Get-CEDeviceContext
$items = @($changeset.Items)
if ($ItemId) {
    $unknown = @($ItemId | Where-Object { @($items.ItemId) -notcontains $_ })
    if ($unknown.Count) { throw "Unknown item id(s): $($unknown -join ', ')" }
    $items = @($items | Where-Object { $ItemId -contains $_.ItemId })
}
elseif (-not $IncludeUnselected) {
    $items = @($items | Where-Object { $_.Selected })
}

$blockedHigh = @($items | Where-Object { $_.Risk -eq 'High' -and -not $IncludeHighRisk })
if ($blockedHigh.Count) {
    Write-Warning ("Skipping High risk item(s) without -IncludeHighRisk: " + (($blockedHigh | ForEach-Object { "$($_.ItemId) $($_.Title)" }) -join '; '))
    $items = @($items | Where-Object { $_.Risk -ne 'High' -or $IncludeHighRisk })
}

$needAdmin = @($items | Where-Object { $_.RequiresAdmin })
if ($needAdmin.Count -and -not $ctx.IsElevated) {
    Write-Warning ("$($needAdmin.Count) item(s) need an elevated session and will be skipped: " + (($needAdmin | ForEach-Object ItemId) -join ', '))
}

if ($items.Count -eq 0) {
    Write-Host 'Nothing to apply.' -ForegroundColor Yellow
    return
}

Write-Host ''
Write-Host "Changeset: $Path" -ForegroundColor Cyan
Write-Host ("Device   : {0} as {1}{2}" -f $ctx.ComputerName, $ctx.RunningAs, $(if ($ctx.IsElevated) { ' [elevated]' } else { '' }))
if ($ctx.CentrallyManaged) {
    Write-Warning 'This device is joined to a domain / Entra ID or enrolled in MDM. Policy-managed settings may be reverted at the next sync; fix them centrally as well.'
}
Write-Host ''
Write-Host 'Items to apply:'
foreach ($i in $items) {
    $flags = @($i.Risk + ' risk')
    if ($i.RequiresReboot) { $flags += 'reboot' }
    if (-not $i.Reversible) { $flags += 'not reversible' }
    if ($i.AutoFail) { $flags += 'AUTO-FAIL fix' }
    Write-Host ("  {0}  {1}  [{2}]" -f $i.ItemId, $i.Title, ($flags -join ', '))
    if ($i.Notes) { Write-Host "        $($i.Notes)" -ForegroundColor DarkGray }
}
Write-Host ''

if (-not $WhatIfPreference -and -not $Force) {
    $answer = Read-Host 'Apply these changes? Type YES to continue'
    if ($answer -ne 'YES') { Write-Host 'Cancelled.'; return }
}

$logPath = Join-Path (Split-Path -Parent $Path) ("apply-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
if (-not $WhatIfPreference) { Start-Transcript -LiteralPath $logPath | Out-Null }
try {
    # Preference variables don't cross into module scope, so pass -WhatIf explicitly.
    $outcome = Invoke-CEChangeset -Items $items -ChangesetPath $Path -WhatIf:$WhatIfPreference
}
finally {
    if (-not $WhatIfPreference) { Stop-Transcript | Out-Null }
}

if ($outcome.WhatIf) {
    Write-Host ''
    Write-Host 'WhatIf: no changes were made.' -ForegroundColor Yellow
    return
}

if ($outcome.Verification.Count) {
    Write-Host ''
    Write-Host 'Re-checked after applying:' -ForegroundColor Cyan
    foreach ($f in $outcome.Verification) {
        $label = if ($f.Subject) { "$($f.Title) ($($f.Subject))" } else { $f.Title }
        $c = switch ($f.Status) { 'Pass' { 'Green' } 'Fail' { 'Red' } 'Warn' { 'Yellow' } default { 'Gray' } }
        Write-Host ('  {0,-8} {1,-7} {2}' -f $f.CheckId, $f.Status, $label) -ForegroundColor $c
    }
}

Write-Host ''
Write-Host "Applied: $($outcome.Applied)  Failed: $($outcome.Failed)  Skipped: $($outcome.Skipped)"
if ($outcome.UndoPath) {
    Write-Host "Undo log  : $($outcome.UndoPath)"
    Write-Host "Roll back : .\Restore-CEChangeset.ps1 -Path '$($outcome.UndoPath)'"
}
Write-Host "Transcript: $logPath"
if ($outcome.NeedsReboot) { Write-Warning 'Restart the device to finish applying some changes, then re-run Invoke-CEAudit.ps1.' }
