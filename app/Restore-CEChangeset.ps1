#Requires -Version 5.1
<#
.SYNOPSIS
    Rolls back changes made by Apply-CEChangeset.ps1 using its undo log.

.DESCRIPTION
    Registry values are restored to their previous value (or removed if they did
    not exist). Command-based changes run the generated undo command, which is
    shown before it runs. Items are undone newest first. Prompts for each change
    unless -Confirm:$false is given. Supports -WhatIf.

.PARAMETER Path
    Path to an undo-<timestamp>.json file.

.PARAMETER ItemId
    Only roll back these items.

.EXAMPLE
    .\Restore-CEChangeset.ps1 -Path .\output\PC01-20260916-101500\undo-20260916-102233.json -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$Path,
    [string[]]$ItemId
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\CEAudit\CEAudit.psd1') -Force

if (-not (Test-CEIsAdmin)) {
    Write-Warning 'Not elevated: most rollbacks touch machine settings and will fail. Re-run as administrator.'
}
# Preference variables don't cross into module scope, so pass them explicitly.
Restore-CEUndoLog -Path $Path -ItemId $ItemId -WhatIf:$WhatIfPreference -Confirm:($ConfirmPreference -ne 'None')
Write-Host 'Rollback complete. Restart if any rolled-back change required a restart, then re-run Invoke-CEAudit.ps1.'
