# ---------------------------------------------------------------------------
# Changeset application shared by Apply-CEChangeset.ps1 and the GUI.
# ---------------------------------------------------------------------------

function Invoke-CEChangeset {
    <#
        Applies the given changeset items in order, writes an undo log next to the
        changeset, and returns a summary. Selection/confirmation is the caller's job.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object[]]$Items,
        [Parameter(Mandatory)][string]$ChangesetPath,
        # Optional synchronized hashtable updated with Current/Done/Total for UIs.
        [hashtable]$ProgressState
    )
    $ctx = Get-CEDeviceContext
    $undoDir = Split-Path -Parent $ChangesetPath
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $undoPath = Join-Path $undoDir "undo-$stamp.json"
    $isWhatIf = [bool]$WhatIfPreference

    $results = @()
    $needReboot = $false
    $n = 0
    try {
        foreach ($i in $Items) {
            $n++
            if ($ProgressState) { $ProgressState.Current = "$($i.ItemId) $($i.Title)"; $ProgressState.Done = $n - 1; $ProgressState.Total = @($Items).Count }
            if ($i.RequiresAdmin -and -not $ctx.IsElevated) {
                Write-Host "-> $($i.ItemId) $($i.Title): skipped (needs administrator)" -ForegroundColor Yellow
                $results += [pscustomobject]@{ ItemId = $i.ItemId; Title = $i.Title; RemediationId = $i.RemediationId; Status = 'Skipped'; Message = 'Requires elevation'; Undo = @(); CheckIds = @($i.CheckIds) }
                continue
            }
            Write-Host "-> $($i.ItemId) $($i.Title)" -ForegroundColor Cyan
            try {
                $r = Invoke-CERemediation -Id $i.RemediationId -Parameters $i.Parameters -UndoDirectory $undoDir -WhatIf:$isWhatIf -Confirm:$false
                if ($r.Status -eq 'Applied' -and $i.RequiresReboot) { $needReboot = $true }
                $colour = switch ($r.Status) { 'Applied' { 'Green' } 'WhatIf' { 'Gray' } default { 'Red' } }
                Write-Host "   $($r.Status) $($r.Message)" -ForegroundColor $colour
                $results += [pscustomobject]@{ ItemId = $i.ItemId; Title = $i.Title; RemediationId = $i.RemediationId; Status = $r.Status; Message = $r.Message; Undo = @($r.Undo); CheckIds = @($i.CheckIds) }
            }
            catch {
                Write-Host "   Failed: $($_.Exception.Message)" -ForegroundColor Red
                $results += [pscustomobject]@{ ItemId = $i.ItemId; Title = $i.Title; RemediationId = $i.RemediationId; Status = 'Failed'; Message = $_.Exception.Message; Undo = @(); CheckIds = @($i.CheckIds) }
            }
        }
    }
    finally {
        if (-not $isWhatIf) {
            $withUndo = @($results | Where-Object { @($_.Undo).Count -gt 0 } | Select-Object ItemId, Title, RemediationId, Status, Undo)
            if ($withUndo.Count -gt 0) {
                [pscustomobject]@{
                    SchemaVersion = 1
                    ComputerName  = $env:COMPUTERNAME
                    AppliedBy     = $ctx.RunningAs
                    AppliedAt     = (Get-Date).ToString('o')
                    Changeset     = $ChangesetPath
                    Items         = $withUndo
                } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $undoPath -Encoding UTF8
            }
            else {
                $undoPath = $null
            }
        }
        else {
            $undoPath = $null
        }
        if ($ProgressState) { $ProgressState.Done = @($Items).Count; $ProgressState.Current = 'Finished' }
    }

    # Verify: re-run the checks behind the applied items.
    $after = @()
    $checkIds = @($results | Where-Object { $_.Status -eq 'Applied' } | ForEach-Object { $_.CheckIds } | Select-Object -Unique)
    if ($checkIds.Count -and -not $isWhatIf) {
        Get-CEDeviceContext -Force | Out-Null
        $after = @(Invoke-CEAuditCore -Id $checkIds)
    }

    return [pscustomobject]@{
        Results        = $results
        UndoPath       = $undoPath
        NeedsReboot    = $needReboot
        Verification   = $after
        Applied        = @($results | Where-Object Status -eq 'Applied').Count
        Failed         = @($results | Where-Object Status -eq 'Failed').Count
        Skipped        = @($results | Where-Object Status -eq 'Skipped').Count
        WhatIf         = $isWhatIf
    }
}

function Get-CEUndoLogs {
    <# Lists undo logs under an output root, newest first. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$OutputRoot)
    if (-not (Test-Path -LiteralPath $OutputRoot)) { return @() }
    return @(Get-ChildItem -LiteralPath $OutputRoot -Recurse -Filter 'undo-*.json' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        ForEach-Object {
            $log = $null
            try { $log = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } catch { $log = $null }
            [pscustomobject]@{
                Path      = $_.FullName
                AppliedAt = $_.LastWriteTime
                AppliedBy = if ($log) { [string]$log.AppliedBy } else { '' }
                Computer  = if ($log) { [string]$log.ComputerName } else { '' }
                Items     = if ($log) { @($log.Items).Count } else { 0 }
                Summary   = if ($log) { (@($log.Items) | ForEach-Object { "$($_.ItemId) $($_.Title)" }) -join '; ' } else { 'Unreadable log' }
            }
        })
}
