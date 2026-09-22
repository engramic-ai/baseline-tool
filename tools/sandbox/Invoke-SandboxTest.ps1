#Requires -Version 5.1
<#
.SYNOPSIS
    The script that runs inside Windows Sandbox. Start it with New-SandboxRun.ps1, not directly.
.DESCRIPTION
    Runs as the sandbox's built-in administrator on a throwaway Windows:

      1. audit                      -> results\<stamp>\1-before
      2. apply the selected fixes   (low/medium risk; winget items only when networking is on)
      3. audit again                -> 2-after
      4. roll everything back from the undo log
      5. audit a third time         -> 3-restored
      6. compare: every finding a fix changed must be back to its "before" status
      7. optionally run the Pester suite elevated (when C:\ps-modules is mapped)

    Writes summary.md and summary.json next to the audits, plus a transcript.
    Refuses to run anywhere but a Windows Sandbox session, so it cannot be
    pointed at a real machine by accident.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'

# --- guard: only ever run in a sandbox -------------------------------------------------------
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or -not (Test-Path 'C:\baseline-tool\src\CEAudit\CEAudit.psd1')) {
    throw 'This script applies and rolls back real fixes. It only runs inside Windows Sandbox; use tools\sandbox\New-SandboxRun.ps1 on the host.'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
# Started by sandbox\Invoke-SandboxBootstrap.ps1, which provides a per-run results folder.
$run = if ($env:SANDBOX_RESULTS) { $env:SANDBOX_RESULTS } else { Join-Path 'C:\results' $stamp }
New-Item -ItemType Directory -Path $run -Force | Out-Null
Start-Transcript -Path (Join-Path $run 'transcript.txt') | Out-Null

function Step { param([string]$Text) Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }
function Get-Statuses {
    param([string]$Folder)
    $j = Get-Content -LiteralPath (Join-Path $Folder 'findings.json') -Raw | ConvertFrom-Json
    $map = @{}
    foreach ($f in @($j.Findings)) { $map[[string]$f.FindingId] = [string]$f.Status }
    return $map
}

try {
    $networking = $false
    if (Test-Path 'C:\results\env.json') { $networking = [bool](Get-Content 'C:\results\env.json' -Raw | ConvertFrom-Json).networking }

    Step 'Copying the repository (the mapped folder is read-only)'
    $work = 'C:\work\baseline-tool'
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    & robocopy.exe 'C:\baseline-tool' $work /E /NFL /NDL /NJH /NJS /XD .git output build .playwright-mcp | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed with exit code $LASTEXITCODE" }
    $app = Join-Path $work 'app'

    Step 'Audit 1 of 3: before'
    $before = Join-Path $run '1-before'
    & (Join-Path $app 'Invoke-CEAudit.ps1') -OutputPath $before -NoOpen
    $changesetPath = Join-Path $before 'changeset.json'
    $changeset = Get-Content -LiteralPath $changesetPath -Raw | ConvertFrom-Json

    $candidates = @($changeset.Items | Where-Object { $_.Selected })
    $skipped = @()
    if (-not $networking) {
        $skipped = @($candidates | Where-Object { $_.RemediationId -eq 'Winget-Upgrade' })
        $candidates = @($candidates | Where-Object { $_.RemediationId -ne 'Winget-Upgrade' })
    }
    $ids = @($candidates | ForEach-Object { [string]$_.ItemId })

    Step "Applying $($ids.Count) selected fix(es)$(if ($skipped.Count) { " ($($skipped.Count) winget item(s) skipped: no network)" })"
    foreach ($c in $candidates) { Write-Host ("  {0}  {1,-6} {2}" -f $c.ItemId, $c.Risk, $c.Title) }
    $applied = $false
    if ($ids.Count) {
        & (Join-Path $app 'Apply-CEChangeset.ps1') -Path $changesetPath -ItemId $ids -Force -Confirm:$false
        $applied = $true
    }
    else { Write-Host '  Nothing selected to apply on this image.' -ForegroundColor Yellow }

    Step 'Audit 2 of 3: after'
    $after = Join-Path $run '2-after'
    & (Join-Path $app 'Invoke-CEAudit.ps1') -OutputPath $after -NoOpen

    $undo = $null
    if ($applied) {
        $undo = Get-ChildItem -LiteralPath $before -Filter 'undo-*.json' | Sort-Object Name -Descending | Select-Object -First 1
        Step "Rolling back from $($undo.Name)"
        & (Join-Path $app 'Restore-CEChangeset.ps1') -Path $undo.FullName -Confirm:$false
    }
    else { Step 'Nothing to roll back' }

    Step 'Audit 3 of 3: restored'
    $restored = Join-Path $run '3-restored'
    & (Join-Path $app 'Invoke-CEAudit.ps1') -OutputPath $restored -NoOpen

    Step 'Comparing'
    $b = Get-Statuses $before; $a = Get-Statuses $after; $r = Get-Statuses $restored
    $rows = foreach ($id in (@($b.Keys) + @($a.Keys) + @($r.Keys) | Sort-Object -Unique)) {
        $sb = if ($b.ContainsKey($id)) { $b[$id] } else { '-' }
        $sa = if ($a.ContainsKey($id)) { $a[$id] } else { '-' }
        $sr = if ($r.ContainsKey($id)) { $r[$id] } else { '-' }
        [pscustomobject]@{ Finding = $id; Before = $sb; After = $sa; Restored = $sr; Changed = ($sa -ne $sb); BackToBefore = ($sr -eq $sb) }
    }
    $changed = @($rows | Where-Object Changed)
    $notRestored = @($rows | Where-Object { $_.Changed -and -not $_.BackToBefore })
    $improved = @($changed | Where-Object { $_.Before -ne 'Pass' -and $_.After -eq 'Pass' })

    $verdict = if ($ids.Count -eq 0) { 'NOTHING TO TEST' } elseif ($notRestored.Count -eq 0) { 'PASS' } else { 'ROLLBACK INCOMPLETE' }
    $lines = @(
        "# Sandbox apply/rollback run $stamp"
        ''
        "Verdict: **$verdict**"
        ''
        "- Fixes applied: $($ids.Count)$(if ($skipped.Count) { " (skipped $($skipped.Count) winget item(s): no network)" })"
        "- Findings changed by the fixes: $($changed.Count) ($($improved.Count) moved to Pass)"
        "- Findings not back to their before status after rollback: $($notRestored.Count)"
        ''
        '| Finding | Before | After | Restored | |'
        '|---|---|---|---|---|'
    )
    foreach ($row in $changed) {
        $flag = if ($row.BackToBefore) { 'restored' } else { '**NOT RESTORED**' }
        $lines += "| $($row.Finding) | $($row.Before) | $($row.After) | $($row.Restored) | $flag |"
    }
    if ($changed.Count -eq 0) { $lines += '| (no finding changed status) | | | | |' }
    $lines += ''
    $lines += 'A fix whose check only re-reads after a restart can show as NOT RESTORED here even though the registry was put back; see the undo log and transcript.'
    Set-Content -LiteralPath (Join-Path $run 'summary.md') -Value ($lines -join "`r`n") -Encoding UTF8
    [pscustomobject]@{
        Stamp = $stamp; Verdict = $verdict; Networking = $networking
        Applied = $ids; SkippedNoNetwork = @($skipped | ForEach-Object ItemId)
        Changed = $changed; NotRestored = $notRestored
        UndoLog = $(if ($undo) { $undo.Name } else { $null })
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $run 'summary.json') -Encoding UTF8

    Write-Host ''
    $changed | Format-Table Finding, Before, After, Restored, BackToBefore -AutoSize | Out-String | Write-Host
    Write-Host "Verdict: $verdict" -ForegroundColor $(if ($verdict -eq 'PASS') { 'Green' } elseif ($verdict -eq 'NOTHING TO TEST') { 'Yellow' } else { 'Red' })

    if (Test-Path 'C:\ps-modules\Pester') {
        Step 'Running the Pester suite elevated (disposable machine: CE_TESTS_ALLOW_ELEVATED=1)'
        $env:PSModulePath = 'C:\ps-modules;' + $env:PSModulePath
        $env:CE_TESTS_ALLOW_ELEVATED = '1'
        Import-Module Pester -MinimumVersion 5.5
        $c = New-PesterConfiguration
        $c.Run.Path = Join-Path $work 'tests'
        $c.Run.PassThru = $true
        $c.Output.Verbosity = 'Normal'
        $c.Output.RenderMode = 'Plaintext'
        $c.TestResult.Enabled = $true
        $c.TestResult.OutputPath = Join-Path $run 'pester.xml'
        $t = Invoke-Pester -Configuration $c
        Add-Content -LiteralPath (Join-Path $run 'summary.md') -Value "`r`nPester (elevated): passed $($t.PassedCount), failed $($t.FailedCount)" -Encoding UTF8
        Write-Host "Pester: passed $($t.PassedCount), failed $($t.FailedCount)" -ForegroundColor $(if ($t.FailedCount) { 'Red' } else { 'Green' })
    }

    Write-Host ''
    Write-Host "Results are on the host under build\sandbox\results\apply-rollback\$(Split-Path -Leaf $run). Close this window to destroy the sandbox." -ForegroundColor Cyan
}
catch {
    Write-Host ''
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    Set-Content -LiteralPath (Join-Path $run 'summary.md') -Value "# Sandbox run $stamp`r`n`r`nVerdict: **FAILED**`r`n`r`n$($_.Exception.Message)" -Encoding UTF8
}
finally {
    Stop-Transcript | Out-Null
}
