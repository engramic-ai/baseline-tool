# ---------------------------------------------------------------------------
# The organisation's decisions on the AI tools Baseline recognises
# (config/ai-approvals.json), used by SC-14, SC-09 and the AI posture. A tool
# is approved, not approved, or not reviewed (not listed). An approval that is
# too old, or doesn't say who approved it and when, is due for review.
# ---------------------------------------------------------------------------

function Get-CEAIApprovalRegister {
    <#
        The register as a lookup of tool id -> decision, plus the problems found in the file
        (unknown ids, duplicates, decisions that aren't 'approved' or 'not-approved'). Entries with
        a problem are left out, so the tool reads as not reviewed until the file is fixed.
    #>
    $cfg = (Get-CEConfig).'ai-approvals'
    $problems = New-Object System.Collections.ArrayList
    $maxAge = 365
    $rawAge = Get-CEObjectValue $cfg 'maxApprovalAgeDays' $null
    if ($null -ne $rawAge) {
        $parsed = 0
        if ([int]::TryParse([string]$rawAge, [ref]$parsed) -and $parsed -gt 0) { $maxAge = $parsed }
        else { [void]$problems.Add("maxApprovalAgeDays '$rawAge' is not a positive number of days, so 365 is used") }
    }

    $known = @{}
    foreach ($t in @(Get-CEObjectValue (Get-CEConfig).'ai-tools' 'tools' @())) { $known[[string](Get-CEObjectValue $t 'id' '')] = $true }

    $entries = @(Get-CEObjectValue $cfg 'tools' @())
    $seen = @{}
    foreach ($e in $entries) {
        $id = [string](Get-CEObjectValue $e 'id' '')
        if (-not $id) { continue }
        if ($seen.ContainsKey($id)) { $seen[$id]++ } else { $seen[$id] = 1 }
    }

    $byId = @{}
    $reported = @{}
    foreach ($e in $entries) {
        $id = [string](Get-CEObjectValue $e 'id' '')
        if (-not $id) { [void]$problems.Add('an entry has no id'); continue }
        if (-not $known.ContainsKey($id)) { [void]$problems.Add("'$id' is not a tool in ai-tools.json"); continue }
        if ($seen[$id] -gt 1) {
            if (-not $reported.ContainsKey($id)) { [void]$problems.Add("'$id' is listed $($seen[$id]) times"); $reported[$id] = $true }
            continue
        }
        $decision = ([string](Get-CEObjectValue $e 'decision' '')).Trim().ToLowerInvariant()
        if (@('approved', 'not-approved') -notcontains $decision) {
            [void]$problems.Add("'$id' has decision '$(Get-CEObjectValue $e 'decision' '')'; use approved or not-approved")
            continue
        }
        $byId[$id] = [pscustomobject]@{
            Decision  = $decision
            DecidedBy = ([string](Get-CEObjectValue $e 'decidedBy' '')).Trim()
            DecidedOn = ConvertTo-CEDateOnly (Get-CEObjectValue $e 'decidedOn' $null)
            RawDate   = [string](Get-CEObjectValue $e 'decidedOn' '')
            Reason    = ([string](Get-CEObjectValue $e 'reason' '')).Trim()
        }
    }

    return [pscustomobject]@{ MaxAgeDays = $maxAge; ById = $byId; Problems = $problems.ToArray() }
}

function Get-CEAIApprovalLabel {
    <# Words for an approval state, as reports show it. #>
    param([string]$State)
    switch ($State) {
        'approved' { 'approved' }
        'stale' { 'due for review' }
        'not-approved' { 'not approved' }
        default { 'not reviewed' }
    }
}

function Get-CEAIApprovalSummary {
    <# "1 approved, 1 not approved, 2 not reviewed" from an AI posture; empty when no tools were found. #>
    param($Posture)
    $parts = @()
    foreach ($pair in @(@('approved', 'approved'), @('unapproved', 'not approved'), @('approvalStale', 'due for review'), @('unreviewed', 'not reviewed'))) {
        $n = [int]$Posture[$pair[0]]
        if ($n) { $parts += "$n $($pair[1])" }
    }
    return ($parts -join ', ')
}

function Get-CEAIApproval {
    <#
        The approval state of one tool: approved, stale (due for review), not-approved or unreviewed,
        with who decided, when, why, and a plain-English Detail for reports.
    #>
    param([Parameter(Mandatory)][string]$ToolId, [Parameter(Mandatory)]$Register, [datetime]$Today = (Get-Date).Date)
    $out = [ordered]@{ State = 'unreviewed'; DecidedBy = ''; DecidedOn = ''; Reason = ''; Detail = 'No decision recorded' }
    if (-not $Register.ById.ContainsKey($ToolId)) { return [pscustomobject]$out }
    $e = $Register.ById[$ToolId]
    $out.DecidedBy = $e.DecidedBy
    $out.DecidedOn = $(if ($e.DecidedOn) { $e.DecidedOn.ToString('yyyy-MM-dd') } else { $e.RawDate })
    $out.Reason = $e.Reason
    $who = @(@($(if ($e.DecidedBy) { "by $($e.DecidedBy)" }), $(if ($out.DecidedOn) { "on $($out.DecidedOn)" })) | Where-Object { $_ }) -join ' '
    $why = if ($e.Reason) { ": $($e.Reason)" } else { '' }

    if ($e.Decision -eq 'not-approved') {
        $out.State = 'not-approved'
        $out.Detail = "Not approved$(if ($who) { " ($who)" })$why"
        return [pscustomobject]$out
    }
    $missing = @()
    if (-not $e.DecidedBy) { $missing += 'who approved it (decidedBy)' }
    if (-not $e.DecidedOn -or $e.DecidedOn -gt $Today) { $missing += 'a valid date that is not in the future (decidedOn, yyyy-MM-dd)' }
    if ($missing.Count) {
        $out.State = 'stale'
        $out.Detail = "Approved, but the record is missing $($missing -join ' and ')"
        return [pscustomobject]$out
    }
    $age = [int]($Today - $e.DecidedOn).TotalDays
    if ($age -gt $Register.MaxAgeDays) {
        $out.State = 'stale'
        $out.Detail = "Approved $who, $age days ago; approvals are reviewed every $($Register.MaxAgeDays) days$why"
        return [pscustomobject]$out
    }
    $out.State = 'approved'
    $out.Detail = "Approved $who$why"
    return [pscustomobject]$out
}
