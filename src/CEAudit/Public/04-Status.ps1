# ---------------------------------------------------------------------------
# Machine status for unattended runs (scheduled task, Intune).
#
# The full audit can take several minutes (Windows Update search), which is
# too slow and too fragile to run inside an Intune compliance discovery
# script. Instead the scheduled task writes a small status.json that the
# discovery and Remediations detection scripts read in milliseconds.
#
# Structure: checks are the source of truth (id -> status + framework tags +
# scope + autoFail). Framework rollups are DERIVED from the checks; the cached
# 'frameworks' block is a convenience for the fast Intune path. There is no
# single pass/fail verdict - each framework carries its own judgement, and
# shadow-AI posture is per-user (Invoke-CEUserProbe.ps1 / user-status.json).
# ---------------------------------------------------------------------------

$script:CEStatusRank = @{ Fail = 0; Error = 1; Warn = 2; Manual = 3; Skipped = 4; Pass = 5; Info = 6; NotApplicable = 7 }

# Which status counts as met / attention / confirm / not-applicable in a rollup.
$script:CEStatusBucket = @{
    Pass = 'met'; Fail = 'attention'; Warn = 'attention'; Error = 'attention'
    Manual = 'confirm'; Info = 'na'; NotApplicable = 'na'; Skipped = 'na'
}

# Canonical frameworks derived from each check's framework tags. CE+ (test
# cases) is handled separately from the summary because it is TC-based.
$script:CEFrameworkDefs = @(
    [pscustomobject]@{ Key = 'ce-v3.3'; Label = 'Cyber Essentials v3.3'; Match = { param($t) $t -like 'CE v3.3*' } }
    [pscustomobject]@{ Key = 'ncsc'; Label = 'NCSC device hardening'; Match = { param($t) $t -eq 'NCSC' } }
)

function Get-CEToolVersion {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $manifest = Join-Path $script:ModuleRoot 'CEAudit.psd1'
    try { return [string](Import-PowerShellDataFile -Path $manifest).ModuleVersion } catch { return '0.0.0' }
}

function Get-CEStatusCheckMap {
    <#
        Findings -> ordered map of check id to { status, frameworks, scope,
        autoFail }. One entry per check, keeping the worst status across its
        findings (e.g. SU-05 is Fail if any app is out of date). This is the
        source of truth; framework rollups are derived from it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings)
    $byId = @{}
    foreach ($c in Get-CECheck) { $byId[[string]$c.Id] = $c }
    $map = [ordered]@{}
    foreach ($f in ($Findings | Sort-Object CheckId)) {
        $id = [string]$f.CheckId
        $cur = $map[$id]
        $replace = $true
        if ($cur) { $replace = $script:CEStatusRank[[string]$f.Status] -lt $script:CEStatusRank[[string]$cur.status] }
        if ($replace) {
            $c = $byId[$id]
            $map[$id] = [ordered]@{
                status     = [string]$f.Status
                frameworks = @(Get-CEObjectValue $f 'Frameworks')
                scope      = [string](Get-CEObjectValue $f 'Scope')
                autoFail   = [bool]($c -and $c.AutoFail)
            }
        }
    }
    return $map
}

function Get-CEFrameworkRollup {
    <#
        Derives per-framework judgement from a check map (from
        Get-CEStatusCheckMap). Returns an ordered map of canonical framework key
        to counts + metPct. Frameworks not present in the map are omitted, so a
        user-scope run only reports the frameworks its checks touch. Pass the
        audit Summary to add the CE+ (TC1-TC5) entry; omit it for user runs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$CheckMap,
        $Summary
    )
    $out = [ordered]@{}
    foreach ($def in $script:CEFrameworkDefs) {
        $b = [ordered]@{ met = 0; attention = 0; confirm = 0; na = 0 }
        $present = $false
        foreach ($id in $CheckMap.Keys) {
            $entry = $CheckMap[$id]
            if (@($entry.frameworks | Where-Object { & $def.Match $_ }).Count -eq 0) { continue }
            $present = $true
            $bucket = $script:CEStatusBucket[[string]$entry.status]
            if (-not $bucket) { $bucket = 'na' }
            $b[$bucket] = [int]$b[$bucket] + 1
        }
        if (-not $present) { continue }
        $applicable = [int]$b.met + [int]$b.attention + [int]$b.confirm
        $metPct = if ($applicable -gt 0) { [int][math]::Round(([double]$b.met / $applicable) * 100) } else { 0 }
        $out[$def.Key] = [ordered]@{
            label         = $def.Label
            applicable    = $applicable
            met           = [int]$b.met
            attention     = [int]$b.attention
            confirm       = [int]$b.confirm
            notApplicable = [int]$b.na
            metPct        = $metPct
        }
    }
    if ($Summary) {
        $ceplus = @(Get-CEObjectValue $Summary 'CEPlus')
        if ($ceplus.Count) {
            $tcs = [ordered]@{}
            $onTrack = 0
            foreach ($t in $ceplus) {
                $tcs[[string]$t.TestCase] = [string]$t.State
                if ([string]$t.State -eq 'Likely pass') { $onTrack++ }
            }
            $out['ce-plus'] = [ordered]@{ label = 'Cyber Essentials Plus'; tcs = $tcs; onTrack = $onTrack; total = $ceplus.Count }
        }
    }
    return $out
}

function ConvertTo-CEStatus {
    <#
        Builds the compact machine status document (schema 1) from an audit.
        Checks are the source of truth; 'frameworks' is a derived cache.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)]$Summary,
        [Parameter(Mandatory)]$Context,
        [string]$ReportFolder = ''
    )
    $checks = Get-CEStatusCheckMap -Findings $Findings
    $frameworks = Get-CEFrameworkRollup -CheckMap $checks -Summary $Summary

    # Auto-fail controls that are actually failing (hard CE auto-fail).
    $autoFails = @($checks.Keys | Where-Object { $checks[$_].autoFail -and @('Fail', 'Error') -contains [string]$checks[$_].status })

    # Compact hardware summary for fleet reporting; the full inventory is in findings.json.
    $hardware = $null
    $hw = Get-CEObjectValue $Context 'Hardware'
    if ($hw) {
        $hardware = [ordered]@{
            manufacturer     = [string]$hw.Manufacturer
            model            = [string]$hw.Model
            systemSku        = [string]$hw.SystemSku
            serialNumber     = [string]$hw.SerialNumber
            isVirtualMachine = [bool]$hw.IsVirtualMachine
            firmwareVersion  = [string]$hw.Firmware.Version
            firmwareDate     = [string]$hw.Firmware.ReleaseDate
            firmwareType     = [string]$hw.Firmware.Type
            tpmManufacturer  = [string]$hw.Tpm.Manufacturer
            tpmFirmware      = [string]$hw.Tpm.FirmwareVersion
            tpmSpec          = [string]$hw.Tpm.SpecVersion
            cpu              = [string](@($hw.Cpu | ForEach-Object { $_.Name }) | Select-Object -First 1)
            disks            = @($hw.Disks | ForEach-Object { [ordered]@{ model = [string]$_.Model; firmware = [string]$_.FirmwareRevision } })
        }
    }

    $counts = [ordered]@{}
    foreach ($k in $Summary.ByStatus.Keys) { $counts[$k] = [int]$Summary.ByStatus[$k] }

    return [pscustomobject]@{
        schemaVersion = 1
        toolVersion   = Get-CEToolVersion
        scope         = 'Machine'
        platform      = 'windows'
        computerName  = $Context.ComputerName
        auditTime     = ([datetime]$Context.AuditTime).ToUniversalTime().ToString('o')
        runAs         = $Context.RunningAs
        elevated      = [bool]$Context.IsElevated
        os            = "$($Context.OSFamily) $($Context.DisplayVersion) $($Context.EditionID) ($($Context.FullBuild))"
        counts        = $counts
        autoFailCount = @($autoFails).Count
        autoFails     = @($autoFails)
        checks        = $checks
        frameworks    = $frameworks
        hardware      = $hardware
        packs         = @(Get-CEPack | ForEach-Object { [ordered]@{ id = $_.Id; version = $_.Version; status = $_.Status } })
        reportFolder  = $ReportFolder
    }
}

function Write-CEStatus {
    <#
        Writes status.json atomically so readers never see a half-written file: to the data folder by
        default, or to -Path. Its folder is made the way Initialize-CEDataFolder makes it: locked when
        it is the data folder and the audit is elevated, and otherwise (a -Path somewhere else) only
        created if it is missing and never moved aside or re-permissioned.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Status,
        [string]$Path = (Join-Path (Get-CEDataRoot) 'status.json')
    )
    $dir = Split-Path -Parent $Path
    # Create the data folder the locked way (Initialize-CEDataFolder) so an elevated audit that makes
    # it before the installer runs never leaves it briefly writable by a standard user. A folder
    # outside the data folder is the caller's: Initialize-CEDataFolder only makes it if it is missing.
    # A bare file name has no folder to make: it is written to the current location.
    if ($dir) { Initialize-CEDataFolder -Path $dir | Out-Null }
    if ($PSCmdlet.ShouldProcess($Path, 'Write compliance status')) {
        # A name of its own each time: anything already at a fixed name (a folder a user made
        # before the install locked the data folder, say) would make every write fail.
        $tmp = '{0}.{1}.tmp' -f $Path, [guid]::NewGuid().ToString('n')
        try {
            $Status | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $tmp -Encoding UTF8
            Move-Item -LiteralPath $tmp -Destination $Path -Force
        }
        catch {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            throw
        }
    }
    return $Path
}

function ConvertTo-CEUtcTime {
    <# A time read from JSON (a string, or a DateTime that PowerShell 7's ConvertFrom-Json made) as UTC, or $null. #>
    param($Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $time = [datetime]::MinValue
    if ($Value -and [datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$time)) {
        return $time.ToUniversalTime()
    }
    return $null
}

function Get-CEAuditFailureProblem {
    <#
        '' when last-error.json at $Path may be read, replaced or deleted, or why not. It must be a
        file, and when elevated it must pass the same trust check the Intune scripts apply to
        status.json (Get-CEDataPathProblem: not a link, administrator-owned, no non-administrator
        write, delete, change-permissions or take-ownership right, no deny against administrators).
        A non-elevated run only affects its own user, so it trusts any file.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $attributes = [IO.File]::GetAttributes($Path)
    if (Test-CEDataLink -Path $Path -Attributes $attributes) { return "$Path is a link (junction or symbolic link)" }
    if ($attributes -band [IO.FileAttributes]::Directory) { return "$Path is a folder, not a file" }
    if (-not (Test-CEIsAdmin)) { return '' }
    $problems = @(Get-CEDataPathProblem -Path $Path)
    if ($problems.Count) { return [string]$problems[0] }
    return ''
}

function Move-CEAuditFailureAside {
    <#
        Moves an untrusted last-error.json out of the data folder (Move-CEDataItemAside), never reading,
        deleting or writing through it, and says so in a warning (the scheduled audit's log) and an
        Application event, ID 1003, naming where it went. One outside the data folder (a -DataRoot that
        is not Get-CEDataRoot) is never moved: Move-CEDataItemAside throws instead.
    #>
    param([Parameter(Mandatory)][string]$Path, [string]$Reason)
    $aside = Move-CEDataItemAside -Path $Path
    $notice = "Moved an untrusted $Path aside to $aside ($Reason). Its failed-run count is not used, so the count starts again; check it, then delete it."
    Write-Warning $notice
    Write-CEEventEntry -Id 1003 -Type Warning -Message "Engramic Baseline - data folder: $notice"
}

function Test-CEPathPresent {
    <# Whether anything - a file, folder or link, even a link whose target is gone - is at $Path. #>
    param([Parameter(Mandatory)][string]$Path)
    try { [void][IO.File]::GetAttributes($Path); return $true }
    catch { return $false }
}

function Write-CEAuditFailure {
    <#
        Records a failed machine (SYSTEM) audit in last-error.json in the data folder, with the run of
        failures since the last successful audit: FailedRuns (failed runs in a row, this one included)
        and FirstFailure (UTC time of the first of them), besides Time, Message and Where. A successful
        audit removes the file (Clear-CEAuditFailure), so the count starts again at 1. Intune's
        discovery script turns these into CEAuditFailedRuns and CEAuditFailingHours.

        The previous file is read only when it passes the same trust check as status.json
        (Get-CEAuditFailureProblem). One that fails it is moved aside out of the data folder, with a
        warning and event 1003, never read, and the count starts again at 1. The new file is written
        to a temporary name and renamed into place, so a reader never sees half of it. Only the
        scheduled machine audit calls this: the per-user probe keeps its own last-error.json in the
        user's profile, which never counts. Returns the record.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [AllowEmptyString()][string]$Where = '',
        [datetime]$Now = [datetime]::UtcNow
    )
    $Now = $Now.ToUniversalTime()
    if (Test-CEIsAdmin) {
        $rootProblem = @(Get-CEDataPathProblem -Path $DataRoot)
        if ($rootProblem.Count) { throw "Did not record the failure: $($rootProblem[0])" }
    }
    $path = Join-Path $DataRoot 'last-error.json'
    $previous = $null
    if (Test-CEPathPresent -Path $path) {
        $problem = Get-CEAuditFailureProblem -Path $path
        if ($problem) { Move-CEAuditFailureAside -Path $path -Reason $problem }
        else {
            try { $previous = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json }
            catch { Write-Warning "Could not read the previous $path, so the failed-run count starts again: $($_.Exception.Message)" }
        }
    }

    $failedRuns = 1
    $firstFailure = $Now
    if ($previous) {
        # A last-error.json from before failures were counted has no FailedRuns: it was one failure.
        $runs = [long]0
        if (-not [long]::TryParse([string](Get-CEObjectValue $previous 'FailedRuns' ''), [ref]$runs) -or $runs -lt 1) { $runs = 1 }
        $failedRuns = [int][math]::Min($runs + 1, 1000000)
        $first = ConvertTo-CEUtcTime (Get-CEObjectValue $previous 'FirstFailure')
        if (-not $first) { $first = ConvertTo-CEUtcTime (Get-CEObjectValue $previous 'Time') }
        if ($first -and $first -le $Now) { $firstFailure = $first }
    }
    $record = [pscustomobject][ordered]@{
        Time         = $Now.ToString('o')
        Message      = $Message
        Where        = $Where
        FailedRuns   = $failedRuns
        FirstFailure = $firstFailure.ToString('o')
    }
    if ($PSCmdlet.ShouldProcess($path, 'Record the failed audit')) {
        $tmp = '{0}.{1}.tmp' -f $path, [guid]::NewGuid().ToString('n')
        try {
            $record | ConvertTo-Json | Set-Content -LiteralPath $tmp -Encoding UTF8
            Move-Item -LiteralPath $tmp -Destination $path -Force
        }
        catch {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            throw
        }
    }
    return $record
}

function Clear-CEAuditFailure {
    <#
        After a successful machine audit: removes last-error.json, so the next failure counts from 1.
        One that fails the trust check (Get-CEAuditFailureProblem) is moved aside out of the data
        folder with a warning and event 1003, never deleted.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$DataRoot)
    $path = Join-Path $DataRoot 'last-error.json'
    if (-not (Test-CEPathPresent -Path $path)) { return }
    $problem = Get-CEAuditFailureProblem -Path $path
    if ($problem) { Move-CEAuditFailureAside -Path $path -Reason $problem; return }
    if ($PSCmdlet.ShouldProcess($path, 'Remove the record of a failed audit')) { [IO.File]::Delete($path) }
}

function Write-CEEventLog {
    <#
        Writes the audit outcome to the Application event log (source registered
        by the installer), so SIEM / Log Analytics can pick it up. Severity is
        derived from the controls, not a single verdict:
        1000 = clean (no attention, no auto-fail), 1001 = attention items,
        1002 = auto-fail controls failing. (1003 is a data folder moved aside,
        written by Initialize-CEDataFolder and the installer.)
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Status)
    $source = 'EngramicBaseline'
    $sourceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$source"
    # Ensure the source is registered, creating the key directly if missing.
    # [Diagnostics.EventLog]::CreateEventSource / SourceExists enumerate every
    # event log and throw when Security/State are inaccessible (hosted CI runners,
    # restricted images), so we never call them. SYSTEM (the scheduled audit) and
    # admins can create the key; an unprivileged app run cannot, and then simply
    # skips event logging. Creating the key is all RegisterEventSource needs.
    if (-not (Test-Path -LiteralPath $sourceKey)) {
        try {
            New-Item -Path $sourceKey -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $sourceKey -Name 'EventMessageFile' -PropertyType ExpandString -Value '%SystemRoot%\System32\EventCreate.exe' -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $sourceKey -Name 'TypesSupported' -PropertyType DWord -Value 7 -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Verbose "Event source not registered and could not be created: $_"
            return
        }
    }

    $autoFail = [int](Get-CEObjectValue $Status 'autoFailCount')
    $checks = Get-CEObjectValue $Status 'checks'
    $attention = 0
    if ($checks) {
        foreach ($k in $checks.Keys) {
            $entry = $checks[$k]
            $st = if ($entry -is [System.Collections.IDictionary]) { if ($entry.Contains('status')) { [string]$entry['status'] } else { '' } } else { [string](Get-CEObjectValue $entry 'status') }
            if (@('Fail', 'Warn', 'Error') -contains $st) { $attention++ }
        }
    }

    if ($autoFail -gt 0) { $id = 1002; $type = 'Error' }
    elseif ($attention -gt 0) { $id = 1001; $type = 'Warning' }
    else { $id = 1000; $type = 'Information' }

    $fw = Get-CEObjectValue $Status 'frameworks'
    $fwLine = @()
    if ($fw) {
        foreach ($k in $fw.Keys) {
            # Not every framework rollup carries metPct (CE+ is TC-based). Read it
            # without tripping strict mode, from a hashtable or a pscustomobject.
            $entry = $fw[$k]
            $pct = if ($entry -is [System.Collections.IDictionary]) { if ($entry.Contains('metPct')) { $entry['metPct'] } else { $null } } else { Get-CEObjectValue $entry 'metPct' }
            if ($null -ne $pct) { $fwLine += "${k}=${pct}%" }
        }
    }
    $lines = @(
        'Engramic Baseline device audit',
        "Auto-fail controls failing: $autoFail  Attention items: $attention",
        "Frameworks: $($fwLine -join '  ')"
    )
    if (@(Get-CEObjectValue $Status 'autoFails').Count) { $lines += "Auto-fail: $(@($Status.autoFails) -join ', ')" }
    $lines += "Report: $(Get-CEObjectValue $Status 'reportFolder')"
    $lines += ''
    $lines += ($Status | ConvertTo-Json -Depth 6 -Compress)
    # Written through RegisterEventSource/ReportEvent (Write-CEEventEntry), never EventLog.WriteEntry.
    Write-CEEventEntry -Id $id -Type $type -Message ($lines -join "`r`n")
}
