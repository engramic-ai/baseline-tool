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
    <# Writes status.json atomically so readers never see a half-written file. #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Status,
        [string]$Path = (Join-Path (Get-CEDataRoot) 'status.json')
    )
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ($PSCmdlet.ShouldProcess($Path, 'Write compliance status')) {
        $tmp = "$Path.tmp"
        $Status | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    }
    return $Path
}

function Write-CEEventLog {
    <#
        Writes the audit outcome to the Application event log (source registered
        by the installer), so SIEM / Log Analytics can pick it up. Severity is
        derived from the controls, not a single verdict:
        1000 = clean (no attention, no auto-fail), 1001 = attention items,
        1002 = auto-fail controls failing.
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
    $message = $lines -join "`r`n"
    if ($message.Length -gt 31000) { $message = $message.Substring(0, 31000) }
    # Write via the low-level RegisterEventSource/ReportEvent API. The managed
    # EventLog.WriteEntry / SourceExists enumerate every event log to find the
    # source's log and throw when Security/State are inaccessible (hosted CI
    # runners, restricted images), even to SYSTEM. RegisterEventSource opens the
    # source directly and never enumerates.
    $typeMap = @{ Error = [uint16]1; Warning = [uint16]2; Information = [uint16]4 }
    try {
        if (-not ('CEAudit.EventReporter' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CEAudit {
    public static class EventReporter {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr RegisterEventSource(string server, string source);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ReportEvent(IntPtr handle, ushort type, ushort category, uint eventId, IntPtr sid, ushort numStrings, uint dataSize, string[] strings, IntPtr rawData);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DeregisterEventSource(IntPtr handle);
        public static int Write(string source, ushort type, uint eventId, string message) {
            IntPtr handle = RegisterEventSource(null, source);
            if (handle == IntPtr.Zero) { return Marshal.GetLastWin32Error(); }
            try {
                bool ok = ReportEvent(handle, type, 0, eventId, IntPtr.Zero, 1, 0, new string[] { message }, IntPtr.Zero);
                return ok ? 0 : Marshal.GetLastWin32Error();
            }
            finally { DeregisterEventSource(handle); }
        }
    }
}
'@ -ErrorAction Stop
        }
        $rc = [CEAudit.EventReporter]::Write($source, $typeMap[$type], [uint32]$id, $message)
        if ($rc -ne 0) { Write-Warning "Event write failed for source '$source' id $id (Win32 error $rc)" }
    }
    catch { Write-Warning "Could not write event: $_" }
}
