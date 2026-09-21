# Engramic Baseline - Intune custom compliance discovery script.
#
# Upload in Intune: Devices > Compliance > Scripts > Add > Windows 10 and later.
#   Run this script using the logged on credentials: No
#   Enforce script signature check: No (or sign it and set Yes)
#   Run script in 64 bit PowerShell Host: Yes (works either way)
# Then reference it from a compliance policy with compliance-rules.json
# (or compliance-rules-autofail-only.json for a softer first rollout).
#
# It only reads %ProgramData%\EngramicBaseline\status.json, written by
# the daily scheduled audit, so it finishes in well under a second. A full
# audit can take minutes and is too slow to run inside Intune's time limit.
# If the audit is more than a day old it kicks the scheduled task so the next
# evaluation (Intune runs these every 8 hours) sees fresh data.
#
# Output: a single line of compressed JSON (Intune requirement). Unknown
# values are reported as failing values so a broken install is never
# reported as compliant.

function Get-CEComplianceData {
    param(
        [string]$DataRoot = (Join-Path $env:ProgramData 'EngramicBaseline'),
        [Nullable[bool]]$Installed = $null,
        [datetime]$Now = [datetime]::UtcNow,
        [switch]$NoKick
    )
    $result = [ordered]@{
        CECheckerInstalled = $false
        CEToolVersion      = '0.0.0'
        CEAuditAgeHours    = [long]99999
        CEAuditError       = $false
        CEAutoFailCount    = [long]-1
        CEFailCount        = [long]-1
        CEReviewCount      = [long]-1
        CEv33MetPct        = [long]-1
        CENcscMetPct       = [long]-1
        CEOSSupported      = $false
        CEPatchingOK       = $false
        CEFirewallOK       = $false
        CEAntimalwareOK    = $false
        CEStandardUserOK   = $false
        CEMfaAttested      = $false
        CEPlusTC2          = 'Unknown'
        CEPlusTC3          = 'Unknown'
        CEPlusTC5          = 'Unknown'
        CEFailing          = ''
    }

    if ($null -eq $Installed) {
        $Installed = $false
        try {
            $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
            $key = $hklm.OpenSubKey('SOFTWARE\EngramicBaseline')
            if ($key) { $Installed = $true; $key.Close() }
        }
        catch { $Installed = $false }
    }
    $result.CECheckerInstalled = [bool]$Installed
    $result.CEAuditError = Test-Path -LiteralPath (Join-Path $DataRoot 'last-error.json')

    $statusPath = Join-Path $DataRoot 'status.json'
    $status = $null
    if (Test-Path -LiteralPath $statusPath) {
        try { $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json } catch { $status = $null }
    }

    if ($status -and $status.SchemaVersion -eq 1) {
        $auditTime = [datetime]::MinValue
        $raw = $status.AuditTime
        if ($raw -is [datetime]) { $auditTime = $raw.ToUniversalTime() }
        elseif ([datetime]::TryParse([string]$raw, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$auditTime)) { $auditTime = $auditTime.ToUniversalTime() }
        if ($auditTime -gt [datetime]::MinValue) {
            $result.CEAuditAgeHours = [long][math]::Max(0, [math]::Floor(($Now - $auditTime).TotalHours))
        }
        $result.CEToolVersion = [string]$status.toolVersion
        $result.CEAutoFailCount = [long]$status.autoFailCount

        # checks: id -> { status, frameworks, scope, autoFail }
        $checks = $status.checks
        $props = @($checks.PSObject.Properties)
        $isCE = { param($p) @($p.Value.frameworks | Where-Object { $_ -like 'CE*' }).Count -gt 0 }
        $ceFailing = @($props | Where-Object { @('Fail', 'Error') -contains [string]$_.Value.status -and (& $isCE $_) })
        $ceReview = @($props | Where-Object { @('Warn', 'Manual') -contains [string]$_.Value.status -and (& $isCE $_) })
        $result.CEFailCount = [long]$ceFailing.Count
        $result.CEReviewCount = [long]$ceReview.Count

        $notFailing = {
            param([string[]]$Ids)
            foreach ($id in $Ids) {
                $c = $checks.$id
                $s = if ($c) { [string]$c.status } else { '' }
                if (-not $s -or @('Fail', 'Error') -contains $s) { return $false }
            }
            return $true
        }
        $result.CEOSSupported = & $notFailing @('SU-01')
        $result.CEPatchingOK = & $notFailing @('SU-03', 'SU-05', 'SU-06')
        $result.CEFirewallOK = & $notFailing @('FW-01', 'FW-02')
        $result.CEAntimalwareOK = & $notFailing @('MP-01', 'MP-02', 'MP-03')
        $result.CEStandardUserOK = & $notFailing @('UA-01', 'UA-02')
        $result.CEMfaAttested = ($checks.'UA-07' -and [string]$checks.'UA-07'.status -eq 'Pass')

        $fw = $status.frameworks
        if ($fw) {
            if ($fw.'ce-v3.3' -and $null -ne $fw.'ce-v3.3'.metPct) { $result.CEv33MetPct = [long]$fw.'ce-v3.3'.metPct }
            if ($fw.'ncsc' -and $null -ne $fw.'ncsc'.metPct) { $result.CENcscMetPct = [long]$fw.'ncsc'.metPct }
            $tcs = if ($fw.'ce-plus') { $fw.'ce-plus'.tcs } else { $null }
            if ($tcs) {
                foreach ($tc in @('TC2', 'TC3', 'TC5')) {
                    $v = [string]$tcs.$tc
                    if ($v) { $result["CEPlus$tc"] = $v }
                }
            }
        }

        $failing = @($ceFailing | ForEach-Object { $_.Name }) + @($status.autoFails) | Where-Object { $_ } | Select-Object -Unique
        $text = ($failing -join ', ')
        if ($text.Length -gt 400) { $text = $text.Substring(0, 397) + '...' }
        $result.CEFailing = $text
    }

    # Nudge the scheduled audit if the data is getting old.
    if (-not $NoKick -and $result.CEAuditAgeHours -ge 24) {
        try {
            $task = Get-ScheduledTask -TaskPath '\EngramicBaseline\' -TaskName 'Audit' -ErrorAction Stop
            if ($task.State -ne 'Running') { $task | Start-ScheduledTask | Out-Null }
        }
        catch { $null = $_ }
    }
    return $result
}

# Run unless dot-sourced (the unit tests dot-source this file).
if ($MyInvocation.InvocationName -ne '.') {
    $data = Get-CEComplianceData
    return $data | ConvertTo-Json -Compress
}
