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

function Get-CEStatusTrustProblem {
    <#
        Why status.json can't be trusted, or '' when it can: the data folder or the file is a link
        (junction or symbolic link), is owned by someone other than SYSTEM, Administrators or
        TrustedInstaller, or has permissions that let anyone else change it. Only the SYSTEM audit
        should write it, and a standard user who could change either could make the device look
        compliant. The owner alone is not enough: a hard link to a file the user can write, such as
        their ntuser.ini, keeps that file's administrator owner. The same function is in
        Detect-CECompliance.ps1 and Discover-CECompliance.ps1 (each is uploaded on its own).
    #>
    param([string]$DataRoot)
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    # Rights that let someone change, delete or re-permission it, including GENERIC_WRITE and GENERIC_ALL.
    $writeRights = 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288 -bor 0x40000000 -bor 0x10000000
    foreach ($path in @($DataRoot, (Join-Path $DataRoot 'status.json'))) {
        $attributes = $null
        try { $attributes = [IO.File]::GetAttributes($path) } catch { continue }
        if ($attributes -band [IO.FileAttributes]::ReparsePoint) { return "$path is a link (junction or symbolic link)" }
        $acl = $null
        try { $acl = Get-Acl -LiteralPath $path } catch { return "the permissions of $path could not be read" }
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($trusted -notcontains $owner) { return "$path is owned by $owner, not an administrator" }
        foreach ($rule in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
            $sid = "$($rule.IdentityReference)"
            if ("$($rule.AccessControlType)" -ne 'Allow') {
                # A deny entry against SYSTEM, Administrators or TrustedInstaller could stop the audit
                # replacing status.json, freezing a forged one in place, so treat it as tampering.
                if ($trusted -contains $sid) { return "$path denies $sid, so the audit may be unable to replace it" }
                continue
            }
            # CREATOR OWNER only applies to new items, which only administrators can create in a locked folder.
            if ($trusted -contains $sid -or $sid -eq 'S-1-3-0') { continue }
            $rights = [long]0
            try { $rights = [long]$rule.FileSystemRights } catch { $rights = [long]::MaxValue }
            if ($rights -band $writeRights) { return "$path can be changed by $sid, not only administrators" }
        }
    }
    return ''
}

function Get-CEComplianceData {
    param(
        [string]$DataRoot = (Join-Path $env:ProgramData 'EngramicBaseline'),
        [Nullable[bool]]$Installed = $null,
        [Nullable[bool]]$Elevated = $null,
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
    # Intune runs this as SYSTEM. A status.json a standard user could have written counts as no
    # data, so every setting reports a failing value.
    if ($null -eq $Elevated) {
        $Elevated = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    $trusted = -not ($Elevated -and (Get-CEStatusTrustProblem -DataRoot $DataRoot))
    if ($trusted -and (Test-Path -LiteralPath $statusPath)) {
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
