# ---------------------------------------------------------------------------
# Readers for local security policy, audit policy and Windows Update state.
# ---------------------------------------------------------------------------

function Get-CEAccountPolicy {
    <#
        Parses 'net accounts' (works without elevation) into a hashtable:
        MinPasswordLength, MaxPasswordAgeDays (-1 = unlimited),
        LockoutThreshold (0 = never), LockoutDurationMinutes, LockoutWindowMinutes.
        Parsing is by line position, not by label, because labels are localised.
    #>
    [CmdletBinding()]
    param()
    $native = Invoke-CENative -FilePath 'net.exe' -ArgumentList @('accounts')
    $values = @()
    foreach ($line in $native.Output) {
        if ($line -match ':\s*(.+?)\s*$') { $values += $Matches[1] }
    }
    # Expected order (en-GB/en-US and most locales):
    # 0 Force logoff, 1 Min pwd age, 2 Max pwd age, 3 Min pwd length,
    # 4 Pwd history, 5 Lockout threshold, 6 Lockout duration, 7 Lockout window, 8 Role
    if ($values.Count -lt 8) { throw "Unexpected 'net accounts' output: $($native.Output -join ' | ')" }

    $toInt = {
        param($v)
        if ($v -match '^\d+$') { return [int]$v }
        return -1   # "Never" / "Unlimited" in any language
    }
    return @{
        MaxPasswordAgeDays     = & $toInt $values[2]
        MinPasswordLength      = & $toInt $values[3]
        LockoutThreshold       = [math]::Max((& $toInt $values[5]), 0)
        LockoutDurationMinutes = & $toInt $values[6]
        LockoutWindowMinutes   = & $toInt $values[7]
        Raw                    = $native.Output
    }
}

function Get-CESecurityPolicy {
    <#
        Exports local security policy with secedit (requires elevation) and
        returns [System Access] and [Registry Values] as a hashtable.
    #>
    [CmdletBinding()]
    param()
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ceaudit-secpol-{0}.inf" -f ([guid]::NewGuid().ToString('N')))
    try {
        $null = Invoke-CENative -FilePath 'secedit.exe' -ArgumentList @('/export', '/cfg', $tmp, '/areas', 'SECURITYPOLICY', '/quiet')
        if (-not (Test-Path $tmp)) { throw 'secedit export produced no file' }
        $policy = @{}
        foreach ($line in (Get-Content -LiteralPath $tmp)) {
            if ($line -match '^\s*([^=\[]+?)\s*=\s*(.*?)\s*$') { $policy[$Matches[1]] = $Matches[2] }
        }
        return $policy
    }
    finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Get-CEAuditPolicy {
    <#
        Returns audit subcategory settings keyed by subcategory GUID
        (GUIDs are locale independent). Requires elevation.
    #>
    [CmdletBinding()]
    param()
    $native = Invoke-CENative -FilePath 'auditpol.exe' -ArgumentList @('/get', '/category:*', '/r')
    $rows = @($native.Output | Where-Object { $_ -and $_ -match ',' }) | ConvertFrom-Csv
    $map = @{}
    foreach ($r in $rows) {
        $guid = ([string]$r.'Subcategory GUID').Trim('{}').ToLowerInvariant()
        if ($guid) {
            $map[$guid] = [pscustomobject]@{
                Name    = $r.Subcategory
                Setting = [string]$r.'Inclusion Setting'
            }
        }
    }
    return $map
}

function Get-CEWindowsUpdateState {
    <#
        Uses the Windows Update Agent COM API to list applicable, not-installed
        software updates and recent install history.
    #>
    [CmdletBinding()]
    param([switch]$Online)
    $session  = New-Object -ComObject 'Microsoft.Update.Session'
    $searcher = $session.CreateUpdateSearcher()
    if (-not $Online) { $searcher.Online = $false }

    $pending = @()
    $search = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    foreach ($u in $search.Updates) {
        $categories = @($u.Categories | ForEach-Object { $_.Name })
        $pending += [pscustomobject]@{
            Title        = [string]$u.Title
            KB           = (@($u.KBArticleIDs) | ForEach-Object { "KB$_" }) -join ','
            Severity     = [string]$u.MsrcSeverity
            Released     = [datetime]$u.LastDeploymentChangeTime
            IsSecurity   = ($categories -contains 'Security Updates' -or [bool]$u.MsrcSeverity)
            Categories   = $categories -join ', '
        }
    }

    $history = @()
    $count = $searcher.GetTotalHistoryCount()
    if ($count -gt 0) {
        foreach ($h in $searcher.QueryHistory(0, [math]::Min($count, 100))) {
            $history += [pscustomobject]@{
                Title      = [string]$h.Title
                Date       = [datetime]$h.Date
                ResultCode = [int]$h.ResultCode   # 2 = succeeded
            }
        }
    }
    return [pscustomobject]@{
        Pending = $pending
        History = $history
    }
}

function Test-CEPendingReboot {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    )
    foreach ($k in $keys) { if (Test-Path $k) { return $true } }
    return $false
}
