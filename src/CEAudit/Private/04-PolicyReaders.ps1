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

function Get-CEHelloPinPolicy {
    <#
        Every Windows Hello PIN minimum-length policy on the device, as objects with Source and Value:
          Group Policy:          HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity
          Intune (device-wide):  HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<tenant ID>\Policies\PINComplexity
          Intune (per user):     HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<tenant ID>\<user SID>\Policies\PINComplexity
        Intune writes the per-user form when a Windows Hello for Business policy targets users.
    #>
    [CmdletBinding()]
    param()
    $out = New-Object System.Collections.ArrayList
    $gp = Get-CERegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity' -Name 'MinimumPINLength'
    if ($null -ne $gp) { [void]$out.Add([pscustomobject]@{ Source = 'Group Policy'; Value = [int]$gp }) }

    $root = 'HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork'
    $tenants = Get-CERegistrySubKeyName -Path $root
    foreach ($tenant in @($tenants | Where-Object { $_ -match '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' })) {
        $device = Get-CERegistryValue -Path "$root\$tenant\Policies\PINComplexity" -Name 'MinimumPINLength'
        if ($null -ne $device) { [void]$out.Add([pscustomobject]@{ Source = 'Intune, all users'; Value = [int]$device }) }
        $sids = Get-CERegistrySubKeyName -Path "$root\$tenant"
        foreach ($sid in @($sids | Where-Object { $_ -match '^S-1-[0-9-]+$' })) {
            $user = Get-CERegistryValue -Path "$root\$tenant\$sid\Policies\PINComplexity" -Name 'MinimumPINLength'
            if ($null -eq $user) { continue }
            $name = $sid
            try { $name = ([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value }
            catch { Write-Verbose "Could not resolve ${sid}: $($_.Exception.Message)" }
            [void]$out.Add([pscustomobject]@{ Source = "Intune, user $name"; Value = [int]$user })
        }
    }
    return , $out.ToArray()
}

function ConvertFrom-CEAppLockerPolicyFile {
    <#
        Parses one AppLocker rule-collection file as Intune's AppLocker CSP stores it: a UTF-16
        XML fragment with a single <RuleCollection Type="Exe" EnforcementMode="Enabled"> root.
        Returns Type, EnforcementMode and RuleCount, or $null when the bytes are not a rule collection.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)
    if ($Bytes.Length -lt 4) { return $null }
    $text = if ($Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { [Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2) }
        elseif ($Bytes[1] -eq 0) { [Text.Encoding]::Unicode.GetString($Bytes) }
        elseif ($Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { [Text.Encoding]::UTF8.GetString($Bytes, 3, $Bytes.Length - 3) }
        else { [Text.Encoding]::UTF8.GetString($Bytes) }
    try {
        $settings = New-Object System.Xml.XmlReaderSettings
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($text)), $settings)
        try {
            $doc = New-Object System.Xml.XmlDocument
            $doc.Load($reader)
        }
        finally { $reader.Close() }
    }
    catch { return $null }
    $root = $doc.DocumentElement
    if (-not $root -or $root.LocalName -ne 'RuleCollection') { return $null }
    $rules = @($root.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -like '*Rule' })
    $mode = $root.GetAttribute('EnforcementMode')
    if (-not $mode) { $mode = 'NotConfigured' }
    return [pscustomobject]@{ Type = $root.GetAttribute('Type'); EnforcementMode = $mode; RuleCount = $rules.Count }
}

function Get-CEMdmAppLockerPolicy {
    <#
        AppLocker rule collections Intune has delivered (AppLocker CSP, ApplicationLaunchRestrictions).
        Windows keeps them as files named Policy under %WINDIR%\System32\AppLocker\MDM, one per rule
        type, and Get-AppLockerPolicy -Effective does not include them. The folder is writable only by
        SYSTEM and administrators. Files over 4 MB, and files that are not rule collections, are skipped.
    #>
    [CmdletBinding()]
    param([string]$Root = (Join-Path $env:windir 'System32\AppLocker\MDM'))
    $out = New-Object System.Collections.ArrayList
    if (-not $env:windir -or -not (Test-Path -LiteralPath $Root)) { return , $out.ToArray() }
    $files = @(Get-ChildItem -LiteralPath $Root -Recurse -Depth 8 -File -Filter 'Policy' -ErrorAction SilentlyContinue)
    foreach ($f in $files) {
        if ($f.Length -gt 4MB) { continue }
        try { $bytes = [IO.File]::ReadAllBytes($f.FullName) }
        catch { Write-Verbose "Could not read $($f.FullName): $($_.Exception.Message)"; continue }
        $c = ConvertFrom-CEAppLockerPolicyFile -Bytes $bytes
        if ($c) { [void]$out.Add($c) }
    }
    return , $out.ToArray()
}

function Get-CELocalPasswordAccount {
    <#
        Which enabled local accounts have a password a person chose. One Windows LAPS manages with a
        strong generated password (see Get-CELapsManagedAccount) does not, so the local password
        policies (length, expiry) only matter for the others. Returns:
          Listed      - $false when local accounts could not be listed (then nothing else is known)
          LapsAccount - the enabled account LAPS manages, or $null
          LapsSummary - how LAPS sets its password ("6-word passphrase, rotated every 30 days")
          Unmanaged   - the other enabled local accounts
          Evidence    - lines for a finding's evidence
    #>
    [CmdletBinding()]
    param()
    $evidence = New-Object System.Collections.ArrayList
    try { $enabled = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled }) }
    catch {
        [void]$evidence.Add("Local accounts could not be listed: $($_.Exception.Message)")
        return [pscustomobject]@{ Listed = $false; LapsAccount = $null; LapsSummary = ''; Unmanaged = @(); Evidence = $evidence.ToArray() }
    }
    $laps = Get-CELapsManagedAccount
    $lapsAccount = $null
    if ($laps.Managed -and $laps.Strong) {
        $lapsAccount = @($enabled | Where-Object { ("$($_.SID)" -split '-')[-1] -eq "$($laps.Rid)" })[0]
    }
    elseif ($laps.Managed) { [void]$evidence.Add("Windows LAPS password is shorter than 12 characters ($($laps.Summary))") }
    elseif ($laps.Reason -ne 'No Windows LAPS policy') { [void]$evidence.Add($laps.Reason) }
    $unmanaged = @($enabled | Where-Object { -not $lapsAccount -or "$($_.SID)" -ne "$($lapsAccount.SID)" })
    if ($lapsAccount) { [void]$evidence.Add("Windows LAPS manages $($lapsAccount.Name): $($laps.Summary)") }
    return [pscustomobject]@{ Listed = $true; LapsAccount = $lapsAccount; LapsSummary = $laps.Summary; Unmanaged = $unmanaged; Evidence = $evidence.ToArray() }
}

function ConvertFrom-CEAdmxPolicyState {
    <#
        An ADMX-backed Intune policy is kept under PolicyManager as the SyncML text it arrived
        in, such as '<enabled/>' or '<disabled/>' followed by any data elements. Returns
        'Enabled', 'Disabled' or $null when the text is neither.
    #>
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = "$Value".Trim()
    if ($text -match '^<enabled\s*/>') { return 'Enabled' }
    if ($text -match '^<disabled\s*/>') { return 'Disabled' }
    return $null
}

function Get-CEPolicySetting {
    <#
        Reads one setting from every place Windows takes it from, and says which applies.
        Intune and Group Policy often keep the same setting in different keys, so a check
        that reads only one of them misses the other.

        -Source is a list of hashtables, in order of precedence:
          Label - 'Intune', 'Group Policy' or 'Local'
          Path, Name - the registry value
          Map  - optional scriptblock turning the raw value into the form the check compares
                 (return $null for "not set")
        A policy (any source but 'Local') beats the local setting. Returns:
          Value    - the value that applies, or $null when no source sets it
          Source   - the label of the source it came from ('' when none)
          Policy   - $true when a policy, not the local setting, decides it
          Conflict - $true when two policies set different values
          Found    - the sources that set a value, each with Label, Path, Name, Raw and Value
          Evidence - one line per source that set a value
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable[]]$Source)
    $found = New-Object System.Collections.ArrayList
    foreach ($s in $Source) {
        $raw = Get-CERegistryValue -Path $s.Path -Name $s.Name
        if ($null -eq $raw) { continue }
        $value = $raw
        if ($s.ContainsKey('Map') -and $s.Map) { $value = & $s.Map $raw }
        if ($null -eq $value) { continue }
        [void]$found.Add([pscustomobject]@{ Label = $s.Label; Path = $s.Path; Name = $s.Name; Raw = $raw; Value = $value })
    }
    $policies = @($found | Where-Object { $_.Label -ne 'Local' })
    $winner = $null
    if ($policies.Count) { $winner = $policies[0] } elseif ($found.Count) { $winner = $found[0] }
    $distinct = @($policies | ForEach-Object { "$($_.Value)" } | Select-Object -Unique)
    $short = { param($p) $p -replace '^HKLM:\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\', 'PolicyManager\' -replace '^HKLM:\\', 'HKLM\' -replace '^HKCU:\\', 'HKCU\' }
    return [pscustomobject]@{
        Value    = $(if ($winner) { $winner.Value } else { $null })
        Source   = $(if ($winner) { $winner.Label } else { '' })
        Policy   = ($policies.Count -gt 0)
        Conflict = ($distinct.Count -gt 1)
        Found    = @($found)
        Evidence = @($found | ForEach-Object { "$($_.Label): $(& $short $_.Path)\$($_.Name) = $($_.Raw)" })
    }
}

function Get-CELapsPolicy {
    <#
        The Windows LAPS policy that applies, or $null. Windows LAPS reads the Intune (CSP)
        key first, then Group Policy. Returns Path, Source ('Intune' or 'Group Policy') and
        BackupDirectory (0 off, 1 Entra ID, 2 Active Directory).
    #>
    [CmdletBinding()]
    param()
    foreach ($p in @(
            @{ Path = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'; Source = 'Intune' },
            @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; Source = 'Group Policy' })) {
        $backup = Get-CERegistryValue -Path $p.Path -Name 'BackupDirectory'
        if ($null -ne $backup) { return [pscustomobject]@{ Path = $p.Path; Source = $p.Source; BackupDirectory = [int]$backup } }
    }
    return $null
}

function Get-CELapsManagedAccount {
    <#
        The local account Windows LAPS manages, as an object:
          Managed  - $true when a LAPS policy backs passwords up and has rotated this account recently
          Rid      - the account's RID (the last part of its SID), from the LAPS state key
          Strong   - $true when the generated password is 12+ characters (or a passphrase of 4+ words)
          Summary  - short text for evidence ("6-word passphrase, rotated every 30 days")
          Reason   - why the account is not treated as managed, when Managed is $false
        The account is matched by RID, never by name or description: names are renamed and
        descriptions are localised. Policy precedence follows Windows LAPS: Intune (CSP) first,
        then Group Policy. Legacy Microsoft LAPS (AdmPwd) is not read.
    #>
    [CmdletBinding()]
    param([datetime]$Now = (Get-Date))
    $result = [ordered]@{ Managed = $false; Rid = $null; Strong = $false; Summary = ''; Reason = '' }
    $lapsPolicy = Get-CELapsPolicy
    if (-not $lapsPolicy) { $result.Reason = 'No Windows LAPS policy'; return [pscustomobject]$result }
    $policy = $lapsPolicy.Path
    $backup = $lapsPolicy.BackupDirectory
    if ($backup -ne 1 -and $backup -ne 2) { $result.Reason = "Windows LAPS is not backing up passwords (BackupDirectory=$backup)"; return [pscustomobject]$result }

    $state = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State'
    $rid = Get-CERegistryValue -Path $state -Name 'LastManagedAccountRid'
    $updated = Get-CERegistryValue -Path $state -Name 'LastPasswordUpdateTime'
    if ($null -eq $rid -or $null -eq $updated) { $result.Reason = 'Windows LAPS has not managed an account yet'; return [pscustomobject]$result }
    $result.Rid = [int64]$rid

    $ageDays = [int](Get-CERegistryValue -Path $policy -Name 'PasswordAgeDays' -Default 30)
    try { $lastUpdate = [datetime]::FromFileTimeUtc([int64]$updated).ToLocalTime() }
    catch { $result.Reason = 'Windows LAPS state has an unreadable password update time'; return [pscustomobject]$result }
    # A few days' slack: rotation waits for the device to be on and to reach the directory.
    if ($lastUpdate -lt $Now.AddDays( - ($ageDays + 7))) {
        $result.Reason = "Windows LAPS last rotated the password on $($lastUpdate.ToString('yyyy-MM-dd')), more than $ageDays days ago"
        return [pscustomobject]$result
    }

    $complexity = [int](Get-CERegistryValue -Path $policy -Name 'PasswordComplexity' -Default 4)
    if ($complexity -ge 6 -and $complexity -le 8) {
        $words = [int](Get-CERegistryValue -Path $policy -Name 'PassphraseLength' -Default 6)
        # Short-word lists include 3-letter words, so 4 words is the floor for 12 characters.
        $result.Strong = ($words -ge 4)
        $result.Summary = "$words-word passphrase, rotated every $ageDays days"
    }
    else {
        $length = [int](Get-CERegistryValue -Path $policy -Name 'PasswordLength' -Default 14)
        $result.Strong = ($length -ge 12)
        $result.Summary = "$length-character random password, rotated every $ageDays days"
    }
    $result.Managed = $true
    return [pscustomobject]$result
}

function Get-CESecurityPolicy {
    <#
        Exports local security policy with secedit (requires elevation) and
        returns [System Access] and [Registry Values] as a hashtable.
    #>
    [CmdletBinding()]
    param()
    # A locked folder in the data folder when elevated, not the shared temp folder (New-CEScratchFolder).
    $dir = New-CEScratchFolder -Area 'scratch'
    $tmp = Join-Path $dir 'secpol.inf'
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
        try { Remove-CEDataTree -Path $dir | Out-Null } catch { Write-Warning "Could not remove the scratch folder $dir ($($_.Exception.Message))." }
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
