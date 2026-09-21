# ---------------------------------------------------------------------------
# Theme 6: NCSC device security guidance (Windows)
# Not required for Cyber Essentials certification, but recommended by NCSC and
# commonly asked about in supply-chain questionnaires.
# ---------------------------------------------------------------------------

function Get-CEDeviceGuard {
    try { return Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop }
    catch { return $null }
}

Register-CECheck -Id 'NC-01' -Category 'NCSCHardening' -Severity 'High' -RequiresAdmin `
    -Title 'System drive encrypted with BitLocker' `
    -Frameworks @('NCSC') `
    -Reference 'NCSC Windows device guidance: enable full disk encryption (BitLocker), with a TPM and PIN for pre-boot authentication.' `
    -Test {
        param($ctx)
        if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
            return New-CEResult -Status 'Manual' -Expected 'System drive encrypted' -Actual 'BitLocker cmdlets unavailable (Windows Home uses Device Encryption)' `
                -Recommendation 'Check Settings > Privacy & security > Device encryption is On.'
        }
        $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        $protectors = @($vol.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
        $evidence = @("VolumeStatus=$($vol.VolumeStatus)", "ProtectionStatus=$($vol.ProtectionStatus)", "EncryptionMethod=$($vol.EncryptionMethod)", "KeyProtectors=$($protectors -join ',')")
        if ("$($vol.ProtectionStatus)" -ne 'On') {
            $actual = if ("$($vol.VolumeStatus)" -eq 'FullyEncrypted') { 'Encrypted but protection is suspended' } else { "System drive not protected ($($vol.VolumeStatus))" }
            New-CEResult -Status 'Fail' -Subject 'Encryption' -Expected 'BitLocker protection On' -Actual $actual -Evidence $evidence `
                -Recommendation 'Turn on BitLocker for the system drive (Control Panel > BitLocker Drive Encryption) and store the recovery key in your Microsoft/Entra account or a password manager BEFORE restarting. If suspended, resume protection.' `
                -Remediation $(if ("$($vol.VolumeStatus)" -eq 'FullyEncrypted') { New-CERemediationRef -Id 'BitLocker-Resume' } else { $null })
            return
        }
        New-CEResult -Status 'Pass' -Subject 'Encryption' -Expected 'BitLocker protection On' -Actual "Protected ($($vol.EncryptionMethod))" -Evidence $evidence
        if ($protectors -notcontains 'RecoveryPassword') {
            New-CEResult -Status 'Warn' -Severity 'Medium' -Subject 'Recovery' -Expected 'A recovery password protector exists and is escrowed' -Actual 'No recovery password protector' -Evidence $evidence `
                -Recommendation 'Add a recovery password (manage-bde -protectors -add C: -RecoveryPassword) and back it up to Entra ID/AD or a password manager.'
        }
        if ($protectors -notcontains 'TpmPin' -and $protectors -notcontains 'TpmPinStartupKey') {
            New-CEResult -Status 'Warn' -Severity 'Medium' -Subject 'Pre-boot PIN' -Expected 'TPM + PIN protector' -Actual 'TPM-only unlock (no pre-boot PIN)' -Evidence $evidence `
                -Recommendation 'NCSC recommends TPM + PIN. Enable "Require additional authentication at startup" (Group Policy/Intune), then run: manage-bde -protectors -add C: -TPMAndPIN. Needs a keyboard at boot, so plan for remote restarts.'
        }
    }

Register-CECheck -Id 'NC-02' -Category 'NCSCHardening' -Severity 'High' `
    -Title 'Secure Boot and TPM 2.0 enabled' `
    -Frameworks @('NCSC') `
    -Reference 'NCSC Windows device guidance: enable Secure Boot; use the TPM for credential and key protection.' `
    -Test {
        param($ctx)
        $sb = $null
        try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sb = $null }
        if ($sb -eq $true) {
            New-CEResult -Status 'Pass' -Subject 'Secure Boot' -Expected 'Secure Boot on' -Actual 'Secure Boot on'
        }
        elseif ($sb -eq $false) {
            New-CEResult -Status 'Fail' -Subject 'Secure Boot' -Expected 'Secure Boot on' -Actual 'Secure Boot off' `
                -Recommendation 'Enable Secure Boot in the UEFI firmware settings. Suspend BitLocker first (Suspend-BitLocker -MountPoint C: -RebootCount 1) to avoid a recovery prompt.'
        }
        else {
            $why = if ($ctx.IsElevated) { 'Secure Boot state unavailable (legacy BIOS boot?)' } else { 'Needs elevation to read Secure Boot state' }
            New-CEResult -Status 'Manual' -Subject 'Secure Boot' -Expected 'Secure Boot on' -Actual $why `
                -Recommendation 'Check System Information (msinfo32) > Secure Boot State.'
        }
        $spec = $null
        try {
            $tpm = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'Win32_Tpm' -ErrorAction Stop
            if ($tpm) { $spec = [string]$tpm.SpecVersion }
        }
        catch { $spec = $null }
        if ($spec -and $spec -match '^2\.0') {
            New-CEResult -Status 'Pass' -Subject 'TPM' -Expected 'TPM 2.0 present' -Actual "TPM spec $(($spec -split ',')[0])"
        }
        elseif ($spec) {
            New-CEResult -Status 'Warn' -Subject 'TPM' -Expected 'TPM 2.0 present' -Actual "TPM spec $spec" -Recommendation 'Upgrade TPM firmware to 2.0 if supported.'
        }
        else {
            New-CEResult -Status 'Manual' -Subject 'TPM' -Expected 'TPM 2.0 present' -Actual 'TPM information unavailable (needs elevation)' -Recommendation 'Run tpm.msc to confirm.'
        }
    }

Register-CECheck -Id 'NC-03' -Category 'NCSCHardening' -Severity 'Medium' `
    -Title 'Virtualisation-based security: Memory Integrity (HVCI) and Credential Guard' `
    -Frameworks @('NCSC') `
    -Reference 'NCSC Windows device guidance: enable virtualisation-based security features including HVCI and Credential Guard.' `
    -Test {
        param($ctx)
        $dg = Get-CEDeviceGuard
        if (-not $dg) {
            return New-CEResult -Status 'Manual' -Expected 'VBS running with HVCI and Credential Guard' -Actual 'Device Guard status unavailable' `
                -Recommendation 'Check Windows Security > Device security > Core isolation.'
        }
        $running = @($dg.SecurityServicesRunning | ForEach-Object { [int]$_ })
        $evidence = @("VirtualizationBasedSecurityStatus=$($dg.VirtualizationBasedSecurityStatus)", "SecurityServicesRunning=$($running -join ',')")
        if ($running -contains 2) {
            New-CEResult -Status 'Pass' -Subject 'HVCI' -Expected 'Memory Integrity running' -Actual 'Memory Integrity (HVCI) running' -Evidence $evidence
        }
        else {
            New-CEResult -Status 'Warn' -Subject 'HVCI' -Expected 'Memory Integrity running' -Actual 'Memory Integrity (HVCI) not running' -Evidence $evidence `
                -Recommendation 'Turn on Core isolation > Memory integrity. Incompatible drivers are listed in Windows Security; update or remove them first. Restart required.' `
                -Remediation (New-CERemediationRef -Id 'VBS-EnableHVCI')
        }
        if ($ctx.EditionClass -ne 'Enterprise') {
            New-CEResult -Status 'NotApplicable' -Subject 'Credential Guard' -Actual "Credential Guard needs Enterprise or Education (this is $($ctx.EditionID))"
        }
        elseif ($running -contains 1) {
            New-CEResult -Status 'Pass' -Subject 'Credential Guard' -Expected 'Credential Guard running' -Actual 'Credential Guard running' -Evidence $evidence
        }
        else {
            New-CEResult -Status 'Warn' -Subject 'Credential Guard' -Expected 'Credential Guard running' -Actual 'Credential Guard not running' -Evidence $evidence `
                -Recommendation 'Enable Credential Guard (UEFI lock recommended via Intune/GPO). Restart required.' `
                -Remediation (New-CERemediationRef -Id 'VBS-EnableCredentialGuard')
        }
    }

Register-CECheck -Id 'NC-04' -Category 'NCSCHardening' -Severity 'Medium' `
    -Title 'Credential theft mitigations (LSA protection, WDigest off, no LM hashes)' `
    -Frameworks @('NCSC') `
    -Reference 'NCSC Windows device guidance: protect credentials in memory; disable legacy authentication.' `
    -Test {
        param($ctx)
        $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $ppl = Get-CERegistryValue -Path $lsa -Name 'RunAsPPL'
        if (@('1', '2') -contains "$ppl") {
            New-CEResult -Status 'Pass' -Subject 'LSA protection' -Expected 'RunAsPPL = 1 or 2' -Actual "RunAsPPL=$ppl"
        }
        else {
            New-CEResult -Status 'Warn' -Subject 'LSA protection' -Expected 'RunAsPPL = 1 or 2' -Actual "RunAsPPL=$ppl" `
                -Recommendation 'Turn on Local Security Authority protection (Windows Security > Device security > Core isolation). Restart required.' `
                -Remediation (New-CERemediationRef -Id 'Lsa-EnablePPL')
        }
        $wd = Get-CERegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
        if ("$wd" -eq '1') {
            New-CEResult -Status 'Fail' -Subject 'WDigest' -Expected 'UseLogonCredential = 0' -Actual 'WDigest stores plaintext credentials in memory' `
                -Recommendation 'Disable WDigest credential caching.' `
                -Remediation (New-CERemediationRef -Id 'Hardening-WDigestOff')
        }
        else {
            New-CEResult -Status 'Pass' -Subject 'WDigest' -Expected 'UseLogonCredential = 0' -Actual "UseLogonCredential=$(if ($null -eq $wd) { 'default (0)' } else { $wd })"
        }
        $nolm = Get-CERegistryValue -Path $lsa -Name 'NoLMHash' -Default 1
        $lmc = Get-CERegistryValue -Path $lsa -Name 'LmCompatibilityLevel'
        if ("$nolm" -ne '1' -or ($null -ne $lmc -and [int]$lmc -lt 5)) {
            New-CEResult -Status 'Fail' -Subject 'LM/NTLMv1' -Expected 'NoLMHash = 1 and LmCompatibilityLevel >= 5 (NTLMv2 only)' -Actual "NoLMHash=$nolm LmCompatibilityLevel=$lmc" `
                -Recommendation 'Stop storing LM hashes and refuse LM/NTLMv1.' `
                -Remediation (New-CERemediationRef -Id 'Hardening-NtlmV2Only')
        }
        else {
            New-CEResult -Status 'Pass' -Subject 'LM/NTLMv1' -Expected 'NTLMv2 only' -Actual "NoLMHash=$nolm LmCompatibilityLevel=$(if ($null -eq $lmc) { 'default' } else { $lmc })"
        }
    }

Register-CECheck -Id 'NC-05' -Category 'NCSCHardening' -Severity 'Medium' `
    -Title 'Legacy name resolution and anonymous access disabled (LLMNR, NetBIOS, anonymous enumeration)' `
    -Frameworks @('NCSC') `
    -Reference 'NCSC Windows device guidance: disable legacy and insecure network protocols.' `
    -Test {
        param($ctx)
        $llmnr = Get-CERegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
        if ("$llmnr" -eq '0') {
            New-CEResult -Status 'Pass' -Subject 'LLMNR' -Expected 'EnableMulticast = 0' -Actual 'LLMNR disabled'
        }
        else {
            New-CEResult -Status 'Warn' -Subject 'LLMNR' -Expected 'EnableMulticast = 0' -Actual 'LLMNR enabled (default)' `
                -Recommendation 'Disable LLMNR to stop name-poisoning credential capture on shared networks.' `
                -Remediation (New-CERemediationRef -Id 'Hardening-LlmnrOff')
        }

        $ifaces = @(Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue)
        $nbOn = @($ifaces | Where-Object { [int](Get-CERegistryValue -Path $_.PSPath -Name 'NetbiosOptions' -Default 0) -ne 2 })
        if ($ifaces.Count -gt 0 -and $nbOn.Count -gt 0) {
            New-CEResult -Status 'Warn' -Severity 'Low' -Subject 'NetBIOS' -Expected 'NetBIOS over TCP/IP disabled on all adapters' `
                -Actual "$($nbOn.Count) of $($ifaces.Count) adapter(s) allow NetBIOS over TCP/IP" `
                -Recommendation 'Disable NetBIOS over TCP/IP unless you rely on legacy file sharing or old NAS devices.' `
                -Remediation (New-CERemediationRef -Id 'Hardening-NetbiosOff')
        }
        else {
            New-CEResult -Status 'Pass' -Subject 'NetBIOS' -Expected 'NetBIOS over TCP/IP disabled' -Actual 'Disabled on all adapters'
        }

        $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $ra = Get-CERegistryValue -Path $lsa -Name 'RestrictAnonymous' -Default 0
        $ras = Get-CERegistryValue -Path $lsa -Name 'RestrictAnonymousSAM' -Default 1
        if ([int]$ra -ge 1 -and [int]$ras -eq 1) {
            New-CEResult -Status 'Pass' -Subject 'Anonymous enumeration' -Expected 'RestrictAnonymous = 1, RestrictAnonymousSAM = 1' -Actual "RestrictAnonymous=$ra RestrictAnonymousSAM=$ras"
        }
        else {
            New-CEResult -Status 'Warn' -Severity 'Low' -Subject 'Anonymous enumeration' -Expected 'RestrictAnonymous = 1, RestrictAnonymousSAM = 1' -Actual "RestrictAnonymous=$ra RestrictAnonymousSAM=$ras" `
                -Recommendation 'Block anonymous enumeration of accounts and shares.' `
                -Remediation (New-CERemediationRef -Id 'Hardening-RestrictAnonymous')
        }

        $sign = Get-CERegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature'
        if ("$sign" -eq '1') {
            New-CEResult -Status 'Pass' -Subject 'SMB signing' -Expected 'SMB client signing required' -Actual 'Required'
        }
        else {
            New-CEResult -Status 'Warn' -Severity 'Low' -Subject 'SMB signing' -Expected 'SMB client signing required' -Actual "RequireSecuritySignature=$sign" `
                -Recommendation 'Require SMB signing (default on Windows 11 24H2 and later).' `
                -Remediation (New-CERemediationRef -Id 'Hardening-SmbClientSigning')
        }
    }

Register-CECheck -Id 'NC-06' -Category 'NCSCHardening' -Severity 'Medium' -RequiresAdmin `
    -Title 'Security logging: audit policy, process command lines, PowerShell and log size' `
    -Frameworks @('NCSC') `
    -Reference 'NCSC Windows device guidance / NCSC logging guidance: implement logging and protective monitoring.' `
    -Test {
        param($ctx)
        $wanted = @(
            @{ Guid = '0cce922b-69ae-11d9-bed3-505054503030'; Name = 'Process Creation'; Need = 'Success' },
            @{ Guid = '0cce9215-69ae-11d9-bed3-505054503030'; Name = 'Logon'; Need = 'Success and Failure' },
            @{ Guid = '0cce923f-69ae-11d9-bed3-505054503030'; Name = 'Credential Validation'; Need = 'Success and Failure' },
            @{ Guid = '0cce9235-69ae-11d9-bed3-505054503030'; Name = 'User Account Management'; Need = 'Success and Failure' },
            @{ Guid = '0cce9237-69ae-11d9-bed3-505054503030'; Name = 'Security Group Management'; Need = 'Success' },
            @{ Guid = '0cce9217-69ae-11d9-bed3-505054503030'; Name = 'Account Lockout'; Need = 'Failure' },
            @{ Guid = '0cce922f-69ae-11d9-bed3-505054503030'; Name = 'Audit Policy Change'; Need = 'Success' }
        )
        $audit = Get-CEAuditPolicy
        $gaps = @()
        $evidence = @()
        foreach ($w in $wanted) {
            $cur = if ($audit.ContainsKey($w.Guid)) { $audit[$w.Guid].Setting } else { 'unknown' }
            $evidence += "$($w.Name): $cur"
            $ok = switch ($w.Need) {
                'Success' { $cur -match 'Success' }
                'Failure' { $cur -match 'Failure' }
                default { $cur -match 'Success' -and $cur -match 'Failure' }
            }
            if (-not $ok) { $gaps += $w }
        }
        if ($gaps.Count -eq 0) {
            New-CEResult -Status 'Pass' -Subject 'Audit policy' -Expected 'Key audit subcategories enabled' -Actual 'All enabled' -Evidence $evidence
        }
        else {
            New-CEResult -Status 'Warn' -Subject 'Audit policy' -Expected 'Key audit subcategories enabled' -Actual "Missing: $(($gaps | ForEach-Object { $_.Name }) -join ', ')" -Evidence $evidence `
                -Recommendation 'Enable auditing for these subcategories.' `
                -Remediation (New-CERemediationRef -Id 'AuditPolicy-Set' -Parameters @{ Subcategories = @($gaps | ForEach-Object { "$($_.Guid)|$($_.Need)" }) })
        }

        $cmd = Get-CERegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled'
        $sbl = Get-CERegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging'
        if ("$cmd" -eq '1' -and "$sbl" -eq '1') {
            New-CEResult -Status 'Pass' -Subject 'Command-line logging' -Expected 'Process command lines and PowerShell script blocks logged' -Actual 'Both enabled'
        }
        else {
            New-CEResult -Status 'Warn' -Subject 'Command-line logging' -Expected 'Process command lines and PowerShell script blocks logged' `
                -Actual "ProcessCreationIncludeCmdLine_Enabled=$cmd EnableScriptBlockLogging=$sbl" `
                -Recommendation 'Log process command lines (event 4688) and PowerShell script blocks (event 4104).' `
                -Remediation (New-CERemediationRef -Id 'Hardening-CommandLineLogging')
        }

        $min = [long](Get-CEConfig).thresholds.minSecurityLogSizeBytes
        $log = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
        if ([long]$log.MaximumSizeInBytes -ge $min) {
            New-CEResult -Status 'Pass' -Subject 'Security log size' -Expected "Security log >= $([math]::Round($min / 1MB)) MB" -Actual "$([math]::Round($log.MaximumSizeInBytes / 1MB)) MB"
        }
        else {
            New-CEResult -Status 'Warn' -Severity 'Low' -Subject 'Security log size' -Expected "Security log >= $([math]::Round($min / 1MB)) MB" -Actual "$([math]::Round($log.MaximumSizeInBytes / 1MB)) MB" `
                -Recommendation 'Increase the Security event log size so events survive long enough to investigate.' `
                -Remediation (New-CERemediationRef -Id 'EventLog-Size' -Parameters @{ LogName = 'Security'; SizeBytes = $min })
        }
    }

Register-CECheck -Id 'NC-07' -Category 'NCSCHardening' -Severity 'Low' `
    -Title 'Backups of important data in place (attestation)' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 repositions backup guidance: back up important data and keep a copy separate from the device. NCSC Small Business Guide: backing up your data.' `
    -Test {
        param($ctx)
        $evidence = @()
        $fh = Get-Service -Name 'fhsvc' -ErrorAction SilentlyContinue
        if ($fh) { $evidence += "File History service: $($fh.Status)" }
        $kfm = Get-CERegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -Name 'KFMSilentOptIn'
        if ($kfm) { $evidence += "OneDrive Known Folder Move policy: $kfm" }
        $sync = @(Get-CEInstalledSoftware | Where-Object { $_.Name -match 'OneDrive|Dropbox|Google Drive|Proton Drive|Backblaze|Acronis|Veeam|Macrium|iDrive|Carbonite' } | ForEach-Object { $_.Name })
        $evidence += $sync | ForEach-Object { "Installed: $_" }
        New-CEResult -Status 'Manual' -Expected 'Important data backed up, with a copy kept separate and restores tested' `
            -Actual "Backup/sync tooling found: $(if ($sync.Count) { $sync -join ', ' } else { 'none detected' })" -Evidence $evidence `
            -Recommendation 'Confirm what data lives on this device, that it is backed up somewhere not permanently connected (sync alone is not a backup), and that you have tested a restore.'
    }

function Get-CESecureBootVariableText {
    <#
        Returns a UEFI Secure Boot variable (db or KEK) decoded as text, so
        certificate common names can be matched. $null when it can't be read.
    #>
    param([Parameter(Mandatory)][ValidateSet('db', 'KEK')][string]$Name)
    try { $var = Get-SecureBootUEFI -Name $Name -ErrorAction Stop } catch { return $null }
    if ($null -eq $var -or $null -eq $var.Bytes) { return $null }
    # Names are normally ASCII in the DER; also decode UTF-16 in case a BMPString was used.
    return [Text.Encoding]::ASCII.GetString($var.Bytes) + "`n" + [Text.Encoding]::Unicode.GetString($var.Bytes)
}

function Get-CESecureBootEvent {
    <# Secure Boot servicing events (Microsoft-Windows-TPM-WMI) from the System log. #>
    param([Parameter(Mandatory)][int[]]$Id, [Parameter(Mandatory)][datetime]$Since)
    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-TPM-WMI'; Id = $Id; StartTime = $Since } -ErrorAction Stop)
    }
    catch {
        # Get-WinEvent throws when nothing matches.
        return ,@()
    }
}

Register-CECheck -Id 'NC-08' -Category 'NCSCHardening' -Severity 'High' -RequiresAdmin `
    -Title 'Secure Boot trusts the 2023 Microsoft certificates' `
    -Frameworks @('NCSC') `
    -Reference 'Microsoft Secure Boot certificate updates: the 2011 KEK and UEFI CAs expire in June 2026 and Windows Production PCA 2011 on 2026-10-19. NCSC Windows device guidance: enable Secure Boot and keep firmware up to date.' `
    -Test {
        param($ctx)
        $cfg = (Get-CEConfig).'secure-boot'
        # An admin override replaces the whole file, so treat missing sections as a config problem, not a crash.
        $events = Get-CEObjectValue $cfg 'events'
        $certificates = @(Get-CEObjectValue $cfg 'certificates' @())
        if ($null -eq $cfg -or $null -eq $events -or $certificates.Count -eq 0) {
            return New-CEResult -Status 'Manual' -Expected 'Secure Boot trusts the 2023 Microsoft certificates' `
                -Actual 'config/secure-boot.json is missing its events or certificates section' `
                -Recommendation 'Restore config/secure-boot.json (or include every section in your override): see the shipped copy.'
        }
        $sb = $null
        try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sb = $null }
        if ($sb -ne $true) {
            $why = if ($sb -eq $false) { 'Secure Boot is off, so the certificates are not used (see NC-02)' } else { 'Not a UEFI Secure Boot device, or its state is unavailable (see NC-02)' }
            return New-CEResult -Status 'NotApplicable' -Actual $why
        }

        $sbKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
        $svc = "$sbKey\Servicing"
        $status = Get-CERegistryValue -Path $svc -Name 'UEFICA2023Status'
        $errCode = Get-CERegistryValue -Path $svc -Name 'UEFICA2023Error'
        $capable = Get-CERegistryValue -Path $svc -Name 'WindowsUEFICA2023Capable'
        $avail = Get-CERegistryValue -Path $sbKey -Name 'AvailableUpdates'
        $evidence = @(
            "UEFICA2023Status=$(if ($null -eq $status) { 'not set' } else { $status })",
            "UEFICA2023Error=$(if ($null -eq $errCode) { 'not set' } else { $errCode })",
            "WindowsUEFICA2023Capable=$(if ($null -eq $capable) { 'not set' } else { $capable })",
            "AvailableUpdates=$(if ($null -eq $avail) { 'not set' } else { '0x{0:X}' -f [long]$avail })"
        )

        # Newest occurrence of each servicing event in the lookback window.
        $allIds = @()
        foreach ($group in $events.PSObject.Properties) { $allIds += @($group.Value | ForEach-Object { [int]$_ }) }
        $latest = @{}
        $lookback = [int](Get-CEObjectValue $cfg 'eventLookbackDays' 30)
        foreach ($e in @(Get-CESecureBootEvent -Id $allIds -Since $ctx.AuditTime.AddDays(-$lookback))) {
            $eid = [int]$e.Id
            if (-not $latest.ContainsKey($eid) -or $e.TimeCreated -gt $latest[$eid].TimeCreated) { $latest[$eid] = $e }
        }
        foreach ($eid in ($latest.Keys | Sort-Object)) { $evidence += "Event $eid last logged $($latest[$eid].TimeCreated.ToString('yyyy-MM-dd HH:mm'))" }
        $seen = { param($group) @(@(Get-CEObjectValue $events $group @()) | Where-Object { $latest.ContainsKey([int]$_) }).Count -gt 0 }
        $newest = {
            param($group)
            $times = @(@(Get-CEObjectValue $events $group @()) | Where-Object { $latest.ContainsKey([int]$_) } | ForEach-Object { $latest[[int]$_].TimeCreated } | Sort-Object -Descending)
            if ($times.Count -gt 0) { return $times[0] }
            return $null
        }

        # A reboot-required event only means "in progress" if nothing has succeeded since.
        $rebootAt = & $newest 'rebootRequired'
        $successAt = & $newest 'success'
        $rebootPending = ($null -ne $rebootAt) -and ($null -eq $successAt -or $rebootAt -gt $successAt)
        $inProgress = ("$status" -eq 'InProgress') -or $rebootPending
        $hints = @()
        if (& $seen 'firmwareBlocked') { $hints += 'Event 1802: Microsoft has blocked the update on this firmware because of a known issue. Install the latest BIOS/UEFI update from the manufacturer first.' }
        if (& $seen 'firmwareError') { $hints += 'Events 1795/1796: the firmware rejected a Secure Boot variable update. Install the latest BIOS/UEFI update from the manufacturer, then restart.' }
        if (& $seen 'bitLockerBlocked') { $hints += 'Event 1032: the update was held back because it would trigger BitLocker recovery with the current BitLocker configuration.' }
        if ($null -ne $errCode -and "$errCode" -ne '0') { $hints += "Windows recorded servicing error $errCode (UEFICA2023Error)." }
        if ($inProgress) { $hints += 'An update is already in progress: restart the device (it may take two restarts) and run the audit again.' }
        $baseRec = 'Install the latest Windows cumulative update and BIOS/UEFI firmware, then apply the 2023 certificates (the fix below, Intune or Group Policy) and restart twice. Keep the BitLocker recovery key to hand.'
        $blocked = (& $seen 'firmwareBlocked')
        $fix = if ($inProgress -or $blocked) { $null } else { New-CERemediationRef -Id 'SecureBoot-Deploy2023Certs' }

        $text = @{ db = (Get-CESecureBootVariableText -Name 'db'); KEK = (Get-CESecureBootVariableText -Name 'KEK') }
        foreach ($cert in $certificates) {
            $var = [string](Get-CEObjectValue $cert 'variable' '')
            $name = [string](Get-CEObjectValue $cert 'name' '')
            $replaces = [string](Get-CEObjectValue $cert 'replaces' '')
            $replacesExpires = [string](Get-CEObjectValue $cert 'replacesExpires' '')
            if (-not $var -or -not $name -or $replacesExpires -notmatch '^\d{4}-\d{2}-\d{2}$') { continue }
            $expires = [datetime]::ParseExact($replacesExpires, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
            $expected = "'$name' in the Secure Boot $var"
            if ($null -eq $text[$var]) {
                New-CEResult -Status 'Manual' -Subject $name -Expected $expected -Actual "Could not read the Secure Boot $var variable" -Evidence $evidence `
                    -Recommendation "Run Get-SecureBootUEFI -Name $var in an elevated PowerShell prompt and look for '$name'."
                continue
            }
            if ($text[$var].Contains($name)) {
                New-CEResult -Status 'Pass' -Subject $name -Expected $expected -Actual "Present in $var" -Evidence $evidence
                continue
            }
            $days = [int][math]::Floor(($expires - $ctx.AuditTime).TotalDays)
            $when = if ($days -lt 0) { "expired on $replacesExpires" } else { "expires on $replacesExpires ($days days)" }
            if (-not [bool](Get-CEObjectValue $cert 'required' $false)) {
                # Only needed where the old third-party CA is trusted (option ROMs, Linux shim).
                if (-not $text[$var].Contains($replaces)) { continue }
                New-CEResult -Status 'Warn' -Severity 'Low' -Subject $name -Expected $expected -Actual "Missing from $var; $replaces $when" -Evidence $evidence `
                    -Recommendation ((@("Needed to keep trusting third-party UEFI components (graphics/network option ROMs, Linux boot loaders) signed after the 2011 CA expires. $baseRec") + $hints) -join ' ') `
                    -Remediation $fix
                continue
            }
            $recs = @($baseRec)
            $certFix = $fix
            if ($var -eq 'KEK' -and (& $seen 'missingOemKek')) {
                $recs = @('Event 1803: the manufacturer has not published a KEK signed by this device''s platform key, so Windows cannot add the 2023 KEK. Install the latest BIOS/UEFI firmware; if that does not include it, ask the manufacturer for a Secure Boot KEK update.')
                $certFix = $null
            }
            $st = if ($days -lt 0) { 'Fail' } else { 'Warn' }
            New-CEResult -Status $st -Subject $name -Expected $expected -Actual "Missing from $var; $replaces $when" -Evidence $evidence `
                -Recommendation (($recs + $hints) -join ' ') -Remediation $certFix
        }

        $bm = "$capable"
        if ($bm -eq '2') {
            New-CEResult -Status 'Pass' -Subject 'Boot manager' -Expected 'Booting a boot manager signed by Windows UEFI CA 2023' -Actual 'WindowsUEFICA2023Capable=2' -Evidence $evidence
        }
        else {
            $actual = if ($bm -eq '1') { 'The 2023 CA is trusted, but the device still boots the 2011-signed boot manager' } else { 'Still booting the 2011-signed boot manager' }
            New-CEResult -Status 'Warn' -Severity 'Medium' -Subject 'Boot manager' -Expected 'Booting a boot manager signed by Windows UEFI CA 2023' -Actual $actual -Evidence $evidence `
                -Recommendation ((@('Windows swaps the boot manager after Windows UEFI CA 2023 is in the DB; it usually needs a restart after the certificate update.') + $hints) -join ' ') `
                -Remediation $(if ($bm -eq '1') { $fix } else { $null })
        }
    }
