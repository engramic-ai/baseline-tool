# ---------------------------------------------------------------------------
# Remediation library: NCSC hardening.
# ---------------------------------------------------------------------------

Register-CERemediation -Id 'BitLocker-Resume' -Title 'Resume suspended BitLocker protection' -Risk 'Low' -RequiresAdmin `
    -Apply {
        param($p, $undo)
        Resume-BitLocker -MountPoint $env:SystemDrive -ErrorAction Stop | Out-Null
        Add-CEUndoCommand $undo 'Suspend BitLocker again (one restart)' "Suspend-BitLocker -MountPoint `$env:SystemDrive -RebootCount 1 | Out-Null"
    }

Register-CERemediation -Id 'VBS-EnableHVCI' -Title 'Turn on Memory Integrity (HVCI)' -Risk 'High' -RequiresAdmin -RequiresReboot `
    -Notes 'Setting this by registry skips the driver compatibility check that the Windows Security toggle performs. Prefer the toggle in Windows Security > Device security > Core isolation.' `
    -Apply {
        param($p, $undo)
        $dg = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        Set-CERegistryValueTracked -Path $dg -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Undo $undo
        Set-CERegistryValueTracked -Path "$dg\Scenarios\HypervisorEnforcedCodeIntegrity" -Name 'Enabled' -Value 1 -Undo $undo
    }

Register-CERemediation -Id 'VBS-EnableCredentialGuard' -Title 'Turn on Credential Guard (without UEFI lock)' -Risk 'High' -RequiresAdmin -RequiresReboot `
    -Notes 'Breaks NTLMv1, MS-CHAPv2 VPN/Wi-Fi with saved credentials, and unconstrained Kerberos delegation. Test first.' `
    -Apply {
        param($p, $undo)
        $dg = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        Set-CERegistryValueTracked -Path $dg -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Undo $undo
        Set-CERegistryValueTracked -Path $dg -Name 'RequirePlatformSecurityFeatures' -Value 1 -Undo $undo
        Set-CERegistryValueTracked -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags' -Value 2 -Undo $undo
    }

Register-CERemediation -Id 'Lsa-EnablePPL' -Title 'Turn on Local Security Authority protection' -Risk 'Medium' -RequiresAdmin -RequiresReboot `
    -Notes 'Uses RunAsPPL=2 (no UEFI lock) so it can be reverted. Some old security or smart-card software may fail to load into LSA.' `
    -Apply {
        param($p, $undo)
        Set-CERegistryValueTracked -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 2 -Undo $undo
    }

# Simple registry hardening settings, one remediation each so risk is explicit.
$script:CEHardeningSettings = @(
    @{ Id = 'WDigestOff'; Title = 'Stop WDigest caching plaintext credentials'; Risk = 'Low'; Reboot = $false; Notes = '';
       Values = @(@{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name = 'UseLogonCredential'; Value = 0 }) },
    @{ Id = 'NtlmV2Only'; Title = 'Refuse LM and NTLMv1 authentication'; Risk = 'Medium'; Reboot = $true; Notes = 'Very old NAS devices and printers may stop working.';
       Values = @(@{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'NoLMHash'; Value = 1 },
                  @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel'; Value = 5 }) },
    @{ Id = 'LlmnrOff'; Title = 'Disable LLMNR name resolution'; Risk = 'Low'; Reboot = $false; Notes = 'Name lookups for devices without DNS entries may fail on home networks; mDNS still works.';
       Values = @(@{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; Value = 0 }) },
    @{ Id = 'RestrictAnonymous'; Title = 'Block anonymous enumeration of accounts and shares'; Risk = 'Low'; Reboot = $true; Notes = '';
       Values = @(@{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Value = 1 },
                  @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; Value = 1 }) },
    @{ Id = 'SmbClientSigning'; Title = 'Require SMB signing for outgoing connections'; Risk = 'Medium'; Reboot = $false; Notes = 'Old NAS devices without signing support will refuse connections.';
       Values = @(@{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'RequireSecuritySignature'; Value = 1 }) },
    @{ Id = 'CommandLineLogging'; Title = 'Log process command lines and PowerShell script blocks'; Risk = 'Low'; Reboot = $false; Notes = 'Command lines can contain secrets; restrict who can read the Security log.';
       Values = @(@{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Value = 1 },
                  @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Value = 1 }) }
)

foreach ($setting in $script:CEHardeningSettings) {
    $splat = @{
        Id            = "Hardening-$($setting.Id)"
        Title         = $setting.Title
        Risk          = $setting.Risk
        RequiresAdmin = $true
        Notes         = $setting.Notes
        Data          = $setting.Values
        Apply         = {
            param($p, $undo, $rem)
            foreach ($v in $rem.Data) {
                Set-CERegistryValueTracked -Path $v.Path -Name $v.Name -Value $v.Value -Undo $undo
            }
        }
    }
    if ($setting.Reboot) { $splat['RequiresReboot'] = $true }
    Register-CERemediation @splat
}

Register-CERemediation -Id 'Hardening-NetbiosOff' -Title 'Disable NetBIOS over TCP/IP on all adapters' -Risk 'Medium' -RequiresAdmin `
    -Notes 'Legacy file sharing by computer name (without DNS) and some old devices rely on NetBIOS.' `
    -Apply {
        param($p, $undo)
        foreach ($iface in @(Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop)) {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\$($iface.PSChildName)"
            Set-CERegistryValueTracked -Path $path -Name 'NetbiosOptions' -Value 2 -Undo $undo
        }
    }

Register-CERemediation -Id 'AuditPolicy-Set' -Title 'Enable key security audit categories' -Risk 'Low' -RequiresAdmin `
    -Validate {
        param($p)
        Assert-CEParam $p 'Subcategories' -Pattern '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\|(Success|Failure|Success and Failure)$'
    } `
    -Apply {
        param($p, $undo)
        $backup = Join-Path $script:CEUndoDirectory ("auditpol-backup-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $b = Invoke-CENative -FilePath 'auditpol.exe' -ArgumentList @('/backup', "/file:$backup")
        if ($b.ExitCode -ne 0) { throw "auditpol backup failed: $($b.Output -join ' ')" }
        Add-CEUndoCommand $undo 'Restore previous audit policy' "auditpol.exe /restore /file:$(ConvertTo-CEPSLiteral $backup)"
        foreach ($entry in @($p.Subcategories)) {
            $guid, $need = ([string]$entry) -split '\|', 2
            $a = @('/set', "/subcategory:{$guid}")
            if ($need -match 'Success') { $a += '/success:enable' }
            if ($need -match 'Failure') { $a += '/failure:enable' }
            $r = Invoke-CENative -FilePath 'auditpol.exe' -ArgumentList $a
            if ($r.ExitCode -ne 0) { throw "auditpol $($a -join ' ') failed: $($r.Output -join ' ')" }
        }
    }

Register-CERemediation -Id 'EventLog-Size' -Title 'Increase event log maximum size' -Risk 'Low' -RequiresAdmin `
    -Validate {
        param($p)
        Assert-CEParam $p 'LogName' -AllowedValues @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational')
        Assert-CEParam $p 'SizeBytes' -Pattern '^\d{1,12}$'
        if ([long]$p.SizeBytes -lt 20MB -or [long]$p.SizeBytes -gt 4GB) { throw 'SizeBytes must be between 20 MB and 4 GB' }
    } `
    -Apply {
        param($p, $undo)
        $before = (Get-WinEvent -ListLog $p.LogName -ErrorAction Stop).MaximumSizeInBytes
        $r = Invoke-CENative -FilePath 'wevtutil.exe' -ArgumentList @('sl', $p.LogName, "/ms:$([long]$p.SizeBytes)")
        if ($r.ExitCode -ne 0) { throw "wevtutil failed: $($r.Output -join ' ')" }
        Add-CEUndoCommand $undo "Restore $($p.LogName) log size" "wevtutil.exe sl $(ConvertTo-CEPSLiteral $p.LogName) /ms:$before"
    }

Register-CERemediation -Id 'SecureBoot-Deploy2023Certs' -Title 'Apply the 2023 Secure Boot certificates and boot manager' -Risk 'High' -RequiresAdmin -RequiresReboot -NotReversible `
    -Notes 'Writes the 2023 Microsoft certificates to the UEFI KEK and DB and swaps the boot manager. Firmware changes cannot be undone from Windows; undo only sets AvailableUpdates to 0, which stops any further certificate updates. Update the BIOS/UEFI first, as some older firmware fails after a KEK or DB write. Keep the BitLocker recovery key to hand. Takes two restarts; run the audit again afterwards.' `
    -Apply {
        param($p, $undo)
        $sb = $false
        try { $sb = ((Confirm-SecureBootUEFI -ErrorAction Stop) -eq $true) } catch { $sb = $false }
        if (-not $sb) { throw 'Secure Boot is not on; the 2023 certificates are only applied while Secure Boot is enabled.' }
        # 0x5944: deploy all needed certificates and the Windows UEFI CA 2023 signed boot manager.
        # Undo sets 0 rather than restoring the old value: an old non-zero bitmask would restart servicing.
        New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates' -Value 0x5944 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Add-CEUndoCommand $undo 'Stop further Secure Boot certificate updates (AvailableUpdates = 0; firmware changes already made stay)' "Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates' -Value 0 -Type DWord"
        Start-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update' -ErrorAction Stop
    }
