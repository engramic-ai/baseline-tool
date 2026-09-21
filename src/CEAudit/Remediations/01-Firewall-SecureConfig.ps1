# ---------------------------------------------------------------------------
# Remediation library: firewalls and secure configuration.
# ---------------------------------------------------------------------------

$script:CEProfileNames = @('Domain', 'Private', 'Public')

Register-CERemediation -Id 'FW-EnableProfiles' -Title 'Turn on Microsoft Defender Firewall' -Risk 'Low' -RequiresAdmin `
    -Validate { param($p) Assert-CEParam $p 'Profiles' -AllowedValues $script:CEProfileNames } `
    -Apply {
        param($p, $undo)
        foreach ($name in @($p.Profiles)) {
            $before = Get-NetFirewallProfile -Name $name -PolicyStore PersistentStore
            Set-NetFirewallProfile -Name $name -Enabled True -ErrorAction Stop
            Add-CEUndoCommand $undo "Restore firewall $name Enabled=$($before.Enabled)" "Set-NetFirewallProfile -Name $(ConvertTo-CEPSLiteral $name) -Enabled $(ConvertTo-CEPSLiteral ([string]$before.Enabled))"
        }
    }

Register-CERemediation -Id 'FW-BlockInboundDefault' -Title 'Block inbound connections by default' -Risk 'Low' -RequiresAdmin `
    -Validate { param($p) Assert-CEParam $p 'Profiles' -AllowedValues $script:CEProfileNames } `
    -Apply {
        param($p, $undo)
        foreach ($name in @($p.Profiles)) {
            $before = Get-NetFirewallProfile -Name $name -PolicyStore PersistentStore
            Set-NetFirewallProfile -Name $name -DefaultInboundAction Block -ErrorAction Stop
            Add-CEUndoCommand $undo "Restore firewall $name DefaultInboundAction=$($before.DefaultInboundAction)" "Set-NetFirewallProfile -Name $(ConvertTo-CEPSLiteral $name) -DefaultInboundAction $(ConvertTo-CEPSLiteral ([string]$before.DefaultInboundAction))"
        }
    }

Register-CERemediation -Id 'FW-DisableRule' -Title 'Disable an inbound firewall rule open to any address on public networks' -Risk 'Medium' -RequiresAdmin -NotSelectedByDefault `
    -Notes 'Only disable rules you have confirmed are not needed. The application may stop accepting connections.' `
    -Validate {
        param($p)
        # Rule names can contain paths, colons and braces (e.g. "UDP Query User{GUID}C:\...\app.exe").
        # Allow any printable text except wildcard characters, which could match more than one rule.
        Assert-CEParam $p 'RuleName' -Pattern '^[^\x00-\x1F*?\[\]`]{1,1024}$'
        $matched = @(Get-NetFirewallRule -Name $p.RuleName -ErrorAction SilentlyContinue | Where-Object { $_.Name -ceq $p.RuleName })
        if ($matched.Count -ne 1) { throw "Firewall rule '$($p.RuleName)' not found (or not unique)" }
    } `
    -Apply {
        param($p, $undo)
        Disable-NetFirewallRule -Name $p.RuleName -ErrorAction Stop
        Add-CEUndoCommand $undo "Re-enable firewall rule $(Get-CEParamValue $p 'DisplayName' $p.RuleName)" "Enable-NetFirewallRule -Name $(ConvertTo-CEPSLiteral $p.RuleName)"
    }

Register-CERemediation -Id 'FW-PublicBlockAll' -Title 'Block all inbound connections on public networks' -Risk 'Medium' -RequiresAdmin `
    -Notes 'Apps that listen for connections (casting, file sharing, dev servers) will not be reachable while on a Public network.' `
    -Apply {
        param($p, $undo)
        $before = Get-NetFirewallProfile -Name Public -PolicyStore PersistentStore
        Set-NetFirewallProfile -Name Public -AllowInboundRules False -ErrorAction Stop
        Add-CEUndoCommand $undo "Restore Public AllowInboundRules=$($before.AllowInboundRules)" "Set-NetFirewallProfile -Name 'Public' -AllowInboundRules $(ConvertTo-CEPSLiteral ([string]$before.AllowInboundRules))"
    }

Register-CERemediation -Id 'FW-EnableLogging' -Title 'Log dropped connections (16 MB log)' -Risk 'Low' -RequiresAdmin `
    -Validate { param($p) Assert-CEParam $p 'Profiles' -AllowedValues $script:CEProfileNames } `
    -Apply {
        param($p, $undo)
        foreach ($name in @($p.Profiles)) {
            $before = Get-NetFirewallProfile -Name $name -PolicyStore PersistentStore
            Set-NetFirewallProfile -Name $name -LogBlocked True -LogMaxSizeKilobytes 16384 -ErrorAction Stop
            Add-CEUndoCommand $undo "Restore firewall logging for $name" "Set-NetFirewallProfile -Name $(ConvertTo-CEPSLiteral $name) -LogBlocked $(ConvertTo-CEPSLiteral ([string]$before.LogBlocked)) -LogMaxSizeKilobytes $([int]$before.LogMaxSizeKilobytes)"
        }
    }

Register-CERemediation -Id 'RDP-RequireNLA' -Title 'Require Network Level Authentication for Remote Desktop' -Risk 'Low' -RequiresAdmin `
    -Apply {
        param($p, $undo)
        Set-CERegistryValueTracked -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Undo $undo
    }

Register-CERemediation -Id 'RDP-Disable' -Title 'Turn off Remote Desktop' -Risk 'Medium' -RequiresAdmin -NotSelectedByDefault `
    -Notes 'Anyone who connects to this device with Remote Desktop will lose access.' `
    -Apply {
        param($p, $undo)
        Set-CERegistryValueTracked -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1 -Undo $undo
    }

function Get-CESafeLocalUser {
    param([hashtable]$p)
    if ($p.ContainsKey('SidSuffix')) {
        return Get-LocalUser | Where-Object { ([string]$_.SID) -match "-$([int]$p.SidSuffix)$" } | Select-Object -First 1
    }
    return Get-LocalUser -Name $p.Name -ErrorAction Stop
}

function Assert-CENotCurrentUser {
    param($User)
    $ctx = Get-CEDeviceContext
    foreach ($who in @($ctx.RunningAs, $ctx.ConsoleUser)) {
        if ($who -and (($who -split '\\')[-1] -eq $User.Name)) { throw "Refusing to disable '$($User.Name)': it is the account running this script or signed in." }
    }
}

function Assert-CEOtherAdminExists {
    param($User)
    $others = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | Where-Object {
        $_.PrincipalSource -ne 'Local' -or ((Get-LocalUser -SID $_.SID -ErrorAction SilentlyContinue).Enabled -and ([string]$_.SID -ne [string]$User.SID))
    })
    if ($others.Count -eq 0) { throw "Refusing to disable '$($User.Name)': no other enabled administrator account was found." }
}

Register-CERemediation -Id 'LocalUser-DisableBySidSuffix' -Title 'Disable a built-in account (Guest / Administrator)' -Risk 'Medium' -RequiresAdmin `
    -Notes 'Refuses to disable the built-in Administrator unless another enabled administrator exists.' `
    -Validate { param($p) Assert-CEParam $p 'SidSuffix' -Integer -AllowedValues @(500, 501) } `
    -Apply {
        param($p, $undo)
        $user = Get-CESafeLocalUser $p
        if (-not $user) { throw 'Account not found' }
        if ([int]$p.SidSuffix -eq 500) { Assert-CENotCurrentUser $user; Assert-CEOtherAdminExists $user }
        if (-not $user.Enabled) { return }
        Disable-LocalUser -SID $user.SID -ErrorAction Stop
        Add-CEUndoCommand $undo "Re-enable account $($user.Name)" "Enable-LocalUser -SID $(ConvertTo-CEPSLiteral ([string]$user.SID))"
    }

Register-CERemediation -Id 'LocalUser-DisableByName' -Title 'Disable an unused local account' -Risk 'High' -RequiresAdmin `
    -Notes 'Confirm the account is not used by a person, a scheduled task or a service before selecting this.' `
    -Validate { param($p) Assert-CEParam $p 'Name' -Pattern '^[^\\/\[\]:;|=,+*?<>"@]{1,20}$' } `
    -Apply {
        param($p, $undo)
        $user = Get-CESafeLocalUser $p
        Assert-CENotCurrentUser $user
        $isAdmin = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | Where-Object { [string]$_.SID -eq [string]$user.SID }).Count -gt 0
        if ($isAdmin) { Assert-CEOtherAdminExists $user }
        Disable-LocalUser -SID $user.SID -ErrorAction Stop
        Add-CEUndoCommand $undo "Re-enable account $($user.Name)" "Enable-LocalUser -SID $(ConvertTo-CEPSLiteral ([string]$user.SID))"
    }

Register-CERemediation -Id 'LocalUser-RequirePassword' -Title 'Require a password for a local account' -Risk 'Medium' -RequiresAdmin -NotSelectedByDefault `
    -Notes 'After applying, set a strong password for the account (the account will not be usable with a blank password).' `
    -Validate { param($p) Assert-CEParam $p 'Name' -Pattern '^[^\\/\[\]:;|=,+*?<>"@]{1,20}$' } `
    -Apply {
        param($p, $undo)
        $user = Get-CESafeLocalUser $p
        $r = Invoke-CENative -FilePath 'net.exe' -ArgumentList @('user', $user.Name, '/passwordreq:yes')
        if ($r.ExitCode -ne 0) { throw "net user failed: $($r.Output -join ' ')" }
        Add-CEUndoCommand $undo "Allow blank password for $($user.Name) again" "net.exe user $(ConvertTo-CEPSLiteral $user.Name) /passwordreq:no"
    }

Register-CERemediation -Id 'Autorun-Disable' -Title 'Disable AutoRun and AutoPlay for all drives' -Risk 'Low' -RequiresAdmin `
    -Apply {
        param($p, $undo)
        $e = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Set-CERegistryValueTracked -Path $e -Name 'NoDriveTypeAutoRun' -Value 255 -Undo $undo
        Set-CERegistryValueTracked -Path $e -Name 'NoAutorun' -Value 1 -Undo $undo
        Set-CERegistryValueTracked -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume' -Value 1 -Undo $undo
    }

Register-CERemediation -Id 'Lock-InactivityTimeout' -Title 'Lock the device after inactivity' -Risk 'Low' -RequiresAdmin -RequiresReboot `
    -Validate { param($p) Assert-CEParam $p 'Seconds' -Integer -Min 60 -Max 900 } `
    -Apply {
        param($p, $undo)
        Set-CERegistryValueTracked -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value ([int]$p.Seconds) -Undo $undo
    }

Register-CERemediation -Id 'AccountLockout-Set' -Title 'Lock accounts after repeated failed sign-ins' -Risk 'Low' -RequiresAdmin `
    -Notes 'Uses local security policy. On domain-joined devices the domain policy overrides this for domain accounts.' `
    -Validate {
        param($p)
        Assert-CEParam $p 'Threshold' -Integer -Min 1 -Max 10
        Assert-CEParam $p 'DurationMinutes' -Integer -Min 1 -Max 99999
        Assert-CEParam $p 'WindowMinutes' -Integer -Min 1 -Max 99999
    } `
    -Apply {
        param($p, $undo)
        $before = Get-CEAccountPolicy
        # Window must be <= duration; set threshold first, then window/duration.
        $args1 = @('accounts', "/lockoutthreshold:$([int]$p.Threshold)")
        $args2 = @('accounts', "/lockoutduration:$([int]$p.DurationMinutes)", "/lockoutwindow:$([int]$p.WindowMinutes)")
        foreach ($a in @(, $args1) + @(, $args2)) {
            $r = Invoke-CENative -FilePath 'net.exe' -ArgumentList $a
            if ($r.ExitCode -ne 0) { throw "net $($a -join ' ') failed: $($r.Output -join ' ')" }
        }
        $cmd = "net.exe accounts /lockoutthreshold:$($before.LockoutThreshold)"
        if ($before.LockoutThreshold -gt 0 -and $before.LockoutDurationMinutes -gt 0) {
            $cmd += "; net.exe accounts /lockoutduration:$($before.LockoutDurationMinutes) /lockoutwindow:$($before.LockoutWindowMinutes)"
        }
        Add-CEUndoCommand $undo 'Restore previous account lockout policy' $cmd
    }

Register-CERemediation -Id 'HelloPin-MinLength' -Title 'Set Windows Hello PIN minimum length' -Risk 'Low' -RequiresAdmin `
    -Notes 'Existing shorter PINs keep working until changed; ask users to change their PIN (Settings > Accounts > Sign-in options > PIN).' `
    -Validate { param($p) Assert-CEParam $p 'Length' -Integer -Min 6 -Max 127 } `
    -Apply {
        param($p, $undo)
        $k = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'
        Set-CERegistryValueTracked -Path $k -Name 'MinimumPINLength' -Value ([int]$p.Length) -Undo $undo
        $max = Get-CERegistryValue -Path $k -Name 'MaximumPINLength'
        if ($null -ne $max -and [int]$max -lt [int]$p.Length) {
            Set-CERegistryValueTracked -Path $k -Name 'MaximumPINLength' -Value 127 -Undo $undo
        }
    }

$script:CEAllowedFeatures = @('SMB1Protocol', 'MicrosoftWindowsPowerShellV2Root', 'TelnetClient', 'TFTP', 'SimpleTCP')
Register-CERemediation -Id 'OptionalFeature-Disable' -Title 'Disable a legacy Windows optional feature' -Risk 'Medium' -RequiresAdmin -RequiresReboot `
    -Notes 'Disabling SMBv1 breaks access to very old NAS devices and printers that only speak SMBv1.' `
    -Validate { param($p) Assert-CEParam $p 'FeatureName' -AllowedValues $script:CEAllowedFeatures } `
    -Apply {
        param($p, $undo)
        Disable-WindowsOptionalFeature -Online -FeatureName $p.FeatureName -NoRestart -ErrorAction Stop | Out-Null
        Add-CEUndoCommand $undo "Re-enable optional feature $($p.FeatureName)" "Enable-WindowsOptionalFeature -Online -FeatureName $(ConvertTo-CEPSLiteral $p.FeatureName) -NoRestart -All | Out-Null"
    }

Register-CERemediation -Id 'RemoteAssistance-Disable' -Title 'Disable Remote Assistance' -Risk 'Low' -RequiresAdmin `
    -Apply {
        param($p, $undo)
        Set-CERegistryValueTracked -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0 -Undo $undo
    }

Register-CERemediation -Id 'Service-Disable' -Title 'Disable an unnecessary service' -Risk 'Low' -RequiresAdmin `
    -Validate { param($p) Assert-CEParam $p 'Name' -AllowedValues @('RemoteRegistry') } `
    -Apply {
        param($p, $undo)
        $svc = Get-Service -Name $p.Name -ErrorAction Stop
        $before = [string]$svc.StartType
        if ($svc.Status -eq 'Running') { Stop-Service -Name $p.Name -Force -ErrorAction Stop }
        Set-Service -Name $p.Name -StartupType Disabled -ErrorAction Stop
        Add-CEUndoCommand $undo "Restore $($p.Name) start type $before" "Set-Service -Name $(ConvertTo-CEPSLiteral $p.Name) -StartupType $(ConvertTo-CEPSLiteral $before)"
    }
