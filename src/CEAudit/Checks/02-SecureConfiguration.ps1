# ---------------------------------------------------------------------------
# Theme 2: Secure configuration  (CE v3.3 "Secure configuration")
# ---------------------------------------------------------------------------

function Get-CELocalUsers {
    return @(Get-LocalUser -ErrorAction Stop)
}

function Get-CESidSuffix {
    param($User)
    return [int](([string]$User.SID) -split '-')[-1]
}

Register-CECheck -Id 'SC-01' -Category 'SecureConfiguration' -Severity 'High' `
    -Title 'Guest account disabled' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 Secure configuration: "remove and disable unnecessary user accounts (such as guest accounts ...)".' `
    -Test {
        param($ctx)
        $guest = Get-CELocalUsers | Where-Object { (Get-CESidSuffix $_) -eq 501 }
        if (-not $guest) { return New-CEResult -Status 'Pass' -Expected 'Guest disabled' -Actual 'No guest account present' }
        if (-not $guest.Enabled) { return New-CEResult -Status 'Pass' -Expected 'Guest disabled' -Actual "Guest account '$($guest.Name)' is disabled" }
        return New-CEResult -Status 'Fail' -Expected 'Guest disabled' -Actual "Guest account '$($guest.Name)' is enabled" `
            -Recommendation 'Disable the built-in Guest account.' `
            -Remediation (New-CERemediationRef -Id 'LocalUser-DisableBySidSuffix' -Parameters @{ SidSuffix = 501 })
    }

Register-CECheck -Id 'SC-02' -Category 'SecureConfiguration' -Severity 'High' `
    -Title 'Built-in Administrator account disabled or LAPS-managed' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 Secure configuration: disable unnecessary administrative accounts; change default or guessable passwords.' `
    -Test {
        param($ctx)
        $admin = Get-CELocalUsers | Where-Object { (Get-CESidSuffix $_) -eq 500 }
        if (-not $admin -or -not $admin.Enabled) {
            return New-CEResult -Status 'Pass' -Expected 'Built-in Administrator disabled' -Actual 'Built-in Administrator is disabled'
        }
        $laps = Get-CERegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'BackupDirectory' -Default 0
        if ([int]$laps -gt 0) {
            return New-CEResult -Status 'Pass' -Expected 'Built-in Administrator disabled or password managed by LAPS' -Actual "Enabled, password managed by Windows LAPS (BackupDirectory=$laps)"
        }
        return New-CEResult -Status 'Fail' -Expected 'Built-in Administrator disabled or password managed by LAPS' `
            -Actual "Built-in Administrator '$($admin.Name)' is enabled with an unmanaged password" `
            -Recommendation 'Disable the built-in Administrator account (use a named, separate admin account instead), or manage its password with Windows LAPS.' `
            -Remediation (New-CERemediationRef -Id 'LocalUser-DisableBySidSuffix' -Parameters @{ SidSuffix = 500 })
    }

Register-CECheck -Id 'SC-03' -Category 'SecureConfiguration' -Severity 'Medium' `
    -Title 'No stale or unused local accounts' `
    -Frameworks @('CE v3.3') `
    -Reference 'CE v3.3 Secure configuration / User access control: "remove or disable user accounts when they are no longer required".' `
    -Test {
        param($ctx)
        $cfg = (Get-CEConfig).thresholds
        $cutoff = (Get-Date).AddDays(-[int]$cfg.staleLocalAccountDays)
        $builtIn = @(500, 501, 503, 504)
        $stale = @(Get-CELocalUsers | Where-Object {
            $_.Enabled -and ($builtIn -notcontains (Get-CESidSuffix $_)) -and ((-not $_.LastLogon) -or ($_.LastLogon -lt $cutoff))
        })
        if ($stale.Count -eq 0) {
            return New-CEResult -Status 'Pass' -Expected "No enabled local accounts unused for $($cfg.staleLocalAccountDays)+ days" -Actual 'None found'
        }
        foreach ($u in $stale) {
            $last = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd') } else { 'never' }
            New-CEResult -Status 'Warn' -Subject $u.Name `
                -Expected "Accounts unused for $($cfg.staleLocalAccountDays)+ days are disabled" `
                -Actual "Local account '$($u.Name)' is enabled; last logon: $last" `
                -Recommendation 'Confirm whether the account is still required. Disable it if not. (Accounts used only for services may legitimately show no interactive logon.)' `
                -Remediation (New-CERemediationRef -Id 'LocalUser-DisableByName' -Parameters @{ Name = [string]$u.Name })
        }
    }

Register-CECheck -Id 'SC-04' -Category 'SecureConfiguration' -Severity 'Critical' `
    -Title 'Every enabled local account requires a password' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 User access control: "authenticate users with unique credentials before granting access"; change default or guessable passwords.' `
    -Test {
        param($ctx)
        $bad = @(Get-CELocalUsers | Where-Object { $_.Enabled -and -not $_.PasswordRequired })
        if ($bad.Count -eq 0) {
            return New-CEResult -Status 'Pass' -Expected 'PasswordRequired = True for enabled accounts' -Actual 'All enabled local accounts require a password'
        }
        foreach ($u in $bad) {
            New-CEResult -Status 'Fail' -Subject $u.Name -Expected 'PasswordRequired = True' `
                -Actual "Local account '$($u.Name)' can have a blank password" `
                -Recommendation 'Require a password for this account and set a strong one (12+ characters, or three random words).' `
                -Remediation (New-CERemediationRef -Id 'LocalUser-RequirePassword' -Parameters @{ Name = [string]$u.Name })
        }
    }

Register-CECheck -Id 'SC-05' -Category 'SecureConfiguration' -Severity 'High' `
    -Title 'AutoRun and AutoPlay disabled' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 Secure configuration: "disable any auto-run feature which allows file execution without user authorisation".' `
    -Test {
        param($ctx)
        $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        $noDrive  = Get-CERegistryValue -Path $p -Name 'NoDriveTypeAutoRun'
        $noAuto   = Get-CERegistryValue -Path $p -Name 'NoAutorun'
        $nonVol   = Get-CERegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume'
        $evidence = @("NoDriveTypeAutoRun=$noDrive", "NoAutorun=$noAuto", "NoAutoplayfornonVolume=$nonVol")
        if ($noDrive -eq 255 -and $noAuto -eq 1 -and $nonVol -eq 1) {
            return New-CEResult -Status 'Pass' -Expected 'AutoRun disabled for all drives' -Actual 'Disabled by machine policy' -Evidence $evidence
        }
        return New-CEResult -Status 'Fail' -Expected 'NoDriveTypeAutoRun=255, NoAutorun=1, NoAutoplayfornonVolume=1 (machine-wide)' `
            -Actual 'AutoRun/AutoPlay not disabled by machine policy' -Evidence $evidence `
            -Recommendation 'Disable AutoRun and AutoPlay for all drive types machine-wide.' `
            -Remediation (New-CERemediationRef -Id 'Autorun-Disable')
    }

Register-CECheck -Id 'SC-06' -Category 'SecureConfiguration' -Severity 'Medium' `
    -Title 'Device locks automatically when inactive' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 Secure configuration: "ensure appropriate device locking controls".' `
    -Test {
        param($ctx)
        $max = [int](Get-CEConfig).thresholds.maxInactivityLockSeconds
        $machine = Get-CERegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs'
        if ($machine -and [int]$machine -gt 0 -and [int]$machine -le $max) {
            return New-CEResult -Status 'Pass' -Expected "Lock after <= $max seconds" -Actual "Machine inactivity limit: $machine seconds"
        }
        # Fall back to the signed-in user's screen saver (their hive when running as SYSTEM).
        $ssActive = $null; $ssSecure = $null; $ssTimeout = $null
        $userRoot = Get-CEUserRegistryRoot
        if ($userRoot) {
            $d = "$userRoot\Control Panel\Desktop"
            $ssActive = Get-CERegistryValue -Path $d -Name 'ScreenSaveActive'
            $ssSecure = Get-CERegistryValue -Path $d -Name 'ScreenSaverIsSecure'
            $ssTimeout = Get-CERegistryValue -Path $d -Name 'ScreenSaveTimeOut'
        }
        $evidence = @("InactivityTimeoutSecs=$machine", "ScreenSaveActive=$ssActive", "ScreenSaverIsSecure=$ssSecure", "ScreenSaveTimeOut=$ssTimeout")
        if ("$ssActive" -eq '1' -and "$ssSecure" -eq '1' -and $ssTimeout -and [int]$ssTimeout -le $max) {
            return New-CEResult -Status 'Pass' -Expected "Lock after <= $max seconds" -Actual "Signed-in user's secure screen saver locks after $ssTimeout seconds" -Evidence $evidence `
                -Recommendation 'Consider enforcing this machine-wide so it applies to every user.'
        }
        return New-CEResult -Status 'Fail' -Expected "Lock after <= $max seconds of inactivity" -Actual 'No machine inactivity limit and no secure screen saver within the limit' -Evidence $evidence `
            -Recommendation "Enforce a machine inactivity limit of $max seconds (15 minutes) or less." `
            -Remediation (New-CERemediationRef -Id 'Lock-InactivityTimeout' -Parameters @{ Seconds = $max })
    }

Register-CECheck -Id 'SC-07' -Category 'SecureConfiguration' -Severity 'High' `
    -Title 'Brute-force protection: account lockout after no more than 10 attempts' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 Device unlocking / Password-based authentication: lock after no more than 10 unsuccessful attempts, or throttle to no more than 10 guesses in 5 minutes.' `
    -Test {
        param($ctx)
        $max = [int](Get-CEConfig).thresholds.maxLockoutThreshold
        $pol = Get-CEAccountPolicy
        $evidence = @("LockoutThreshold=$($pol.LockoutThreshold)", "LockoutDurationMinutes=$($pol.LockoutDurationMinutes)", "LockoutWindowMinutes=$($pol.LockoutWindowMinutes)")
        $note = ''
        if ($ctx.DomainJoined) { $note = ' Domain accounts follow the domain password policy; check it in Group Policy too.' }
        if ($pol.LockoutThreshold -ge 1 -and $pol.LockoutThreshold -le $max) {
            return New-CEResult -Status 'Pass' -Expected "Lockout threshold 1-$max" -Actual "Locks after $($pol.LockoutThreshold) failed attempts" -Evidence $evidence -Recommendation $note.Trim()
        }
        $actual = if ($pol.LockoutThreshold -eq 0) { 'Accounts never lock out' } else { "Locks after $($pol.LockoutThreshold) attempts" }
        return New-CEResult -Status 'Fail' -Expected "Lockout threshold 1-$max" -Actual $actual -Evidence $evidence `
            -Recommendation ("Set the account lockout threshold to $max with a 10 minute lockout." + $note) `
            -Remediation (New-CERemediationRef -Id 'AccountLockout-Set' -Parameters @{ Threshold = $max; DurationMinutes = 10; WindowMinutes = 10 })
    }

Register-CECheck -Id 'SC-08' -Category 'SecureConfiguration' -Severity 'High' `
    -Title 'Device unlock PIN is at least 6 characters' `
    -Frameworks @('CE v3.3') `
    -Reference 'CE v3.3 Device unlocking credentials: "minimum password or PIN length of at least 6 characters" where the credential only unlocks the device.' `
    -Test {
        param($ctx)
        $min = [int](Get-CEConfig).thresholds.minDeviceUnlockPinLength
        $value = Get-CERegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity' -Name 'MinimumPINLength'
        if ($null -ne $value -and [int]$value -ge $min) {
            return New-CEResult -Status 'Pass' -Expected "Windows Hello PIN minimum length >= $min" -Actual "Minimum PIN length policy: $value"
        }
        $actual = if ($null -eq $value) { 'Not configured (Windows default allows a 4-digit PIN)' } else { "Minimum PIN length policy: $value" }
        return New-CEResult -Status 'Fail' -Expected "Windows Hello PIN minimum length >= $min" -Actual $actual `
            -Recommendation "Set the Windows Hello PIN minimum length to $min, then have users change any shorter PIN (Settings > Accounts > Sign-in options)." `
            -Remediation (New-CERemediationRef -Id 'HelloPin-MinLength' -Parameters @{ Length = $min })
    }

Register-CECheck -Id 'SC-09' -Category 'SecureConfiguration' -Severity 'Medium' `
    -Title 'Installed software reviewed; unnecessary software removed' `
    -Frameworks @('CE v3.3') `
    -Reference 'CE v3.3 Secure configuration: "remove or disable unnecessary software (including applications, system utilities and network services)".' `
    -Test {
        param($ctx)
        $software = @(Get-CEInstalledSoftware)
        $remotePatterns = @('AnyDesk*', 'TeamViewer*', 'RustDesk*', 'UltraViewer*', 'LogMeIn*', 'ScreenConnect*', 'ConnectWise Control*', 'Splashtop*', 'Chrome Remote Desktop*', '*VNC*', 'Supremo*', 'Remote Utilities*')
        $results = @()
        $results += New-CEResult -Status 'Manual' -Expected 'Only software with a business need is installed' `
            -Actual "$($software.Count) programs installed (full list in evidence)" `
            -Recommendation 'Review the list and uninstall anything not needed. Keep the reviewed list as evidence.' `
            -Evidence @($software | ForEach-Object { "$($_.Name) $($_.Version)" })
        foreach ($s in $software) {
            foreach ($pat in $remotePatterns) {
                if ($s.Name -like $pat) {
                    $results += New-CEResult -Status 'Warn' -Subject $s.Name `
                        -Expected 'Remote access tools only where approved and protected with MFA' `
                        -Actual "Remote access software installed: $($s.Name) $($s.Version)" `
                        -Recommendation 'Remove it if not needed. If needed, enforce MFA on the vendor account and restrict unattended access.'
                    break
                }
            }
        }
        # AI agents can run commands and change files on behalf of a cloud account, much like a remote access tool.
        foreach ($tool in @((Get-CEAIToolState -Context $ctx).Tools | Where-Object { $_.CanActOnDevice })) {
            $results += New-CEResult -Status 'Warn' -Subject $tool.Name `
                -Expected 'AI agents that can run commands or change files only where approved, with MFA on their account' `
                -Actual "AI agent that can act on this device: $($tool.Name)" -Evidence @($tool.Signals) `
                -Recommendation "Remove it if it isn't needed. If it is: record who approved it, make sure its account uses MFA (UA-07), don't run it with administrator rights (UA-10), and keep it asking before it runs commands or changes files. $($tool.Notes)".Trim()
        }
        return $results
    }

Register-CECheck -Id 'SC-10' -Category 'SecureConfiguration' -Severity 'Medium' -RequiresAdmin `
    -Title 'Legacy Windows features disabled (SMBv1, PowerShell 2.0, Telnet, TFTP)' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 Secure configuration: remove unnecessary network services. NCSC: disable legacy protocols.' `
    -Test {
        param($ctx)
        $features = @(
            @{ Name = 'SMB1Protocol'; Label = 'SMBv1'; Severity = 'High' },
            @{ Name = 'MicrosoftWindowsPowerShellV2Root'; Label = 'PowerShell 2.0 engine'; Severity = 'Medium' },
            @{ Name = 'TelnetClient'; Label = 'Telnet client'; Severity = 'Low' },
            @{ Name = 'TFTP'; Label = 'TFTP client'; Severity = 'Low' },
            @{ Name = 'SimpleTCP'; Label = 'Simple TCP/IP services'; Severity = 'Medium' }
        )
        foreach ($f in $features) {
            $state = Get-WindowsOptionalFeature -Online -FeatureName $f.Name -ErrorAction SilentlyContinue
            if (-not $state -or "$($state.State)" -notmatch '^Enabled') {
                $st = if ($state) { "$($state.State)" } else { 'not present' }
                New-CEResult -Status 'Pass' -Subject $f.Label -Expected 'Disabled' -Actual "$($f.Label): $st"
                continue
            }
            New-CEResult -Status 'Fail' -Subject $f.Label -Severity $f.Severity -Expected 'Disabled' -Actual "$($f.Label) is enabled" `
                -Recommendation "Disable the $($f.Label) optional feature." `
                -Remediation (New-CERemediationRef -Id 'OptionalFeature-Disable' -Parameters @{ FeatureName = $f.Name })
        }
    }

Register-CECheck -Id 'SC-11' -Category 'SecureConfiguration' -Severity 'Low' `
    -Title 'Remote Assistance and Remote Registry disabled' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 Secure configuration: remove or disable unnecessary network services.' `
    -Test {
        param($ctx)
        $ra = Get-CERegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Default 0
        if ([int]$ra -eq 1) {
            New-CEResult -Status 'Warn' -Subject 'Remote Assistance' -Expected 'Disabled' -Actual 'Remote Assistance invitations allowed' `
                -Recommendation 'Disable Remote Assistance unless your support process depends on it.' `
                -Remediation (New-CERemediationRef -Id 'RemoteAssistance-Disable')
        }
        else {
            New-CEResult -Status 'Pass' -Subject 'Remote Assistance' -Expected 'Disabled' -Actual 'Remote Assistance disabled'
        }
        $svc = Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue
        if ($svc -and "$($svc.StartType)" -ne 'Disabled') {
            New-CEResult -Status 'Warn' -Subject 'Remote Registry' -Expected 'Service disabled' -Actual "RemoteRegistry start type: $($svc.StartType)" `
                -Recommendation 'Disable the Remote Registry service.' `
                -Remediation (New-CERemediationRef -Id 'Service-Disable' -Parameters @{ Name = 'RemoteRegistry' })
        }
        else {
            New-CEResult -Status 'Pass' -Subject 'Remote Registry' -Expected 'Service disabled' -Actual 'RemoteRegistry disabled or absent'
        }
    }

Register-CECheck -Id 'SC-12' -Category 'SecureConfiguration' -Severity 'Medium' -Scope 'User' `
    -Title 'Virtual machines, WSL distributions and containers are treated as in-scope devices' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 scope: virtual devices, such as virtual machines and virtual desktops, that can access organisational data or services are in scope and need the same controls as physical devices.' `
    -Test {
        param($ctx)
        $st = Get-CEVirtualisationState -Context $ctx
        $items = @()
        $items += @($st.HyperV.Machines | ForEach-Object { "Hyper-V virtual machine '$($_.Name)' ($($_.State))" })
        $items += @($st.VMware | ForEach-Object { "VMware virtual machine '$($_.Name)'" })
        $items += @($st.VirtualBox | ForEach-Object { "VirtualBox virtual machine '$($_.Name)'" })
        $userDistros = @($st.Wsl | Where-Object { -not $_.Tooling })
        $items += @($userDistros | ForEach-Object { "WSL $($_.Version) distribution '$($_.Name)'$(if ($_.Running -eq $true) { ' (running)' } elseif ($_.Running -eq $false) { ' (stopped)' })" })
        $tooling = @($st.Wsl | Where-Object { $_.Tooling })
        if ($tooling.Count) { $items += "Container platform ($(@($tooling | ForEach-Object { $_.Name }) -join ', '))" }
        $items += @($st.Containers | ForEach-Object { "Container '$($_.Name)' ($($_.Image))" })
        $evidence = @($items) + @($st.Notes)
        $expected = 'Each virtual machine, WSL distribution and container used for work meets the Cyber Essentials requirements, or is removed'

        if ($items.Count -eq 0) {
            if (@($st.Notes).Count) {
                New-CEResult -Status 'Info' -Expected $expected -Actual "None found, but not everything could be checked: $(@($st.Notes) -join '; ')" -Evidence $evidence `
                    -Recommendation 'Run the audit again from an elevated prompt while signed in to check everything.'
            }
            else {
                New-CEResult -Status 'Pass' -Expected $expected -Actual 'No virtual machines, WSL distributions or containers found' -Evidence $evidence
            }
            return
        }
        New-CEResult -Status 'Manual' -Expected $expected -Actual "$($items.Count) found: $($items -join '; ')" -Evidence $evidence `
            -Recommendation 'For each one used for work, confirm it runs a supported operating system and applications, gets security updates within 14 days, has malware protection and a firewall where it applies, and uses its own non-admin account for everyday work. Delete the ones nobody needs.'

        $shared = @()
        $shared += @($st.VMware | Where-Object { @($_.SharedFolders).Count } | ForEach-Object { "VMware '$($_.Name)': $(@($_.SharedFolders) -join ', ')" })
        $shared += @($st.VirtualBox | Where-Object { @($_.SharedFolders).Count } | ForEach-Object { "VirtualBox '$($_.Name)': $(@($_.SharedFolders) -join ', ')" })
        if ($shared.Count) {
            New-CEResult -Status 'Warn' -Severity 'Medium' -Subject 'Shared folders' -Expected 'Virtual machines cannot read or change the host''s files' `
                -Actual "Host folders shared with virtual machines: $($shared -join '; ')" -Evidence $evidence `
                -Recommendation 'Turn off shared folders you do not need. Malware inside the virtual machine can read, encrypt or plant files in a shared folder. Share a single dedicated folder read-only rather than your profile or a whole drive.'
        }

        $mounting = @($userDistros | Where-Object { $_.Automount -ne $false })
        if ($mounting.Count) {
            $lines = @($mounting | ForEach-Object { "$($_.Name) ($(if ($_.Automount -eq $true) { $_.AutomountSource } else { "on by default, $($_.AutomountSource)" }))" })
            New-CEResult -Status 'Warn' -Severity 'Medium' -Subject 'WSL drive mounting' -Expected 'WSL distributions do not mount the Windows drives' `
                -Actual "Windows drives (C: at /mnt/c) are mounted in: $($lines -join '; ')" -Evidence $evidence `
                -Recommendation 'Anything running inside WSL can read and change your Windows files through /mnt/c. If you do not need that, add "[automount]" and "enabled = false" to /etc/wsl.conf in the distribution, then run "wsl --shutdown". If you do need it, record why.'
        }
    }

Register-CECheck -Id 'SC-13' -Category 'SecureConfiguration' -Severity 'High' -Scope 'User' `
    -Title 'AI agent credentials are not stored in plaintext configuration' `
    -Frameworks @('NCSC') `
    -Reference 'NCSC device security guidance (secure configuration): secrets such as API tokens should not be held in plaintext in user-writable configuration. A credential stored in clear text in an AI agent config is a secure-configuration weakness, more so when the file can be modified by other users.' `
    -Test {
        param($ctx)
        $mcp = Get-CEMcpInventory -Context $ctx
        $servers = @($mcp.mcpServers)
        if (-not $servers.Count) {
            return New-CEResult -Status 'NotApplicable' -Actual 'No MCP server configuration found for the recognised AI tools'
        }
        $expected = 'AI agent credentials referenced via an environment variable or credential manager, not stored in plaintext config'
        if (@($servers | Where-Object { $_.transport -eq 'not-read' }).Count -eq $servers.Count) {
            return New-CEResult -Status 'Manual' -Expected $expected `
                -Actual 'MCP configuration is present, but shadow AI is collected per user; run as the signed-in user to check for plaintext credentials'
        }
        $plain = @()
        $plainAcl = @()
        foreach ($s in $servers) {
            $acl = [string]$s.configAclIssue
            foreach ($c in @($s.credentials)) {
                if ($c.storage -ne 'plaintext-config') { continue }
                $where = "$($s.serverName) in $($s.configPath): $($c.provider) $($c.type)"
                if ($acl) { $plainAcl += "$where (config $acl)" } else { $plain += $where }
            }
        }
        if ($plainAcl.Count) {
            return New-CEResult -Status 'Fail' -Expected $expected `
                -Actual "Plaintext credential(s) in a config other users can modify: $($plainAcl -join '; ')" `
                -Recommendation 'Move the value into a user environment variable and reference it (e.g. "${env:NAME}"), and restrict the config file so only its owner can write to it.' `
                -Evidence $plainAcl
        }
        if ($plain.Count) {
            return New-CEResult -Status 'Warn' -Expected $expected `
                -Actual "Credential(s) held in plaintext config: $($plain -join '; ')" `
                -Recommendation 'Move the value to a user environment variable and reference it as "${env:NAME}" so the secret is not stored in the config file.' `
                -Evidence $plain
        }
        return New-CEResult -Status 'Pass' -Expected $expected `
            -Actual "$($servers.Count) MCP server(s) configured; no plaintext credentials found"
    }
