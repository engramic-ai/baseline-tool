# ---------------------------------------------------------------------------
# Theme 1: Firewalls  (CE v3.3 "Firewalls")
# ---------------------------------------------------------------------------

function Get-CEThirdPartyFirewall {
    try {
        return @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'FirewallProduct' -ErrorAction Stop |
            Where-Object { $_.displayName -notmatch 'Windows Defender|Microsoft Defender' } |
            ForEach-Object {
                # productState bits 12-13: 0x1000 = enabled
                [pscustomobject]@{ Name = $_.displayName; Enabled = (([int]$_.productState -band 0x1000) -ne 0) }
            })
    }
    catch { return @() }
}

Register-CECheck -Id 'FW-01' -Category 'Firewalls' -Severity 'Critical' `
    -Title 'Software firewall enabled on every network profile' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 Firewalls: "protect every device in scope with a correctly configured firewall"; software firewalls on devices used on untrusted networks.' `
    -Test {
        param($ctx)
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        $off = @($profiles | Where-Object { "$($_.Enabled)" -ne 'True' } | ForEach-Object { $_.Name })
        $evidence = @($profiles | ForEach-Object { "$($_.Name): Enabled=$($_.Enabled)" })
        if ($off.Count -eq 0) {
            return New-CEResult -Status 'Pass' -Expected 'Enabled on Domain, Private and Public' -Actual 'Enabled on all profiles' -Evidence $evidence
        }
        $third = @(Get-CEThirdPartyFirewall | Where-Object { $_.Enabled })
        if ($third.Count -gt 0) {
            return New-CEResult -Status 'Manual' -Severity 'Medium' `
                -Expected 'A firewall active on every profile' `
                -Actual "Windows Firewall off for: $($off -join ', '). Third-party firewall reported active: $(($third | ForEach-Object Name) -join ', ')" `
                -Recommendation 'Confirm the third-party firewall blocks unsolicited inbound connections on all networks, then record this in your evidence pack.' `
                -Evidence $evidence
        }
        return New-CEResult -Status 'Fail' -Expected 'Enabled on Domain, Private and Public' `
            -Actual "Disabled for: $($off -join ', ')" `
            -Recommendation 'Turn Microsoft Defender Firewall on for every profile.' `
            -Evidence $evidence `
            -Remediation (New-CERemediationRef -Id 'FW-EnableProfiles' -Parameters @{ Profiles = $off })
    }

Register-CECheck -Id 'FW-02' -Category 'Firewalls' -Severity 'High' `
    -Title 'Unauthenticated inbound connections blocked by default' `
    -Frameworks @('CE v3.3', 'CE+ TC1') `
    -Reference 'CE v3.3 Firewalls: "block unauthenticated inbound connections by default".' `
    -Test {
        param($ctx)
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        $allow = @($profiles | Where-Object { "$($_.DefaultInboundAction)" -eq 'Allow' } | ForEach-Object { $_.Name })
        $evidence = @($profiles | ForEach-Object { "$($_.Name): DefaultInboundAction=$($_.DefaultInboundAction)" })
        if ($allow.Count -eq 0) {
            return New-CEResult -Status 'Pass' -Expected 'DefaultInboundAction = Block' -Actual 'Block (or default) on all profiles' -Evidence $evidence
        }
        return New-CEResult -Status 'Fail' -Expected 'DefaultInboundAction = Block' -Actual "Allow on: $($allow -join ', ')" `
            -Recommendation 'Set the default inbound action to Block on every profile.' -Evidence $evidence `
            -Remediation (New-CERemediationRef -Id 'FW-BlockInboundDefault' -Parameters @{ Profiles = $allow })
    }

Register-CECheck -Id 'FW-03' -Category 'Firewalls' -Severity 'Medium' `
    -Title 'Inbound allow rules are approved, documented and still needed' `
    -Frameworks @('CE v3.3') `
    -Reference 'CE v3.3 Firewalls: "inbound firewall rules are approved and documented by an authorised person"; "remove or disable unnecessary firewall rules".' `
    -Test {
        param($ctx)
        $rules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { -not $_.DisplayGroup })
        if ($rules.Count -eq 0) {
            return New-CEResult -Status 'Pass' -Expected 'No undocumented custom inbound allow rules' -Actual 'No custom (non-Windows) inbound allow rules enabled'
        }
        $results = @()
        $risky = @()
        $evidence = @()
        foreach ($r in $rules) {
            $addr = ($r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue)
            $remote = if ($addr) { (@($addr.RemoteAddress) -join ',') } else { 'Any' }
            $ruleProfile = "$($r.Profile)"
            $line = "$($r.DisplayName) [profile=$ruleProfile; remote=$remote]"
            $evidence += $line
            if (($ruleProfile -match 'Any|Public') -and ($remote -eq 'Any')) { $risky += $r }
        }
        $results += New-CEResult -Status 'Manual' -Expected 'Every custom inbound allow rule has a documented business need' `
            -Actual "$($rules.Count) custom inbound allow rule(s) enabled" `
            -Recommendation 'Review each rule. Record the business justification and approver for the ones you keep; disable the rest.' `
            -Evidence $evidence
        foreach ($r in ($risky | Select-Object -First 25)) {
            $results += New-CEResult -Status 'Warn' -Subject $r.DisplayName `
                -Expected 'No inbound allow rules open to any address on public networks' `
                -Actual "Rule '$($r.DisplayName)' allows inbound from any address on Public networks" `
                -Recommendation 'Disable the rule, or restrict it to the Private/Domain profile and specific remote addresses.' `
                -Remediation (New-CERemediationRef -Id 'FW-DisableRule' -Parameters @{ RuleName = [string]$r.Name; DisplayName = [string]$r.DisplayName })
        }
        return $results
    }

Register-CECheck -Id 'FW-04' -Category 'Firewalls' -Severity 'High' `
    -Title 'Remote Desktop is disabled or protected' `
    -Frameworks @('CE v3.3', 'CE+ TC1', 'NCSC') `
    -Reference 'CE v3.3 Firewalls/User access control: remote administrative access must be protected by MFA or an IP allow list; disable unnecessary services.' `
    -Test {
        param($ctx)
        $deny = Get-CERegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Default 1
        if ([int]$deny -eq 1) {
            return New-CEResult -Status 'Pass' -Expected 'RDP disabled, or enabled with NLA and restricted access' -Actual 'Remote Desktop is disabled'
        }
        $nla = Get-CERegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Default 0
        $results = @()
        if ([int]$nla -ne 1) {
            $results += New-CEResult -Status 'Fail' -Subject 'NLA' -Expected 'Network Level Authentication required' -Actual 'RDP enabled without NLA' `
                -Recommendation 'Require Network Level Authentication for Remote Desktop.' `
                -Remediation (New-CERemediationRef -Id 'RDP-RequireNLA')
        }
        $results += New-CEResult -Status 'Warn' -Subject 'Enabled' -Expected 'RDP disabled unless there is a documented need' `
            -Actual 'Remote Desktop is enabled' `
            -Recommendation 'Disable RDP if not needed. If needed, never expose it to the internet; reach it via a VPN or gateway enforcing MFA, and restrict the firewall rule to trusted addresses.' `
            -Remediation (New-CERemediationRef -Id 'RDP-Disable')
        return $results
    }

Register-CECheck -Id 'FW-05' -Category 'Firewalls' -Severity 'Medium' `
    -Title 'Public network profile blocks all inbound connections' `
    -Frameworks @('NCSC') `
    -Reference 'NCSC Windows device guidance: configure Windows Defender Firewall to block inbound traffic on untrusted networks.' `
    -Test {
        param($ctx)
        $public = Get-NetFirewallProfile -Name Public -PolicyStore ActiveStore -ErrorAction Stop
        if ("$($public.AllowInboundRules)" -eq 'False') {
            return New-CEResult -Status 'Pass' -Expected 'Public: AllowInboundRules = False' -Actual 'Public profile ignores inbound allow rules'
        }
        return New-CEResult -Status 'Warn' -Expected 'Public: AllowInboundRules = False' -Actual "Public: AllowInboundRules = $($public.AllowInboundRules)" `
            -Recommendation 'On public Wi-Fi, block all inbound connections including those normally allowed.' `
            -Remediation (New-CERemediationRef -Id 'FW-PublicBlockAll')
    }

Register-CECheck -Id 'FW-06' -Category 'Firewalls' -Severity 'Low' `
    -Title 'Firewall logs dropped connections' `
    -Frameworks @('NCSC') `
    -Reference 'NCSC Windows device guidance: implement logging and protective monitoring.' `
    -Test {
        param($ctx)
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        $bad = @($profiles | Where-Object { "$($_.LogBlocked)" -ne 'True' -or [int]$_.LogMaxSizeKilobytes -lt 16384 } | ForEach-Object { $_.Name })
        $evidence = @($profiles | ForEach-Object { "$($_.Name): LogBlocked=$($_.LogBlocked) LogMaxSizeKB=$($_.LogMaxSizeKilobytes)" })
        if ($bad.Count -eq 0) {
            return New-CEResult -Status 'Pass' -Expected 'LogBlocked = True, log >= 16 MB' -Actual 'Configured on all profiles' -Evidence $evidence
        }
        return New-CEResult -Status 'Warn' -Expected 'LogBlocked = True, log >= 16 MB' -Actual "Not configured on: $($bad -join ', ')" -Evidence $evidence `
            -Recommendation 'Log dropped packets with a 16 MB log so incidents can be investigated.' `
            -Remediation (New-CERemediationRef -Id 'FW-EnableLogging' -Parameters @{ Profiles = $bad })
    }

Register-CECheck -Id 'FW-07' -Category 'Firewalls' -Severity 'Medium' `
    -Title 'Virtual machines and containers do not expose services to the network' `
    -Frameworks @('CE v3.3', 'CE+ TC1') `
    -Reference 'CE v3.3 Firewalls: block unauthenticated inbound connections and only allow services that have a business need. Bridged networking and published ports can put services on the network outside the device firewall rules you have reviewed.' `
    -Test {
        param($ctx)
        $st = Get-CEVirtualisationState -Context $ctx
        $any = @($st.HyperV.Machines).Count + @($st.VMware).Count + @($st.VirtualBox).Count + @($st.Wsl).Count + @($st.Containers).Count + @($st.Listeners).Count
        if ($any -eq 0 -and -not $st.WslNetworking) {
            return New-CEResult -Status 'NotApplicable' -Actual 'No virtual machines, WSL distributions or containers found'
        }

        $bridged = @()
        $bridged += @($st.HyperV.Machines | Where-Object { @($_.ExternalSwitches).Count } | ForEach-Object { "Hyper-V '$($_.Name)' on external switch $(@($_.ExternalSwitches) -join ', ')" })
        $bridged += @($st.VMware | Where-Object { @($_.Networks) -contains 'bridged' } | ForEach-Object { "VMware '$($_.Name)' uses bridged networking" })
        $bridged += @($st.VirtualBox | Where-Object { $_.Bridged -gt 0 } | ForEach-Object { "VirtualBox '$($_.Name)' uses bridged networking" })
        if (@('bridged', 'mirrored') -contains $st.WslNetworking -and @($st.Wsl).Count) { $bridged += "WSL uses $($st.WslNetworking) networking (.wslconfig)" }

        $published = @()
        $published += @($st.Listeners | Where-Object { $_.Exposed } | ForEach-Object { "$($_.Product) ($($_.Process)) listening on $($_.Address):$($_.Port)" })
        $published += @($st.VirtualBox | ForEach-Object { $vm = $_; @($vm.PortForwards | Where-Object { $_.Exposed } | ForEach-Object { "VirtualBox '$($vm.Name)' forwards $($_.Protocol) port $($_.HostPort) on all interfaces" }) })
        $published += @($st.HyperV.NatMappings | Where-Object { $_ -match ' (0\.0\.0\.0|::):' } | ForEach-Object { "Hyper-V NAT mapping $_" })
        $published += @($st.Containers | Where-Object { $_.Ports -match '(0\.0\.0\.0|\[::\]|:::):\d+' } | ForEach-Object { "Container '$($_.Name)' publishes $($_.Ports)" })

        $evidence = @($st.Listeners | ForEach-Object { "Listener: $($_.Product) ($($_.Process)) $($_.Address):$($_.Port)" }) + @($st.Notes)
        if ($st.WslNetworking) { $evidence += "WSL networkingMode=$($st.WslNetworking)" }

        if ($bridged.Count -eq 0 -and $published.Count -eq 0) {
            $unchecked = if (@($st.Notes).Count) { " (not checked: $(@($st.Notes) -join '; '))" } else { '' }
            return New-CEResult -Status 'Pass' -Expected 'No bridged networking or ports published to the network' -Actual "Virtual machines and containers are not exposed to the network$unchecked" -Evidence $evidence
        }
        if ($bridged.Count) {
            New-CEResult -Status 'Warn' -Subject 'Bridged networking' -Expected 'Virtual machines use NAT or host-only networking unless they must be reachable' `
                -Actual ($bridged -join '; ') -Evidence $evidence `
                -Recommendation 'A bridged (or mirrored WSL) virtual machine is its own device on your network, outside this device''s firewall rules. Switch it to NAT or host-only networking, or make sure its own firewall blocks inbound connections and it is patched like any other device.'
        }
        if ($published.Count) {
            New-CEResult -Status 'Warn' -Subject 'Published ports' -Expected 'Ports for virtual machines and containers are only published to this device (127.0.0.1)' `
                -Actual ($published -join '; ') -Evidence $evidence `
                -Recommendation 'Publish ports to 127.0.0.1 unless other devices need them (for example "docker run -p 127.0.0.1:8080:80", or host IP 127.0.0.1 in VirtualBox port forwarding). If a port must be reachable, document why and restrict it with a firewall rule (FW-03).'
        }
    }
