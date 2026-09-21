# ---------------------------------------------------------------------------
# Theme 4: User access control  (CE v3.3 "User access control")
# CE+ TC4 (MFA on cloud services) and TC5 (account separation).
# ---------------------------------------------------------------------------

function Get-CETokenGroupSids {
    <# SIDs in the current token, including deny-only groups (UAC filtered admin). #>
    $native = Invoke-CENative -FilePath 'whoami.exe' -ArgumentList @('/groups', '/fo', 'csv', '/nh')
    $rows = @($native.Output | Where-Object { $_ -match ',' }) | ConvertFrom-Csv -Header 'Name', 'Type', 'SID', 'Attributes'
    return @($rows | ForEach-Object { [string]$_.SID })
}

function Get-CELocalAdminMembers {
    <# Members of the local Administrators group. ADSI fallback copes with unresolvable Entra SIDs. #>
    try {
        return @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = [string]$_.Name; Type = [string]$_.ObjectClass; Source = [string]$_.PrincipalSource }
        })
    }
    catch {
        $group = [ADSI]'WinNT://./Administrators,group'
        return @($group.Invoke('Members') | ForEach-Object {
            $path = [string]$_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
            $class = [string]$_.GetType().InvokeMember('Class', 'GetProperty', $null, $_, $null)
            $name = ($path -replace '^WinNT://', '') -replace '/', '\'
            [pscustomobject]@{ Name = $name; Type = $class; Source = 'ADSI' }
        })
    }
}

Register-CECheck -Id 'UA-01' -Category 'UserAccessControl' -Severity 'Critical' `
    -Title 'Everyday account is a standard user (separate admin account)' `
    -Frameworks @('CE v3.3', 'CE+ TC5', 'NCSC') `
    -Reference 'CE v3.3 User access control: "use separate accounts to perform administrative activities only". CE+ TC5: an admin action from the user account must prompt for separate admin credentials.' `
    -Test {
        param($ctx)
        $fix = 'Create a separate, named local admin account (or use your Entra/LAPS admin), confirm you can sign in with it, then remove the everyday account from the Administrators group (Settings > Accounts > Other users > Change account type > Standard User). Sign out and back in.'
        if (-not $ctx.IsElevated) {
            $sids = Get-CETokenGroupSids
            if ($sids -contains 'S-1-5-32-544') {
                return New-CEResult -Status 'Fail' -Expected 'Everyday account is not a member of Administrators' `
                    -Actual "$($ctx.RunningAs) is a local administrator (UAC consent prompt only, no separate credentials)" `
                    -Recommendation $fix
            }
            return New-CEResult -Status 'Pass' -Expected 'Everyday account is not a member of Administrators' -Actual "$($ctx.RunningAs) is a standard user"
        }

        # Elevated session: work out who the everyday (console) user is.
        if (-not $ctx.ConsoleUser) {
            return New-CEResult -Status 'Manual' -Expected 'Everyday account is not a member of Administrators' `
                -Actual 'No interactive console user detected (remote session?)' `
                -Recommendation 'Run the audit un-elevated as the everyday user to test this.'
        }
        if ($ctx.ConsoleUser -eq $ctx.RunningAs) {
            return New-CEResult -Status 'Fail' -Expected 'Everyday account is not a member of Administrators' `
                -Actual "The signed-in user $($ctx.ConsoleUser) elevated this session with their own account, so it is an administrator" `
                -Recommendation $fix
        }
        $members = Get-CELocalAdminMembers
        $leaf = ($ctx.ConsoleUser -split '\\')[-1]
        $isMember = @($members | Where-Object { $_.Name -eq $ctx.ConsoleUser -or ($_.Name -split '\\')[-1] -eq $leaf })
        if ($isMember.Count -gt 0) {
            return New-CEResult -Status 'Fail' -Expected 'Everyday account is not a member of Administrators' `
                -Actual "Signed-in user $($ctx.ConsoleUser) is a member of Administrators" -Recommendation $fix -Evidence @($members | ForEach-Object Name)
        }
        return New-CEResult -Status 'Pass' -Expected 'Everyday account is not a member of Administrators' `
            -Actual "Signed-in user $($ctx.ConsoleUser) is not a direct member of Administrators; this session was elevated with a separate account ($($ctx.RunningAs))" `
            -Recommendation 'Group-based membership (e.g. Entra device administrators) is not expanded here; confirm with an un-elevated run.' `
            -Evidence @($members | ForEach-Object Name)
    }

Register-CECheck -Id 'UA-02' -Category 'UserAccessControl' -Severity 'High' `
    -Title 'User Account Control enforced with secure prompts' `
    -Frameworks @('CE v3.3', 'CE+ TC5', 'NCSC') `
    -Reference 'CE+ TC5: attempting an administrative process must trigger an additional prompt and not run with user credentials.' `
    -Test {
        param($ctx)
        $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $lua    = Get-CERegistryValue -Path $p -Name 'EnableLUA' -Default 1
        $admin  = Get-CERegistryValue -Path $p -Name 'ConsentPromptBehaviorAdmin' -Default 5
        $user   = Get-CERegistryValue -Path $p -Name 'ConsentPromptBehaviorUser' -Default 3
        $secure = Get-CERegistryValue -Path $p -Name 'PromptOnSecureDesktop' -Default 1
        $evidence = @("EnableLUA=$lua", "ConsentPromptBehaviorAdmin=$admin", "ConsentPromptBehaviorUser=$user", "PromptOnSecureDesktop=$secure")
        $problems = @()
        $severity = 'Medium'
        if ([int]$lua -ne 1) { $problems += 'UAC is turned off (EnableLUA=0)'; $severity = 'Critical' }
        if ([int]$admin -eq 0) { $problems += 'Admins elevate without any prompt (ConsentPromptBehaviorAdmin=0)'; $severity = 'Critical' }
        if (@(0, 1, 3) -notcontains [int]$user) { $problems += "Unexpected ConsentPromptBehaviorUser=$user" }
        if ([int]$secure -ne 1) { $problems += 'Prompts not shown on the secure desktop' }
        if ($problems.Count -eq 0) {
            return New-CEResult -Status 'Pass' -Expected 'UAC on; prompts on secure desktop; standard users asked for credentials' -Actual 'UAC configured correctly' -Evidence $evidence
        }
        $status = if ($severity -eq 'Critical') { 'Fail' } else { 'Warn' }
        return New-CEResult -Status $status -Severity $severity -Expected 'UAC on; prompts on secure desktop; standard users asked for credentials' `
            -Actual ($problems -join '; ') -Evidence $evidence `
            -Recommendation 'Restore UAC defaults: on, consent/credential prompts on the secure desktop. A restart is needed if UAC was off.' `
            -Remediation (New-CERemediationRef -Id 'UAC-Harden')
    }

Register-CECheck -Id 'UA-03' -Category 'UserAccessControl' -Severity 'Medium' `
    -Title 'Administrator group membership is minimal and justified' `
    -Frameworks @('CE v3.3') `
    -Reference 'CE v3.3 User access control: "remove or disable special access privileges when no longer required"; have a process to approve accounts.' `
    -Test {
        param($ctx)
        $max = [int](Get-CEConfig).thresholds.maxLocalAdmins
        $members = @(Get-CELocalAdminMembers)
        $evidence = @($members | ForEach-Object { "$($_.Name) ($($_.Type), $($_.Source))" })
        if ($members.Count -le $max) {
            return New-CEResult -Status 'Manual' -Severity 'Low' -Expected "At most $max justified administrator entries" `
                -Actual "$($members.Count) member(s) of Administrators" -Evidence $evidence `
                -Recommendation 'Confirm each member is an approved administrative account used only for admin tasks.'
        }
        return New-CEResult -Status 'Warn' -Expected "At most $max justified administrator entries" `
            -Actual "$($members.Count) members of Administrators" -Evidence $evidence `
            -Recommendation 'Remove administrator rights from any account that does not need them.'
    }

Register-CECheck -Id 'UA-04' -Category 'UserAccessControl' -Severity 'High' `
    -Title 'Local password policy: minimum length 12' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 Password-based authentication: minimum 12 characters with no maximum, OR minimum 8 with automatic blocking of common passwords.' `
    -Test {
        param($ctx)
        $min = [int](Get-CEConfig).thresholds.minPasswordLength
        $pol = Get-CEAccountPolicy
        $len = [int]$pol.MinPasswordLength
        $note = 'Microsoft and Entra ID accounts are governed by the cloud password policy (8+ characters with banned-password lists), which also satisfies CE.'
        if ($len -ge $min) {
            return New-CEResult -Status 'Pass' -Expected "Minimum length >= $min" -Actual "Local minimum password length: $len" -Recommendation $note
        }
        $status = if ($len -ge 8) { 'Warn' } else { 'Fail' }
        $extra = if ($len -ge 8) { ' 8-11 characters is only acceptable if common passwords are automatically blocked, which local Windows policy does not do.' } else { '' }
        return New-CEResult -Status $status -Expected "Minimum length >= $min" -Actual "Local minimum password length: $len.$extra" `
            -Recommendation "Set the local minimum password length to $min. Existing passwords are not re-checked until they are next changed. $note" `
            -Remediation (New-CERemediationRef -Id 'PasswordPolicy-Set' -Parameters @{ MinLength = $min })
    }

Register-CECheck -Id 'UA-05' -Category 'UserAccessControl' -Severity 'Low' `
    -Title 'No forced periodic password expiry' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 Password-based authentication: support users by "not enforcing regular password expiry".' `
    -Test {
        param($ctx)
        $pol = Get-CEAccountPolicy
        if ($pol.MaxPasswordAgeDays -le 0) {
            return New-CEResult -Status 'Pass' -Expected 'Maximum password age: unlimited' -Actual 'Passwords do not expire'
        }
        return New-CEResult -Status 'Warn' -Expected 'Maximum password age: unlimited' -Actual "Passwords expire every $($pol.MaxPasswordAgeDays) days" `
            -Recommendation 'Remove periodic expiry; change passwords only when compromise is suspected.' `
            -Remediation (New-CERemediationRef -Id 'PasswordPolicy-Set' -Parameters @{ MaxAgeUnlimited = $true })
    }

Register-CECheck -Id 'UA-06' -Category 'UserAccessControl' -Severity 'Low' -RequiresAdmin `
    -Title 'No forced password complexity rules' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 Password-based authentication: support users by "not enforcing password complexity requirements".' `
    -Test {
        param($ctx)
        $pol = Get-CESecurityPolicy
        if ("$($pol['PasswordComplexity'])" -eq '1') {
            return New-CEResult -Status 'Warn' -Expected 'PasswordComplexity = 0 (with 12+ minimum length)' -Actual 'Password complexity rules are enforced' `
                -Recommendation 'Once a 12-character minimum is in place (UA-04), turn off complexity rules and encourage three random words.' `
                -Remediation (New-CERemediationRef -Id 'PasswordComplexity-Disable')
        }
        return New-CEResult -Status 'Pass' -Expected 'PasswordComplexity = 0' -Actual 'Complexity rules not enforced'
    }

Register-CECheck -Id 'UA-07' -Category 'UserAccessControl' -Severity 'Critical' -AutoFail `
    -Title 'MFA enforced on every cloud service (attestation)' `
    -Frameworks @('CE v3.3', 'CE+ TC4') `
    -Reference 'CE v3.3 (auto-fail): "authentication to cloud services must always use MFA" where available; cloud services cannot be excluded from scope. CE+ TC4 tests user and admin accounts for an MFA prompt.' `
    -Test {
        param($ctx)
        $cfg = (Get-CEConfig).'cloud-services'
        $maxAge = [int]$cfg.maxAttestationAgeDays
        $software = @(Get-CEInstalledSoftware)
        $detected = @{}
        foreach ($s in $software) {
            foreach ($h in $cfg.detectionHints) {
                if ($s.Name -like $h.pattern) { $detected[$h.service] = $s.Name }
            }
        }
        $services = @{}
        foreach ($svc in $cfg.services) { $services[$svc.name] = $svc }
        if ($ctx.EntraJoined -and -not $detected.ContainsKey('Microsoft 365 / Entra ID')) { $detected['Microsoft 365 / Entra ID'] = 'Device is Entra ID joined' }
        foreach ($tool in @((Get-CEAIToolState -Context $ctx).Tools | Where-Object { $_.Service })) {
            if (-not $detected.ContainsKey($tool.Service)) { $detected[$tool.Service] = $tool.Name }
        }

        $names = @(@($detected.Keys) + @($services.Keys | Where-Object { $null -ne $services[$_].mfaEnforced }) | Sort-Object -Unique)
        if ($names.Count -eq 0) {
            return New-CEResult -Status 'Manual' -Expected 'MFA enforced for all users and admins of every cloud service' `
                -Actual 'No cloud services detected or attested' `
                -Recommendation 'List every cloud service your organisation uses (email, file storage, finance, CRM, code hosting, password manager...) in config/cloud-services.json and confirm MFA is enforced for users and admins.'
        }
        foreach ($name in $names) {
            $hint = if ($detected.ContainsKey($name)) { "detected via: $($detected[$name])" } else { 'listed in config' }
            $svc = $services[$name]
            if (-not $svc -or $null -eq $svc.mfaEnforced) {
                New-CEResult -Status 'Manual' -Subject $name -Expected 'MFA attested for users and admins' `
                    -Actual "$name ($hint): no MFA attestation recorded" `
                    -Recommendation "Confirm MFA is enforced for every user and admin account on $name, then record it in config/cloud-services.json (mfaEnforced, adminMfaEnforced, verifiedOn, verifiedBy)."
                continue
            }
            if (-not $svc.mfaEnforced -or ($svc.PSObject.Properties['adminMfaEnforced'] -and $svc.adminMfaEnforced -eq $false)) {
                New-CEResult -Status 'Fail' -Subject $name -Expected 'MFA enforced for users and admins' `
                    -Actual "$name ($hint): attested as NOT enforcing MFA for all accounts" `
                    -Recommendation "Enable MFA for all users and admins on $name now. This is an automatic fail for Cyber Essentials."
                continue
            }
            $age = $null
            if ($svc.verifiedOn) { $age = [int]((Get-Date).Date - (ConvertTo-CEDate $svc.verifiedOn)).TotalDays }
            if ($null -eq $age -or $age -gt $maxAge) {
                New-CEResult -Status 'Warn' -Subject $name -Expected "MFA attestation newer than $maxAge days" `
                    -Actual "$name ($hint): MFA attested but verification date missing or stale" `
                    -Recommendation 'Re-verify MFA enforcement and update verifiedOn.'
                continue
            }
            New-CEResult -Status 'Pass' -Subject $name -Expected 'MFA enforced for users and admins' `
                -Actual "$name ($hint): MFA attested on $($svc.verifiedOn) by $($svc.verifiedBy)"
        }
    }

Register-CECheck -Id 'UA-08' -Category 'UserAccessControl' -Severity 'Medium' `
    -Title 'Windows Hello for Business in use on managed devices' `
    -Frameworks @('NCSC') `
    -Reference 'NCSC Windows device guidance: configure Windows Hello for Business (hardware-backed credentials) for sign-in.' `
    -AppliesTo { param($ctx) if ($ctx.EntraJoined -or $ctx.DomainJoined) { $true } else { 'Standalone device: Windows Hello for Business applies to Entra ID or domain-joined devices.' } } `
    -Test {
        param($ctx)
        if ($ctx.HelloProvisioned) {
            return New-CEResult -Status 'Pass' -Expected 'Windows Hello for Business provisioned' -Actual 'NgcSet = YES'
        }
        return New-CEResult -Status 'Warn' -Expected 'Windows Hello for Business provisioned' -Actual 'No Windows Hello for Business credential for this user' `
            -Recommendation 'Enable Windows Hello for Business via Intune or Group Policy so users sign in with a hardware-backed credential.'
    }

Register-CECheck -Id 'UA-09' -Category 'UserAccessControl' -Severity 'Medium' `
    -Title 'Local admin passwords managed by Windows LAPS' `
    -Frameworks @('NCSC') `
    -Reference 'NCSC Windows device guidance / CE v3.3: unique, non-guessable admin passwords.' `
    -AppliesTo { param($ctx) if ($ctx.CentrallyManaged) { $true } else { 'Standalone device: LAPS requires Entra ID or Active Directory to store passwords.' } } `
    -Test {
        param($ctx)
        $dir = Get-CERegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'BackupDirectory' -Default 0
        if ([int]$dir -gt 0) {
            $where = if ([int]$dir -eq 1) { 'Entra ID' } else { 'Active Directory' }
            return New-CEResult -Status 'Pass' -Expected 'Windows LAPS backing up to Entra ID or AD' -Actual "Windows LAPS enabled (backup to $where)"
        }
        return New-CEResult -Status 'Warn' -Expected 'Windows LAPS backing up to Entra ID or AD' -Actual 'Windows LAPS not configured' `
            -Recommendation 'Configure Windows LAPS in Intune (Endpoint security > Account protection) or Group Policy.'
    }

Register-CECheck -Id 'UA-10' -Category 'UserAccessControl' -Severity 'High' -Scope 'User' `
    -Title 'AI agents do not run with administrator rights' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 User access control: use administrator accounts only for administrative tasks. An AI agent running with administrator rights can make any change to the device when it acts on instructions from a prompt, a web page or a document.' `
    -Test {
        param($ctx)
        $st = Get-CEAIToolState -Context $ctx
        $agents = @($st.Tools | Where-Object { $_.CanActOnDevice })
        $hidden = @($st.UninspectedProcesses)
        if ($agents.Count -eq 0 -and $hidden.Count -eq 0) {
            return New-CEResult -Status 'NotApplicable' -Actual 'No AI agents that can act on this device were found'
        }
        $expected = 'AI agents run as a standard user, without elevation'
        $admin = @()
        $unknown = @()
        $evidence = @()
        foreach ($a in $agents) {
            foreach ($p in @($a.Processes)) {
                $line = "$($a.Name): $($p.Image) pid $($p.ProcessId)$(if ($p.Owner) { " as $($p.Owner)" })"
                $evidence += "$line, elevated=$(if ($null -eq $p.Elevated) { 'unknown' } else { $p.Elevated })"
                if ($p.AsSystem -or $p.Elevated -eq $true) { $admin += $line }
                elseif ($null -eq $p.Elevated) { $unknown += $line }
            }
        }
        $unknown += @($hidden | ForEach-Object { "Possible AI agent $_ (path not readable)" })
        $running = @($agents | Where-Object { @($_.Processes).Count }).Count

        if ($admin.Count) {
            New-CEResult -Status 'Warn' -Expected $expected -Actual "Running with administrator rights: $($admin -join '; ')" -Evidence $evidence `
                -Recommendation 'Close the agent and start it again from a normal (not "Run as administrator") terminal or app. If an admin task is needed, do that step yourself rather than giving the agent administrator rights.'
        }
        if ($unknown.Count) {
            New-CEResult -Status 'Manual' -Subject 'Not checked' -Expected $expected -Actual "Couldn't check: $($unknown -join '; ')" -Evidence $evidence `
                -Recommendation 'Run the audit from an elevated prompt to check these processes, or confirm in Task Manager (Details tab, "Elevated" column) that they are not elevated.'
        }
        if (-not $admin.Count -and -not $unknown.Count) {
            $actual = if ($running) { "$running AI agent(s) running, none with administrator rights" } else { "$($agents.Count) AI agent(s) installed, none running at the time of the audit" }
            New-CEResult -Status 'Pass' -Expected $expected -Actual $actual -Evidence $evidence
        }
    }
