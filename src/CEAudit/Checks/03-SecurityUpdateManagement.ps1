# ---------------------------------------------------------------------------
# Theme 3: Security update management  (CE v3.3 "Security update management")
# Includes the v3.3 auto-fail areas A6.4 (OS/firmware updates within 14 days)
# and A6.5 (application updates within 14 days). CE+ TC2 tests the same thing
# with an authenticated vulnerability scan.
# ---------------------------------------------------------------------------

function Get-CEWingetUpgrades {
    <#
        Returns @{ Available = <winget usable?>; Packages = <packages with an upgrade> }.
        Prefers the Microsoft.WinGet.Client module; falls back to parsing winget.exe output.
    #>
    [CmdletBinding()]
    param()
    if (Get-Module -ListAvailable -Name 'Microsoft.WinGet.Client' -ErrorAction SilentlyContinue) {
        Import-Module Microsoft.WinGet.Client -ErrorAction Stop
        $pkgs = @(Get-WinGetPackage | Where-Object { $_.IsUpdateAvailable } | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Id = $_.Id; Version = [string]$_.InstalledVersion; Available = [string]($_.AvailableVersions | Select-Object -First 1); Source = $_.Source }
        })
        return [pscustomobject]@{ Available = $true; Packages = $pkgs }
    }
    $winget = Get-CEWingetPath
    if (-not $winget) {
        return [pscustomobject]@{ Available = $false; Packages = @() }
    }

    $prev = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [Text.Encoding]::UTF8
        $native = Invoke-CENative -FilePath $winget -ArgumentList @('upgrade', '--include-unknown', '--accept-source-agreements', '--disable-interactivity')
    }
    finally {
        [Console]::OutputEncoding = $prev
    }
    return [pscustomobject]@{ Available = $true; Packages = @(ConvertFrom-CEWingetTable -Lines $native.Output) }
}

function ConvertFrom-CEWingetTable {
    <#
        Parses the fixed-width tables printed by 'winget upgrade'.

        winget can print more than one table (e.g. a second one for packages
        that "require explicit targeting"), each with its own column widths, and
        progress spinners are written onto the same line as the first header
        using carriage returns. So: keep only the text after the last CR on each
        line, find every dashed separator, take column positions from the header
        line just above it (works in any display language), and read rows until
        the table ends.
    #>
    [CmdletBinding()]
    param([string[]]$Lines)

    $clean = @(foreach ($raw in $Lines) {
        $line = [string]$raw
        $cr = $line.LastIndexOf([char]13)
        if ($cr -ge 0) { $line = $line.Substring($cr + 1) }
        # Drop backspace spinner sequences and other control characters.
        ($line -replace '.?\x08', '' -replace '[\x00-\x08\x0B-\x1F]', '').TrimEnd()
    })

    $isSeparator = { param($l) $l -match '^-{10,}$' }
    $rows = @()
    for ($i = 1; $i -lt $clean.Count; $i++) {
        if (-not (& $isSeparator $clean[$i])) { continue }
        $header = $clean[$i - 1]
        $starts = @([regex]::Matches($header, '\S+') | ForEach-Object { $_.Index })
        if ($starts.Count -lt 4) { continue }

        for ($j = $i + 1; $j -lt $clean.Count; $j++) {
            $line = $clean[$j]
            if (-not $line.Trim()) { break }                                     # blank line ends the table
            if (& $isSeparator $line) { break }                                  # malformed; stop
            if ($j + 1 -lt $clean.Count -and (& $isSeparator $clean[$j + 1])) { break }  # next table's header
            if ($line.Length -le $starts[3]) { continue }                        # footer, e.g. "2 upgrades available."
            # A real row has a gap just before every column; prose (footers, notes) doesn't line up.
            $aligned = $true
            for ($c = 2; $c -lt $starts.Count -and $starts[$c] -lt $line.Length; $c++) {
                if ($line[$starts[$c] - 1] -ne ' ') { $aligned = $false; break }
            }
            if (-not $aligned) { continue }

            $cols = @()
            for ($c = 0; $c -lt $starts.Count; $c++) {
                $from = $starts[$c]
                $to = if ($c + 1 -lt $starts.Count) { $starts[$c + 1] } else { $line.Length }
                if ($from -ge $line.Length) { $cols += ''; continue }
                $cols += $line.Substring($from, [math]::Min($to, $line.Length) - $from).Trim()
            }
            $id = $cols[1]
            if (-not $id -or $id -match '^-+$' -or $id -match '\s') { continue }
            $rows += [pscustomobject]@{
                Name      = $cols[0]
                Id        = $id
                Version   = $cols[2]
                Available = $cols[3]
                Source    = if ($cols.Count -gt 4) { $cols[4] } else { '' }
                # winget shortens long names/ids with an ellipsis when the console is narrow.
                Truncated = ($id -notmatch '^[\w][\w\.\-\+]*$')
            }
        }
    }
    return $rows
}

Register-CECheck -Id 'SU-01' -Category 'SecurityUpdateManagement' -Severity 'Critical' -AutoFail `
    -Title 'Operating system is licensed and supported by Microsoft' `
    -Frameworks @('CE v3.3', 'CE+ TC2') `
    -Reference 'CE v3.3 Security update management: all software must be licensed and supported, and removed when it becomes unsupported.' `
    -Test {
        param($ctx)
        $lc = (Get-CEConfig).'os-lifecycle'
        $today = (Get-Date).Date
        $results = @()

        $reviewed = ConvertTo-CEDate $lc.lastReviewed
        if (($today - $reviewed).TotalDays -gt [int]$lc.reviewWarningDays) {
            $results += New-CEResult -Status 'Warn' -Subject 'Lifecycle data' -Severity 'Low' -Expected "Lifecycle data reviewed within $($lc.reviewWarningDays) days" `
                -Actual "config/os-lifecycle.json last reviewed $($lc.lastReviewed)" -Recommendation "Update config/os-lifecycle.json from $($lc.source)."
        }

        # Pass / warn / fail against an end-of-support date.
        $judge = {
            param([string]$Label, $EndText, [string]$FailFix, [string]$WarnFix)
            $end = ConvertTo-CEDate $EndText
            $daysLeft = [int]($end - $today).TotalDays
            $endShown = $end.ToString('yyyy-MM-dd')
            if ($daysLeft -lt 0) {
                New-CEResult -Status 'Fail' -Expected 'Supported Windows version' -Actual "${Label}: support ended $endShown" -Recommendation $FailFix
            }
            elseif ($daysLeft -le [int]$lc.upcomingEndWarningDays) {
                New-CEResult -Status 'Warn' -Severity 'High' -Expected 'Supported Windows version' -Actual "${Label}: support ends $endShown ($daysLeft days)" -Recommendation $WarnFix
            }
            else {
                New-CEResult -Status 'Pass' -Expected 'Supported Windows version' -Actual "${Label}: supported until $endShown"
            }
        }

        if ($ctx.OSFamily -eq 'Windows Server') {
            $entry = @($lc.windowsServer) | Where-Object { [int]$_.build -eq $ctx.Build } | Select-Object -First 1
            if (-not $entry) {
                $results += New-CEResult -Status 'Manual' -Expected 'Build listed in config/os-lifecycle.json' `
                    -Actual "Windows Server build $($ctx.FullBuild) ($($ctx.ProductName)) is not in the lifecycle data" `
                    -Recommendation 'Check this Windows Server release is still supported (Microsoft lifecycle pages) and add it to config/os-lifecycle.json.'
                return $results
            }
            $results += & $judge "Windows Server $($entry.version) $($ctx.EditionID) (build $($ctx.FullBuild))" $entry.extendedEnd `
                'Migrate to a supported Windows Server release, or enrol in Extended Security Updates and record the evidence.' `
                'Plan the migration to a newer Windows Server release (or ESU) before this date.'
            return $results
        }

        if ($ctx.OSFamily -eq 'Windows 10') {
            $results += New-CEResult -Status 'Fail' -Expected 'Supported Windows version' `
                -Actual "Windows 10 build $($ctx.FullBuild): support ended $($lc.windows10.endOfSupport)" `
                -Recommendation 'Upgrade to a supported Windows 11 release. A device enrolled in Extended Security Updates can remain in scope only while ESU is active and updates are applied; record the ESU evidence if so.'
            return $results
        }
        if ($ctx.OSFamily -ne 'Windows 11') {
            $results += New-CEResult -Status 'Fail' -Expected 'Supported Windows version' -Actual "Unrecognised OS build $($ctx.FullBuild)" -Recommendation 'Move to a supported Windows 11 release.'
            return $results
        }

        $entry = $lc.windows11 | Where-Object { [int]$_.build -eq $ctx.Build } | Select-Object -First 1
        if (-not $entry) {
            $results += New-CEResult -Status 'Manual' -Expected 'Build listed in config/os-lifecycle.json' -Actual "Windows 11 build $($ctx.Build) ($($ctx.DisplayVersion)) not in lifecycle data" `
                -Recommendation 'Check the build is in support on Microsoft release health and add it to config/os-lifecycle.json.'
            return $results
        }
        $endText = if ($ctx.EditionClass -eq 'Enterprise') { $entry.enterprise } else { $entry.homePro }
        if (-not $endText) {
            $results += New-CEResult -Status 'Manual' -Expected 'Known end-of-servicing date' -Actual "Windows 11 $($entry.version) ($($ctx.EditionID)): end date not recorded" `
                -Recommendation 'Confirm the end-of-servicing date on Microsoft release health and add it to config/os-lifecycle.json.'
            return $results
        }
        $results += & $judge "Windows 11 $($entry.version) $($ctx.EditionID) (build $($ctx.FullBuild))" $endText `
            'Install the latest Windows 11 feature update now (Settings > Windows Update).' `
            'Plan the upgrade to the next Windows 11 feature update before this date, or the device drops out of scope.'
        return $results
    }

Register-CECheck -Id 'SU-02' -Category 'SecurityUpdateManagement' -Severity 'High' `
    -Title 'Windows automatic updates enabled and not paused' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 Security update management: "have automatic updates enabled where possible". NCSC: enable automatic updates via Windows Update for Business.' `
    -Test {
        param($ctx)
        $au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        $noAuto   = Get-CERegistryValue -Path $au -Name 'NoAutoUpdate'
        $auOption = Get-CERegistryValue -Path $au -Name 'AUOptions'
        $deferQ   = Get-CERegistryValue -Path $wu -Name 'DeferQualityUpdatesPeriodInDays'
        $pauseEnd = Get-CERegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime'
        $svc      = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
        $evidence = @("NoAutoUpdate=$noAuto", "AUOptions=$auOption", "DeferQualityUpdatesPeriodInDays=$deferQ", "PauseUpdatesExpiryTime=$pauseEnd", "wuauserv StartType=$(if ($svc) { $svc.StartType })")

        $results = @()
        if ("$noAuto" -eq '1' -or "$auOption" -eq '2' -or ($svc -and "$($svc.StartType)" -eq 'Disabled')) {
            $results += New-CEResult -Status 'Fail' -Subject 'Automatic updates' -Expected 'Automatic download and install' `
                -Actual 'Automatic updates are disabled or set to notify only' -Evidence $evidence `
                -Recommendation 'Enable automatic download and installation of updates.' `
                -Remediation (New-CERemediationRef -Id 'WindowsUpdate-EnableAuto')
        }
        else {
            $results += New-CEResult -Status 'Pass' -Subject 'Automatic updates' -Expected 'Automatic download and install' -Actual 'Automatic updates enabled' -Evidence $evidence
        }

        if ($pauseEnd) {
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParse([string]$pauseEnd, [ref]$parsed) -and $parsed -gt (Get-Date)) {
                $results += New-CEResult -Status 'Fail' -Subject 'Paused' -Expected 'Updates not paused' -Actual "Updates paused until $($parsed.ToString('yyyy-MM-dd'))" `
                    -Recommendation 'Resume updates. Pausing risks missing the 14-day window.' `
                    -Remediation (New-CERemediationRef -Id 'WindowsUpdate-Resume')
            }
        }
        $window = [int](Get-CEConfig).thresholds.patchWindowDays
        if ($deferQ -and [int]$deferQ -gt 0) {
            $status = if ([int]$deferQ -ge $window) { 'Fail' } else { 'Warn' }
            $results += New-CEResult -Status $status -Subject 'Deferral' -Expected "Quality update deferral well under $window days" `
                -Actual "Quality updates deferred by $deferQ days" `
                -Recommendation "Keep quality-update deferral short (0-3 days) with an install deadline, so security fixes land within $window days of release." `
                -Remediation (New-CERemediationRef -Id 'WindowsUpdate-RemoveQualityDeferral')
        }
        if ($ctx.CentrallyManaged -and ($noAuto -or $auOption -or $deferQ)) {
            $results += New-CEResult -Status 'Info' -Subject 'Managed' -Actual 'Update policy is set centrally (GPO/Intune). Fix it at the source; local changes may be overwritten.'
        }
        return $results
    }

Register-CECheck -Id 'SU-03' -Category 'SecurityUpdateManagement' -Severity 'Critical' -AutoFail `
    -Title 'No Windows security updates outstanding for more than 14 days' `
    -Frameworks @('CE v3.3', 'CE+ TC2') `
    -Reference 'CE v3.3 A6.4 (auto-fail): critical/high-risk (CVSS v3 >= 7) or unrated OS updates installed within 14 days of release. CE+ TC2 fails on any such missing fix older than 14 days.' `
    -Test {
        param($ctx)
        $window = [int](Get-CEConfig).thresholds.patchWindowDays
        $state = Get-CEWindowsUpdateState -Online
        $now = Get-Date
        $results = @()
        $overdue = @($state.Pending | Where-Object { $_.IsSecurity -and ($now - $_.Released).TotalDays -gt $window })
        $recent  = @($state.Pending | Where-Object { $_.IsSecurity -and ($now - $_.Released).TotalDays -le $window })
        $other   = @($state.Pending | Where-Object { -not $_.IsSecurity -and ($now - $_.Released).TotalDays -gt $window })
        $fmt = { param($u) "$($u.Title) [$($u.KB)] severity=$(if ($u.Severity) { $u.Severity } else { 'unrated' }) released=$($u.Released.ToString('yyyy-MM-dd'))" }

        if ($overdue.Count -gt 0) {
            $results += New-CEResult -Status 'Fail' -Subject 'Overdue' -Expected "Security updates installed within $window days of release" `
                -Actual "$($overdue.Count) security update(s) outstanding for more than $window days" `
                -Evidence @($overdue | ForEach-Object { & $fmt $_ }) `
                -Recommendation 'Install these updates now and restart. This is an automatic fail for Cyber Essentials.' `
                -Remediation (New-CERemediationRef -Id 'WindowsUpdate-InstallSecurity')
        }
        elseif ($recent.Count -gt 0) {
            $oldest = ($recent | Sort-Object Released | Select-Object -First 1).Released
            $deadline = $oldest.AddDays($window).ToString('yyyy-MM-dd')
            $results += New-CEResult -Status 'Warn' -Severity 'High' -Subject 'Due' -Expected "Security updates installed within $window days of release" `
                -Actual "$($recent.Count) security update(s) pending, still inside the window (install by $deadline)" `
                -Evidence @($recent | ForEach-Object { & $fmt $_ }) `
                -Recommendation "Install before $deadline." `
                -Remediation (New-CERemediationRef -Id 'WindowsUpdate-InstallSecurity')
        }
        else {
            $results += New-CEResult -Status 'Pass' -Subject 'Overdue' -Expected "Security updates installed within $window days of release" -Actual 'No applicable security updates pending'
        }

        if ($other.Count -gt 0) {
            $results += New-CEResult -Status 'Warn' -Severity 'Medium' -Subject 'Unclassified' `
                -Expected 'Updates without a published severity are treated as critical' `
                -Actual "$($other.Count) other update(s) pending for more than $window days" `
                -Evidence @($other | ForEach-Object { & $fmt $_ }) `
                -Recommendation 'CE treats vendor updates with no severity as in scope for the 14-day rule. Review and install (driver/firmware updates included).' `
                -Remediation (New-CERemediationRef -Id 'WindowsUpdate-InstallSecurity' -Parameters @{ IncludeAll = $true })
        }

        $lastOk = $state.History | Where-Object { $_.ResultCode -eq 2 } | Sort-Object Date -Descending | Select-Object -First 1
        if ($lastOk) {
            $age = [int]($now - $lastOk.Date).TotalDays
            if ($age -gt 35) {
                $results += New-CEResult -Status 'Warn' -Severity 'High' -Subject 'History' -Expected 'An update installed within the last monthly cycle' `
                    -Actual "Last successful update install was $age days ago ($($lastOk.Title))" `
                    -Recommendation 'Check Windows Update is working: Settings > Windows Update > Check for updates.'
            }
        }
        return $results
    }

Register-CECheck -Id 'SU-04' -Category 'SecurityUpdateManagement' -Severity 'Medium' `
    -Title 'No restart pending to finish installing updates' `
    -Frameworks @('CE v3.3', 'CE+ TC2') `
    -Reference 'CE+ TC2: installed-but-not-active fixes are still reported as missing by the authenticated scan.' `
    -Test {
        param($ctx)
        if (Test-CEPendingReboot) {
            return New-CEResult -Status 'Warn' -Expected 'No pending restart' -Actual 'A restart is required to finish installing updates' `
                -Recommendation 'Restart the device. Until then the fixes are not active.'
        }
        return New-CEResult -Status 'Pass' -Expected 'No pending restart' -Actual 'No restart pending'
    }

Register-CECheck -Id 'SU-05' -Category 'SecurityUpdateManagement' -Severity 'High' -AutoFail `
    -Title 'Applications are up to date (winget)' `
    -Frameworks @('CE v3.3', 'CE+ TC2') `
    -Reference 'CE v3.3 A6.5 (auto-fail): application updates fixing critical/high-risk or unrated vulnerabilities installed within 14 days of release.' `
    -Test {
        param($ctx)
        $winget = Get-CEWingetUpgrades
        $upgrades = @($winget.Packages)
        if (-not $winget.Available) {
            return New-CEResult -Status 'Manual' -Expected 'All applications on the latest vendor-supported version' `
                -Actual 'winget (App Installer) was not found on this device' `
                -Recommendation 'Install App Installer from the Microsoft Store, or check each application for updates manually.'
        }
        if ($upgrades.Count -eq 0) {
            $note = if ($ctx.IsSystem) { 'Running as SYSTEM, so apps installed only for a user are not included. Run the app as the user to check those.' } else { '' }
            return New-CEResult -Status 'Pass' -Expected 'All applications on the latest version' -Actual 'winget reports no available upgrades' -Recommendation $note
        }
        foreach ($u in $upgrades) {
            if ($u.PSObject.Properties['Truncated'] -and $u.Truncated) {
                New-CEResult -Status 'Fail' -Subject $u.Name -Expected 'Latest vendor version installed within 14 days of release' `
                    -Actual "$($u.Name): installed $($u.Version), available $($u.Available) (winget shortened the package id)" `
                    -Recommendation 'Update this app, e.g. with: winget upgrade --all. Its id was shortened in winget output, so no automatic fix is offered.'
                continue
            }
            New-CEResult -Status 'Fail' -Subject $u.Id -Expected 'Latest vendor version installed within 14 days of release' `
                -Actual "$($u.Name): installed $($u.Version), available $($u.Available)" `
                -Recommendation 'Update now. If this release is under 14 days old you are still inside the window, but you cannot rely on the scanner knowing that.' `
                -Remediation (New-CERemediationRef -Id 'Winget-Upgrade' -Parameters @{ PackageId = [string]$u.Id; Name = [string]$u.Name })
        }
    }

Register-CECheck -Id 'SU-06' -Category 'SecurityUpdateManagement' -Severity 'Critical' `
    -Title 'No unsupported (end-of-life) software installed' `
    -Frameworks @('CE v3.3', 'CE+ TC2') `
    -Reference 'CE v3.3 Security update management: software must be supported and "removed from devices when it becomes unsupported".' `
    -Test {
        param($ctx)
        $cfg = (Get-CEConfig).'unsupported-software'
        $today = (Get-Date).Date
        $software = @(Get-CEInstalledSoftware)
        $hits = 0
        foreach ($s in $software) {
            foreach ($p in $cfg.products) {
                if ($s.Name -notlike $p.pattern) { continue }
                if ($p.PSObject.Properties['versionPattern'] -and $p.versionPattern) {
                    $ver = if ($s.Version) { $s.Version } else { $s.Name }
                    if ($ver -notmatch $p.versionPattern -and $s.Name -notmatch $p.versionPattern) { continue }
                }
                $end = ConvertTo-CEDate $p.endOfSupport
                $days = [int]($end - $today).TotalDays
                $hits++
                if ($days -lt 0) {
                    New-CEResult -Status 'Fail' -Subject $s.Name -Expected 'Only vendor-supported software installed' `
                        -Actual "$($s.Name) $($s.Version) went out of support on $($p.endOfSupport)" `
                        -Recommendation 'Uninstall it, or upgrade to a supported version (Settings > Apps > Installed apps).'
                }
                elseif ($days -le [int]$cfg.upcomingEndWarningDays) {
                    New-CEResult -Status 'Warn' -Subject $s.Name -Severity 'High' -Expected 'Only vendor-supported software installed' `
                        -Actual "$($s.Name) $($s.Version) goes out of support on $($p.endOfSupport) ($days days)" `
                        -Recommendation 'Plan the upgrade or removal before the end-of-support date.'
                }
                break
            }
        }
        if ($hits -eq 0) {
            New-CEResult -Status 'Pass' -Expected 'Only vendor-supported software installed' `
                -Actual "No matches against $(@($cfg.products).Count) known end-of-life products" `
                -Recommendation 'This list is not exhaustive; review SC-09 inventory for other unsupported software.'
        }
    }

Register-CECheck -Id 'SU-07' -Category 'SecurityUpdateManagement' -Severity 'High' `
    -Title 'Browsers and Microsoft Store apps are allowed to auto-update' `
    -Frameworks @('CE v3.3') `
    -Reference 'CE v3.3 Security update management: "have automatic updates enabled where possible".' `
    -Test {
        param($ctx)
        $blocks = @(
            @{ Label = 'Microsoft Edge'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'; Names = @('UpdateDefault', 'Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'); Bad = 0; Key = 'Edge' },
            @{ Label = 'Google Chrome'; Path = 'HKLM:\SOFTWARE\Policies\Google\Update'; Names = @('UpdateDefault', 'Update{8A69D345-D564-463C-AFF1-A69D9E530F96}'); Bad = 0; Key = 'Chrome' },
            @{ Label = 'Mozilla Firefox'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Names = @('DisableAppUpdate'); Bad = 1; Key = 'Firefox' },
            @{ Label = 'Microsoft Store apps'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'; Names = @('AutoDownload'); Bad = 2; Key = 'Store' },
            @{ Label = 'Microsoft 365 Apps'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate'; Names = @('enableautomaticupdates'); Bad = 0; Key = 'Office' }
        )
        foreach ($b in $blocks) {
            $blockedBy = @()
            foreach ($n in $b.Names) {
                $v = Get-CERegistryValue -Path $b.Path -Name $n
                if ($null -ne $v -and [int]$v -eq $b.Bad) { $blockedBy += "$n=$v" }
            }
            if ($blockedBy.Count -gt 0) {
                New-CEResult -Status 'Fail' -Subject $b.Label -Expected 'Automatic updates allowed' -Actual "$($b.Label) updates disabled by policy ($($blockedBy -join ', '))" `
                    -Recommendation "Allow $($b.Label) to update automatically." `
                    -Remediation (New-CERemediationRef -Id 'AppUpdate-Unblock' -Parameters @{ App = $b.Key })
            }
            else {
                New-CEResult -Status 'Pass' -Subject $b.Label -Expected 'Automatic updates allowed' -Actual "No policy blocking $($b.Label) updates"
            }
        }
        $c2r = Get-CERegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -Name 'UpdatesEnabled'
        if ("$c2r" -eq 'False') {
            New-CEResult -Status 'Fail' -Subject 'Office Click-to-Run' -Expected 'UpdatesEnabled = True' -Actual 'Office Click-to-Run updates disabled' `
                -Recommendation 'In any Office app: File > Account > Update Options > Enable Updates.' `
                -Remediation (New-CERemediationRef -Id 'AppUpdate-Unblock' -Parameters @{ App = 'OfficeC2R' })
        }
    }

function Get-CEFirmwareCatalogResult {
    <#
        Compares the installed BIOS with the firmware catalog. Returns a result,
        or $null when the catalog can't decide (then SU-08 falls back to BIOS age).
        Appends what it found to the caller's Evidence list either way.
    #>
    param($Context, $Hardware, [Parameter(Mandatory)][System.Collections.ArrayList]$Evidence)
    $lookup = Get-CEFirmwareCatalogRecord -Hardware $Hardware
    [void]$Evidence.Add("Firmware catalog: $($lookup.Status)$(if ($lookup.Message) { " - $($lookup.Message)" })")
    if ($lookup.Status -ne 'Found') { return $null }

    $cfg = (Get-CEConfig).'firmware-catalog'
    $rec = $lookup.Record
    $vendor = [string]$rec.vendor
    $checked = ConvertTo-CEUtcDateTime $rec.checkedAt
    $maxRecordAge = [int](Get-CEObjectValue $cfg 'maxRecordAgeDays' 7)
    $recordAge = ($Context.AuditTime.ToUniversalTime() - $checked).TotalDays
    $recName = [string](Get-CEObjectValue $rec 'name' '')
    [void]$Evidence.Add("Catalog model: $recName ($vendor $(Get-CEObjectValue $rec 'id' '')), checked $($checked.ToString('yyyy-MM-dd HH:mm')) UTC")
    if ($recordAge -gt $maxRecordAge) {
        [void]$Evidence.Add("Catalog record is $([math]::Floor($recordAge)) days old (limit $maxRecordAge), so it was not used")
        return $null
    }

    $installed = [string]$Hardware.Firmware.Version
    $releases = @($rec.releases)
    $latest = $releases[0]
    $latestVersion = [string](Get-CEObjectValue $latest 'version' '')
    $cmp = Compare-CEFirmwareVersion -Vendor $vendor -Installed $installed -Catalog $latestVersion
    if ($null -eq $cmp) {
        [void]$Evidence.Add("Could not compare installed '$installed' with catalog version '$latestVersion'")
        return $null
    }

    $window = [int](Get-CEConfig).thresholds.patchWindowDays
    $maxAge = [int](Get-CEConfig).thresholds.firmwareAgeWarnDays
    $model = if ($recName) { $recName } else { "$($Hardware.Manufacturer) $($Hardware.Model)".Trim() }
    $daysSince = {
        param($date)
        $d = ConvertTo-CEDateOnly $date
        if ($null -eq $d) { return $null }
        return [int][math]::Floor(($Context.AuditTime.Date - $d).TotalDays)
    }
    $dateText = { param($date) $d = ConvertTo-CEDateOnly $date; if ($d) { $d.ToString('yyyy-MM-dd') } else { '' } }
    $relDate = { param($r) Get-CEObjectValue $r 'date' $null }
    $describe = { param($r) $dt = & $dateText (& $relDate $r); "$(Get-CEObjectValue $r 'version' '?')$(if ($dt) { " ($dt)" })$(if (Get-CEObjectValue $r 'criticality') { " [$(Get-CEObjectValue $r 'criticality' '')]" })" }
    $tool = switch ($vendor) { 'dell' { 'Dell Command | Update' } 'hp' { 'HP Image Assistant' } 'lenovo' { 'Lenovo System Update or Commercial Vantage' } }
    $expected = 'Latest BIOS/UEFI for this model, or an update released within the patch window'
    $latestAge = & $daysSince (& $relDate $latest)

    if ($cmp -ge 0) {
        if ($null -ne $latestAge -and $latestAge -gt $maxAge) {
            return New-CEResult -Status 'Warn' -Subject 'Firmware' -Expected $expected -Evidence $Evidence `
                -Actual "BIOS $installed is the latest for $model, but no firmware has been released for this model since $(& $dateText (& $relDate $latest))" `
                -Recommendation 'Check the model is still supported by the manufacturer. Cyber Essentials requires devices to receive vendor security updates.'
        }
        return New-CEResult -Status 'Pass' -Subject 'Firmware' -Expected $expected -Evidence $Evidence `
            -Actual "BIOS $installed is the latest for $model (released $(& $dateText (& $relDate $latest)))"
    }

    $newer = @($releases | Where-Object { $c = Compare-CEFirmwareVersion -Vendor $vendor -Installed $installed -Catalog ([string]$_.version); $c -eq -1 })
    $overdueUrgent = @($newer | Where-Object { (Get-CEObjectValue $_ 'criticality') -eq 'Urgent' -and $null -ne (& $daysSince (& $relDate $_)) -and (& $daysSince (& $relDate $_)) -gt $window })
    [void]$Evidence.Add("Newer releases: $((@($newer | ForEach-Object { & $describe $_ })) -join ', ')")
    $rec2 = "Install BIOS $latestVersion for $model using $tool or the manufacturer support page. Suspend BitLocker first (Suspend-BitLocker -MountPoint C: -RebootCount 1) and keep the device on mains power."
    $behind = "BIOS $installed installed; latest is $(& $describe $latest), $($newer.Count) newer release(s)"
    if ($overdueUrgent.Count) {
        $oldest = $overdueUrgent[-1]
        return New-CEResult -Status 'Fail' -Subject 'Firmware' -Expected $expected -Evidence $Evidence `
            -Actual "$behind; the manufacturer marked $(Get-CEObjectValue $oldest 'version' '?') urgent $(& $daysSince (& $relDate $oldest)) days ago" -Recommendation $rec2
    }
    if ($null -eq $latestAge -or $latestAge -gt $window) {
        return New-CEResult -Status 'Warn' -Subject 'Firmware' -Expected $expected -Actual $behind -Evidence $Evidence -Recommendation $rec2
    }
    return New-CEResult -Status 'Pass' -Subject 'Firmware' -Expected $expected -Evidence $Evidence `
        -Actual "$behind; released $latestAge days ago, within the $window-day patch window" -Recommendation $rec2
}

Register-CECheck -Id 'SU-08' -Category 'SecurityUpdateManagement' -Severity 'High' `
    -Title 'Device firmware (BIOS/UEFI and TPM) is up to date' `
    -Frameworks @('CE v3.3', 'NCSC') `
    -Reference 'CE v3.3 security update management: firmware is in scope and must be supported and updated within 14 days of a high or critical fix. NCSC Windows device guidance: keep firmware up to date.' `
    -Test {
        param($ctx)
        $hw = Get-CEObjectValue $ctx 'Hardware'
        if ($null -eq $hw) {
            return New-CEResult -Status 'Manual' -Expected 'Current firmware without known vulnerabilities' -Actual 'Hardware inventory unavailable' `
                -Recommendation 'Check the BIOS/UEFI version in System Information (msinfo32) against the manufacturer support page.'
        }
        $fw = $hw.Firmware
        $evidence = New-Object System.Collections.ArrayList
        $evidence.AddRange(@("Manufacturer=$($hw.Manufacturer)", "Model=$($hw.Model)", "SKU=$($hw.SystemSku)", "BIOS vendor=$($fw.Vendor)",
            "BIOS version=$($fw.Version)", "BIOS release date=$($fw.ReleaseDate)", "Firmware type=$($fw.Type)"))

        $maxAge = [int](Get-CEConfig).thresholds.firmwareAgeWarnDays
        $expected = "BIOS/UEFI released within the last $maxAge days, or confirmed as the latest for this model"
        if ($hw.IsVirtualMachine) {
            New-CEResult -Status 'NotApplicable' -Subject 'Firmware' -Actual "Virtual machine ($($hw.Model)): firmware comes from the host platform" -Evidence $evidence
        }
        else {
            $catalogResult = Get-CEFirmwareCatalogResult -Context $ctx -Hardware $hw -Evidence $evidence
            if ($catalogResult) {
                $catalogResult
            }
            elseif (-not $fw.ReleaseDate) {
                New-CEResult -Status 'Manual' -Subject 'Firmware' -Expected $expected -Actual "BIOS/UEFI $($fw.Version): release date unknown" -Evidence $Evidence `
                    -Recommendation "Check the manufacturer support page for $($hw.Manufacturer) $($hw.Model) and install any newer BIOS/UEFI."
            }
            else {
                $released = [datetime]::ParseExact($fw.ReleaseDate, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
                $age = [int][math]::Floor(($ctx.AuditTime - $released).TotalDays)
                $actual = "BIOS/UEFI $($fw.Version) released $($fw.ReleaseDate) ($([math]::Max(0, [math]::Floor($age / 30.44))) months ago)"
                if ($age -gt $maxAge) {
                    New-CEResult -Status 'Warn' -Subject 'Firmware' -Expected $expected -Actual $actual -Evidence $Evidence `
                        -Recommendation "Check the manufacturer support page for $($hw.Manufacturer) $($hw.Model) (or Dell Command | Update, HP Image Assistant, Lenovo System Update) and install any newer BIOS/UEFI. Suspend BitLocker first. If the manufacturer has stopped releasing firmware for this model, Cyber Essentials treats it as unsupported."
                }
                else {
                    New-CEResult -Status 'Pass' -Subject 'Firmware' -Expected $expected -Actual $actual -Evidence $Evidence
                }
            }
        }

        $tpm = $hw.Tpm
        $tpmExpected = 'TPM firmware not affected by known vulnerabilities'
        $tpmEvidence = @("TPM manufacturer=$($tpm.Manufacturer)", "TPM firmware=$($tpm.FirmwareVersion)", "TPM spec=$($tpm.SpecVersion)")
        if (-not $tpm.Readable) {
            $why = if ($ctx.IsElevated) { 'TPM information unavailable' } else { 'Needs elevation to read the TPM firmware version' }
            New-CEResult -Status 'Manual' -Subject 'TPM firmware' -Expected $tpmExpected -Actual $why `
                -Recommendation 'Run Get-Tpm in an elevated PowerShell prompt and check ManufacturerVersion against the manufacturer''s advisories.'
            return
        }
        if (-not $tpm.Present) {
            New-CEResult -Status 'NotApplicable' -Subject 'TPM firmware' -Actual 'No TPM found (see NC-02)'
            return
        }
        $list = (Get-CEConfig).'tpm-firmware-advisories'
        $hits = @()
        foreach ($adv in @(Get-CEObjectValue $list 'advisories' @())) {
            if (@(Get-CEObjectValue $adv 'manufacturers' @()) -notcontains $tpm.Manufacturer) { continue }
            foreach ($range in @(Get-CEObjectValue $adv 'affected' @())) {
                if (Test-CEVersionInRange -Version $tpm.FirmwareVersion -From ([string](Get-CEObjectValue $range 'from' '')) -To ([string](Get-CEObjectValue $range 'to' ''))) { $hits += $adv; break }
            }
        }
        if ($hits.Count -eq 0) {
            New-CEResult -Status 'Pass' -Subject 'TPM firmware' -Expected $tpmExpected -Evidence $tpmEvidence `
                -Actual "$($tpm.Manufacturer) TPM firmware $($tpm.FirmwareVersion): no known advisories ($(@(Get-CEObjectValue $list 'advisories' @()).Count) checked, list reviewed $(Get-CEObjectValue $list 'lastReviewed' 'unknown'))"
            return
        }
        $names = @($hits | ForEach-Object { "$(Get-CEObjectValue $_ 'title' 'advisory') ($(@(Get-CEObjectValue $_ 'cves' @()) -join ', '))" })
        $severity = if (@($hits | Where-Object { @('Critical', 'High') -contains (Get-CEObjectValue $_ 'severity' '') }).Count) { 'High' } else { 'Medium' }
        New-CEResult -Status 'Fail' -Severity $severity -Subject 'TPM firmware' -Expected $tpmExpected -Evidence ($tpmEvidence + @($hits | ForEach-Object { @(Get-CEObjectValue $_ 'references' @()) })) `
            -Actual "$($tpm.Manufacturer) TPM firmware $($tpm.FirmwareVersion) is affected by: $($names -join '; ')" `
            -Recommendation ((@($hits | ForEach-Object { [string](Get-CEObjectValue $_ 'advice' '') }) | Where-Object { $_ } | Select-Object -Unique) -join ' ')
    }
