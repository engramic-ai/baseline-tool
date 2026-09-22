# ---------------------------------------------------------------------------
# Reporting: summary, CE+ readiness, JSON / Markdown / HTML output.
# Source kept ASCII-only so Windows PowerShell 5.1 reads it correctly.
# ---------------------------------------------------------------------------

$script:CEPlusTestCases = @(
    @{ Id = 'TC1'; Name = 'Remote vulnerability assessment'; Scope = 'Internet-facing services. Tested externally by the assessor; this device audit only covers local firewall exposure.' },
    @{ Id = 'TC2'; Name = 'Check patching (authenticated scan)'; Scope = 'OS and application fixes older than 14 days (CVSS >= 7, critical/high, or unrated).' },
    # EvidenceCheck: the estimate can only be 'Likely pass' once that check has passed.
    @{ Id = 'TC3'; Name = 'Check malware protection'; Scope = 'Email attachment and browser download tests; anti-malware operational and updated.'; EvidenceCheck = 'MP-11' },
    @{ Id = 'TC4'; Name = 'Check MFA configuration'; Scope = 'MFA prompt on every cloud service for user and admin accounts (attestation).' },
    @{ Id = 'TC5'; Name = 'Check account separation'; Scope = 'Admin actions from the user account must require separate credentials.' }
)

function Get-CESummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        # Only some checks ran (-Id, -Category, -ExcludeId), so no overall verdict is given.
        [switch]$PartialRun,
        # How many checks the engine selected. A check can run and leave no finding,
        # so counting findings would undercount; that is only the fallback.
        [int]$ChecksRun = -1
    )
    if ($ChecksRun -lt 0) { $ChecksRun = @($Findings | ForEach-Object { $_.CheckId } | Sort-Object -Unique).Count }

    $byStatus = [ordered]@{}
    foreach ($s in $script:CEValidStatus) { $byStatus[$s] = @($Findings | Where-Object { $_.Status -eq $s }).Count }

    $byCategory = foreach ($c in $script:CEValidCategory) {
        $fs = @($Findings | Where-Object { $_.Category -eq $c })
        [pscustomobject]@{
            Category = $c
            Pass     = @($fs | Where-Object Status -eq 'Pass').Count
            Fail     = @($fs | Where-Object Status -eq 'Fail').Count
            Warn     = @($fs | Where-Object Status -eq 'Warn').Count
            Manual   = @($fs | Where-Object Status -eq 'Manual').Count
            Other    = @($fs | Where-Object { @('Pass', 'Fail', 'Warn', 'Manual') -notcontains $_.Status }).Count
        }
    }

    $ceFindings = @($Findings | Where-Object { @($_.Frameworks | Where-Object { $_ -like 'CE*' }).Count -gt 0 })
    $autoFails = @($Findings | Where-Object { $_.AutoFail })
    $ceFails = @($ceFindings | Where-Object { $_.Status -eq 'Fail' })
    $ceOpen = @($ceFindings | Where-Object { @('Warn', 'Manual', 'Skipped', 'Error') -contains $_.Status })

    $verdict = if ($PartialRun) { "PARTIAL: $ChecksRun of $(@(Get-CECheck).Count) checks run" }
               elseif ($autoFails.Count -gt 0) { 'FAIL: automatic-fail items present' }
               elseif ($ceFails.Count -gt 0) { 'NOT READY: Cyber Essentials requirements failing' }
               elseif ($ceOpen.Count -gt 0) { 'NEEDS REVIEW: no failures, but items need checking or attesting' }
               else { 'READY (this device): Cyber Essentials device controls pass' }

    $tc = foreach ($t in $script:CEPlusTestCases) {
        $fs = @($Findings | Where-Object { $_.Frameworks -contains "CE+ $($t.Id)" })
        $state = if ($fs.Count -eq 0) { 'Not assessed' }
                 elseif (@($fs | Where-Object Status -eq 'Fail').Count) { 'Likely fail' }
                 elseif (@($fs | Where-Object { @('Warn', 'Manual', 'Skipped', 'Error') -contains $_.Status }).Count) { 'Check' }
                 else { 'Likely pass' }
        if ($state -eq 'Likely pass' -and $t.ContainsKey('EvidenceCheck')) {
            $proof = @($fs | Where-Object { $_.CheckId -eq $t.EvidenceCheck })
            if ($proof.Count -eq 0 -or @($proof | Where-Object { $_.Status -ne 'Pass' }).Count) { $state = 'Check' }
        }
        [pscustomobject]@{
            TestCase = $t.Id
            Name     = $t.Name
            State    = $state
            Failing  = @($fs | Where-Object Status -eq 'Fail' | ForEach-Object FindingId)
            Scope    = $t.Scope
        }
    }

    return [pscustomobject]@{
        Verdict      = $verdict
        PartialRun   = [bool]$PartialRun
        ByStatus     = $byStatus
        ByCategory   = @($byCategory)
        AutoFails    = @($autoFails | ForEach-Object FindingId)
        CEFailCount  = $ceFails.Count
        CEPlus       = @($tc)
    }
}

function ConvertTo-CEHtmlText {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function ConvertTo-CEMarkdownCell {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '\|', '\|' -replace "`r?`n", ' ')
}

function Get-CECategoryLabel {
    param([string]$Category)
    if ($Category -and $script:CECategoryLabels.Contains($Category)) { return $script:CECategoryLabels[$Category] }
    return $Category
}

function Get-CEHardwareRow {
    <# Label/value pairs describing the device hardware, shared by the Markdown and HTML reports. #>
    param($Context)
    $hw = Get-CEObjectValue $Context 'Hardware'
    if ($null -eq $hw) { return ,@() }
    $rows = New-Object System.Collections.ArrayList
    $add = { param($label, $value) if ("$value".Trim()) { [void]$rows.Add([pscustomobject]@{ Label = $label; Value = "$value".Trim() }) } }
    # Avoid 'Dell Inc. Dell Pro Max' when the model already starts with the brand.
    $brand = ("$($hw.Manufacturer)" -split '\s+')[0]
    $model = if ($brand -and "$($hw.Model)" -like "$brand*") { "$($hw.Model)" } else { "$($hw.Manufacturer) $($hw.Model)".Trim() }
    if ($hw.SystemSku) { $model += " (SKU $($hw.SystemSku))" }
    if ($hw.IsVirtualMachine) { $model += ' [virtual machine]' }
    & $add 'Model' $model
    & $add 'Serial number' $hw.SerialNumber
    & $add 'Baseboard' $hw.Baseboard
    $fw = $hw.Firmware
    & $add 'BIOS/UEFI' ("$($fw.Vendor) $($fw.Version)".Trim() + $(if ($fw.ReleaseDate) { ", released $($fw.ReleaseDate)" }) + $(if ($fw.Type) { " ($($fw.Type))" }))
    $tpm = $hw.Tpm
    $tpmText = if (-not $tpm.Readable) { 'Not read (needs elevation)' }
               elseif (-not $tpm.Present) { 'None found' }
               else { "$($tpm.Manufacturer) firmware $($tpm.FirmwareVersion), TPM $($tpm.SpecVersion)" }
    & $add 'TPM' $tpmText
    foreach ($c in @($hw.Cpu)) {
        & $add 'CPU' ("$($c.Name)" + $(if ($c.Cores) { ", $($c.Cores) cores" }) + $(if ($c.MicrocodeRevision) { ", microcode $($c.MicrocodeRevision)" }))
    }
    foreach ($d in @($hw.Disks)) {
        & $add 'Disk' ("$($d.Model)" + $(if ($d.SizeGB) { ", $($d.SizeGB) GB" }) + $(if ($d.InterfaceType) { ", $($d.InterfaceType)" }) + $(if ($d.FirmwareRevision) { ", firmware $($d.FirmwareRevision)" }) + $(if ($d.SerialNumber) { ", serial $($d.SerialNumber)" }))
    }
    return ,$rows.ToArray()
}

function Get-CEMalwareTestInfo {
    <# Test file links and the MP-11 result, for the malware download test section of the reports. #>
    param($Findings)
    $cfg = (Get-CEConfig).'malware-test'
    if ($null -eq $cfg) { return $null }
    $files = @(@(Get-CEObjectValue $cfg 'testFiles' @()) | Where-Object { "$(Get-CEObjectValue $_ 'url' '')" -match '^https://' })
    $result = @($Findings | Where-Object { $_.CheckId -eq 'MP-11' }) | Select-Object -First 1
    return [pscustomobject]@{
        Files        = $files
        DownloadPage = [string](Get-CEObjectValue $cfg 'downloadPage' '')
        Result       = $result
    }
}

function Export-CEMarkdown {
    param($Findings, $Summary, $Context, $Changeset, [string]$Path, [string]$ChangesetPath)

    $sb = New-Object System.Text.StringBuilder
    $w = { param($line) [void]$sb.AppendLine($line) }

    & $w "# Engramic Baseline device audit: $($Context.ComputerName)"
    & $w ''
    & $w "- **Audited:** $($Context.AuditTime.ToString('yyyy-MM-dd HH:mm')) by $($Context.RunningAs)$(if (-not $Context.IsElevated) { ' (not elevated: some checks skipped)' })"
    & $w "- **OS:** $($Context.OSFamily) $($Context.DisplayVersion) $($Context.EditionID), build $($Context.FullBuild)"
    & $w "- **Join state:** domain=$($Context.DomainJoined), Entra ID=$($Context.EntraJoined), MDM=$($Context.MdmEnrolled)"
    & $w '- **Standard:** Cyber Essentials Requirements for IT Infrastructure v3.3 (Danzell), CE+ test specification, NCSC Windows device guidance'
    $packs = @(Get-CEPack | Where-Object { $_.Status -eq 'Loaded' })
    if ($packs.Count) { & $w "- **Packs:** $((@($packs | ForEach-Object { "$($_.Name) $($_.Version)" })) -join ', ')" }
    & $w ''
    $checkMap = Get-CEStatusCheckMap -Findings $Findings
    $fwRoll = Get-CEFrameworkRollup -CheckMap $checkMap -Summary $Summary
    $ai = Get-CEAiPosture -Context $Context
    if ($Summary.PartialRun) {
        & $w "## $($Summary.Verdict)"
        & $w ''
    }
    else {
        & $w '## AI on this device'
        & $w ''
        & $w "**$($ai.agentsFound) AI tool(s) found** - $(if ($ai.contained) { 'contained (none running as administrator, no root distribution)' } else { "$($ai.deviations) deviation(s)" })."
        & $w ''
        foreach ($a in @($ai.agents)) {
            $how = if ($a.elevated -or $a.asSystem) { '**running as administrator**' } elseif ($a.running) { 'running, standard user' } else { 'present' }
            & $w "- $($a.name) - $how"
        }
        foreach ($env in @($ai.environments)) {
            if ($env.type -eq 'wsl') { & $w "- WSL $($env.wslVersion): $($env.name) - $(if ($env.defaultUidRoot) { '**defaults to root**' } else { 'non-root' })" }
            else { & $w "- $($env.type): $($env.name)" }
        }
        & $w ''
        & $w '## Frameworks'
        & $w ''
        & $w '| Framework | Met | % of applicable |'
        & $w '|---|---|---:|'
        foreach ($k in $fwRoll.Keys) {
            $x = $fwRoll[$k]
            if ($k -eq 'ce-plus') { & $w "| $($x.label) | $($x.onTrack) / $($x.total) TCs on track | - |" }
            else { & $w "| $($x.label) | $($x.met) / $($x.applicable) controls | $($x.metPct)% |" }
        }
        & $w ''
    }
    & $w ('| ' + (($Summary.ByStatus.Keys) -join ' | ') + ' |')
    & $w ('|' + (($Summary.ByStatus.Keys | ForEach-Object { '---:' }) -join '|') + '|')
    & $w ('| ' + (($Summary.ByStatus.Values) -join ' | ') + ' |')
    & $w ''
    if ($Summary.AutoFails.Count) {
        & $w '### Automatic-fail items'
        & $w ''
        foreach ($id in $Summary.AutoFails) {
            $f = $Findings | Where-Object FindingId -eq $id | Select-Object -First 1
            & $w "- **$id** $($f.Title): $($f.Actual)"
        }
        & $w ''
    }
    & $w '## Cyber Essentials Plus readiness (device tests)'
    & $w ''
    & $w '| Test | What is tested | Estimate |'
    & $w '|---|---|---|'
    foreach ($t in $Summary.CEPlus) { & $w "| $($t.TestCase) $($t.Name) | $(ConvertTo-CEMarkdownCell $t.Scope) | **$($t.State)** |" }
    & $w ''
    $mt = Get-CEMalwareTestInfo $Findings
    if ($mt -and @($mt.Files).Count) {
        & $w '## Malware download test (CE+ TC3)'
        & $w ''
        & $w "Last result: **$(if ($mt.Result) { $mt.Result.Status } else { 'not checked' })**$(if ($mt.Result) { " - $(ConvertTo-CEMarkdownCell $mt.Result.Actual)" })"
        & $w ''
        & $w 'In each browser used on this device, download these harmless EICAR test files. Browsers show some of them as text instead of downloading, so save those with Save link as. Anti-malware should block each download or delete the file at once. Expect an alert in your antivirus console. Then run the audit again to record the result.'
        & $w ''
        foreach ($file in $mt.Files) { & $w "- [$($file.name)]($($file.url))$(if (Get-CEObjectValue $file 'saveAs' $false) { ' (right-click and choose Save link as)' })" }
        & $w ''
    }
    $hwRows = Get-CEHardwareRow $Context
    if ($hwRows.Count) {
        & $w '## Device hardware'
        & $w ''
        & $w '| Component | Details |'
        & $w '|---|---|'
        foreach ($r in $hwRows) { & $w "| $($r.Label) | $(ConvertTo-CEMarkdownCell $r.Value) |" }
        & $w ''
    }
    & $w '## By control theme'
    & $w ''
    & $w '| Theme | Pass | Fail | Warn | Manual | Other |'
    & $w '|---|---:|---:|---:|---:|---:|'
    foreach ($c in $Summary.ByCategory) { & $w "| $(Get-CECategoryLabel $c.Category) | $($c.Pass) | $($c.Fail) | $($c.Warn) | $($c.Manual) | $($c.Other) |" }
    & $w ''
    & $w "## Changeset ($(@($Changeset.Items).Count) automated, $(@($Changeset.ManualActions).Count) manual)"
    & $w ''
    & $w "Review and apply with: ``.\app\Apply-CEChangeset.ps1 -Path '$ChangesetPath' -WhatIf``"
    & $w ''
    if (@($Changeset.Items).Count) {
        & $w '| Item | Sel | Change | Why | Severity | Risk | Reboot |'
        & $w '|---|:-:|---|---|---|---|:-:|'
        foreach ($i in $Changeset.Items) {
            $sel = if ($i.Selected) { 'x' } else { ' ' }
            $af = if ($i.AutoFail) { ' **AUTO-FAIL**' } else { '' }
            & $w "| $($i.ItemId) | $sel | $(ConvertTo-CEMarkdownCell $i.Title) ($($i.RemediationId)) | $(ConvertTo-CEMarkdownCell $i.Why) | $($i.Severity)$af | $($i.Risk) | $(if ($i.RequiresReboot) { 'yes' }) |"
        }
        & $w ''
    }
    if (@($Changeset.ManualActions).Count) {
        & $w '### Manual actions'
        & $w ''
        foreach ($m in $Changeset.ManualActions) {
            $af = if ($m.AutoFail) { ' **AUTO-FAIL**' } else { '' }
            & $w "- [ ] **$($m.FindingId)** [$($m.Status)/$($m.Severity)]$af $($m.Title): $($m.Actual)"
            if ($m.Recommendation) { & $w "  - $($m.Recommendation)" }
        }
        & $w ''
    }
    & $w '## All findings'
    foreach ($cat in $script:CEValidCategory) {
        $fs = @($Findings | Where-Object Category -eq $cat)
        if (-not $fs.Count) { continue }
        & $w ''
        & $w "### $(Get-CECategoryLabel $cat)"
        & $w ''
        & $w '| ID | Status | Check | Result | Frameworks |'
        & $w '|---|---|---|---|---|'
        foreach ($f in $fs) {
            $t = if ($f.Subject) { "$($f.Title) ($($f.Subject))" } else { $f.Title }
            & $w "| $($f.FindingId) | $($f.Status) | $(ConvertTo-CEMarkdownCell $t) | $(ConvertTo-CEMarkdownCell $f.Actual) | $($f.Frameworks -join ', ') |"
        }
    }
    & $w ''
    & $w '---'
    & $w 'This report supports self-assessment. It does not replace assessment by an IASME-licensed Certification Body, and it cannot see network devices, cloud tenants or other devices in scope.'
    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8
}

function Export-CEHtml {
    param($Findings, $Summary, $Context, $Changeset, [string]$Path, [string]$ChangesetPath)

    $e = { param($t) ConvertTo-CEHtmlText $t }
    # Status/severity presentation comes from the shared model (Get-CEStatusStyle /
    # Get-CESeverityStyle) so the report and the app match exactly.
    $sevStyles = Get-CESeverityStyle
    $sevTokL = (@($sevStyles.Keys | ForEach-Object { "--sev-$($_):$($sevStyles[$_].Light);" }) -join ' ')
    $sevTokD = (@($sevStyles.Keys | ForEach-Object { "--sev-$($_):$($sevStyles[$_].Dark);" }) -join ' ')
    $sevClasses = (@($sevStyles.Keys | ForEach-Object { ".sev-$($_){color:var(--sev-$($_));font-weight:600}" }) -join ' ')
    $stPill = { param($s) $x = Get-CEStatusStyle ([string]$s); "<span class='st st-$s'>&#$($x.Icon); $(ConvertTo-CEHtmlText $x.Label)</span>" }
    $sevCell = { param($sv) if (-not "$sv") { return '' } "<span class='sev sev-$sv'>$(ConvertTo-CEHtmlText ([string]$sv))</span>" }
    $rows = foreach ($f in $Findings) {
        $t = if ($f.Subject) { "$($f.Title) <span class='sub'>($(& $e $f.Subject))</span>" } else { & $e $f.Title }
        $ev = ''
        if (@($f.Evidence).Count) {
            $ev = "<details><summary>Evidence ($(@($f.Evidence).Count))</summary><pre>" + ((@($f.Evidence) | ForEach-Object { & $e ([string]$_) }) -join "`n") + '</pre></details>'
        }
        $af = if ($f.AutoFail) { "<span class='badge autofail'>AUTO-FAIL</span>" } else { '' }
        $rem = if ($f.Remediation) { "<div class='rem'>Automated fix: <code>$(& $e $f.Remediation.Id)</code></div>" } else { '' }
@"
<tr data-status="$($f.Status)" data-cat="$($f.Category)">
<td><code>$(& $e $f.FindingId)</code></td>
<td>$(& $stPill $f.Status)$af</td>
<td><strong>$t</strong><div class="ref">$(& $e $f.Reference)</div></td>
<td><div>$(& $e $f.Actual)</div><div class="exp">Expected: $(& $e $f.Expected)</div>$(if ($f.Recommendation) { "<div class='rec'>$(& $e $f.Recommendation)</div>" })$rem$ev</td>
<td>$(& $sevCell $f.Severity)</td>
<td>$((@($f.Frameworks) | ForEach-Object { "<span class='fw'>$(& $e $_)</span>" }) -join ' ')</td>
</tr>
"@
    }

    $tcRows = foreach ($t in $Summary.CEPlus) {
        $cls = switch ($t.State) { 'Likely pass' { 'Pass' } 'Likely fail' { 'Fail' } 'Check' { 'Warn' } default { 'Skipped' } }
        "<tr><td><strong>$($t.TestCase)</strong> $(& $e $t.Name)</td><td>$(& $e $t.Scope)</td><td><span class='st st-$cls'>&#$((Get-CEStatusStyle $cls).Icon); $(& $e $t.State)</span></td></tr>"
    }
    $mt = Get-CEMalwareTestInfo $Findings
    $mtHtml = ''
    if ($mt -and @($mt.Files).Count) {
        $mtStatus = if ($mt.Result) { [string]$mt.Result.Status } else { 'Skipped' }
        $mtText = if ($mt.Result) { & $e $mt.Result.Actual } else { 'MP-11 was not run.' }
        $links = ($mt.Files | ForEach-Object {
            $how = if (Get-CEObjectValue $_ 'saveAs' $false) { ' <span class="ref">right-click and choose <em>Save link as</em></span>' } else { ' <span class="ref">click to download</span>' }
            "<li><a href=`"$(& $e $_.url)`" target=`"_blank`" rel=`"noopener noreferrer`">$(& $e $_.name)</a>$how</li>"
        }) -join ''
        $page = if ($mt.DownloadPage -match '^https://') { " More formats are on <a href=`"$(& $e $mt.DownloadPage)`" target=`"_blank`" rel=`"noopener noreferrer`">EICAR's download page</a>." } else { '' }
        $mtHtml = @"
<h2 id="malware-test">Malware download test (CE+ TC3)</h2>
<div class="testbox">
<p>A Cyber Essentials Plus assessor checks that malware is stopped when someone downloads it. You can run the same test here with EICAR's industry-standard test files. They are harmless, but every anti-malware product treats them as malware.</p>
<p class="warnline"><strong>Expect an alert.</strong> Your anti-malware will report a detection, and your IT or security team may see it in their console. Let them know before you test.</p>
<ol>
<li>Open this report in each browser used on this device and download each file below. Browsers show the plain files as text instead of downloading them, so right-click those and choose <em>Save link as</em>.</li>
<li><strong>Protected:</strong> the browser or anti-malware blocks the download, or the file is deleted as soon as it arrives.<br><strong>Not protected:</strong> the file stays in Downloads or opens. Delete it and fix malware protection before going further.</li>
<li>Run the audit again to record the result. Microsoft Defender detections are picked up automatically. With other anti-malware, record the outcome in <code>config/malware-test.json</code>.</li>
</ol>
<ul class="testfiles">$links</ul>
<p class="ref">Nothing malicious is included with this tool: the links go to EICAR (eicar.org).$page</p>
<p>Last result: $(& $stPill $mtStatus) $mtText</p>
</div>
"@
    }
    $hwRows = Get-CEHardwareRow $Context
    $hwHtml = ''
    if ($hwRows.Count) {
        $hwHtml = "<h2>Device hardware</h2>`n<div class=`"tablewrap`"><table><thead><tr><th>Component</th><th>Details</th></tr></thead><tbody>" +
            (($hwRows | ForEach-Object { "<tr><td>$(& $e $_.Label)</td><td>$(& $e $_.Value)</td></tr>" }) -join '') + '</tbody></table></div>'
    }
    $itemRows = foreach ($i in $Changeset.Items) {
        $af = if ($i.AutoFail) { "<span class='badge autofail'>AUTO-FAIL</span>" } else { '' }
        $sel = if ($i.Selected) { 'Yes' } else { 'No' }
        "<tr><td><code>$($i.ItemId)</code></td><td>$sel</td><td><strong>$(& $e $i.Title)</strong><div class='ref'><code>$(& $e $i.RemediationId)</code> for $(& $e ($i.FindingIds -join ', '))</div>$(if ($i.Notes) { "<div class='rec'>$(& $e $i.Notes)</div>" })</td><td>$(& $e $i.Why)</td><td>$(& $sevCell $i.Severity) $af</td><td>$(& $sevCell $i.Risk)</td><td>$(if ($i.RequiresReboot) { 'Yes' })</td></tr>"
    }
    $manualRows = foreach ($m in $Changeset.ManualActions) {
        $af = if ($m.AutoFail) { "<span class='badge autofail'>AUTO-FAIL</span>" } else { '' }
        "<li>$(& $stPill $m.Status)$af <strong>$(& $e $m.Title)</strong> <code>$(& $e $m.FindingId)</code><br>$(& $e $m.Actual)<div class='rec'>$(& $e $m.Recommendation)</div></li>"
    }
    $statCards = foreach ($k in @('Pass', 'Fail', 'Warn', 'Manual', 'Skipped', 'NotApplicable', 'Error')) {
        $label = if ($k -eq 'NotApplicable') { 'Not applicable' } else { $k }
        "<button class='card st-$k$(if ($Summary.ByStatus[$k] -eq 0) { ' zero' })' data-filter='$k'><span class='n'>$($Summary.ByStatus[$k])</span><span class='l'>&#$((Get-CEStatusStyle $k).Icon); $label</span></button>"
    }
    $checkMap = Get-CEStatusCheckMap -Findings $Findings
    $fwRoll = Get-CEFrameworkRollup -CheckMap $checkMap -Summary $Summary
    $aiPosture = Get-CEAiPosture -Context $Context

    $attn = @($checkMap.Keys | Where-Object { @('Fail', 'Warn', 'Error') -contains [string]$checkMap[$_].status }).Count
    $confirm = @($checkMap.Keys | Where-Object { [string]$checkMap[$_].status -eq 'Manual' }).Count
    $aiMsg = if ($aiPosture.agentsFound -eq 0) { 'no AI tools detected' } elseif ($aiPosture.contained) { 'AI tools contained' } else { "$($aiPosture.deviations) AI deviation(s)" }
    $ctrlMsg = if ($attn) { "<span class='bad'>$attn control$(if ($attn -ne 1) { 's' }) need attention</span>" } else { 'No controls failing' }
    if ($confirm) { $ctrlMsg += " &middot; $confirm to confirm" }
    $msgHtml = if ($Summary.PartialRun) { "<div class='msg'>$(& $e $Summary.Verdict)</div>" } else { "<div class='msg'>$ctrlMsg. $aiMsg.</div>" }

    $fwBars = ''
    if (-not $Summary.PartialRun) {
        $fwBars = "<h2>Frameworks</h2><div class='fwbars'>"
        foreach ($k in $fwRoll.Keys) {
            $x = $fwRoll[$k]
            if ($k -eq 'ce-plus') { $pct = if ($x.total) { [int][math]::Round(($x.onTrack / $x.total) * 100) } else { 0 }; $frac = "$($x.onTrack) / $($x.total) TCs"; $dev = $x.total - $x.onTrack }
            else { $pct = $x.metPct; $frac = "$($x.met) / $($x.applicable)"; $dev = $x.attention + $x.confirm }
            $devCls = if ($dev -gt 0) { '' } else { 'ok' }
            $devTxt = if ($dev -gt 0) { "&#9660; $dev" } else { '&mdash;' }
            $fwBars += "<div class='fwbar'><div class='lab'>$(& $e $x.label)</div><div class='frac'>$frac</div><div class='track'><div class='fill' style='width:$pct%'></div></div><div class='pct'>$pct%</div><div class='dev $devCls'>$devTxt</div></div>"
        }
        $fwBars += '</div>'
    }

    $agentsLi = (@($aiPosture.agents) | ForEach-Object {
            $how = if ($_.elevated -or $_.asSystem) { "<span class='agent-admin'>running as administrator</span>" } elseif ($_.running) { 'running, standard user' } else { 'present' }
            "<li>$(& $e $_.name) &mdash; $how</li>"
        }) -join ''
    $envLi = (@($aiPosture.environments) | ForEach-Object {
            if ($_.type -eq 'wsl') {
                $root = if ($_.defaultUidRoot) { "<span class='agent-admin'>defaults to root</span>" } else { 'non-root' }
                "<li>WSL $($_.wslVersion): $(& $e $_.name) &mdash; $root$(if ($_.autoMount) { ', Windows drives mounted' })</li>"
            }
            else { "<li>$(& $e $_.type): $(& $e $_.name)</li>" }
        }) -join ''
    $mcpLi = (@($aiPosture.mcpServers) | Where-Object { $_.serverName } | ForEach-Object {
            $creds = @($_.credentials)
            $plainN = @($creds | Where-Object { $_.storage -eq 'plaintext-config' }).Count
            $credTxt = if (-not $creds.Count) { 'no credentials' }
            elseif ($plainN) { "<span class='agent-admin'>$plainN credential$(if ($plainN -ne 1) { 's' }) in plaintext</span>" }
            else { "$($creds.Count) credential$(if ($creds.Count -ne 1) { 's' }), referenced" }
            $detail = if ($_.endpoint) { [string]$_.endpoint } elseif ($_.command) { [string]$_.command } else { '' }
            "<li>$(& $e $_.serverName) <span class='ref'>($(& $e $_.toolId), $(& $e $_.transport))</span>$(if ($detail) { " &mdash; $(& $e $detail)" }) &mdash; $credTxt</li>"
        }) -join ''
    $aiDevCls = if ($aiPosture.contained) { 'ok' } else { 'bad' }
    $aiDevTxt = if ($aiPosture.contained) { 'contained' } else { "$($aiPosture.deviations) deviation(s)" }
    $aiEmpty = if ($aiPosture.agentsFound -eq 0) { "<p class='ref'>No AI tools detected in this session.$(if ($Context.IsSystem) { ' Shadow AI is collected per user; run as the signed-in user for the full picture.' })</p>" } else { '' }
    $aiHtml = "<h2 id='ai'>AI on this device</h2><div class='aibox'><div class='h'><strong>$($aiPosture.agentsFound) AI tool(s) found</strong><span class='dev0 $aiDevCls'>$aiDevTxt</span></div>$aiEmpty$(if ($agentsLi) { "<ul>$agentsLi</ul>" })$(if ($envLi) { "<div class='ref' style='margin-top:8px'>Where AI runs</div><ul>$envLi</ul>" })$(if ($mcpLi) { "<div class='ref' style='margin-top:8px'>MCP servers</div><ul>$mcpLi</ul>" })</div>"

    $applyCmd = & $e ".\app\Apply-CEChangeset.ps1 -Path '$ChangesetPath' -WhatIf"

    $html = @"
<!DOCTYPE html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Engramic Baseline - $(& $e $Context.ComputerName)</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap">
<style>
:root { --bg:#f2f4f4; --fg:#0b0f0e; --muted:#566360; --card:#ffffff; --line:#e2e8e6;
  --pass:#008687; --fail:#c23f2c; --warn:#a9721a; --manual:#3d6aa0; --skip:#7d8783; --brand:#008687; $sevTokL
  --sans:'Geist','Geist Fallback','IBM Plex Sans',system-ui,'Segoe UI',sans-serif;
  --mono:'Geist Mono','IBM Plex Mono',ui-monospace,'Cascadia Mono',Consolas,monospace; }
@media (prefers-color-scheme: dark) { :root { --bg:#0b0e0d; --fg:#eef2f0; --muted:#9aa4a0; --card:#141a18; --line:#253029;
  --pass:#35b8b5; --fail:#e88a7c; --warn:#dcac57; --manual:#8fb2e0; --skip:#8b958f; --brand:#35b8b5; $sevTokD } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 var(--sans); }
main { max-width:1200px; margin:0 auto; padding:24px 16px 64px; }
h1 { font-size:1.6rem; margin:0 0 4px; } h2 { margin-top:36px; font-size:1.2rem; }
.meta { color:var(--muted); font-size:.9rem; }
.verdict { margin:20px 0; padding:14px 18px; border-radius:10px; background:var(--card); border-left:6px solid; font-weight:600; }
.verdict.Pass { border-color:var(--pass); } .verdict.Fail { border-color:var(--fail); } .verdict.Warn { border-color:var(--warn); }
.cards { display:flex; flex-wrap:wrap; gap:8px; }
.card { flex:1 1 110px; background:var(--card); border:1px solid var(--line); border-radius:10px; padding:10px 12px; text-align:left; cursor:pointer; color:inherit; font:inherit; }
.card.active { outline:2px solid currentColor; }
.card .n { display:block; font-size:1.5rem; font-weight:700; } .card .l { font-size:.8rem; color:var(--muted); }
.tablewrap { overflow-x:auto; background:var(--card); border:1px solid var(--line); border-radius:10px; }
table { border-collapse:collapse; width:100%; }
th, td { padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; text-align:left; }
th { font-size:.8rem; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
tr:last-child td { border-bottom:none; }
.st { display:inline-block; font-size:.75rem; font-weight:700; padding:1px 8px; border-radius:99px; border:1px solid currentColor; white-space:nowrap; }
.st-Pass { color:var(--pass); } .st-Fail, .st-Error { color:var(--fail); } .st-Warn { color:var(--warn); } .st-Manual, .st-Info { color:var(--manual); }
.st-Skipped, .st-NotApplicable { color:var(--skip); }
.sev { white-space:nowrap; } $sevClasses
.card.zero { opacity:.5; }
.badge.autofail { display:inline-block; white-space:nowrap; margin:2px 0 0 6px; font-size:.7rem; font-weight:700; color:#fff; background:var(--fail); padding:1px 6px; border-radius:4px; }
.ref, .exp, .sub { color:var(--muted); font-size:.82rem; }
.rec { margin-top:4px; font-size:.88rem; } .rem { margin-top:4px; font-size:.82rem; }
.fw { display:inline-block; font-size:.72rem; border:1px solid var(--line); border-radius:4px; padding:0 4px; margin:1px; white-space:nowrap; }
pre { white-space:pre-wrap; font-size:.8rem; max-height:280px; overflow:auto; background:var(--bg); padding:8px; border-radius:6px; }
code { font-size:.85em; }
.toolbar { display:flex; gap:8px; flex-wrap:wrap; margin:12px 0; }
select, input { font:inherit; padding:6px 8px; border-radius:6px; border:1px solid var(--line); background:var(--card); color:var(--fg); }
ul.manual { padding-left:18px; } ul.manual li { margin-bottom:10px; }
.testbox { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:4px 16px; }
.testbox li { margin-bottom:6px; } .warnline { border-left:4px solid var(--warn); padding-left:10px; }
ul.testfiles a { font-weight:600; }
.cmd { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:10px; overflow-x:auto; }
footer { margin-top:40px; color:var(--muted); font-size:.82rem; }
.brandbar { display:flex; align-items:center; gap:10px; margin-bottom:6px; }
.brandbar .glyph { height:26px; width:31px; color:var(--fg); --glyph-accent:var(--brand); flex:none; }
.brandbar .wm { font-family:var(--sans); font-weight:700; letter-spacing:.12em; text-transform:uppercase; font-size:1.05rem; }
.st, .fw, code, pre { font-family:var(--mono); }
.msg { font-size:1.05rem; font-weight:600; margin:16px 0 12px; text-wrap:balance; }
.msg .bad { color:var(--fail); }
.fwbars { display:flex; flex-direction:column; gap:8px; margin:0 0 22px; }
.fwbar { display:grid; grid-template-columns:200px 72px 1fr 46px 58px; align-items:center; gap:10px; }
.fwbar .lab { font-size:.9rem; } .fwbar .frac { font-family:var(--mono); font-size:.78rem; color:var(--muted); text-align:right; }
.fwbar .track { position:relative; height:15px; background:var(--bg); border:1px solid var(--line); }
.fwbar .fill { position:absolute; top:0; bottom:0; left:0; background:var(--fg); }
.fwbar .pct { font-family:var(--mono); font-size:.85rem; font-weight:700; text-align:right; }
.fwbar .dev { font-family:var(--mono); font-size:.8rem; font-weight:600; text-align:right; color:var(--warn); }
.fwbar .dev.ok { color:var(--muted); }
.aibox { border:1px solid var(--line); border-left:3px solid var(--brand); border-radius:10px; padding:14px 16px; background:var(--card); margin:0 0 8px; }
.aibox .h { display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; align-items:baseline; }
.aibox .dev0 { font-family:var(--mono); font-size:.82rem; font-weight:600; }
.aibox .dev0.ok { color:var(--pass); } .aibox .dev0.bad { color:var(--fail); }
.aibox ul { margin:8px 0 0; padding-left:18px; } .aibox li { margin:2px 0; font-size:.9rem; }
.agent-admin { color:var(--fail); font-weight:600; }
@media (max-width:640px) { .fwbar { grid-template-columns:1fr 58px; } .fwbar .frac, .fwbar .track { grid-column:1 / -1; } }
</style>
</head>
<body>
<main>
<div class="brandbar"><svg class="glyph" viewBox="1.5 5 45 38" aria-hidden="true"><path fill="currentColor" d="M9,6 L30,6 L39,15 L39,30 L9,30 Z"></path><path fill="var(--glyph-accent)" d="M2,35 L46,35 L46,42 L2,42 Z"></path></svg><span class="wm">Engramic Baseline</span></div>
<h1>Device audit</h1>
<div class="meta">$(& $e $Context.ComputerName) &middot; $(& $e "$($Context.OSFamily) $($Context.DisplayVersion) $($Context.EditionID) build $($Context.FullBuild)") &middot; audited $($Context.AuditTime.ToString('d MMMM yyyy HH:mm')) by $(& $e $Context.RunningAs)$(if (-not $Context.IsElevated) { ' &middot; <strong>not elevated: some checks skipped</strong>' })</div>
<div class="meta">Domain joined: $($Context.DomainJoined) &middot; Entra ID joined: $($Context.EntraJoined) &middot; MDM enrolled: $($Context.MdmEnrolled)$(if (@(Get-CEPack | Where-Object { $_.Status -eq 'Loaded' }).Count) { ' &middot; Packs: ' + (& $e ((@(Get-CEPack | Where-Object { $_.Status -eq 'Loaded' } | ForEach-Object { "$($_.Name) $($_.Version)" })) -join ', ')) })</div>
$msgHtml
$aiHtml
$fwBars
<h2>Controls by status</h2>
<div class="cards">$($statCards -join '')</div>

<h2>Cyber Essentials Plus readiness</h2>
<div class="tablewrap"><table><thead><tr><th>Test case</th><th>What is tested</th><th>Estimate</th></tr></thead><tbody>$($tcRows -join '')</tbody></table></div>

$mtHtml

$hwHtml

<h2>Changeset: $(@($Changeset.Items).Count) automated fixes</h2>
<p>Preview, then apply from the repo folder:</p>
<div class="cmd"><code>$applyCmd</code></div>
<div class="tablewrap"><table><thead><tr><th>Item</th><th>Selected</th><th>Change</th><th>Why</th><th>Severity</th><th>Risk</th><th>Reboot</th></tr></thead><tbody>$($itemRows -join '')</tbody></table></div>

<h2>Manual actions ($(@($Changeset.ManualActions).Count))</h2>
<ul class="manual">$($manualRows -join '')</ul>

<h2>All findings</h2>
<div class="toolbar">
<select id="cat"><option value="">All themes</option>$(($script:CEValidCategory | ForEach-Object { "<option value='$_'>$(Get-CECategoryLabel $_)</option>" }) -join '')</select>
<input id="q" type="search" placeholder="Filter text">
</div>
<div class="tablewrap"><table id="findings"><thead><tr><th>ID</th><th>Status</th><th>Check</th><th>Result</th><th>Severity</th><th>Frameworks</th></tr></thead><tbody>
$($rows -join "`n")
</tbody></table></div>
<footer>Checks map to Cyber Essentials: Requirements for IT Infrastructure v3.3 (Danzell), the Cyber Essentials Plus test specification and NCSC Windows device security guidance. This is a self-assessment aid: it does not replace an IASME-licensed Certification Body and cannot see network devices, cloud tenants or other devices in scope.</footer>
</main>
<script>
(function () {
  var status = '';
  var rows = Array.prototype.slice.call(document.querySelectorAll('#findings tbody tr'));
  var cat = document.getElementById('cat'), q = document.getElementById('q');
  function apply() {
    var text = q.value.toLowerCase();
    rows.forEach(function (r) {
      var ok = (!status || r.getAttribute('data-status') === status) &&
               (!cat.value || r.getAttribute('data-cat') === cat.value) &&
               (!text || r.textContent.toLowerCase().indexOf(text) !== -1);
      r.style.display = ok ? '' : 'none';
    });
  }
  Array.prototype.forEach.call(document.querySelectorAll('.card'), function (c) {
    c.addEventListener('click', function () {
      var f = c.getAttribute('data-filter');
      status = (status === f) ? '' : f;
      Array.prototype.forEach.call(document.querySelectorAll('.card'), function (x) { x.classList.toggle('active', x.getAttribute('data-filter') === status); });
      apply();
    });
  });
  cat.addEventListener('change', apply); q.addEventListener('input', apply);
})();
</script>
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
}

function Export-CEReport {
    <#
        Writes findings.json, report.md, report.html, changeset.json and changeset.md
        to OutputPath. Returns the paths.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$PartialRun,
        [int]$ChecksRun = -1
    )
    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $summary = Get-CESummary -Findings $Findings -PartialRun:$PartialRun -ChecksRun $ChecksRun
    $changeset = New-CEChangeset -Findings $Findings -Context $Context

    $paths = [ordered]@{
        Findings      = Join-Path $OutputPath 'findings.json'
        Changeset     = Join-Path $OutputPath 'changeset.json'
        Markdown      = Join-Path $OutputPath 'report.md'
        Html          = Join-Path $OutputPath 'report.html'
    }

    [pscustomobject]@{
        Context  = $Context
        Summary  = $summary
        Findings = $Findings
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $paths.Findings -Encoding UTF8

    $changeset | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $paths.Changeset -Encoding UTF8

    Export-CEMarkdown -Findings $Findings -Summary $summary -Context $Context -Changeset $changeset -Path $paths.Markdown -ChangesetPath $paths.Changeset
    Export-CEHtml -Findings $Findings -Summary $summary -Context $Context -Changeset $changeset -Path $paths.Html -ChangesetPath $paths.Changeset

    return [pscustomobject]@{
        Summary   = $summary
        Changeset = $changeset
        Paths     = [pscustomobject]$paths
    }
}
