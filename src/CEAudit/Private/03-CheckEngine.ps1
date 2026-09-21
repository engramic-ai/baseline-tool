# ---------------------------------------------------------------------------
# Check registry and execution engine.
#
# A check is registered once with its metadata (what requirement it maps to,
# how severe a failure is, whether it is a Cyber Essentials auto-fail) and a
# Test scriptblock. The Test scriptblock returns one or more results created
# with New-CEResult. The engine merges metadata + result into a Finding.
# ---------------------------------------------------------------------------

$script:CEValidStatus   = @('Pass', 'Fail', 'Warn', 'Manual', 'Info', 'NotApplicable', 'Skipped', 'Error')
$script:CEValidSeverity = @('Critical', 'High', 'Medium', 'Low', 'Info')
# Categories in report order. Packs add their own with Register-CECategory.
$script:CECategoryLabels = [ordered]@{
    Firewalls                = 'Firewalls'
    SecureConfiguration      = 'Secure configuration'
    SecurityUpdateManagement = 'Security update management'
    UserAccessControl        = 'User access control'
    MalwareProtection        = 'Malware protection'
    NCSCHardening            = 'NCSC hardening (beyond CE)'
}
$script:CEValidCategory = New-Object System.Collections.ArrayList
foreach ($key in $script:CECategoryLabels.Keys) { [void]$script:CEValidCategory.Add($key) }
$script:CECategoryPack = @{}

function Register-CECategory {
    <# Adds a finding category (used by packs). Ids are PascalCase words, e.g. AIAgents. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Z][A-Za-z0-9]{2,39}$')][string]$Id,
        [Parameter(Mandatory)][ValidateLength(1, 60)][string]$Label
    )
    if ($script:CEValidCategory -contains $Id) { throw "Category '$Id' already exists" }
    $script:CECategoryLabels[$Id] = $Label
    [void]$script:CEValidCategory.Add($Id)
    $script:CECategoryPack[$Id] = $script:CECurrentPack
}

function Get-CECategory {
    <# Registered categories in report order, with the pack that added them (empty for built-in ones). #>
    [CmdletBinding()]
    param()
    return @($script:CEValidCategory | ForEach-Object {
        [pscustomobject]@{ Id = $_; Label = $script:CECategoryLabels[$_]; Pack = $(if ($script:CECategoryPack.ContainsKey($_)) { $script:CECategoryPack[$_] } else { $null }) }
    })
}

function Register-CECheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Z]{2}-\d{2}$')][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Category,
        # Which frameworks the check evidences, e.g. 'CE v3.3', 'CE+ TC2', 'NCSC'
        [Parameter(Mandatory)][string[]]$Frameworks,
        # Human-readable pointer to the requirement text.
        [Parameter(Mandatory)][string]$Reference,
        [Parameter(Mandatory)][string]$Severity,
        # True when failing this check fails a CE assessment outright (v3.3 auto-fail questions).
        [switch]$AutoFail,
        [switch]$RequiresAdmin,
        # Machine checks assess the device and run as SYSTEM or the user. User checks
        # assess the signed-in person's footprint (shadow AI, their WSL, their agents)
        # and are only meaningful in that user's own session - see Invoke-CEUserProbe.ps1.
        [ValidateSet('Machine', 'User')][string]$Scope = 'Machine',
        # Optional: return $false (or a string reason) when the check does not apply.
        [scriptblock]$AppliesTo,
        [Parameter(Mandatory)][scriptblock]$Test
    )
    if ($script:CEValidCategory -notcontains $Category) { throw "Invalid category '$Category' for $Id" }
    if ($script:CEValidSeverity -notcontains $Severity) { throw "Invalid severity '$Severity' for $Id" }
    if ($script:CEChecks | Where-Object { $_.Id -eq $Id }) { throw "Duplicate check id $Id" }

    [void]$script:CEChecks.Add([pscustomobject]@{
        Id            = $Id
        Title         = $Title
        Category      = $Category
        Frameworks    = $Frameworks
        Reference     = $Reference
        Severity      = $Severity
        AutoFail      = [bool]$AutoFail
        RequiresAdmin = [bool]$RequiresAdmin
        Scope         = $Scope
        AppliesTo     = $AppliesTo
        Test          = $Test
        # Id of the pack that registered the check; $null for built-in checks.
        Pack          = $script:CECurrentPack
    })
}

function Get-CECheck {
    [CmdletBinding()]
    param(
        [string[]]$Id,
        [string[]]$Category,
        [string[]]$Framework,
        [ValidateSet('Machine', 'User')][string[]]$Scope
    )
    $checks = $script:CEChecks
    if ($Id)        { $checks = $checks | Where-Object { $Id -contains $_.Id } }
    if ($Category)  { $checks = $checks | Where-Object { $Category -contains $_.Category } }
    if ($Scope)     { $checks = $checks | Where-Object { $Scope -contains $_.Scope } }
    if ($Framework) {
        $checks = $checks | Where-Object {
            $fw = $_.Frameworks
            @($Framework | Where-Object { $f = $_; @($fw | Where-Object { $_ -like "$f*" }).Count -gt 0 }).Count -gt 0
        }
    }
    return @($checks)
}

function New-CERemediationRef {
    <#
        Points a result at a remediation in the library (Remediations\*.ps1).
        Parameters must be simple values; they are validated again at apply time.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [hashtable]$Parameters = @{}
    )
    return [pscustomobject]@{
        Id         = $Id
        Parameters = $Parameters
    }
}

function New-CEResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Status,
        [string]$Expected = '',
        [string]$Actual = '',
        [string]$Recommendation = '',
        # Optional subject when one check yields several results (e.g. per account, per app).
        [string]$Subject = '',
        [object[]]$Evidence = @(),
        # Override the check's default severity for this result.
        [string]$Severity,
        [object]$Remediation = $null
    )
    if ($script:CEValidStatus -notcontains $Status) { throw "Invalid status '$Status'" }
    return [pscustomobject]@{
        PSTypeName     = 'CEAudit.Result'
        Status         = $Status
        Expected       = $Expected
        Actual         = $Actual
        Recommendation = $Recommendation
        Subject        = $Subject
        Evidence       = $Evidence
        Severity       = $Severity
        Remediation    = $Remediation
    }
}

function ConvertTo-CEFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Check,
        [Parameter(Mandatory)]$Result
    )
    $findingId = $Check.Id
    if ($Result.Subject) {
        $slug = ($Result.Subject -replace '[^A-Za-z0-9]+', '-').Trim('-')
        if ($slug.Length -gt 40) { $slug = $slug.Substring(0, 40) }
        $findingId = "$($Check.Id):$slug"
    }
    $severity = $Check.Severity
    if ($Result.Severity) { $severity = $Result.Severity }
    if (@('Pass', 'NotApplicable', 'Info') -contains $Result.Status) { $effectiveSeverity = 'Info' } else { $effectiveSeverity = $severity }

    return [pscustomobject]@{
        FindingId      = $findingId
        CheckId        = $Check.Id
        Title          = $Check.Title
        Subject        = $Result.Subject
        Category       = $Check.Category
        Frameworks     = @($Check.Frameworks)
        Reference      = $Check.Reference
        Scope          = $Check.Scope
        Status         = $Result.Status
        Severity       = $effectiveSeverity
        AutoFail       = ($Check.AutoFail -and $Result.Status -eq 'Fail')
        Expected       = $Result.Expected
        Actual         = $Result.Actual
        Recommendation = $Result.Recommendation
        Evidence       = @($Result.Evidence)
        Remediation    = $Result.Remediation
        Pack           = $Check.Pack
    }
}

function Invoke-CEAuditCore {
    <#
        Runs the registered checks and returns findings. Each check is isolated:
        an exception becomes an 'Error' finding rather than aborting the audit.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Id,
        [string[]]$Category,
        [string[]]$Framework,
        [ValidateSet('Machine', 'User')][string[]]$Scope,
        [string[]]$ExcludeId,
        # Optional synchronized hashtable updated with Current/Done/Total for UIs.
        [hashtable]$ProgressState
    )
    $ctx = Get-CEDeviceContext
    # Pass -Scope only when set; its ValidateSet rejects a $null argument. Wrap the
    # whole if in @() so a single check is not unrolled to a scalar.
    $checks = @(
        if ($Scope) { Get-CECheck -Id $Id -Category $Category -Framework $Framework -Scope $Scope }
        else { Get-CECheck -Id $Id -Category $Category -Framework $Framework }
    )
    if ($ExcludeId) { $checks = @($checks | Where-Object { $ExcludeId -notcontains $_.Id }) }

    $i = 0
    foreach ($check in $checks) {
        $i++
        Write-Progress -Activity 'Cyber Essentials audit' -Status "$($check.Id) $($check.Title)" -PercentComplete (($i / [math]::Max($checks.Count, 1)) * 100)
        if ($ProgressState) { $ProgressState.Current = "$($check.Id) $($check.Title)"; $ProgressState.Done = $i - 1; $ProgressState.Total = $checks.Count }

        if ($check.RequiresAdmin -and -not $ctx.IsElevated) {
            ConvertTo-CEFinding -Check $check -Result (New-CEResult -Status 'Skipped' -Actual 'Not run: requires an elevated (Run as administrator) PowerShell session.' -Recommendation 'Re-run the audit from an elevated PowerShell prompt.')
            continue
        }

        if ($check.AppliesTo) {
            $applies = $null
            try { $applies = & $check.AppliesTo $ctx } catch { $applies = "Applicability test failed: $_" }
            if ($applies -is [string] -or $applies -eq $false) {
                $reason = if ($applies -is [string]) { $applies } else { 'Not applicable to this device.' }
                ConvertTo-CEFinding -Check $check -Result (New-CEResult -Status 'NotApplicable' -Actual $reason)
                continue
            }
        }

        try {
            $results = @(& $check.Test $ctx)
            if ($results.Count -eq 0) {
                $results = @(New-CEResult -Status 'Error' -Actual 'Check returned no result.')
            }
            foreach ($r in $results) {
                if ($null -eq $r -or -not ($r.PSObject.TypeNames -contains 'CEAudit.Result')) { continue }
                ConvertTo-CEFinding -Check $check -Result $r
            }
        }
        catch {
            ConvertTo-CEFinding -Check $check -Result (New-CEResult -Status 'Error' -Actual "Check failed: $($_.Exception.Message)" -Recommendation 'Investigate manually; see Evidence.' -Evidence @("$($_.InvocationInfo.PositionMessage)"))
        }
    }
    Write-Progress -Activity 'Cyber Essentials audit' -Completed
    if ($ProgressState) { $ProgressState.Done = $checks.Count; $ProgressState.Current = 'Finished' }
}
