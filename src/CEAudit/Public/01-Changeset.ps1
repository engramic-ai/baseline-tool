# ---------------------------------------------------------------------------
# Changeset generation: turns findings into an ordered, reviewable list of
# remediation items plus a list of manual actions.
# ---------------------------------------------------------------------------

$script:CESeverityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
$script:CERiskRank = @{ Low = 0; Medium = 1; High = 2 }

function New-CEChangeset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)]$Context
    )
    $actionable = @($Findings | Where-Object { @('Fail', 'Warn') -contains $_.Status -and $_.Remediation })

    # Merge findings that point at the same remediation with the same parameters.
    $groups = [ordered]@{}
    foreach ($f in $actionable) {
        $paramJson = ($f.Remediation.Parameters | ConvertTo-Json -Compress -Depth 5)
        $key = "$($f.Remediation.Id)|$paramJson"
        if (-not $groups.Contains($key)) { $groups[$key] = New-Object System.Collections.ArrayList }
        [void]$groups[$key].Add($f)
    }

    $items = @()
    foreach ($key in $groups.Keys) {
        $fs = $groups[$key]
        $first = $fs[0]
        $rem = Get-CERemediation -Id $first.Remediation.Id
        if (-not $rem) {
            Write-Warning "Finding $($first.FindingId) references unknown remediation '$($first.Remediation.Id)'; skipped."
            continue
        }
        $worst = ($fs | Sort-Object { $script:CESeverityRank[$_.Severity] } | Select-Object -First 1).Severity
        # Name the target in the title when the fix is aimed at something specific.
        $params = ConvertTo-CEHashtable $first.Remediation.Parameters
        $subject = @($fs | Where-Object { $_.Subject } | ForEach-Object { $_.Subject } | Select-Object -Unique)
        $target = $null
        if ($params.ContainsKey('DisplayName')) { $target = $params.DisplayName }
        elseif ($params.ContainsKey('Name')) { $target = $params.Name }
        elseif ($subject.Count -eq 1 -and @(@('RuleName', 'PackageId', 'App', 'Target', 'FeatureName', 'Kind', 'Value') | Where-Object { $params.ContainsKey($_) }).Count -gt 0) { $target = $subject[0] }
        $title = $rem.Title
        if ($target -and $title -notmatch [regex]::Escape([string]$target)) { $title = "$title ($target)" }

        $notes = @()
        if ($rem.Notes) { $notes += $rem.Notes }
        if ($Context.CentrallyManaged -and $rem.RequiresAdmin) {
            $notes += 'Device is centrally managed: make this change in Group Policy / Intune too, or it may be reverted.'
        }

        $items += [pscustomobject]@{
            ItemId         = ''
            Selected       = $rem.SelectedByDefault
            Title          = $title
            RemediationId  = $rem.Id
            Parameters     = $first.Remediation.Parameters
            FindingIds     = @($fs | ForEach-Object { $_.FindingId })
            CheckIds       = @($fs | ForEach-Object { $_.CheckId } | Select-Object -Unique)
            Category       = $first.Category
            Frameworks     = @($fs | ForEach-Object { $_.Frameworks } | Select-Object -Unique)
            Severity       = $worst
            AutoFail       = [bool](@($fs | Where-Object { $_.AutoFail }).Count)
            Risk           = $rem.Risk
            RequiresAdmin  = $rem.RequiresAdmin
            RequiresReboot = $rem.RequiresReboot
            Reversible     = $rem.Reversible
            Why            = (@($fs | ForEach-Object { $_.Actual } | Select-Object -Unique) -join ' | ')
            Notes          = ($notes -join ' ')
        }
    }

    $items = @($items | Sort-Object `
        @{ Expression = { -not $_.AutoFail } }, `
        @{ Expression = { $script:CESeverityRank[$_.Severity] } }, `
        @{ Expression = { $script:CERiskRank[$_.Risk] } }, `
        @{ Expression = { $_.CheckIds[0] } })
    $n = 0
    foreach ($i in $items) { $n++; $i.ItemId = 'C{0:D3}' -f $n }

    $manual = @($Findings |
        Where-Object { (@('Fail', 'Warn', 'Manual') -contains $_.Status) -and -not $_.Remediation } |
        Sort-Object @{ Expression = { $_.Status -ne 'Fail' } }, @{ Expression = { $script:CESeverityRank[$_.Severity] } }, CheckId |
        ForEach-Object {
            [pscustomobject]@{
                FindingId      = $_.FindingId
                Status         = $_.Status
                Severity       = $_.Severity
                AutoFail       = $_.AutoFail
                Title          = if ($_.Subject) { "$($_.Title) ($($_.Subject))" } else { $_.Title }
                Actual         = $_.Actual
                Recommendation = $_.Recommendation
                Frameworks     = $_.Frameworks
            }
        })

    return [pscustomobject]@{
        SchemaVersion  = 1
        GeneratedAt    = (Get-Date).ToString('o')
        ComputerName   = $Context.ComputerName
        OS             = "$($Context.OSFamily) $($Context.DisplayVersion) $($Context.EditionID) ($($Context.FullBuild))"
        GeneratedBy    = $Context.RunningAs
        Items          = $items
        ManualActions  = $manual
    }
}
