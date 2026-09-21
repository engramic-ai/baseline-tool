# ---------------------------------------------------------------------------
# Local evaluation of Intune custom compliance rules, so the rules JSON and the
# discovery script can be tested together before anything is uploaded.
# Mirrors the documented schema: Operator IsEquals/NotEquals/GreaterThan/
# GreaterEquals/LessThan/LessEquals; DataType Boolean/Int64/Double/String/
# DateTime/Version.
# ---------------------------------------------------------------------------

function ConvertTo-CERuleValue {
    param($Value, [string]$DataType)
    switch ($DataType) {
        'Boolean' {
            if ($Value -is [bool]) { return $Value }
            if ([string]$Value -match '^(?i:true|false)$') { return [bool]::Parse([string]$Value) }
            throw "not a Boolean: '$Value'"
        }
        'Int64' {
            $n = [long]0
            if ($Value -is [bool] -or -not [long]::TryParse([string]$Value, [ref]$n)) { throw "not an Int64: '$Value'" }
            return $n
        }
        'Double' {
            $d = [double]0
            if (-not [double]::TryParse([string]$Value, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { throw "not a Double: '$Value'" }
            return $d
        }
        'String' {
            if ($Value -isnot [string]) { throw "not a String: '$Value'" }
            return $Value
        }
        'DateTime' {
            if ($Value -is [datetime]) { return $Value }
            return [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture)
        }
        'Version' { return [version][string]$Value }
        default { throw "unsupported DataType '$DataType'" }
    }
}

function Test-CEComplianceRules {
    <#
        Evaluates discovery output (JSON string) against a custom compliance
        rules file. Returns one object per rule plus validation problems.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DiscoveryOutput,
        [Parameter(Mandatory)][string]$RulesPath
    )
    $problems = @()
    $text = $DiscoveryOutput.Trim()
    if ($text -match "[`r`n]") { $problems += 'Discovery output is not a single line (use ConvertTo-Json -Compress).' }
    if ([Text.Encoding]::UTF8.GetByteCount($text) -gt 1MB) { $problems += 'Discovery output is larger than 1 MB.' }
    $data = $null
    try { $data = $text | ConvertFrom-Json } catch { $problems += "Discovery output is not valid JSON: $($_.Exception.Message)" }

    $rulesText = Get-Content -LiteralPath $RulesPath -Raw
    if ([Text.Encoding]::UTF8.GetByteCount($rulesText) -gt 100KB) { $problems += 'Rules file is larger than 100 KB.' }
    $rules = @(($rulesText | ConvertFrom-Json).Rules)
    if ($rules.Count -gt 100) { $problems += 'Rules file has more than 100 rules.' }

    $ops = @('IsEquals', 'NotEquals', 'GreaterThan', 'GreaterEquals', 'LessThan', 'LessEquals')
    $results = foreach ($r in $rules) {
        $state = 'Compliant'
        $detail = ''
        $actual = $null
        if ($ops -notcontains $r.Operator) { $problems += "Rule $($r.SettingName): unsupported operator '$($r.Operator)'." }
        if (-not @($r.RemediationStrings | Where-Object { $_.Language -eq 'en_US' }).Count) { $problems += "Rule $($r.SettingName): needs an en_US remediation string." }
        if (-not $data -or -not ($data.PSObject.Properties.Name -ccontains $r.SettingName)) {
            $state = 'NotDiscovered'
            $detail = 'Setting missing from discovery output (Intune reports this as an error).'
        }
        else {
            $actual = $data.($r.SettingName)
            try {
                $a = ConvertTo-CERuleValue $actual $r.DataType
                $b = ConvertTo-CERuleValue $r.Operand $r.DataType
                $cmp = if ($r.DataType -eq 'String') { [string]::CompareOrdinal($a, $b) } else { ([IComparable]$a).CompareTo($b) }
                $ok = switch ($r.Operator) {
                    'IsEquals' { $cmp -eq 0 }
                    'NotEquals' { $cmp -ne 0 }
                    'GreaterThan' { $cmp -gt 0 }
                    'GreaterEquals' { $cmp -ge 0 }
                    'LessThan' { $cmp -lt 0 }
                    'LessEquals' { $cmp -le 0 }
                    default { $false }
                }
                if (-not $ok) {
                    $state = 'NonCompliant'
                    $title = @($r.RemediationStrings | Where-Object { $_.Language -eq 'en_US' })[0].Title
                    $detail = ([string]$title).Replace('{ActualValue}', [string]$actual)
                }
            }
            catch {
                $state = 'TypeError'
                $detail = "Value '$actual' does not match DataType $($r.DataType): $($_.Exception.Message)"
            }
        }
        [pscustomobject]@{
            SettingName = $r.SettingName
            Rule        = "$($r.Operator) $($r.Operand) ($($r.DataType))"
            Actual      = $actual
            State       = $state
            Detail      = $detail
        }
    }
    return [pscustomobject]@{
        Compliant = ($problems.Count -eq 0 -and @($results | Where-Object State -ne 'Compliant').Count -eq 0)
        Rules     = @($results)
        Problems  = @($problems)
    }
}
