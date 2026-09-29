#Requires -Version 5.1
<#
    What tools\parity\Compare-Parity.ps1 and tools\contracts\Compare-IntuneReaders.ps1 share: the ledger of
    accepted differences (tests\parity\divergences.json), the account a comparison runs as, and how two sets of
    values are flattened, compared, printed and judged.
#>

Set-StrictMode -Version 2.0

$script:ParityContexts = @('standard user', 'elevated administrator', 'SYSTEM')

function Get-ParityContext {
    <# The account this process runs as, as the ledger names contexts: SYSTEM, elevated administrator or standard user. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -eq 'S-1-5-18') { return 'SYSTEM' }
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return 'elevated administrator' }
    return 'standard user'
}

function Read-ParityLedger {
    <#
        The entries of the ledger, each checked: a path, a kind (ignored or explained), a reason, and a scope of
        known contexts and of check identifiers or *. Throws on the first problem, so a ledger that cannot be read
        never lets a difference through. Each entry gets the pattern that finds the paths it covers (the path
        itself and everything under it, * standing for any part of one name) and a flag for whether it explained
        a difference in this run.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $document = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    if (-not $document.PSObject.Properties['divergences']) { throw "$Path has no divergences list." }
    $entries = New-Object System.Collections.ArrayList
    $number = 0
    foreach ($item in @($document.divergences)) {
        $number++
        $where = "$Path, entry $number"
        foreach ($name in 'path', 'kind', 'reason', 'scope') {
            if (-not $item.PSObject.Properties[$name]) { throw "$where has no $name." }
        }
        $entryPath = [string]$item.path
        if (-not $entryPath.Trim()) { throw "$where has an empty path." }
        $kind = [string]$item.kind
        if (@('ignored', 'explained') -cnotcontains $kind) { throw "$where ($entryPath): kind is '$kind', not ignored or explained." }
        if (-not ([string]$item.reason).Trim()) { throw "$where ($entryPath) gives no reason." }
        foreach ($name in 'contexts', 'checks') {
            if (-not $item.scope.PSObject.Properties[$name] -or @($item.scope.$name).Count -eq 0) { throw "$where ($entryPath): the scope names no $name." }
        }
        $contexts = @($item.scope.contexts | ForEach-Object { [string]$_ })
        foreach ($context in $contexts) {
            if ($script:ParityContexts -cnotcontains $context) { throw "$where ($entryPath): '$context' is not a context; the contexts are $($script:ParityContexts -join ', ')." }
        }
        $checks = @($item.scope.checks | ForEach-Object { [string]$_ })
        foreach ($check in $checks) {
            if ($check -ne '*' -and $check -cnotmatch '^[A-Z]{2}-\d{2}$') { throw "$where ($entryPath): '$check' is not a check identifier or *." }
        }
        $pattern = '^' + ([regex]::Escape($entryPath) -replace '\\\*', '[^.]*') + '(?:$|[.\[])'
        [void]$entries.Add([pscustomobject]@{
                Path     = $entryPath
                Kind     = $kind
                Reason   = [string]$item.reason
                Contexts = $contexts
                Checks   = $checks
                Pattern  = New-Object System.Text.RegularExpressions.Regex($pattern, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
                Used     = $false
            })
    }
    return , $entries.ToArray()
}

function Select-ParityLedgerEntry {
    <# The entries whose scope covers this context and at least one of these checks. #>
    [CmdletBinding()]
    param([object[]]$Ledger, [Parameter(Mandatory = $true)][string]$Context, [string[]]$CheckId)
    $selected = @($Ledger | Where-Object {
            $entry = $_
            $entry.Contexts -ccontains $Context -and ($entry.Checks -contains '*' -or @($entry.Checks | Where-Object { $CheckId -contains $_ }).Count -gt 0)
        })
    return , $selected
}

function ConvertTo-ParityFlatValue {
    <# Every value under $Value as an ordered map of path to text, such as checks.SU-01.frameworks[1] = "CE+ TC2". #>
    [CmdletBinding()]
    param($Value, [string]$Path, [System.Collections.Specialized.OrderedDictionary]$Into)
    if ($null -eq $Value) { $Into[$Path] = 'null'; return }
    if ($Value -is [string]) { $Into[$Path] = '"' + $Value + '"'; return }
    if ($Value -is [bool]) { $Into[$Path] = $Value.ToString().ToLowerInvariant(); return }
    if ($Value -is [datetime]) { $Into[$Path] = '"' + $Value.ToString('o', [Globalization.CultureInfo]::InvariantCulture) + '"'; return }
    if ($Value -is [System.Collections.IDictionary]) {
        if ($Value.Count -eq 0) { $Into[$Path] = '{}'; return }
        foreach ($key in $Value.Keys) { ConvertTo-ParityFlatValue -Value $Value[$key] -Path "$Path.$key" -Into $Into }
        return
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $properties = @($Value.PSObject.Properties)
        if ($properties.Count -eq 0) { $Into[$Path] = '{}'; return }
        foreach ($property in $properties) { ConvertTo-ParityFlatValue -Value $property.Value -Path "$Path.$($property.Name)" -Into $Into }
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @($Value)
        if ($items.Count -eq 0) { $Into[$Path] = '[]'; return }
        for ($i = 0; $i -lt $items.Count; $i++) { ConvertTo-ParityFlatValue -Value $items[$i] -Path "$Path[$i]" -Into $Into }
        return
    }
    $Into[$Path] = [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
}

function Add-ParityReaderValue {
    <#
        What the Intune scripts reported (tools\contracts\Invoke-IntuneReaders.ps1) as paths and text: for each
        script and host, such as discovery[64-bit] or detection[32-bit], its exit code, whether it tried to start
        the scheduled audit, and each value it reported, or its whole output when that is not in its usual form.
    #>
    [CmdletBinding()]
    param([object[]]$Result, [System.Collections.Specialized.OrderedDictionary]$Into)
    foreach ($run in $Result) {
        $prefix = if ($run.Script -eq 'Discover') { 'discovery' } else { 'detection' }
        $at = '{0}[{1}]' -f $prefix, $run.Bitness
        $Into["$at.exitCode"] = [string]$run.ExitCode
        $Into["$at.taskStartRequested"] = ([bool]$run.TaskStartRequested).ToString().ToLowerInvariant()
        if ($null -ne $run.Values) { ConvertTo-ParityFlatValue -Value $run.Values -Path $at -Into $Into }
        else { $Into["$at.output"] = '"' + (@($run.Output) -join ' / ') + '"' }
    }
}

function Compare-ParityValue {
    <#
        One row per path in either map, the module's paths in their order and each path only baseline.exe has
        placed after the one before it in its own order: both values, and whether they match, are ignored, are
        explained or differ, with the ledger entry that ignores or explains them. An entry of kind ignored covers
        its paths whatever their values; an entry of kind explained covers them only when they differ, and is
        marked as used.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Collections.Specialized.OrderedDictionary]$Module,
        [Parameter(Mandatory = $true)][System.Collections.Specialized.OrderedDictionary]$Baseline,
        [object[]]$Entry = @()
    )
    $paths = New-Object System.Collections.ArrayList
    foreach ($key in $Module.Keys) { [void]$paths.Add($key) }
    $after = -1
    foreach ($key in $Baseline.Keys) {
        $at = $paths.IndexOf($key)
        if ($at -lt 0) { $at = $after + 1; $paths.Insert($at, $key) }
        $after = $at
    }
    foreach ($key in $paths) {
        $a = if ($Module.Contains($key)) { [string]$Module[$key] } else { '(missing)' }
        $b = if ($Baseline.Contains($key)) { [string]$Baseline[$key] } else { '(missing)' }
        $rule = @($Entry | Where-Object { $_.Pattern.IsMatch($key) }) | Select-Object -First 1
        if ($rule -and $rule.Kind -eq 'ignored') { $result = 'ignored' }
        elseif ([string]::Equals($a, $b, [StringComparison]::Ordinal)) { $result = 'match'; $rule = $null }
        elseif ($rule) { $result = 'explained'; $rule.Used = $true }
        else { $result = 'DIFFERENT' }
        [pscustomobject]@{ Path = $key; Module = $a; Baseline = $b; Result = $result; Entry = $rule }
    }
}

function Write-ParityComparison {
    <#
        Prints the rows: a match with its value, a difference with both values, and each ledger entry once, with
        how many values it covered and why.
    #>
    [CmdletBinding()]
    param([object[]]$Row)
    $shown = @{}
    foreach ($item in $Row) {
        switch ($item.Result) {
            'match' { Write-Host ('  match      {0} = {1}' -f $item.Path, $item.Module) }
            'DIFFERENT' { Write-Host ('  DIFFERENT  {0}: module {1}, baseline.exe {2}' -f $item.Path, $item.Module, $item.Baseline) }
            default {
                $key = $item.Result + '|' + $item.Entry.Path
                if ($shown.ContainsKey($key)) { continue }
                $shown[$key] = $true
                $covered = @($Row | Where-Object { $_.Result -eq $item.Result -and $null -ne $_.Entry -and $_.Entry.Path -eq $item.Entry.Path })
                $values = if ($covered.Count -eq 1) { ': module {0}, baseline.exe {1}' -f $item.Module, $item.Baseline } else { " ($($covered.Count) values)" }
                Write-Host ('  {0,-10} {1}{2}; {3}' -f $item.Result, $item.Entry.Path, $values, $item.Entry.Reason)
            }
        }
    }
}

function Get-ParityVerdict {
    <#
        The counts of each result, the rows that differ with no ledger entry to explain them, and the explained
        entries in scope that explained nothing in this run (which can be taken off the ledger once no context
        or check needs them). Passed is true when nothing is unexplained.
    #>
    [CmdletBinding()]
    param([object[]]$Row, [object[]]$Entry)
    $unexplained = @($Row | Where-Object { $_.Result -eq 'DIFFERENT' })
    return [pscustomobject][ordered]@{
        Compared    = @($Row).Count
        Match       = @($Row | Where-Object { $_.Result -eq 'match' }).Count
        Ignored     = @($Row | Where-Object { $_.Result -eq 'ignored' }).Count
        Explained   = @($Row | Where-Object { $_.Result -eq 'explained' }).Count
        Unexplained = $unexplained.Count
        Passed      = $unexplained.Count -eq 0
        Different   = @($unexplained | ForEach-Object { [pscustomobject][ordered]@{ Path = $_.Path; Module = $_.Module; Baseline = $_.Baseline } })
        Unused      = @($Entry | Where-Object { $_.Kind -eq 'explained' -and -not $_.Used } | ForEach-Object { $_.Path })
    }
}

function ConvertTo-ParityRecord {
    <# The rows as plain records for a JSON result file: each value and result, with the path and reason of its ledger entry. #>
    [CmdletBinding()]
    param([object[]]$Row)
    $records = @(foreach ($item in $Row) {
            [pscustomobject][ordered]@{
                Path     = $item.Path
                Module   = $item.Module
                Baseline = $item.Baseline
                Result   = $item.Result
                Ledger   = if ($item.Entry) { $item.Entry.Path } else { $null }
                Reason   = if ($item.Entry) { $item.Entry.Reason } else { $null }
            }
        })
    return , $records
}

Export-ModuleMember -Function Get-ParityContext, Read-ParityLedger, Select-ParityLedgerEntry, ConvertTo-ParityFlatValue, Add-ParityReaderValue, Compare-ParityValue, Write-ParityComparison, Get-ParityVerdict, ConvertTo-ParityRecord
