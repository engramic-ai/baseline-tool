# ---------------------------------------------------------------------------
# Remediation engine.
#
# Remediations live in a fixed library (Remediations\*.ps1). A changeset only
# ever refers to a library Id plus simple parameters, so a changeset file can
# never inject arbitrary code. Every parameter is re-validated at apply time.
#
# Each Apply scriptblock receives ($Params, $Undo). It must record how to undo
# what it changed by calling Set-CERegistryValueTracked / Remove-CERegistryValueTracked
# (automatic undo) or Add-CEUndoCommand (a fixed, generated command).
# ---------------------------------------------------------------------------

$script:CEValidRisk = @('Low', 'Medium', 'High')

function Register-CERemediation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Low', 'Medium', 'High')][string]$Risk,
        [switch]$RequiresAdmin,
        [switch]$RequiresReboot,
        # Low/Medium risk items are pre-selected in the changeset unless this is set.
        [switch]$NotSelectedByDefault,
        # Whether changes can be rolled back from the undo log.
        [switch]$NotReversible,
        [string]$Notes = '',
        # Optional static data handed to Apply as its third argument.
        $Data = $null,
        # Throw if the parameters are not acceptable.
        [scriptblock]$Validate = { param($p) },
        [Parameter(Mandatory)][scriptblock]$Apply
    )
    if ($script:CERemediations.ContainsKey($Id)) { throw "Duplicate remediation id $Id" }
    $script:CERemediations[$Id] = [pscustomobject]@{
        Id                = $Id
        Title             = $Title
        Risk              = $Risk
        RequiresAdmin     = [bool]$RequiresAdmin
        RequiresReboot    = [bool]$RequiresReboot
        SelectedByDefault = ((-not $NotSelectedByDefault) -and $Risk -ne 'High')
        Reversible        = (-not $NotReversible)
        Notes             = $Notes
        Validate          = $Validate
        Apply             = $Apply
        Data              = $Data
    }
}

function Get-CERemediation {
    [CmdletBinding()]
    param([string]$Id)
    if ($Id) { return $script:CERemediations[$Id] }
    return @($script:CERemediations.Values | Sort-Object Id)
}

function ConvertTo-CEHashtable {
    <# JSON objects come back as PSCustomObject; remediations expect hashtables. #>
    param($InputObject)
    if ($null -eq $InputObject) { return @{} }
    if ($InputObject -is [hashtable]) { return $InputObject }
    $h = @{}
    foreach ($prop in $InputObject.PSObject.Properties) { $h[$prop.Name] = $prop.Value }
    return $h
}

function Assert-CEParam {
    <# Small validation helper used inside Validate blocks. #>
    param(
        [Parameter(Mandatory)][hashtable]$Params,
        [Parameter(Mandatory)][string]$Name,
        [string]$Pattern,
        [object[]]$AllowedValues,
        [int]$Min = [int]::MinValue,
        [int]$Max = [int]::MaxValue,
        [switch]$Optional,
        [switch]$Integer
    )
    if (-not $Params.ContainsKey($Name) -or $null -eq $Params[$Name]) {
        if ($Optional) { return }
        throw "Missing parameter '$Name'"
    }
    foreach ($v in @($Params[$Name])) {
        if ($Integer) {
            $n = 0
            if (-not [int]::TryParse([string]$v, [ref]$n)) { throw "Parameter '$Name' must be an integer (got '$v')" }
            if ($n -lt $Min -or $n -gt $Max) { throw "Parameter '$Name'=$n outside $Min..$Max" }
        }
        if ($Pattern -and ([string]$v -notmatch $Pattern)) { throw "Parameter '$Name' value '$v' is not allowed" }
        if ($AllowedValues -and ($AllowedValues -notcontains $v)) { throw "Parameter '$Name' value '$v' is not one of: $($AllowedValues -join ', ')" }
    }
}

function Get-CEParamValue {
    <#
        Reads an optional remediation parameter. The module runs under strict
        mode, where $p.Missing throws on a hashtable, so optional parameters
        must always be read through this helper.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Params,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )
    if ($Params.ContainsKey($Name)) { return $Params[$Name] }
    return $Default
}

function Get-CERegistryState {
    param([string]$Path, [string]$Name)
    $exists = Test-CERegistryValueExists -Path $Path -Name $Name
    $state = @{ Path = $Path; Name = $Name; Existed = $exists; Value = $null; Kind = $null }
    if ($exists) {
        $key = Get-Item -LiteralPath $Path
        $state.Kind = [string]$key.GetValueKind($Name)
        $raw = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
        if ($raw -is [byte[]]) { $state.Value = [Convert]::ToBase64String($raw); $state.Kind = 'BinaryBase64' } else { $state.Value = $raw }
    }
    return $state
}

function Set-CERegistryValueTracked {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord', 'String', 'QWord', 'ExpandString', 'MultiString')][string]$Type = 'DWord',
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Undo
    )
    $before = Get-CERegistryState -Path $Path -Name $Name
    if ($before.Existed -and "$($before.Value)" -eq "$Value" -and $before.Kind -eq $Type) {
        Write-Verbose "Already set: $Path\$Name = $Value"
        return
    }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value ($Type)")) {
        $keyExisted = Test-Path -LiteralPath $Path
        if (-not $keyExisted) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        $before['Type'] = 'Registry'
        $before['KeyCreated'] = (-not $keyExisted)
        $Undo.Add([pscustomobject]$before)
    }
}

function Remove-CERegistryValueTracked {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Undo
    )
    $before = Get-CERegistryState -Path $Path -Name $Name
    if (-not $before.Existed) { return }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", 'Remove value')) {
        Remove-ItemProperty -LiteralPath $Path -Name $Name -Force
        $before['Type'] = 'Registry'
        $before['KeyCreated'] = $false
        $Undo.Add([pscustomobject]$before)
    }
}

function Add-CEUndoCommand {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Undo,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Command
    )
    $Undo.Add([pscustomobject]@{ Type = 'Command'; Description = $Description; Command = $Command })
}

function ConvertTo-CEPSLiteral {
    <# Quote a value for safe embedding in a generated undo command. #>
    param($Value)
    if ($null -eq $Value) { return '$null' }
    if ($Value -is [bool]) { if ($Value) { return '$true' } else { return '$false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [byte]) { return "$Value" }
    return "'" + ([string]$Value -replace "'", "''") + "'"
}

function Invoke-CERemediation {
    <#
        Applies one remediation by library Id. Returns a result object with the
        undo records. Honors -WhatIf.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Id,
        $Parameters,
        # Where remediations may write backup files (e.g. auditpol backups).
        [string]$UndoDirectory = [IO.Path]::GetTempPath()
    )
    $script:CEUndoDirectory = $UndoDirectory
    $rem = $script:CERemediations[$Id]
    if (-not $rem) { throw "Unknown remediation '$Id'. Changesets can only reference the built-in library." }
    $p = ConvertTo-CEHashtable $Parameters
    & $rem.Validate $p

    $ctx = Get-CEDeviceContext
    if ($rem.RequiresAdmin -and -not $ctx.IsElevated) { throw "Remediation '$Id' requires an elevated PowerShell session." }

    $undo = New-Object System.Collections.Generic.List[object]
    $status = 'Applied'
    $message = ''
    if ($PSCmdlet.ShouldProcess($rem.Title, "Apply remediation $Id")) {
        try {
            # Already confirmed at this level; don't re-prompt for every registry write.
            $ConfirmPreference = 'None'
            $WhatIfPreference = $false
            $null = & $rem.Apply $p $undo $rem
        }
        catch {
            $status = 'Failed'
            $message = $_.Exception.Message
        }
    }
    else {
        $status = 'WhatIf'
    }
    return [pscustomobject]@{
        RemediationId  = $Id
        Title          = $rem.Title
        Parameters     = $p
        Status         = $status
        Message        = $message
        RequiresReboot = $rem.RequiresReboot
        Undo           = $undo.ToArray()
        Timestamp      = (Get-Date).ToString('o')
    }
}

function Restore-CEUndoLog {
    <#
        Rolls back changes recorded in an undo log produced by Apply-CEChangeset.ps1.
        Entries are processed newest first.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$ItemId
    )
    $log = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($log.ComputerName -and $log.ComputerName -ne $env:COMPUTERNAME) {
        throw "Undo log is for $($log.ComputerName), not $($env:COMPUTERNAME)."
    }
    $entries = @($log.Items)
    if ($ItemId) { $entries = @($entries | Where-Object { $ItemId -contains $_.ItemId }) }
    [array]::Reverse($entries)

    foreach ($item in $entries) {
        $records = @($item.Undo)
        [array]::Reverse($records)
        foreach ($r in $records) {
            if ($r.Type -eq 'Registry') {
                $target = "$($r.Path)\$($r.Name)"
                if (-not $r.Existed) {
                    if ($PSCmdlet.ShouldProcess($target, "[$($item.ItemId)] Remove value (did not exist before)")) {
                        Remove-ItemProperty -LiteralPath $r.Path -Name $r.Name -Force -ErrorAction SilentlyContinue
                        if ($r.KeyCreated) {
                            $key = Get-Item -LiteralPath $r.Path -ErrorAction SilentlyContinue
                            if ($key -and $key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) { Remove-Item -LiteralPath $r.Path -Force -ErrorAction SilentlyContinue }
                        }
                    }
                }
                else {
                    $kind = $r.Kind
                    $value = $r.Value
                    if ($kind -eq 'BinaryBase64') { $kind = 'Binary'; $value = [Convert]::FromBase64String($value) }
                    if ($kind -eq 'MultiString') { $value = [string[]]@($value) }
                    if ($PSCmdlet.ShouldProcess($target, "[$($item.ItemId)] Restore previous value '$value' ($kind)")) {
                        if (-not (Test-Path -LiteralPath $r.Path)) { New-Item -Path $r.Path -Force | Out-Null }
                        New-ItemProperty -LiteralPath $r.Path -Name $r.Name -Value $value -PropertyType $kind -Force | Out-Null
                    }
                }
            }
            elseif ($r.Type -eq 'Command') {
                Write-Host "[$($item.ItemId)] $($r.Description)"
                Write-Host "    $($r.Command)" -ForegroundColor DarkGray
                if ($PSCmdlet.ShouldProcess($r.Description, "[$($item.ItemId)] Run undo command")) {
                    $sb = [scriptblock]::Create($r.Command)
                    & $sb
                }
            }
        }
    }
}
