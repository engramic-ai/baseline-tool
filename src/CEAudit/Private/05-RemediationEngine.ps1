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

# Undo 'Command' entries are generated from this fixed set of cmdlets and tools
# (see the Remediations\*.ps1 that call Add-CEUndoCommand). Restore-CEUndoLog will
# only run a command whose AST invokes solely these, by name, so a tampered or
# forged undo log cannot turn a rollback into arbitrary elevated code execution.
$script:CEUndoAllowedCommands = @(
    'Set-NetFirewallProfile', 'Enable-NetFirewallRule', 'Set-NetFirewallRule',
    'Enable-LocalUser', 'Disable-LocalUser',
    'Add-MpPreference', 'Remove-MpPreference', 'Set-MpPreference',
    'Enable-WindowsOptionalFeature', 'Disable-WindowsOptionalFeature',
    'Set-Service', 'Set-ItemProperty',
    'Set-CESecurityPolicyValue', 'Suspend-BitLocker', 'Write-Warning',
    # Two generated undo commands pipe to Out-Null; without it here they were refused at rollback.
    'Out-Null',
    'net', 'net.exe', 'auditpol', 'auditpol.exe', 'wevtutil', 'wevtutil.exe'
)

# Registry keys the shipped remediations write, and therefore the only keys an undo record may
# touch. Naming a command is not enough on its own: without this, a tampered log could restore a
# "previous value" into Winlogon\Userinit, a Run key or a service ImagePath and get code execution
# as whoever runs the rollback. A prefix matches the key itself or anything beneath it.
$script:CEUndoAllowedRegistryPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
    'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings',
    'HKLM:\SOFTWARE\Policies\Google\Chrome',
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
    'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance',
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot',
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server',
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
    'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters',
    'HKCU:\Software\Policies\Microsoft\Office'
)
$script:CEUndoAllowedRegistryKinds = @('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord', 'BinaryBase64')

function Test-CEUndoRegistryPathAllowed {
    <# Returns $null if an undo record may write this key, otherwise the reason it was refused. #>
    param([string]$Path)
    if (-not $Path) { return 'the record has no registry path' }
    # Reject anything that could walk out of an allowed prefix, or that the provider would expand.
    if ($Path -match '\.\.|\*|\?|/') { return "registry path '$Path' contains a wildcard or a relative segment" }
    $norm = $Path.TrimEnd('\')
    foreach ($allowed in $script:CEUndoAllowedRegistryPaths) {
        if ($norm -eq $allowed) { return $null }
        if ($norm.StartsWith($allowed + '\', [StringComparison]::OrdinalIgnoreCase)) { return $null }
    }
    return "registry path '$Path' is outside the keys this tool changes"
}

function Test-CEUndoCommandAllowed {
    <#
        Returns $null if an undo command is safe to run, otherwise the reason it
        was refused. Safe means it parses, contains no script blocks or method /
        static calls, and every command it invokes is named literally and appears
        in $script:CEUndoAllowedCommands. A structured undo model would remove the
        need to run command strings at all; until then this constrains them.
    #>
    param([string]$Command)
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($Command, [ref]$tokens, [ref]$errs)
    if ($errs -and @($errs).Count) { return 'does not parse' }
    $danger = @($ast.FindAll({
                param($n)
                ($n -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) -or
                ($n -is [System.Management.Automation.Language.InvokeMemberExpressionAst])
            }, $true))
    if ($danger.Count) { return 'contains a script block or method call' }
    # A redirection turns any allow-listed command into an arbitrary file write.
    $redirects = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.RedirectionAst] }, $true))
    if ($redirects.Count) { return 'contains a redirection' }
    $commands = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
    if (-not $commands.Count) { return 'no command to run' }
    foreach ($c in $commands) {
        $name = $c.GetCommandName()
        if (-not $name) { return 'command invoked indirectly' }
        if ($script:CEUndoAllowedCommands -notcontains $name) { return "command '$name' is not allow-listed" }
        # Naming an allow-listed command is not enough: several of them will hand over the machine
        # if their arguments are chosen freely.
        $refused = Test-CEUndoCommandArgument -Command $c -Name $name
        if ($refused) { return $refused }
    }
    return $null
}

function Test-CEUndoCommandArgument {
    <#
        Argument rules for the allow-listed commands that can escalate. net can add an
        administrator, Set-Service can repoint a service binary, and Set-ItemProperty can write
        any key, so each is held to the shape the shipped remediations actually generate.
    #>
    param([System.Management.Automation.Language.CommandAst]$Command, [string]$Name)
    $elements = @($Command.CommandElements)
    $text = { param($i) if ($i -lt $elements.Count) { [string]$elements[$i].Extent.Text.Trim("'" + '"') } else { '' } }

    switch -Regex ($Name) {
        '^net(\.exe)?$' {
            # 'net accounts ...' and 'net user <name> /passwordreq:...' are the only forms generated.
            $verb = (& $text 1)
            if ($verb -notin @('accounts', 'user')) { return "'net $verb' is not allowed in an undo command" }
            if ($verb -eq 'user') {
                $switches = @($elements | Select-Object -Skip 2 | ForEach-Object { [string]$_.Extent.Text } | Where-Object { $_ -like '/*' })
                foreach ($sw in $switches) {
                    if ($sw -notmatch '^/passwordreq:(yes|no)$') { return "'net user $sw' is not allowed in an undo command" }
                }
            }
            return $null
        }
        '^Set-Service$' {
            foreach ($e in $elements) {
                if ($e -is [System.Management.Automation.Language.CommandParameterAst] -and
                    $e.ParameterName -match '^(BinaryPathName|Path)$') { return 'Set-Service may not change a service binary in an undo command' }
            }
            return $null
        }
        '^Set-ItemProperty$' {
            for ($i = 0; $i -lt $elements.Count; $i++) {
                $e = $elements[$i]
                if ($e -is [System.Management.Automation.Language.CommandParameterAst] -and $e.ParameterName -match '^(LiteralPath|Path)$') {
                    $value = if ($e.Argument) { [string]$e.Argument.Extent.Text } else { (& $text ($i + 1)) }
                    return (Test-CEUndoRegistryPathAllowed ([string]$value).Trim("'" + '"'))
                }
            }
            return 'Set-ItemProperty in an undo command must name the key it writes'
        }
        default { return $null }
    }
}

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
    # An elevated rollback replays instructions from a file. If a standard user can write that file
    # or its folder, they choose what an administrator runs, so refuse rather than warn.
    if (Test-CEIsAdmin) {
        $acl = @(Get-CEPathAclProblem -Path $Path) + @(Get-CEPathAclProblem -Path (Split-Path -Parent $Path))
        if ($acl.Count) {
            throw ("Refusing to roll back from '$Path': standard users can change it, so an elevated rollback would run " +
                   "instructions they control. $($acl -join '; '). Move the results folder somewhere only administrators can write, " +
                   'or roll back as the user who owns it.')
        }
    }
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
                $refused = Test-CEUndoRegistryPathAllowed ([string]$r.Path)
                if (-not $refused -and $r.Existed -and ($script:CEUndoAllowedRegistryKinds -notcontains [string]$r.Kind)) {
                    $refused = "value kind '$($r.Kind)' is not one this tool writes"
                }
                if ($refused) {
                    Write-Warning "[$($item.ItemId)] Refusing to restore $target ($refused). The undo log may be tampered with or from a different version; skipping this step."
                    continue
                }
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
                $refused = Test-CEUndoCommandAllowed ([string]$r.Command)
                if ($refused) {
                    Write-Warning "[$($item.ItemId)] Refusing to run undo command ($refused). The undo log may be tampered with or from a different version; skipping this step."
                    continue
                }
                if ($PSCmdlet.ShouldProcess($r.Description, "[$($item.ItemId)] Run undo command")) {
                    $sb = [scriptblock]::Create($r.Command)
                    & $sb
                }
            }
        }
    }
}
