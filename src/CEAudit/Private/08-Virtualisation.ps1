# ---------------------------------------------------------------------------
# Virtual machines, WSL distributions and containers on this device (SC-12,
# FW-07). Everything is read from settings files, the registry and CIM/cmdlets:
# nothing is started. Per-user data comes from the signed-in user's profile
# and hive, so it also works when the audit runs as SYSTEM.
# ---------------------------------------------------------------------------

function Get-CEUserProfilePath {
    <# Profile folder of the person using the device (the signed-in user when running as SYSTEM). #>
    param($Context)
    if (-not $Context.IsSystem) { return [string]$env:USERPROFILE }
    if (-not $Context.ConsoleUserSid) { return $null }
    $p = Get-CERegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($Context.ConsoleUserSid)" -Name 'ProfileImagePath'
    if ($p) { return [string]$p }
    return $null
}

function Test-CEAboveUserRights {
    <#
        Whether this audit reads the user's profile with more rights than the account that owns it:
        as SYSTEM, or elevated. Then the profile read layer's rules apply (15-ProfileReads.ps1 and
        SECURITY.md): symbolic links are not followed, a junction only after its target is checked,
        no file content through any link, and files stored online only are not downloaded. In the
        user's own non-elevated session (the per-user probe) their links are followed as usual.
        No context counts as above.
    #>
    param($Context)
    if ($null -eq $Context) { return $true }
    return ([bool](Get-CEObjectValue $Context 'IsSystem' $false) -or [bool](Get-CEObjectValue $Context 'IsElevated' $false))
}

function ConvertFrom-CEIniText {
    <# INI-style text (wsl.conf, .wslconfig) to a hashtable of section -> key -> value, lower-cased names. #>
    param([AllowEmptyCollection()][string[]]$Lines)
    $data = @{}
    $section = ''
    foreach ($raw in @($Lines)) {
        $line = ("$raw" -replace '[#;].*$', '').Trim()
        if (-not $line) { continue }
        if ($line -match '^\[(.+)\]$') { $section = $Matches[1].Trim().ToLowerInvariant(); continue }
        if ($line -match '^([^=]+)=(.*)$') {
            if (-not $data.ContainsKey($section)) { $data[$section] = @{} }
            $data[$section][$Matches[1].Trim().ToLowerInvariant()] = $Matches[2].Trim().Trim('"')
        }
    }
    return $data
}

function ConvertFrom-CEVmxText {
    <# A VMware .vmx file to name, network connection types and enabled shared folders. #>
    param([AllowEmptyCollection()][string[]]$Lines, [string]$Path = '')
    $kv = @{}
    foreach ($line in @($Lines)) {
        if ("$line" -match '^\s*([A-Za-z0-9_.:]+)\s*=\s*"(.*)"\s*$') { $kv[$Matches[1].ToLowerInvariant()] = $Matches[2] }
    }
    $get = { param($k) if ($kv.ContainsKey($k)) { $kv[$k] } else { $null } }
    $networks = @()
    foreach ($key in @($kv.Keys | Where-Object { $_ -match '^ethernet(\d+)\.present$' } | Sort-Object)) {
        $n = ([regex]::Match($key, '\d+')).Value
        if ((& $get $key) -notmatch '^true$') { continue }
        $type = & $get "ethernet$n.connectiontype"
        if (-not $type) { $type = 'bridged' }  # VMware's default when the setting is absent
        if ($type -eq 'custom' -and (& $get "ethernet$n.vnet") -match '^vmnet0$') { $type = 'bridged' }
        $networks += $type.ToLowerInvariant()
    }
    $shared = @()
    if ((& $get 'isolation.tools.hgfs.disable') -notmatch '^true$') {
        foreach ($key in @($kv.Keys | Where-Object { $_ -match '^sharedfolder(\d+)\.present$' } | Sort-Object)) {
            $n = ([regex]::Match($key, '\d+')).Value
            if ((& $get $key) -match '^true$' -and (& $get "sharedfolder$n.enabled") -match '^true$') {
                $shared += [string](& $get "sharedfolder$n.hostpath")
            }
        }
    }
    $name = & $get 'displayname'
    if (-not $name) { $name = [IO.Path]::GetFileNameWithoutExtension($Path) }
    return [pscustomobject]@{ Name = [string]$name; Networks = @($networks); SharedFolders = @($shared | Where-Object { $_ }) }
}

function ConvertFrom-CEVboxXml {
    <# A VirtualBox .vbox machine file to name, bridged adapters, shared folders and NAT port forwards. #>
    param([Parameter(Mandatory)][string]$Xml)
    $doc = New-Object System.Xml.XmlDocument
    $doc.XmlResolver = $null
    $doc.LoadXml($Xml)
    $machine = $doc.SelectSingleNode("//*[local-name()='Machine']")
    if (-not $machine) { return $null }
    $attr = { param($node, $name) $a = $node.Attributes.GetNamedItem($name); if ($a) { [string]$a.Value } else { '' } }
    $bridged = 0
    $forwards = @()
    foreach ($adapter in @($machine.SelectNodes(".//*[local-name()='Adapter']"))) {
        if ((& $attr $adapter 'enabled') -ne 'true') { continue }
        if ($adapter.SelectSingleNode("*[local-name()='BridgedInterface']")) { $bridged++ }
        foreach ($fw in @($adapter.SelectNodes(".//*[local-name()='Forwarding']"))) {
            $hostIp = & $attr $fw 'hostip'
            $forwards += [pscustomobject]@{
                Name     = & $attr $fw 'name'
                Protocol = $(if ((& $attr $fw 'proto') -eq '0') { 'udp' } else { 'tcp' })
                HostIp   = $hostIp
                HostPort = & $attr $fw 'hostport'
                Exposed  = (-not $hostIp -or $hostIp -eq '0.0.0.0' -or $hostIp -eq '::')
            }
        }
    }
    $shared = @($machine.SelectNodes(".//*[local-name()='SharedFolder']") | ForEach-Object { & $attr $_ 'hostPath' } | Where-Object { $_ })
    return [pscustomobject]@{ Name = (& $attr $machine 'name'); Bridged = $bridged; SharedFolders = $shared; PortForwards = @($forwards) }
}

function ConvertFrom-CEWslListOutput {
    <# wsl.exe writes UTF-16, which shows up as text with NUL characters; returns the clean non-empty lines. #>
    param([AllowEmptyCollection()][string[]]$Lines)
    return ,@(@($Lines) | ForEach-Object { ("$_" -replace "`0", '').Trim() } | Where-Object { $_ })
}

function Test-CEHyperVPlatform {
    <#
        Whether the Hyper-V platform is on this device: its Virtual Machine Management service (vmms)
        exists. Asked of the service manager, not of a program found on PATH. Only a service Windows
        says is not there counts as absent; when it can't be told, Hyper-V counts as present, so its
        virtual machines are never passed over without being listed.
    #>
    try { return [bool]@(Get-Service -Name 'vmms' -ErrorAction Stop).Count }
    catch {
        if ("$($_.FullyQualifiedErrorId)" -like 'NoServiceFoundForGivenName*') { return $false }
        return $true
    }
}

function Get-CEHyperVMachine {
    <#
        Hyper-V VMs with whether they are on an external (bridged) switch. Needs elevation. No Hyper-V
        platform (no vmms service) is no virtual machines, even where the management tools are installed.
        When they could not be listed (no elevation, no Hyper-V PowerShell module, or listing failed),
        Readable is false, Message says why for SC-12, and Reason and Remedy are the fixed strings of the
        not-read record FW-07 reports (Add-CEHyperVNotRead). NotRead lists what could not be read once
        they were listed: a VM whose network adapters, or the NAT port mappings, could not be read.
    #>
    param($Context)
    $none = [pscustomobject]@{ Readable = $true; Message = ''; Machines = @(); NatMappings = @(); NotRead = @() }
    if (-not (Test-CEHyperVPlatform)) { return $none }
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Readable = $false; Message = "Hyper-V virtual machines could not be listed: $($script:CEHyperVText.NoModule)"; Machines = @(); NatMappings = @()
            NotRead = @(); Reason = $script:CEHyperVText.NoModule; Remedy = $script:CEHyperVText.NoModuleRemedy }
    }
    if (-not $Context.IsElevated) {
        return [pscustomobject]@{ Readable = $false; Message = 'Hyper-V virtual machines need elevation to list'; Machines = @(); NatMappings = @()
            NotRead = @(); Reason = $script:CEHyperVText.NeedsElevation; Remedy = $script:CEHyperVText.ElevateRemedy }
    }
    try {
        $external = @(Get-VMSwitch -ErrorAction Stop | Where-Object { "$($_.SwitchType)" -eq 'External' } | ForEach-Object { $_.Name })
        $vms = @(Get-VM -ErrorAction Stop)
    }
    catch {
        # The error's type only: its text can name a path.
        $why = "it could not be read ($(Get-CEErrorTypeName $_))"
        return [pscustomobject]@{ Readable = $false; Message = "Hyper-V virtual machines could not be listed: $why"; Machines = @(); NatMappings = @()
            NotRead = @(); Reason = $why; Remedy = $script:CEHyperVText.ErrorRemedy }
    }
    $notRead = New-Object System.Collections.ArrayList
    $machines = New-Object System.Collections.ArrayList
    foreach ($vm in $vms) {
        if ($null -eq $vm) { continue }
        $switches = @()
        try { $switches = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop | ForEach-Object { [string]$_.SwitchName } | Where-Object { $_ }) }
        catch {
            [void]$notRead.Add([pscustomobject]@{ Location = "Hyper-V virtual machine '$($vm.Name)'"
                    Reason = "its network adapters could not be read ($(Get-CEErrorTypeName $_))"; Remedy = $script:CEHyperVText.AdapterRemedy })
        }
        [void]$machines.Add([pscustomobject]@{ Name = [string]$vm.Name; State = [string]$vm.State; ExternalSwitches = @($switches | Where-Object { $external -contains $_ }) })
    }
    $nat = @()
    if (Get-Command Get-NetNatStaticMapping -ErrorAction SilentlyContinue) {
        try {
            $nat = @(Get-NetNatStaticMapping -ErrorAction Stop | ForEach-Object {
                    "$($_.Protocol) $($_.ExternalIPAddress):$($_.ExternalPort) -> $($_.InternalIPAddress):$($_.InternalPort)"
                })
        }
        catch {
            [void]$notRead.Add([pscustomobject]@{ Location = 'NAT port mappings'
                    Reason = "they could not be read ($(Get-CEErrorTypeName $_))"; Remedy = $script:CEHyperVText.NatRemedy })
        }
    }
    return [pscustomobject]@{ Readable = $true; Message = ''; Machines = $machines.ToArray(); NatMappings = $nat; NotRead = $notRead.ToArray() }
}

$script:CEHyperVText = @{
    NeedsElevation = 'an audit without elevation cannot list them'
    ElevateRemedy  = 'List them from an elevated prompt (Get-VM, and Get-VMNetworkAdapter for the switch each one uses), or run the audit elevated.'
    ErrorRemedy    = 'Check that the Hyper-V Virtual Machine Management service is running and run the audit elevated again, or list them from an elevated prompt (Get-VM, Get-VMNetworkAdapter).'
    NoModule       = 'Hyper-V is installed without its PowerShell module, so the audit cannot list them'
    NoModuleRemedy = 'Install the Hyper-V PowerShell module (Hyper-V Module for Windows PowerShell) and run the audit elevated again, or list the VMs by hand in Hyper-V Manager, with the switch each one uses.'
    AdapterRemedy  = 'Check the switch it uses from an elevated prompt (Get-VMNetworkAdapter), or run the audit elevated again.'
    NatRemedy      = 'List them from an elevated prompt (Get-NetNatStaticMapping), or run the audit elevated again.'
}

function Add-CEHyperVNotRead {
    <#
        Records Hyper-V virtual machines that could not be listed, and what could not be read once they
        were (topic hyperv), so FW-07 is never Not applicable or a Pass without them. Unlike a skip in the
        profile, the user's own session can't list them either: the remedy is an elevated run, an
        elevated prompt, or the Hyper-V PowerShell module.
    #>
    param($Log, $HyperV)
    if ($null -eq $HyperV) { return }
    if (-not [bool](Get-CEObjectValue $HyperV 'Readable' $true)) {
        Add-CENotRead -Log $Log -Location 'Hyper-V virtual machines' -Kind 'existence' -Topic 'hyperv' `
            -Reason ([string](Get-CEObjectValue $HyperV 'Reason' $script:CEHyperVText.NeedsElevation)) `
            -Remedy ([string](Get-CEObjectValue $HyperV 'Remedy' $script:CEHyperVText.ElevateRemedy))
    }
    foreach ($r in @(Get-CEObjectValue $HyperV 'NotRead' @())) {
        if ($null -eq $r) { continue }
        Add-CENotRead -Log $Log -Location ([string]$r.Location) -Kind 'existence' -Topic 'hyperv' -Reason ([string]$r.Reason) -Remedy ([string]$r.Remedy)
    }
}

function Get-CEVmFileCap {
    <# How many VM files one inventory can make an elevated or SYSTEM audit read (maxVmFilesPerInventory, default 64). #>
    return (ConvertTo-CEBoundedInt (Get-CEObjectValue (Get-CEConfig).'virtualisation' 'maxVmFilesPerInventory') -Default 64 -Min 1 -Max 10000)
}

function Add-CEVmCapRecord {
    <# Records that an inventory names more VM files than an elevated or SYSTEM audit reads. #>
    param($Log, [string]$Location, [int]$Cap)
    Add-CENotRead -Log $Log -Location $Location -Kind 'file-content' -Topic 'vm-file' -NeedsUserSession $true `
        -Reason "the audit reads at most $Cap virtual machine files named in one inventory above the user's rights" `
        -Remedy 'Or raise maxVmFilesPerInventory in virtualisation.json.'
}

function Get-CEVMwareMachine {
    <#
        VMware Workstation/Player VMs from the user's inventory.vmls, read through the profile read
        layer (15-ProfileReads.ps1). -Above (the audit has more rights than the user): at most
        Get-CEVmFileCap files are read, and the layer's rules apply. What could not be read is
        written to -Log.
    #>
    param([string]$ProfilePath, $Log, [bool]$Above = $true)
    if (-not $ProfilePath) { return ,@() }
    $invRel = 'AppData\Roaming\VMware\inventory.vmls'
    $text = Read-CEProfileFile -ProfilePath $ProfilePath -Relative $invRel -MaxBytes 1MB -Log $Log -Above $Above -Topic 'vm-inventory'
    if ($null -eq $text) { return ,@() }
    $paths = New-Object System.Collections.ArrayList
    foreach ($line in @($text -split '\r?\n')) {
        if ("$line" -match '^\s*vmlist\d+\.config\s*=\s*"(.+\.vmx)"' -and -not $paths.Contains($Matches[1])) { [void]$paths.Add($Matches[1]) }
    }
    $cap = Get-CEVmFileCap
    $count = 0
    $machines = New-Object System.Collections.ArrayList
    foreach ($p in $paths) {
        if ($Above -and ++$count -gt $cap) { Add-CEVmCapRecord -Log $Log -Location (Get-CEProfileLocation $invRel) -Cap $cap; break }
        $vmx = Read-CENamedFile -Path $p -ProfilePath $ProfilePath -MaxBytes 1MB -Product 'VMware' -Log $Log -Above $Above -Topic 'vm-file'
        if ($null -eq $vmx) { continue }
        $vm = ConvertFrom-CEVmxText -Lines @($vmx -split '\r?\n') -Path $p
        $vm | Add-Member -NotePropertyName Path -NotePropertyValue $p
        [void]$machines.Add($vm)
    }
    return ,$machines.ToArray()
}

function Get-CEVirtualBoxMachine {
    <#
        VirtualBox VMs registered in the user's VirtualBox.xml, read through the profile read layer;
        see Get-CEVMwareMachine for -Above and -Log. A settings file that can't be parsed, and a
        .vbox file with no machine in it, are recorded too.
    #>
    param([string]$ProfilePath, $Log, [bool]$Above = $true)
    if (-not $ProfilePath) { return ,@() }
    $regRel = '.VirtualBox\VirtualBox.xml'
    $registry = Join-Path $ProfilePath $regRel
    $text = Read-CEProfileFile -ProfilePath $ProfilePath -Relative $regRel -MaxBytes 4MB -Log $Log -Above $Above -Topic 'vm-inventory'
    if ($null -eq $text) { return ,@() }
    $cap = Get-CEVmFileCap
    $count = 0
    $machines = New-Object System.Collections.ArrayList
    $entries = @()
    try {
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.LoadXml($text)
        $entries = @($doc.SelectNodes("//*[local-name()='MachineEntry']"))
    }
    catch {
        Write-Verbose "Could not parse VirtualBox.xml: $(Get-CEErrorTypeName $_)"
        Add-CENotRead -Log $Log -Location (Get-CEProfileLocation $regRel) -Kind 'file-content' -Reason $script:CENotReadText.Parse -Topic 'vm-inventory' `
            -Remedy 'Check that VirtualBox.xml is a valid VirtualBox settings file, or check the virtual machines by hand.'
        return ,@()
    }
    foreach ($entry in $entries) {
        $src = [string]$entry.GetAttribute('src')
        if (-not $src) { continue }
        if (-not [IO.Path]::IsPathRooted($src)) { $src = Join-Path (Split-Path -Parent $registry) $src }
        if ($Above -and ++$count -gt $cap) { Add-CEVmCapRecord -Log $Log -Location (Get-CEProfileLocation $regRel) -Cap $cap; break }
        $vboxText = Read-CENamedFile -Path $src -ProfilePath $ProfilePath -MaxBytes 4MB -Product 'VirtualBox' -Log $Log -Above $Above -Topic 'vm-file'
        if ($null -eq $vboxText) { continue }
        $vm = $null
        try { $vm = ConvertFrom-CEVboxXml -Xml $vboxText } catch { Write-Verbose "Could not parse a .vbox file: $(Get-CEErrorTypeName $_)" }
        if ($vm) { $vm | Add-Member -NotePropertyName Path -NotePropertyValue $src; [void]$machines.Add($vm); continue }
        $rel = Get-CERelativeToProfile -Path $src -ProfilePath $ProfilePath
        Add-CENotRead -Log $Log -Location $(if ($rel) { Get-CEProfileLocation $rel } else { $src }) -Kind 'file-content' -Reason $script:CENotReadText.Parse -Topic 'vm-file' `
            -Remedy 'Check that the file is a VirtualBox .vbox machine file, or check the virtual machine by hand.'
    }
    return ,$machines.ToArray()
}

function Get-CEWslRegistryEntry {
    <# Registered WSL distributions (name and WSL version) from the user's Lxss key. #>
    $root = Get-CEUserRegistryRoot
    if (-not $root) { return ,@() }
    $entries = New-Object System.Collections.ArrayList
    foreach ($k in @(Get-ChildItem -Path "$root\Software\Microsoft\Windows\CurrentVersion\Lxss" -ErrorAction SilentlyContinue)) {
        $name = [string](Get-CERegistryValue -Path $k.PSPath -Name 'DistributionName')
        if ($name) {
            [void]$entries.Add([pscustomobject]@{
                Name       = $name
                Version    = [int](Get-CERegistryValue -Path $k.PSPath -Name 'Version' -Default 2)
                DefaultUid = [int](Get-CERegistryValue -Path $k.PSPath -Name 'DefaultUid' -Default 1000)
            })
        }
    }
    return ,$entries.ToArray()
}

function Test-CEWslDistributionName {
    <# A distribution name the audit will put in a \\wsl.localhost path: letters, digits, '.', '_' and '-' only, at most 64. #>
    param([string]$Name)
    return ([bool]$Name -and $Name -match '^[A-Za-z0-9._-]{1,64}$' -and $Name -ne '.' -and $Name -ne '..')
}

function Read-CEWslConf {
    <#
        /etc/wsl.conf of a running distribution through \\wsl.localhost, at most 1 MB.
        Returns Reachable (the distribution's /etc could be read), Exists and Lines. Throws when
        the name is not one Test-CEWslDistributionName accepts, or the file can't be read.
    #>
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Test-CEWslDistributionName $Name)) { throw 'the distribution name has characters the audit does not put in a path' }
    $etc = "\\wsl.localhost\$Name\etc"
    if (-not (Test-Path -LiteralPath $etc -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ Reachable = $false; Exists = $false; Lines = @() } }
    $file = Join-Path $etc 'wsl.conf'
    if (-not (Test-Path -LiteralPath $file -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ Reachable = $true; Exists = $false; Lines = @() } }
    $why = [ref]''
    $text = Read-CEBoundedText -Path $file -MaxBytes 1MB -FollowLinks -SkipReason $why
    if ($null -eq $text) { throw "/etc/wsl.conf was not read: $($why.Value)" }
    return [pscustomobject]@{ Reachable = $true; Exists = $true; Lines = @($text -split '\r?\n') }
}

function Get-CEWslDistribution {
    <# WSL distributions of the user, with Windows drive mounting read from /etc/wsl.conf when the distribution is running. #>
    param($Context)
    $keys = Get-CEWslRegistryEntry
    if ($keys.Count -eq 0) { return ,@() }
    $running = @()
    $runningKnown = $false
    if (-not $Context.IsSystem) {
        try {
            $native = Invoke-CENative -FilePath 'wsl.exe' -ArgumentList @('--list', '--running', '--quiet')
            $running = ConvertFrom-CEWslListOutput -Lines $native.Output
            $runningKnown = $true
        }
        catch { $runningKnown = $false }
    }
    $distros = New-Object System.Collections.ArrayList
    foreach ($k in $keys) {
        $name = $k.Name
        $isRunning = $(if ($runningKnown) { $running -contains $name } else { $null })
        $automount = $null
        $how = if ($Context.IsSystem) { 'not verified: the audit ran as SYSTEM' } elseif (-not $isRunning) { 'not verified: the distribution is not running' } else { '' }
        if ($isRunning) {
            try {
                $read = Read-CEWslConf -Name $name
                if (-not $read.Reachable) { $how = 'not verified: the distribution''s files could not be read' }
                elseif (-not $read.Exists) { $automount = $true; $how = 'no /etc/wsl.conf, so the default applies' }
                else {
                    $conf = ConvertFrom-CEIniText -Lines $read.Lines
                    $value = if ($conf.ContainsKey('automount') -and $conf['automount'].ContainsKey('enabled')) { $conf['automount']['enabled'] } else { 'true' }
                    $automount = ($value -notmatch '^false$')
                    $how = 'read from /etc/wsl.conf'
                }
            }
            catch { $how = "not verified: $($_.Exception.Message)" }
        }
        [void]$distros.Add([pscustomobject]@{
            Name       = $name
            Version    = $k.Version
            DefaultUid = [int](Get-CEObjectValue $k 'DefaultUid' 1000)
            Running    = $isRunning
            Automount  = $automount
            AutomountSource = $how
        })
    }
    return ,$distros.ToArray()
}

function Get-CEWslNetworkingMode {
    <# networkingMode from the user's .wslconfig, read through the profile read layer ('' when unset or not read; see -Log). #>
    param([string]$ProfilePath, $Log, [bool]$Above = $true)
    if (-not $ProfilePath) { return '' }
    $text = Read-CEProfileFile -ProfilePath $ProfilePath -Relative '.wslconfig' -MaxBytes 1MB -Log $Log -Above $Above -Topic 'wslconfig'
    if ($null -eq $text) { return '' }
    $ini = ConvertFrom-CEIniText -Lines @($text -split '\r?\n')
    if ($ini.ContainsKey('wsl2') -and $ini['wsl2'].ContainsKey('networkingmode')) { return ([string]$ini['wsl2']['networkingmode']).ToLowerInvariant() }
    return ''
}

# Signer names on the Docker CLI (the certificate's common name).
$script:CEDockerPublishers = @('Docker Inc', 'Docker, Inc.')

function Resolve-CEDockerPath {
    <# docker.exe signed by Docker: the Docker Desktop copy first, then PATH (see Resolve-CETrustedTool). #>
    $candidates = @()
    if ($env:ProgramFiles) { $candidates += Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe' }
    $candidates += @(Get-Command 'docker.exe' -CommandType Application -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    return (Resolve-CETrustedTool -Candidate $candidates -Publisher $script:CEDockerPublishers)
}

function Get-CEContainer {
    <# Running Docker containers, when a verified docker CLI (Resolve-CEDockerPath) is available in a user session. #>
    param($Context, [string]$DockerPath)
    if ($Context.IsSystem -or -not $DockerPath) { return ,@() }
    try {
        $native = Invoke-CENative -FilePath $DockerPath -ArgumentList @('ps', '--format', '{{.Names}}|{{.Image}}|{{.Ports}}')
        if ($native.ExitCode -ne 0) { return ,@() }
        return ,@(@($native.Output) | Where-Object { $_ -match '^[^|]+\|' } | ForEach-Object {
            $parts = "$_" -split '\|', 3
            [pscustomobject]@{ Name = $parts[0]; Image = $parts[1]; Ports = $(if ($parts.Count -gt 2) { $parts[2] } else { '' }) }
        })
    }
    catch { return ,@() }
}

function Get-CEVirtualisationListener {
    <# TCP ports listened on by processes that publish ports for VMs and containers (config/virtualisation.json). #>
    $known = @{}
    foreach ($p in @(Get-CEObjectValue (Get-CEConfig).'virtualisation' 'portProcesses' @())) { $known[([string]$p.process).ToLowerInvariant()] = [string]$p.product }
    if ($known.Count -eq 0 -or -not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { return ,@() }
    $names = @{}
    $found = New-Object System.Collections.ArrayList
    foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        if (-not $c) { continue }
        $procId = [int]$c.OwningProcess
        if (-not $names.ContainsKey($procId)) {
            $procName = ''
            try { $procName = ([string](Get-Process -Id $procId -ErrorAction Stop).ProcessName).ToLowerInvariant() } catch { $procName = '' }
            $names[$procId] = $procName
        }
        $proc = $names[$procId]
        if (-not $known.ContainsKey($proc)) { continue }
        $addr = [string]$c.LocalAddress
        [void]$found.Add([pscustomobject]@{
            Product = $known[$proc]
            Process = $proc
            Address = $addr
            Port    = [int]$c.LocalPort
            Exposed = -not ($addr -match '^127\.' -or $addr -eq '::1')
        })
    }
    return ,@($found.ToArray() | Sort-Object Product, Port, Address -Unique)
}

function Get-CEVirtualisationState {
    <#
        Everything SC-12 and FW-07 look at, gathered once per audit: HyperV, VMware, VirtualBox, Wsl,
        WslNetworking, Containers, Listeners, Notes (what could not be checked for reasons other
        than reading the profile: a SYSTEM audit has no user session) and NotRead (the locations in
        the user's profile, and the VM files their settings name, that could not be read, see
        15-ProfileReads.ps1, and Hyper-V virtual machines that could not be listed, topic hyperv).
    #>
    param($Context)
    $cacheKey = "$($Context.ComputerName)|$($Context.AuditTime.Ticks)|$($Context.IsElevated)|$($Context.IsSystem)"
    if ($script:CEVirtualisationCache -and $script:CEVirtualisationCache.Key -eq $cacheKey) { return $script:CEVirtualisationCache.State }
    $state = Get-CEVirtualisationStateUncached -Context $Context
    $script:CEVirtualisationCache = @{ Key = $cacheKey; State = $state }
    return $state
}

function Get-CEVirtualisationStateUncached {
    param($Context)
    $profilePath = Get-CEUserProfilePath -Context $Context
    $cfg = (Get-CEConfig).'virtualisation'
    $toolingPatterns = @(Get-CEObjectValue $cfg 'toolingDistributions' @())
    $wsl = Get-CEWslDistribution -Context $Context
    foreach ($d in $wsl) {
        $d | Add-Member -NotePropertyName Tooling -NotePropertyValue (@($toolingPatterns | Where-Object { $d.Name -like $_ }).Count -gt 0)
    }
    $log = New-CENotReadLog
    $notes = @()
    if (-not $profilePath) {
        Add-CENotRead -Log $log -Location '%USERPROFILE%' -Kind 'existence' -Reason $script:CENotReadText.NoProfile -Topic 'profile' `
            -Remedy 'Run the audit while the person who uses this device is signed in at the console.'
    }
    elseif (-not (Test-CEProfileReady $profilePath)) {
        Add-CENotRead -Log $log -Location '%USERPROFILE%' -Kind 'folder-listing' -Reason $script:CENotReadText.NotLocal -Topic 'profile' `
            -Remedy 'Check the virtual machines in this profile by hand.'
    }
    elseif ($Context.IsSystem) { $notes += 'Ran as SYSTEM: WSL drive mounting and Docker containers need a user session to check' }
    $hyperV = Get-CEHyperVMachine -Context $Context
    Add-CEHyperVNotRead -Log $log -HyperV $hyperV
    $docker = $null
    if (-not $Context.IsSystem) {
        $docker = Resolve-CEDockerPath
        if (-not $docker.Path -and @($docker.Refused).Count) {
            $notes += "Docker containers were not checked: $(@($docker.Refused) -join '; ') is not signed by Docker, so it was not run"
        }
    }
    # The profile read layer's rules apply when the audit has more rights than the user.
    $above = Test-CEAboveUserRights -Context $Context
    $vmware = Get-CEVMwareMachine -ProfilePath $profilePath -Log $log -Above $above   # assign first: it returns ,array
    $vbox = Get-CEVirtualBoxMachine -ProfilePath $profilePath -Log $log -Above $above
    $networking = Get-CEWslNetworkingMode -ProfilePath $profilePath -Log $log -Above $above
    return [pscustomobject]@{
        HyperV         = $hyperV
        VMware         = $vmware
        VirtualBox     = $vbox
        Wsl            = $wsl
        WslNetworking  = $networking
        Containers     = Get-CEContainer -Context $Context -DockerPath $(if ($docker) { $docker.Path } else { '' })
        Listeners      = Get-CEVirtualisationListener
        Notes          = $notes
        NotRead        = (Get-CENotReadRecordArray $log)
    }
}
