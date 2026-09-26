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

function Get-CEHyperVMachine {
    <# Hyper-V VMs with whether they are on an external (bridged) switch. Needs elevation. #>
    param($Context)
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ Readable = $true; Message = ''; Machines = @(); NatMappings = @() } }
    if (-not $Context.IsElevated) { return [pscustomobject]@{ Readable = $false; Message = 'Hyper-V virtual machines need elevation to list'; Machines = @(); NatMappings = @() } }
    try {
        $external = @(Get-VMSwitch -ErrorAction Stop | Where-Object { "$($_.SwitchType)" -eq 'External' } | ForEach-Object { $_.Name })
        $machines = @(Get-VM -ErrorAction Stop | ForEach-Object {
            $vm = $_
            $switches = @(Get-VMNetworkAdapter -VMName $vm.Name -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.SwitchName } | Where-Object { $_ })
            [pscustomobject]@{ Name = [string]$vm.Name; State = [string]$vm.State; ExternalSwitches = @($switches | Where-Object { $external -contains $_ }) }
        })
        $nat = @()
        if (Get-Command Get-NetNatStaticMapping -ErrorAction SilentlyContinue) {
            $nat = @(Get-NetNatStaticMapping -ErrorAction SilentlyContinue | ForEach-Object {
                "$($_.Protocol) $($_.ExternalIPAddress):$($_.ExternalPort) -> $($_.InternalIPAddress):$($_.InternalPort)"
            })
        }
        return [pscustomobject]@{ Readable = $true; Message = ''; Machines = $machines; NatMappings = $nat }
    }
    catch {
        return [pscustomobject]@{ Readable = $false; Message = "Hyper-V could not be read: $($_.Exception.Message)"; Machines = @(); NatMappings = @() }
    }
}

function Test-CELocalFilePath {
    <#
        True only for an absolute path on a fixed local drive (C:\...). Rejects UNC
        paths (\\host\share, \\?\, \\.\), drive-relative and rooted-relative
        paths, and mapped or removable drives. VM inventory files live in a standard
        user's own profile, so a SYSTEM-run audit must not open a path they name that
        points off the machine (an SMB path would coerce SYSTEM to authenticate).
    #>
    param([string]$Path)
    if (-not $Path) { return $false }
    if ($Path -match '^[\\/]{2}') { return $false }
    if ($Path -notmatch '^[A-Za-z]:[\\/]') { return $false }
    try { if (-not [IO.Path]::IsPathRooted($Path)) { return $false } } catch { return $false }
    try {
        $full = [IO.Path]::GetFullPath($Path)
        if ($full -match '^[\\/]{2}') { return $false }
        $root = [IO.Path]::GetPathRoot($full)
        return ([IO.DriveInfo]::new($root).DriveType -eq 'Fixed')
    }
    catch { return $false }
}

function Read-CEBoundedText {
    <#
        Text of a file a standard user may control, or $null when it is missing, is a junction or
        symbolic link, is larger than MaxBytes or can't be read. Never reads more than the size it
        checked, so a file that grows after the check is not read in full either. Opened for reading
        only; nothing in it is run. The check and the open are separate steps (see SECURITY.md).
    #>
    param([string]$Path, [int]$MaxBytes)
    if (-not $Path -or $MaxBytes -le 0) { return $null }
    try {
        $fi = New-Object IO.FileInfo $Path
        if (-not $fi.Exists -or ([int]($fi.Attributes -band [IO.FileAttributes]::ReparsePoint)) -ne 0 -or $fi.Length -gt $MaxBytes) { return $null }
        $size = [int]$fi.Length
        $buf = New-Object byte[] ($size + 1)
        $total = 0
        $fs = New-Object IO.FileStream -ArgumentList $Path, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::ReadWrite)
        try {
            while ($total -lt $buf.Length) {
                $n = $fs.Read($buf, $total, $buf.Length - $total)
                if ($n -le 0) { break }
                $total += $n
            }
        }
        finally { $fs.Dispose() }
        if ($total -gt $size) { Write-Verbose "$Path grew while it was read; not used"; return $null }
        $reader = New-Object IO.StreamReader -ArgumentList (New-Object IO.MemoryStream -ArgumentList $buf, 0, $total), ([Text.Encoding]::UTF8), $true
        try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
    }
    catch { Write-Verbose "Could not read ${Path}: $($_.Exception.Message)"; return $null }
}

function Read-CEProfileText {
    <#
        Text of a file below the user's profile, reached through plain folders only and read with
        Read-CEBoundedText; $null when that fails. A SYSTEM audit reads these from a profile the
        user controls.
    #>
    param([string]$ProfilePath, [string]$Relative, [int]$MaxBytes)
    if (-not (Test-CEPlainProfileItem -ProfilePath $ProfilePath -Relative $Relative -NoLink)) { return $null }
    return (Read-CEBoundedText -Path (Join-Path $ProfilePath $Relative) -MaxBytes $MaxBytes)
}

function Get-CEVMwareMachine {
    <# VMware Workstation/Player VMs from the user's inventory.vmls. #>
    param([string]$ProfilePath)
    if (-not $ProfilePath) { return ,@() }
    $text = Read-CEProfileText -ProfilePath $ProfilePath -Relative 'AppData\Roaming\VMware\inventory.vmls' -MaxBytes 1MB
    if ($null -eq $text) { return ,@() }
    $paths = New-Object System.Collections.ArrayList
    foreach ($line in @($text -split '\r?\n')) {
        if ("$line" -match '^\s*vmlist\d+\.config\s*=\s*"(.+\.vmx)"' -and -not $paths.Contains($Matches[1])) { [void]$paths.Add($Matches[1]) }
    }
    $machines = New-Object System.Collections.ArrayList
    foreach ($p in $paths) {
        # The path comes from a user-writable file; never open one that points off this machine.
        if (-not (Test-CELocalFilePath $p)) { Write-Verbose "Skipping non-local VMware path $p"; continue }
        $vmx = Read-CEBoundedText -Path $p -MaxBytes 1MB
        if ($null -eq $vmx) { continue }
        $vm = ConvertFrom-CEVmxText -Lines @($vmx -split '\r?\n') -Path $p
        $vm | Add-Member -NotePropertyName Path -NotePropertyValue $p
        [void]$machines.Add($vm)
    }
    return ,$machines.ToArray()
}

function Get-CEVirtualBoxMachine {
    <# VirtualBox VMs registered in the user's VirtualBox.xml. #>
    param([string]$ProfilePath)
    if (-not $ProfilePath) { return ,@() }
    $registry = Join-Path $ProfilePath '.VirtualBox\VirtualBox.xml'
    $text = Read-CEProfileText -ProfilePath $ProfilePath -Relative '.VirtualBox\VirtualBox.xml' -MaxBytes 4MB
    if ($null -eq $text) { return ,@() }
    $machines = New-Object System.Collections.ArrayList
    try {
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.LoadXml($text)
        foreach ($entry in @($doc.SelectNodes("//*[local-name()='MachineEntry']"))) {
            $src = [string]$entry.GetAttribute('src')
            if (-not $src) { continue }
            if (-not [IO.Path]::IsPathRooted($src)) { $src = Join-Path (Split-Path -Parent $registry) $src }
            # src comes from a user-writable file; never open one that points off this machine.
            if (-not (Test-CELocalFilePath $src)) { Write-Verbose "Skipping non-local VirtualBox path $src"; continue }
            $vboxText = Read-CEBoundedText -Path $src -MaxBytes 4MB
            if ($null -eq $vboxText) { continue }
            try {
                $vm = ConvertFrom-CEVboxXml -Xml $vboxText
                if ($vm) { $vm | Add-Member -NotePropertyName Path -NotePropertyValue $src; [void]$machines.Add($vm) }
            }
            catch { Write-Verbose "Could not read $src : $_" }
        }
    }
    catch { Write-Verbose "Could not read $registry : $_" }
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

function Read-CEWslConf {
    <#
        /etc/wsl.conf of a running distribution through \\wsl.localhost.
        Returns Reachable (the distribution's /etc could be read), Exists and Lines.
    #>
    param([Parameter(Mandatory)][string]$Name)
    $etc = "\\wsl.localhost\$Name\etc"
    if (-not (Test-Path -LiteralPath $etc -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ Reachable = $false; Exists = $false; Lines = @() } }
    $file = Join-Path $etc 'wsl.conf'
    if (-not (Test-Path -LiteralPath $file -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ Reachable = $true; Exists = $false; Lines = @() } }
    return [pscustomobject]@{ Reachable = $true; Exists = $true; Lines = @(Get-Content -LiteralPath $file -ErrorAction Stop) }
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
    param([string]$ProfilePath)
    if (-not $ProfilePath) { return '' }
    $text = Read-CEProfileText -ProfilePath $ProfilePath -Relative '.wslconfig' -MaxBytes 1MB
    if ($null -eq $text) { return '' }
    $ini = ConvertFrom-CEIniText -Lines @($text -split '\r?\n')
    if ($ini.ContainsKey('wsl2') -and $ini['wsl2'].ContainsKey('networkingmode')) { return ([string]$ini['wsl2']['networkingmode']).ToLowerInvariant() }
    return ''
}

function Get-CEContainer {
    <# Running Docker containers, when the docker CLI is available in a user session. #>
    param($Context)
    if ($Context.IsSystem -or -not (Get-Command docker -ErrorAction SilentlyContinue)) { return ,@() }
    try {
        $native = Invoke-CENative -FilePath 'docker' -ArgumentList @('ps', '--format', '{{.Names}}|{{.Image}}|{{.Ports}}')
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
    <# Everything SC-12 and FW-07 look at, gathered once per audit. #>
    param($Context)
    $cacheKey = "$($Context.ComputerName)|$($Context.AuditTime.Ticks)|$($Context.IsElevated)"
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
    $notes = @()
    if (-not $profilePath) { $notes += 'No signed-in user, so per-user virtual machines and WSL distributions were not checked' }
    elseif ($Context.IsSystem) { $notes += 'Ran as SYSTEM: WSL drive mounting and Docker containers need a user session to check' }
    $hyperV = Get-CEHyperVMachine -Context $Context
    if (-not $hyperV.Readable) { $notes += $hyperV.Message }
    return [pscustomobject]@{
        HyperV         = $hyperV
        VMware         = Get-CEVMwareMachine -ProfilePath $profilePath
        VirtualBox     = Get-CEVirtualBoxMachine -ProfilePath $profilePath
        Wsl            = $wsl
        WslNetworking  = Get-CEWslNetworkingMode -ProfilePath $profilePath
        Containers     = Get-CEContainer -Context $Context
        Listeners      = Get-CEVirtualisationListener
        Notes          = $notes
    }
}
