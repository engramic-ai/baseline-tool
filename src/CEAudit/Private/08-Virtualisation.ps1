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
        Whether this audit reads the user's profile with more rights than the user has: as SYSTEM,
        or elevated (a standard user's links could steer an elevated "Restart as administrator"
        audit as well). Then links the user made below their profile are not followed, and files
        stored online only are not downloaded (see SECURITY.md). In the user's own non-elevated
        session (the per-user probe) their links are followed as usual. No context counts as above.
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

function Get-CEUserFileSkipReason {
    <#
        Why an audit with more rights than the user must not open this file (a FileInfo), or '' when
        it may: it is a junction or symbolic link (Test-CELinkItem), or it is stored online only
        (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, RECALL_ON_OPEN or OFFLINE), so reading it would make
        the sync app download it. A downloaded OneDrive or other cloud file is read: it keeps a
        reparse point, but not a link one. Attributes only: nothing is opened.
    #>
    param($Item)
    if (Test-CELinkItem $Item) { return 'it is a junction or symbolic link' }
    if (([long]$Item.Attributes -band 0x441000) -ne 0) { return 'it is stored online only, and an elevated or SYSTEM audit does not download it' }
    return ''
}

function Read-CEBoundedText {
    <#
        Text of a file a standard user may control, or $null when it is missing, is larger than
        MaxBytes or can't be read, and, unless -FollowLinks (an audit in the user's own session), when
        Get-CEUserFileSkipReason gives a reason not to open it (a link, or a file stored online only).
        Never reads more than the size of the opened file, so a file that grows after that is not
        read in full either. Opened for reading only; nothing in it is run. The check and the open
        are separate steps (see SECURITY.md). -SkipReason receives why the file was not read
        ('missing' when it isn't there); -ByteCount the number of bytes read.
    #>
    param([string]$Path, [int]$MaxBytes, [switch]$FollowLinks, [ref]$SkipReason, [ref]$ByteCount)
    if ($null -ne $SkipReason) { $SkipReason.Value = '' }
    if (-not $Path -or $MaxBytes -le 0) { return $null }
    $why = ''
    try {
        $fi = New-Object IO.FileInfo $Path
        if (-not $fi.Exists) { $why = 'missing' }
        elseif (-not $FollowLinks) { $why = Get-CEUserFileSkipReason -Item $fi }
        if (-not $why) {
            $fs = New-Object IO.FileStream -ArgumentList $Path, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::ReadWrite)
            try {
                # The size of the opened file: a link followed in the user's own session is measured at its target.
                $size = [long]$fs.Length
                if ($size -gt $MaxBytes) { $why = "it is larger than $([Math]::Round($MaxBytes / 1MB, 2)) MB" }
                else {
                    $buf = New-Object byte[] ($size + 1)
                    $total = 0
                    while ($total -lt $buf.Length) {
                        $n = $fs.Read($buf, $total, $buf.Length - $total)
                        if ($n -le 0) { break }
                        $total += $n
                    }
                    if ($total -gt $size) { $why = 'it grew while it was read' }
                }
            }
            finally { $fs.Dispose() }
        }
    }
    catch { $why = "it could not be read: $($_.Exception.Message)" }
    if ($why) {
        Write-Verbose "Not reading ${Path}: $why"
        if ($null -ne $SkipReason) { $SkipReason.Value = $why }
        return $null
    }
    if ($null -ne $ByteCount) { $ByteCount.Value = [long]$total }
    $reader = New-Object IO.StreamReader -ArgumentList (New-Object IO.MemoryStream -ArgumentList $buf, 0, $total), ([Text.Encoding]::UTF8), $true
    try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
}

function Read-CEProfileText {
    <#
        Text of a file below the user's profile, read with Read-CEBoundedText; $null when that fails.
        Unless -FollowLinks (an audit in the user's own session), it is reached through plain folders
        only: a SYSTEM or elevated audit reads these from a profile the user controls.
    #>
    param([string]$ProfilePath, [string]$Relative, [int]$MaxBytes, [switch]$FollowLinks)
    if (-not (Test-CEPlainProfileItem -ProfilePath $ProfilePath -Relative $Relative -NoLink -FollowLinks:$FollowLinks)) { return $null }
    return (Read-CEBoundedText -Path (Join-Path $ProfilePath $Relative) -MaxBytes $MaxBytes -FollowLinks:$FollowLinks)
}

function Get-CEFolderChainProblem {
    <#
        For Path, an absolute local path taken from a file the user controls: '' when every folder on
        the way to it is a plain folder, 'missing' when one is not there, and otherwise why not.
        Folders are checked from the drive root, or from ProfilePath when Path is below it (the
        profile folder itself may be a link: profile containers and moved profiles are). The file
        itself is not looked at. Attributes only: nothing is opened.
    #>
    param([string]$Path, [string]$ProfilePath)
    if (-not (Test-CELocalFilePath $Path)) { return 'it is not on a local fixed drive' }
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $base = [IO.Path]::GetPathRoot($full)
        if ($ProfilePath -and (Test-CELocalFilePath $ProfilePath)) {
            $prof = [IO.Path]::GetFullPath($ProfilePath).TrimEnd('\', '/') + '\'
            if ($full.StartsWith($prof, [StringComparison]::OrdinalIgnoreCase)) { $base = $prof }
        }
        $rel = $full.Substring($base.Length)
        if (-not (Test-CERelativePathText $rel)) { return 'its path has a part Windows would read as another name' }
        $p = $base
        foreach ($seg in @((Split-Path -Parent $rel) -split '\\' | Where-Object { $_ })) {
            $p = Join-Path $p $seg
            $d = New-Object IO.DirectoryInfo $p
            if (-not $d.Exists) { return 'missing' }
            if (Test-CELinkItem $d) { return "the folder $p on the way to it is a junction or symbolic link" }
        }
        return ''
    }
    catch { return "its path could not be checked: $($_.Exception.Message)" }
}

function Get-CEVmFileCap {
    <# How many VM files one inventory can make an elevated or SYSTEM audit read (maxVmFilesPerInventory, default 64). #>
    return (ConvertTo-CEBoundedInt (Get-CEObjectValue (Get-CEConfig).'virtualisation' 'maxVmFilesPerInventory') -Default 64 -Min 1 -Max 10000)
}

function Read-CENamedVmFile {
    <#
        Text of a virtual machine file named in the user's VMware or VirtualBox inventory, or $null.
        The path comes from a file the user controls, so it must be on a local fixed drive and, unless
        -FollowLinks (an audit in the user's own session), every folder on the way must be a plain
        folder and the file must be neither a link nor stored online only. A file that is there but
        is not read is reported rather than dropped: in -Unread when only an audit with more rights
        than the user skips it (a link, a file stored online only), and otherwise (too large, or it
        could not be read) in -Notes. Without -Unread, both go to -Notes.
    #>
    param([string]$Path, [string]$Product, [string]$ProfilePath, [int]$MaxBytes, [switch]$FollowLinks,
        [System.Collections.ArrayList]$Notes, [System.Collections.ArrayList]$Unread)
    # Never open a path that points off this machine (an SMB path would coerce SYSTEM to authenticate).
    if (-not (Test-CELocalFilePath $Path)) { Write-Verbose "Skipping non-local $Product path $Path"; return $null }
    $why = ''
    if (-not $FollowLinks) {
        $why = Get-CEFolderChainProblem -Path $Path -ProfilePath $ProfilePath
        if (-not $why) {
            try { $fi = New-Object IO.FileInfo $Path; if ($fi.Exists) { $why = Get-CEUserFileSkipReason -Item $fi } }
            catch { $why = "its path could not be checked: $($_.Exception.Message)" }
        }
    }
    # Skipped only because this audit has more rights than the user: their own session reads it.
    $aboveUserSkip = [bool]$why
    $text = $null
    if (-not $why) {
        $reason = [ref]''
        $text = Read-CEBoundedText -Path $Path -MaxBytes $MaxBytes -FollowLinks:$FollowLinks -SkipReason $reason
        if ($null -eq $text) { $why = [string]$reason.Value }
    }
    if ($why -and $why -ne 'missing') {
        $note = "$Product virtual machine file $Path found, not read: $why"
        if ($aboveUserSkip -and $null -ne $Unread) { [void]$Unread.Add($note) }
        elseif ($null -ne $Notes) { [void]$Notes.Add($note) }
    }
    return $text
}

function Add-CEVmCapNote {
    param([System.Collections.ArrayList]$Notes, [string]$Product, [int]$Cap)
    if ($null -ne $Notes) {
        [void]$Notes.Add("The $Product inventory names more than $Cap virtual machine files; an elevated or SYSTEM audit reads only the first $Cap (maxVmFilesPerInventory in virtualisation.json), so the rest were not checked")
    }
}

function Get-CEUnreadVmFileAdvice {
    <#
        What to do about VM files an elevated or SYSTEM audit found and did not read (UnreadVmFiles).
        -MachineCheck for a Machine-scope check such as FW-07, which the per-user probe does not run:
        only a full audit in the user's own session checks it.
    #>
    param([switch]$MachineCheck)
    $how = if ($MachineCheck) {
        'run the full audit without elevation while signed in as that user (app\Invoke-CEAudit.ps1 from a prompt that is not elevated, or the GUI without Restart as administrator)'
    }
    else { 'run the per-user probe (app\Invoke-CEUserProbe.ps1), or the tool without elevation while signed in as that user' }
    return "An elevated or SYSTEM audit does not open these files. Check them in the user's own session: $how. Or move the virtual machine folder off the junction or symbolic link, make it available offline, or raise maxVmFilesPerInventory in virtualisation.json, as each note says."
}

function Get-CEVmFileNoteAdvice {
    <# What to do about VM files that were found and not read for another reason (too large, or not readable). #>
    return 'Check that each virtual machine file named can be read and is a VMware .vmx (up to 1 MB) or VirtualBox .vbox (up to 4 MB) file, then run the audit again.'
}

function Get-CEVMwareMachine {
    <#
        VMware Workstation/Player VMs from the user's inventory.vmls. Unless -FollowLinks (an audit in
        the user's own session), at most Get-CEVmFileCap files are read; VM files found but not read,
        and the cap when it is reached, are added to -Unread and -Notes as Read-CENamedVmFile says.
    #>
    param([string]$ProfilePath, [switch]$FollowLinks, [System.Collections.ArrayList]$Notes, [System.Collections.ArrayList]$Unread)
    if ($null -eq $Unread) { $Unread = $Notes }
    if (-not $ProfilePath) { return ,@() }
    $text = Read-CEProfileText -ProfilePath $ProfilePath -Relative 'AppData\Roaming\VMware\inventory.vmls' -MaxBytes 1MB -FollowLinks:$FollowLinks
    if ($null -eq $text) { return ,@() }
    $paths = New-Object System.Collections.ArrayList
    foreach ($line in @($text -split '\r?\n')) {
        if ("$line" -match '^\s*vmlist\d+\.config\s*=\s*"(.+\.vmx)"' -and -not $paths.Contains($Matches[1])) { [void]$paths.Add($Matches[1]) }
    }
    $cap = Get-CEVmFileCap
    $count = 0
    $machines = New-Object System.Collections.ArrayList
    foreach ($p in $paths) {
        if (-not (Test-CELocalFilePath $p)) { Write-Verbose "Skipping non-local VMware path $p"; continue }
        if (-not $FollowLinks -and ++$count -gt $cap) { Add-CEVmCapNote -Notes $Unread -Product 'VMware' -Cap $cap; break }
        $vmx = Read-CENamedVmFile -Path $p -Product 'VMware' -ProfilePath $ProfilePath -MaxBytes 1MB -FollowLinks:$FollowLinks -Notes $Notes -Unread $Unread
        if ($null -eq $vmx) { continue }
        $vm = ConvertFrom-CEVmxText -Lines @($vmx -split '\r?\n') -Path $p
        $vm | Add-Member -NotePropertyName Path -NotePropertyValue $p
        [void]$machines.Add($vm)
    }
    return ,$machines.ToArray()
}

function Get-CEVirtualBoxMachine {
    <#
        VirtualBox VMs registered in the user's VirtualBox.xml. Unless -FollowLinks, at most
        Get-CEVmFileCap files are read; see Get-CEVMwareMachine for -Notes and -Unread.
    #>
    param([string]$ProfilePath, [switch]$FollowLinks, [System.Collections.ArrayList]$Notes, [System.Collections.ArrayList]$Unread)
    if ($null -eq $Unread) { $Unread = $Notes }
    if (-not $ProfilePath) { return ,@() }
    $registry = Join-Path $ProfilePath '.VirtualBox\VirtualBox.xml'
    $text = Read-CEProfileText -ProfilePath $ProfilePath -Relative '.VirtualBox\VirtualBox.xml' -MaxBytes 4MB -FollowLinks:$FollowLinks
    if ($null -eq $text) { return ,@() }
    $cap = Get-CEVmFileCap
    $count = 0
    $machines = New-Object System.Collections.ArrayList
    try {
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.LoadXml($text)
        foreach ($entry in @($doc.SelectNodes("//*[local-name()='MachineEntry']"))) {
            $src = [string]$entry.GetAttribute('src')
            if (-not $src) { continue }
            if (-not [IO.Path]::IsPathRooted($src)) { $src = Join-Path (Split-Path -Parent $registry) $src }
            if (-not (Test-CELocalFilePath $src)) { Write-Verbose "Skipping non-local VirtualBox path $src"; continue }
            if (-not $FollowLinks -and ++$count -gt $cap) { Add-CEVmCapNote -Notes $Unread -Product 'VirtualBox' -Cap $cap; break }
            $vboxText = Read-CENamedVmFile -Path $src -Product 'VirtualBox' -ProfilePath $ProfilePath -MaxBytes 4MB -FollowLinks:$FollowLinks -Notes $Notes -Unread $Unread
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
    param([string]$ProfilePath, [switch]$FollowLinks)
    if (-not $ProfilePath) { return '' }
    $text = Read-CEProfileText -ProfilePath $ProfilePath -Relative '.wslconfig' -MaxBytes 1MB -FollowLinks:$FollowLinks
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
        WslNetworking, Containers, Listeners, Notes (what could not be checked), VmFileNotes (the
        Notes about VM files found and not read, and the maxVmFilesPerInventory limit) and
        UnreadVmFiles (those of VmFileNotes that only an elevated or SYSTEM audit skips: a link, a
        file stored online only, the limit; the user's own session reads them).
    #>
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
    $docker = $null
    if (-not $Context.IsSystem) {
        $docker = Resolve-CEDockerPath
        if (-not $docker.Path -and @($docker.Refused).Count) {
            $notes += "Docker containers were not checked: $(@($docker.Refused) -join '; ') is not signed by Docker, so it was not run"
        }
    }
    # Links in the user's profile are followed only in their own non-elevated session.
    $follow = -not (Test-CEAboveUserRights -Context $Context)
    $vmNotes = New-Object System.Collections.ArrayList
    $vmUnread = New-Object System.Collections.ArrayList
    $vmware = Get-CEVMwareMachine -ProfilePath $profilePath -FollowLinks:$follow -Notes $vmNotes -Unread $vmUnread   # assign first: it returns ,array
    $vbox = Get-CEVirtualBoxMachine -ProfilePath $profilePath -FollowLinks:$follow -Notes $vmNotes -Unread $vmUnread
    $notes += @($vmNotes) + @($vmUnread)
    return [pscustomobject]@{
        HyperV         = $hyperV
        VMware         = $vmware
        VirtualBox     = $vbox
        Wsl            = $wsl
        WslNetworking  = Get-CEWslNetworkingMode -ProfilePath $profilePath -FollowLinks:$follow
        Containers     = Get-CEContainer -Context $Context -DockerPath $(if ($docker) { $docker.Path } else { '' })
        Listeners      = Get-CEVirtualisationListener
        Notes          = $notes
        # VM files found but not read for any reason, and the maxVmFilesPerInventory limit (also in Notes).
        VmFileNotes    = @($vmNotes) + @($vmUnread)
        # Those only an elevated or SYSTEM audit skips. Only the user's own session reads these files.
        UnreadVmFiles  = @($vmUnread)
    }
}
