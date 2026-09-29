# ---------------------------------------------------------------------------
# The one read layer for locations the signed-in user controls: everything below
# their profile folder, and the virtual machine files their settings name. The
# audit may read these as SYSTEM or elevated (Test-CEAboveUserRights), with more
# rights than the user who owns them. Then:
#   * folders are listed, and items checked for, through a junction only when the
#     junction's own target, read without following it, is on a local fixed drive
#     or a local volume and nothing on the way to it is a symbolic link or a link
#     the audit does not recognise (Get-CEJunctionProblem);
#   * symbolic links and other links are never followed, even to list names;
#   * file contents are never read through any link, and a file stored online only
#     is never downloaded.
# Whether something is there is read with Get-CEItemPresence, which tells "Windows says
# nothing is there" apart from "the audit may not look": only the first is missing.
# Nothing skipped is dropped: each primitive writes a record to a not-read log
# (New-CENotReadLog), which the state builders return as NotRead and the checks
# report as Manual (New-CENotReadResult). Reasons are fixed strings: no error
# text, file contents or absolute profile paths ever reach a record.
# In the user's own non-elevated session links are followed as usual.
# ---------------------------------------------------------------------------

$script:CENotReadText = @{
    SymlinkOnWay   = 'a symbolic link on the way is not followed by an elevated or SYSTEM audit (it could point off this computer)'
    JunctionOnWay  = 'a junction on the way leads through a symbolic link or to a location the audit does not recognise'
    LinkForContent = 'a junction or symbolic link on the way is not followed when reading file contents above the user''s rights'
    ItemIsLink     = 'it is a junction or symbolic link, which is not followed when reading file contents above the user''s rights'
    Cloud          = 'it is stored online only, and an elevated or SYSTEM audit does not download it'
    UnknownReparse = 'a reparse point of a kind the audit does not recognise'
    NotLocal       = 'it is not on a local fixed drive'
    Parse          = 'it could not be parsed by the audit'
    NoProfile      = 'no signed-in user profile was found'
    OddName        = 'a name ending in a dot or a space is not read (Windows would read it as another name)'
    OddPath        = 'its path has a part Windows would read as another name'
    Grew           = 'it grew while it was read'
    Budget         = 'the audit had already read as much of these files as it reads in one audit'
    Malformed      = 'catalog path is malformed'
}

function Get-CEErrorTypeName {
    <#
        The type name of the error in an ErrorRecord, unwrapped from the exception PowerShell puts
        around a failed .NET call. Records carry this, never the message, which can quote a path or
        the text that could not be parsed.
    #>
    param($ErrorRecord)
    $e = $ErrorRecord.Exception
    while ($e -is [System.Management.Automation.MethodInvocationException] -or $e -is [System.Management.Automation.GetValueInvocationException]) {
        if (-not $e.InnerException) { break }
        $e = $e.InnerException
    }
    return $e.GetType().Name
}

function Get-CEReparseTag {
    <#
        The reparse tag of Path (0 when it is not a reparse point), or -1 when it can't be read.
        Reads the folder entry only (FindFirstFileW), so the item is not opened: a link is not
        followed and a cloud file is not downloaded. Tests mock this.
    #>
    param([string]$Path)
    # FindFirstFileW treats * and ? as wildcards, which would name another item (the ? of a \\?\ prefix is not one).
    if (-not $Path -or ($Path -replace '^\\\\\?\\', '') -match '[*?]' -or -not (Test-CEIsWindows)) { return [long]-1 }
    try {
        if (-not ('CEAudit.ReparseTag' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CEAudit {
    public static class ReparseTag {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct FindData {
            public uint Attributes;
            public uint CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
            public uint SizeHigh, SizeLow, Reserved0, Reserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string FileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string AlternateFileName;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr FindFirstFileW(string name, out FindData data);
        [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr handle);
        public static long Get(string path) {
            FindData data;
            IntPtr handle = FindFirstFileW(path, out data);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1)) { return -1; }
            FindClose(handle);
            if ((data.Attributes & 0x400) == 0) { return 0; }
            return (long)data.Reserved0;
        }
    }
}
'@ -ErrorAction Stop
        }
        return [long][CEAudit.ReparseTag]::Get($Path.TrimEnd('\', '/'))
    }
    catch {
        Write-Verbose "Could not read the reparse tag of ${Path}: $(Get-CEErrorTypeName $_)"
        return [long]-1
    }
}

function Get-CEReparseKind {
    <#
        What an item (a FileSystemInfo, or anything with Attributes and FullName) is, from its
        attributes and reparse tag only; nothing is opened:
          none        not a reparse point, and not stored online only
          junction    a mount point (tag 0xA0000003)
          symlink     a symbolic link (0xA000000C)
          surrogate   another name-surrogate link (bit 0x20000000), such as a WSL symbolic link
          unreadable  a reparse point whose tag can't be read
          cloud       stored online only (OFFLINE, RECALL_ON_OPEN or RECALL_ON_DATA_ACCESS,
                      mask 0x441000): opening or listing it makes the sync app download it
          reparse     another reparse point present here: a downloaded cloud file or folder, a
                      deduplicated or compressed file
        The only function that decides what is a link.
    #>
    param($Item)
    if ($null -eq $Item) { return 'none' }
    $attrs = [long]$Item.Attributes
    if ($attrs -lt 0) { return 'none' }   # the item is not there
    $isReparse = ($attrs -band [long][IO.FileAttributes]::ReparsePoint) -ne 0
    if ($isReparse) {
        $tag = [long](Get-CEReparseTag -Path ([string]$Item.FullName))
        if ($tag -lt 0) { return 'unreadable' }
        # [Convert]: PowerShell reads a hex literal above 0x7FFFFFFF as a negative Int32.
        if ($tag -eq [Convert]::ToInt64('A0000003', 16)) { return 'junction' }
        if ($tag -eq [Convert]::ToInt64('A000000C', 16)) { return 'symlink' }
        if (($tag -band 0x20000000) -ne 0) { return 'surrogate' }
    }
    if (($attrs -band 0x441000) -ne 0) { return 'cloud' }
    if ($isReparse) { return 'reparse' }
    return 'none'
}

function Get-CEItemPresence {
    <#
        What is at Path, from its attributes only (GetFileAttributesEx: a link is not followed, a
        file stored online only is not downloaded, nothing is opened):
          State 'present'     with Attributes, FullName, Name and IsFolder (Get-CEReparseKind takes it)
          State 'missing'     only when Windows says nothing is there (file or path not found)
          State 'unreadable'  anything else, with Reason, a fixed string naming the error's type
        DirectoryInfo.Exists and FileInfo.Exists are also false when the audit may not read an
        item's attributes, which a user can arrange on folders they own, so the layer never uses them.
    #>
    param([string]$Path)
    $name = ([string]$Path).TrimEnd('\', '/') -replace '^.*[\\/]', ''
    try {
        $a = [IO.File]::GetAttributes($Path)
        return [pscustomobject]@{ State = 'present'; Attributes = $a; FullName = $Path; Name = $name; IsFolder = (($a -band [IO.FileAttributes]::Directory) -ne 0); Reason = '' }
    }
    catch {
        $t = Get-CEErrorTypeName $_
        $state = if ($t -eq 'FileNotFoundException' -or $t -eq 'DirectoryNotFoundException') { 'missing' } else { 'unreadable' }
        return [pscustomobject]@{ State = $state; Attributes = -1; FullName = $Path; Name = $name; IsFolder = $false; Reason = $(if ($state -eq 'missing') { '' } else { "it could not be read ($t)" }) }
    }
}

function Test-CERelativePathText {
    <#
        A relative path with no empty, '.', '..', drive or wildcard parts, and no part ending in '.' or
        a space (Windows drops those when it uses the path, so it would name a different folder).
    #>
    param([string]$Relative)
    if (-not $Relative -or $Relative -match '^[\\/]' -or $Relative -match '[:*?"<>|]') { return $false }
    foreach ($seg in ($Relative -split '[\\/]')) { if (-not $seg -or $seg -match '[. ]$') { return $false } }
    return $true
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
        Text of a file a standard user may control, or $null when it is missing, is larger than
        MaxBytes or can't be read, and, unless -FollowLinks (an audit in the user's own session),
        when the file itself is a link or stored online only (Get-CEReparseKind). Never reads more
        than the size of the opened file, so a file that grows after that is not read in full
        either. Opened for reading only; nothing in it is run. The only function that opens a
        user's file. -SkipReason receives why the file was not read, as a fixed string ('missing'
        only when Windows says no file is there, see Get-CEItemPresence); -ByteCount the number of bytes read.
    #>
    param([string]$Path, [int]$MaxBytes, [switch]$FollowLinks, [ref]$SkipReason, [ref]$ByteCount)
    if ($null -ne $SkipReason) { $SkipReason.Value = '' }
    if (-not $Path -or $MaxBytes -le 0) { return $null }
    $why = ''
    try {
        $fi = Get-CEItemPresence -Path $Path
        if ($fi.State -eq 'missing' -or ($fi.State -eq 'present' -and $fi.IsFolder)) { $why = 'missing' }
        elseif ($fi.State -ne 'present') { $why = $fi.Reason }
        elseif (-not $FollowLinks) {
            $kind = Get-CEReparseKind -Item $fi
            if ($kind -eq 'cloud') { $why = $script:CENotReadText.Cloud }
            elseif (@('junction', 'symlink', 'surrogate', 'unreadable') -contains $kind) { $why = $script:CENotReadText.ItemIsLink }
        }
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
                    if ($total -gt $size) { $why = $script:CENotReadText.Grew }
                }
            }
            finally { $fs.Dispose() }
        }
    }
    catch { $why = "it could not be read ($(Get-CEErrorTypeName $_))" }
    if ($why) {
        Write-Verbose "Not reading ${Path}: $why"
        if ($null -ne $SkipReason) { $SkipReason.Value = $why }
        return $null
    }
    if ($null -ne $ByteCount) { $ByteCount.Value = [long]$total }
    $reader = New-Object IO.StreamReader -ArgumentList (New-Object IO.MemoryStream -ArgumentList $buf, 0, $total), ([Text.Encoding]::UTF8), $true
    try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
}

# --- The not-read log ------------------------------------------------------

function New-CENotReadLog {
    <# An empty log for one state builder: Records (grouped by Index) and the junctions already judged. #>
    return [pscustomobject]@{ Records = (New-Object System.Collections.ArrayList); Index = @{}; JunctionCache = @{} }
}

function Add-CENotRead {
    <#
        Records that Location was not read. Kind: folder-listing, file-content or existence.
        Records with the same Location, Kind, Reason and Topic are one record with a Count.
        Reason must be a fixed string, never error text or file contents.
    #>
    param($Log, [string]$Location, [ValidateSet('folder-listing', 'file-content', 'existence')][string]$Kind, [string]$Reason,
        [string]$Remedy = '', [string]$Topic, [bool]$NeedsUserSession = $false)
    if ($null -eq $Log) { return }
    $key = "$Location|$Kind|$Reason|$Topic"
    if ($Log.Index.ContainsKey($key)) { $Log.Index[$key].Count++; return }
    $rec = [ordered]@{ Location = $Location; Kind = $Kind; Reason = $Reason; Remedy = $Remedy; Topic = $Topic; NeedsUserSession = $NeedsUserSession; Count = 1 }
    $Log.Index[$key] = $rec
    [void]$Log.Records.Add($rec)
}

function Get-CENotReadRecordArray {
    <# The records of a log as an array (empty when there are none). #>
    param($Log)
    if ($null -eq $Log) { return , @() }
    return , @($Log.Records.ToArray())
}

function Get-CEProfileLocation {
    <# How a location below the profile is shown: %USERPROFILE%\Relative, never the absolute path. #>
    param([string]$Relative)
    if (-not $Relative) { return '%USERPROFILE%' }
    return '%USERPROFILE%\' + ($Relative -replace '/', '\')
}

function Get-CERelativeToProfile {
    <# Path relative to ProfilePath when it is below it, otherwise $null. #>
    param([string]$Path, [string]$ProfilePath)
    if (-not $Path -or -not $ProfilePath) { return $null }
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $prof = [IO.Path]::GetFullPath($ProfilePath).TrimEnd('\', '/') + '\'
    }
    catch { return $null }
    if ($full.StartsWith($prof, [StringComparison]::OrdinalIgnoreCase) -and $full.Length -gt $prof.Length) { return $full.Substring($prof.Length) }
    return $null
}

function Get-CENotReadReason {
    <# The fixed reason for an item of this kind met on the way (Mode Listing) or on the way to file contents (Mode Content). #>
    param([string]$Kind, [ValidateSet('Listing', 'Content')][string]$Mode)
    if ($Kind -eq 'cloud') { return $script:CENotReadText.Cloud }
    if ($Mode -eq 'Content') { return $script:CENotReadText.LinkForContent }
    switch ($Kind) {
        'symlink' { return $script:CENotReadText.SymlinkOnWay }
        'junction' { return $script:CENotReadText.JunctionOnWay }
        default { return $script:CENotReadText.UnknownReparse }
    }
}

function Test-CELinkReason {
    <# Whether Reason is one the layer gives for a link or a file stored online only: skips that only an audit above the user's rights makes. #>
    param([string]$Reason)
    $t = $script:CENotReadText
    return (@($t.SymlinkOnWay, $t.JunctionOnWay, $t.LinkForContent, $t.ItemIsLink, $t.Cloud, $t.UnknownReparse) -contains $Reason)
}

function Add-CEWayNotRead {
    <#
        Records Location as not read for Reason, from Get-CEPathChainProblem or Get-CEItemPresence.
        A link or a file stored online only can be read in the user's own session (NeedsUserSession);
        anything else (the audit may not read a folder's attributes) needs its permissions checked.
    #>
    param($Log, [string]$Location, [string]$Kind, [string]$Reason, [string]$Topic,
        [string]$Remedy = 'Check the permissions on this folder, then run the audit again.')
    if (Test-CELinkReason $Reason) { Add-CENotRead -Log $Log -Location $Location -Kind $Kind -Reason $Reason -Topic $Topic -NeedsUserSession $true }
    else { Add-CENotRead -Log $Log -Location $Location -Kind $Kind -Reason $Reason -Topic $Topic -Remedy $Remedy }
}

# --- Junctions ---------------------------------------------------------------

function Get-CEJunctionTarget {
    <#
        The target a junction (mount point) names, as stored in it (\??\C:\... or \??\Volume{...}\...),
        read with FSCTL_GET_REPARSE_POINT on the junction itself (opened with
        FILE_FLAG_OPEN_REPARSE_POINT, so it is not followed); $null when it is not a junction or
        can't be read. Callers make sure every folder above Path has been cleared first. Tests mock this.
    #>
    param([string]$Path)
    if (-not $Path -or -not (Test-CEIsWindows)) { return $null }
    try {
        if (-not ('CEAudit.Junction' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CEAudit {
    public static class Junction {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(IntPtr handle, uint code, IntPtr inBuf, int inSize, byte[] outBuf, int outSize, out int returned, IntPtr overlapped);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        public static string Target(string path) {
            // FILE_READ_ATTRIBUTES; share read, write and delete; OPEN_EXISTING; OPEN_REPARSE_POINT | BACKUP_SEMANTICS.
            IntPtr h = CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x00200000 | 0x02000000, IntPtr.Zero);
            if (h == IntPtr.Zero || h == new IntPtr(-1)) { return null; }
            try {
                byte[] buf = new byte[16384];
                int returned;
                // FSCTL_GET_REPARSE_POINT
                if (!DeviceIoControl(h, 0x000900A8, IntPtr.Zero, 0, buf, buf.Length, out returned, IntPtr.Zero)) { return null; }
                if (returned < 16 || BitConverter.ToUInt32(buf, 0) != 0xA0000003) { return null; }
                int offset = BitConverter.ToUInt16(buf, 8);
                int length = BitConverter.ToUInt16(buf, 10);
                if (16 + offset + length > returned) { return null; }
                return System.Text.Encoding.Unicode.GetString(buf, 16 + offset, length);
            }
            finally { CloseHandle(h); }
        }
    }
}
'@ -ErrorAction Stop
        }
        return [CEAudit.Junction]::Target($Path.TrimEnd('\', '/'))
    }
    catch {
        Write-Verbose "Could not read the junction target of ${Path}: $(Get-CEErrorTypeName $_)"
        return $null
    }
}

function Get-CEJunctionProblem {
    <#
        '' when an audit with more rights than the user may list names and check existence
        through the junction at Path; otherwise the fixed reason why not. Its target, read without
        following it, must be \??\X:\... on a local fixed drive or \??\Volume{GUID}\..., its names
        must be ones Windows' path rules leave as they are (no part ending in '.' or a space, no
        '.' or '..'), and every folder on the way to that target, walked from the top, must be a
        plain folder, a reparse point that is not a link and not stored online only, or a junction
        that passes the same test (at most 8 deep). The walk uses \\?\ paths, so it looks at the
        names the kernel follows, not ones Windows would rewrite. A folder is only looked at once
        every folder above it is cleared. The walk stops early, passing, only where Windows says
        nothing is there (Get-CEItemPresence): a folder the audit may not look at could hide a link.
        Results are kept in the log per junction.
    #>
    param([string]$Path, $Log, [int]$Depth = 0, [hashtable]$Visited)
    $bad = $script:CENotReadText.JunctionOnWay
    if ($null -eq $Visited) { $Visited = @{} }
    $key = (([string]$Path) -replace '^\\\\\?\\', '').TrimEnd('\').ToLowerInvariant()
    if ($null -ne $Log -and $Log.JunctionCache.ContainsKey($key)) { return $Log.JunctionCache[$key] }
    if ($Depth -ge 8 -or $Visited.ContainsKey($key)) { return $bad }
    $Visited[$key] = $true
    $result = $bad
    try {
        $target = [string](Get-CEJunctionTarget -Path $Path)
        $root = $null
        $rest = ''
        if ($target -match '^\\\?\?\\([A-Za-z]:)(\\.*)?$') {
            $drive = $Matches[1] + '\'
            $rest = if ($Matches[2]) { $Matches[2].Trim('\') } else { '' }
            if (Test-CELocalFilePath $drive) { $root = '\\?\' + $drive }
        }
        elseif ($target -match '^\\\?\?\\(Volume\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})(\\.*)?$') {
            $root = '\\?\' + $Matches[1] + '\'
            $rest = if ($Matches[2]) { $Matches[2].Trim('\') } else { '' }
        }
        # A name Windows would rewrite (foo. read as foo) names another folder than the one the kernel follows.
        if ($rest -and -not (Test-CERelativePathText $rest)) { $root = $null }
        if ($null -ne $root) {
            $result = ''
            $p = $root
            foreach ($seg in @($rest -split '\\' | Where-Object { $_ })) {
                $p = $p.TrimEnd('\') + '\' + $seg
                $item = Get-CEItemPresence -Path $p
                if ($item.State -eq 'missing') { break }   # Windows says nothing is there: nothing to follow into
                if ($item.State -ne 'present') { $result = $bad; break }
                $kind = Get-CEReparseKind -Item $item
                if ($kind -eq 'junction' -and (Get-CEJunctionProblem -Path $p -Log $Log -Depth ($Depth + 1) -Visited $Visited) -eq '') { continue }
                if ($kind -ne 'none' -and $kind -ne 'reparse') { $result = $bad; break }
                if (-not $item.IsFolder) { break }   # a plain file: nothing is followed through it
            }
        }
    }
    catch { $result = $bad }
    if ($null -ne $Log) { $Log.JunctionCache[$key] = $result }
    return $result
}

function Get-CEPathChainProblem {
    <#
        Walks the folders Base\Relative from the top, as the rule table in SECURITY.md says:
        returns '' when every folder is there and may be passed, 'missing' when Windows says one is
        not there (or it is a plain file), and otherwise the fixed reason the walk stopped, which
        includes a folder the audit may not look at (and the relative path it stopped at in
        -StoppedAt). Mode Listing (names and existence): plain folders, reparse points that are not
        links and junctions that pass Get-CEJunctionProblem may be passed. Mode Content (file
        contents): only plain folders and reparse points that are not links. Not -Above (the
        user's own session): every folder only has to be there and readable. Base itself is not judged.
    #>
    param([string]$Base, [string]$Relative, [ValidateSet('Listing', 'Content')][string]$Mode, $Log, [bool]$Above = $true, [ref]$StoppedAt)
    if (-not $Relative) { return '' }
    $p = $Base
    $sofar = ''
    foreach ($seg in @($Relative -split '[\\/]' | Where-Object { $_ })) {
        $p = $p.TrimEnd('\', '/') + '\' + $seg
        $sofar = if ($sofar) { "$sofar\$seg" } else { $seg }
        $item = Get-CEItemPresence -Path $p
        if ($item.State -eq 'missing') { return 'missing' }
        if ($item.State -ne 'present') {
            if ($null -ne $StoppedAt) { $StoppedAt.Value = $sofar }
            return $item.Reason
        }
        if ($Above) {
            $kind = Get-CEReparseKind -Item $item
            $pass = ($kind -eq 'none' -or $kind -eq 'reparse' -or ($Mode -eq 'Listing' -and $kind -eq 'junction' -and (Get-CEJunctionProblem -Path $p -Log $Log) -eq ''))
            if (-not $pass) {
                if ($null -ne $StoppedAt) { $StoppedAt.Value = $sofar }
                return (Get-CENotReadReason -Kind $kind -Mode $Mode)
            }
        }
        if (-not $item.IsFolder) { return 'missing' }   # a plain file: nothing is below it
    }
    return ''
}

function Test-CEProfileReady {
    <# Whether ProfilePath can be read through this layer: an existing folder on a local fixed drive. #>
    param([string]$ProfilePath)
    if (-not $ProfilePath -or -not (Test-CELocalFilePath $ProfilePath)) { return $false }
    $item = Get-CEItemPresence -Path $ProfilePath
    return ($item.State -eq 'present' -and $item.IsFolder)
}

# --- Primitives ---------------------------------------------------------------

function Test-CEProfileItem {
    <#
        Whether Relative names a file or folder below ProfilePath: $true, $false (Windows says it is
        not there), or $null when a folder on the way could not be passed or the item could not be
        looked at (a not-read record is written). The item itself is
        judged by its own attributes, whatever it is, and never followed: a tool folder that is a
        link still counts as found. Attributes only: nothing is opened.
    #>
    param([string]$ProfilePath, [string]$Relative, $Log, [bool]$Above = $true, [string]$Topic, [string]$Location)
    if (-not (Test-CEProfileReady $ProfilePath) -or -not (Test-CERelativePathText $Relative)) { return $false }
    if (-not $Location) { $Location = Get-CEProfileLocation $Relative }
    $parent = Split-Path -Parent $Relative
    try {
        if ($parent) {
            $why = Get-CEPathChainProblem -Base $ProfilePath -Relative $parent -Mode Listing -Log $Log -Above $Above
            if ($why -eq 'missing') { return $false }
            if ($why) {
                Add-CEWayNotRead -Log $Log -Location $Location -Kind 'existence' -Reason $why -Topic $Topic
                return $null
            }
        }
        $item = Get-CEItemPresence -Path ([IO.Path]::Combine($ProfilePath, $Relative))
        if ($item.State -eq 'present') { return $true }
        if ($item.State -eq 'missing') { return $false }
        Add-CEWayNotRead -Log $Log -Location $Location -Kind 'existence' -Reason $item.Reason -Topic $Topic
        return $null
    }
    catch {
        Add-CENotRead -Log $Log -Location $Location -Kind 'existence' -Reason "it could not be read ($(Get-CEErrorTypeName $_))" -Topic $Topic `
            -Remedy 'Check the permissions on this folder, then run the audit again.'
        return $null
    }
}

function Get-CEProfileChildName {
    <#
        Names of the child folders of ProfilePath\Relative, or of its files ending in -Extension.
        Every folder from the profile down to and including Relative is walked as for a listing
        (Get-CEPathChainProblem). Without -Descend the names are returned whatever each child is,
        since nothing goes into them. With -Descend (the caller goes into each child) a child that
        may not be passed is left out and recorded; -Label chromium or firefox shows such a child
        by its privacy-safe browser profile label (Get-CEBrowserProfileLabel), never its name.
        -Exclude names are left out before anything is judged. Looks at no more than -Max entries;
        reaching that, an error while listing, and a name ending in '.' or a space are recorded.
        Names only: nothing is opened. Returns ,names.
    #>
    param([string]$ProfilePath, [string]$Relative, [int]$Max, [string]$Extension, [switch]$Descend, [string]$Label,
        [string[]]$Exclude = @(), $Log, [bool]$Above = $true, [string]$Topic, [string]$Location, [string]$CapRemedy = 'Check the rest of this folder by hand.')
    $names = New-Object System.Collections.ArrayList
    if (-not (Test-CEProfileReady $ProfilePath) -or -not (Test-CERelativePathText $Relative)) { return , $names.ToArray() }
    if (-not $Location) { $Location = Get-CEProfileLocation $Relative }
    $why = Get-CEPathChainProblem -Base $ProfilePath -Relative $Relative -Mode Listing -Log $Log -Above $Above
    if ($why -eq 'missing') { return , $names.ToArray() }
    if ($why) {
        Add-CEWayNotRead -Log $Log -Location $Location -Kind 'folder-listing' -Reason $why -Topic $Topic
        return , $names.ToArray()
    }
    $seen = 0
    try {
        $di = New-Object IO.DirectoryInfo ([IO.Path]::Combine($ProfilePath, $Relative))
        # Assign the enumerable directly: routing it through 'if' in an expression would read the whole folder first.
        if ($Extension) { $items = $di.EnumerateFiles('*' + $Extension) } else { $items = $di.EnumerateDirectories() }
        foreach ($i in $items) {
            if (@($Exclude) -contains $i.Name) { continue }
            if (++$seen -gt $Max) {
                Add-CENotRead -Log $Log -Location $Location -Kind 'folder-listing' -Reason "the audit reads at most $Max entries here" -Topic $Topic -Remedy $CapRemedy
                break
            }
            if ($i.Name -match '[. ]$') {
                Add-CENotRead -Log $Log -Location $Location -Kind 'folder-listing' -Reason $script:CENotReadText.OddName -Topic $Topic `
                    -Remedy 'Rename the entry, or check it by hand.'
                continue
            }
            if ($Descend -and $Above) {
                $kind = Get-CEReparseKind -Item $i
                $pass = ($kind -eq 'none' -or $kind -eq 'reparse' -or ($kind -eq 'junction' -and (Get-CEJunctionProblem -Path $i.FullName -Log $Log) -eq ''))
                if (-not $pass) {
                    $childLabel = $i.Name
                    if ($Label) { $childLabel = Get-CEBrowserProfileLabel -Engine $Label -Folder $i.Name }
                    Add-CENotRead -Log $Log -Location "$Location\$childLabel" -Kind 'folder-listing' -Reason (Get-CENotReadReason -Kind $kind -Mode Listing) -Topic $Topic -NeedsUserSession $true
                    continue
                }
            }
            [void]$names.Add($i.Name)
        }
    }
    catch {
        Add-CENotRead -Log $Log -Location $Location -Kind 'folder-listing' -Reason "it could not be read ($(Get-CEErrorTypeName $_))" -Topic $Topic `
            -Remedy 'Check the permissions on this folder, then run the audit again.'
    }
    return , $names.ToArray()
}

function Read-CEProfileFile {
    <#
        Text of the file ProfilePath\Relative, or $null. Above the user's rights, every folder on
        the way and the file itself must be plain (reparse points that are not links are fine) and
        not stored online only; then Read-CEBoundedText reads at most MaxBytes. -Budget, a byte
        count shared by several reads, lowers the limit and takes off the bytes read. Anything
        there and not read is recorded under -Location (default %USERPROFILE%\Relative); a file
        Windows says is not there is not.
    #>
    param([string]$ProfilePath, [string]$Relative, [int]$MaxBytes, [ref]$ByteCount, [ref]$Budget, $Log, [bool]$Above = $true,
        [string]$Topic, [string]$Location, [string]$FileRemedy = 'Check that the file can be read, then run the audit again.')
    if ($null -ne $ByteCount) { $ByteCount.Value = [long]0 }
    if (-not (Test-CEProfileReady $ProfilePath) -or -not (Test-CERelativePathText $Relative)) { return $null }
    if (-not $Location) { $Location = Get-CEProfileLocation $Relative }
    $add = { param($reason, [bool]$user, [string]$remedy) Add-CENotRead -Log $Log -Location $Location -Kind 'file-content' -Reason $reason -Topic $Topic -NeedsUserSession $user -Remedy $remedy }
    $parent = Split-Path -Parent $Relative
    if ($parent) {
        $why = Get-CEPathChainProblem -Base $ProfilePath -Relative $parent -Mode Content -Log $Log -Above $Above
        if ($why -eq 'missing') { return $null }
        if ($why) { Add-CEWayNotRead -Log $Log -Location $Location -Kind 'file-content' -Reason $why -Topic $Topic; return $null }
    }
    $full = [IO.Path]::Combine($ProfilePath, $Relative)
    $max = [long]$MaxBytes
    $byBudget = $false
    if ($null -ne $Budget) {
        if ([long]$Budget.Value -lt $max) { $max = [long]$Budget.Value; $byBudget = $true }
        if ($max -le 0) {
            if ((Get-CEItemPresence -Path $full).State -ne 'missing') { & $add $script:CENotReadText.Budget $false 'Check the rest by hand.' }
            return $null
        }
    }
    $reason = [ref]''
    $bytes = [ref][long]0
    $text = Read-CEBoundedText -Path $full -MaxBytes ([int]$max) -FollowLinks:(-not $Above) -SkipReason $reason -ByteCount $bytes
    if ($null -eq $text) {
        $why = [string]$reason.Value
        if (-not $why -or $why -eq 'missing') { return $null }
        if ($why -eq $script:CENotReadText.Cloud -or $why -eq $script:CENotReadText.ItemIsLink) { & $add $why $true '' }
        elseif ($why -like 'it is larger than*') {
            if ($byBudget) { & $add $script:CENotReadText.Budget $false 'Check the rest by hand.' }
            else { & $add $why $false "Check that this is the file the audit expects (at most $([Math]::Round($MaxBytes / 1MB, 2)) MB), or check it by hand." }
        }
        else { & $add $why $false $FileRemedy }
        return $null
    }
    if ($null -ne $ByteCount) { $ByteCount.Value = [long]$bytes.Value }
    if ($null -ne $Budget) { $Budget.Value = [long]$Budget.Value - [long]$bytes.Value }
    return $text
}

function Read-CENamedFile {
    <#
        Text of a file whose path a file the user controls names (a virtual machine file in their
        VMware or VirtualBox inventory), or $null. A path off local fixed drives is never opened and
        is recorded, in every session (an SMB path would make SYSTEM authenticate to it). Above
        the user's rights, every folder from the drive root, or from ProfilePath when the file is
        below it, and the file itself, follow the content rule of Read-CEProfileFile. The record
        shows the path relative to the profile when it is below it, otherwise as the inventory names it.
    #>
    param([string]$Path, [string]$ProfilePath, [int]$MaxBytes, [string]$Product, $Log, [bool]$Above = $true, [string]$Topic = 'vm-file')
    $rel = Get-CERelativeToProfile -Path $Path -ProfilePath $ProfilePath
    $location = if ($rel -and (Test-CEProfileReady $ProfilePath)) { Get-CEProfileLocation $rel } else { $Path }
    $add = { param($reason, [bool]$user, [string]$remedy) Add-CENotRead -Log $Log -Location $location -Kind 'file-content' -Reason $reason -Topic $Topic -NeedsUserSession $user -Remedy $remedy }
    if (-not (Test-CELocalFilePath $Path)) {
        & $add $script:CENotReadText.NotLocal $false "Move the $Product virtual machine to a local fixed drive, or check its networking and shared folders by hand."
        return $null
    }
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $base = [IO.Path]::GetPathRoot($full)
        if ($rel -and (Test-CEProfileReady $ProfilePath)) { $base = [IO.Path]::GetFullPath($ProfilePath).TrimEnd('\', '/') + '\' }
        $relText = $full.Substring($base.Length)
    }
    catch { & $add "it could not be read ($(Get-CEErrorTypeName $_))" $false 'Check the path in the inventory.'; return $null }
    if (-not (Test-CERelativePathText $relText)) { & $add $script:CENotReadText.OddPath $false 'Check the path in the inventory, or check the virtual machine by hand.'; return $null }
    $parent = Split-Path -Parent $relText
    if ($parent) {
        $why = Get-CEPathChainProblem -Base $base -Relative $parent -Mode Content -Log $Log -Above $Above
        if ($why -eq 'missing') { return $null }
        if ($why) { Add-CEWayNotRead -Log $Log -Location $location -Kind 'file-content' -Reason $why -Topic $Topic; return $null }
    }
    $reason = [ref]''
    $text = Read-CEBoundedText -Path $full -MaxBytes $MaxBytes -FollowLinks:(-not $Above) -SkipReason $reason
    if ($null -eq $text) {
        $why = [string]$reason.Value
        if (-not $why -or $why -eq 'missing') { return $null }
        if ($why -eq $script:CENotReadText.Cloud -or $why -eq $script:CENotReadText.ItemIsLink) { & $add $why $true '' }
        elseif ($why -like 'it is larger than*') { & $add $why $false "Check that this is the $Product virtual machine file the inventory names (the audit reads at most $([Math]::Round($MaxBytes / 1MB, 2)) MB), or check the virtual machine by hand." }
        else { & $add $why $false "Check that the $Product virtual machine file can be read, then run the audit again." }
    }
    return $text
}

function Get-CEMachineChildName {
    <#
        Names of the child folders of Path, a folder only administrators can change (Program Files).
        Leaves out links and names ending in '.' or a space; at most -Max entries. Names only.
    #>
    param([string]$Path, [int]$Max)
    $names = New-Object System.Collections.ArrayList
    $seen = 0
    try {
        $di = New-Object IO.DirectoryInfo $Path
        $items = $di.EnumerateDirectories()
        foreach ($i in $items) {
            if (++$seen -gt $Max) { Write-Verbose "Stopped listing $Path at $Max entries"; break }
            if (@('none', 'reparse') -notcontains (Get-CEReparseKind -Item $i)) { continue }
            if ($i.Name -match '[. ]$') { continue }
            [void]$names.Add($i.Name)
        }
    }
    catch { Write-Verbose "Could not list ${Path}: $(Get-CEErrorTypeName $_)" }
    return , $names.ToArray()
}

# --- For the checks ------------------------------------------------------------

function Get-CENotReadRemedy {
    <#
        Where a check can read what an elevated or SYSTEM audit skips. Machine: a full audit in the
        user's own session (the per-user probe does not run Machine checks). User: the per-user probe.
    #>
    param([ValidateSet('Machine', 'User')][string]$Scope)
    if ($Scope -eq 'Machine') {
        return 'run the full audit without elevation while signed in as that user (app\Invoke-CEAudit.ps1 from a prompt that is not elevated, or the GUI without Restart as administrator)'
    }
    return 'run the per-user probe (app\Invoke-CEUserProbe.ps1), or the tool without elevation while signed in as that user'
}

function Get-CENotReadField {
    <# A field of a record, which is an ordered dictionary live and a PSObject when read back from JSON. #>
    param($Record, [string]$Name, $Default = $null)
    if ($null -eq $Record) { return $Default }
    if ($Record -is [System.Collections.IDictionary]) {
        foreach ($k in @($Record.Keys)) { if ([string]$k -eq $Name) { return $Record[$k] } }
        return $Default
    }
    return (Get-CEObjectValue $Record $Name $Default)
}

function Select-CENotRead {
    <# The records whose Topic is one of Topics. A record with no topic (written by an older version) counts for every check. #>
    param([object[]]$Records, [string[]]$Topics)
    return , @(@($Records) | Where-Object {
            if ($null -eq $_) { return $false }
            $t = [string](Get-CENotReadField $_ 'Topic' (Get-CENotReadField $_ 'topic' ''))
            (-not $t) -or (@($Topics) -contains $t)
        })
}

function Format-CENotRead {
    <# One line for a record: "<Location> (<what>): <reason>", with the count when it stands for several. #>
    param($Record)
    $loc = [string](Get-CENotReadField $Record 'Location' (Get-CENotReadField $Record 'location' ''))
    $kind = [string](Get-CENotReadField $Record 'Kind' (Get-CENotReadField $Record 'kind' ''))
    $reason = [string](Get-CENotReadField $Record 'Reason' (Get-CENotReadField $Record 'reason' ''))
    $count = [int](Get-CENotReadField $Record 'Count' (Get-CENotReadField $Record 'count' 1))
    $what = switch ($kind) { 'folder-listing' { 'folder not listed' } 'file-content' { 'file not read' } default { 'not checked' } }
    $times = if ($count -gt 1) { ", $count times" } else { '' }
    return "$loc ($what$times): $reason"
}

function Get-CENotReadAdvice {
    <#
        What to do about Records, as sentences: why an elevated or SYSTEM audit skips links and
        files stored online only (when a record was skipped for that), where to read what needs the
        user's own session (only when a record needs it; Scope is the check's scope), then each
        record's own remedy, once each. The report, SC-13 and New-CENotReadResult use it.
    #>
    param([object[]]$Records, [ValidateSet('Machine', 'User')][string]$Scope)
    $recs = @($Records | Where-Object { $null -ne $_ })
    $advice = @()
    if (@($recs | Where-Object { Test-CELinkReason ([string](Get-CENotReadField $_ 'Reason' (Get-CENotReadField $_ 'reason' ''))) }).Count) {
        $advice += "An elevated or SYSTEM audit does not follow the user's symbolic links (or junctions whose target it can't verify), never reads a file's contents through a junction or symbolic link, and does not download files stored online only."
    }
    $user = @($recs | Where-Object { [bool](Get-CENotReadField $_ 'NeedsUserSession' (Get-CENotReadField $_ 'needsUserSession' $false)) })
    if ($user.Count -eq $recs.Count -and $user.Count) { $advice += "To read these, $(Get-CENotReadRemedy -Scope $Scope)." }
    elseif ($user.Count) { $advice += "To read those skipped because the audit ran with more rights than the user, $(Get-CENotReadRemedy -Scope $Scope)." }
    $advice += @($recs | ForEach-Object { [string](Get-CENotReadField $_ 'Remedy' (Get-CENotReadField $_ 'remedy' '')) } | Where-Object { $_ } | Select-Object -Unique)
    return , @($advice)
}

function New-CENotReadResult {
    <#
        One Manual result for the records a check depends on: what was not read, why, what that
        means for the check (-Consequence) and how to read it. Scope is the check's scope, which
        decides where a skip only an elevated or SYSTEM audit makes can be read.
    #>
    param([object[]]$Records, [ValidateSet('Machine', 'User')][string]$Scope, [string]$Expected, [string]$Consequence = 'this result may be incomplete')
    $recs = @($Records | Where-Object { $null -ne $_ })
    $lines = @($recs | ForEach-Object { Format-CENotRead $_ })
    $advice = Get-CENotReadAdvice -Records $recs -Scope $Scope   # assign first: it returns ,array
    return New-CEResult -Status 'Manual' -Subject 'Not read' -Expected $Expected `
        -Actual "$($recs.Count) location(s) could not be read, so ${Consequence}: $($lines -join '; ')" `
        -Recommendation ($advice -join ' ') -Evidence $lines
}
