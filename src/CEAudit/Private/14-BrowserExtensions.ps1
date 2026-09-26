# ---------------------------------------------------------------------------
# AI browser extensions in the user's browser profiles (config/browser-profiles.json),
# for the catalog in config/ai-tools.json. Folder and file NAMES only: no file in a
# browser profile is opened, so history, cookies, settings and extension data are never
# read. Runs the same way as SYSTEM over a standard user's profile: listings are capped,
# only catalog ids are returned, and when the audit has more rights than the user
# (Test-CEAboveUserRights) links below the profile folder are skipped.
# ---------------------------------------------------------------------------

function Get-CEReparseTag {
    <#
        The reparse tag of Path (0 when it is not a reparse point), or -1 when it can't be read.
        Reads the folder entry only (FindFirstFileW), so the item is not opened: a link is not
        followed and a cloud file is not downloaded. Tests mock this.
    #>
    param([string]$Path)
    # FindFirstFileW treats * and ? as wildcards, which would name another item.
    if (-not $Path -or $Path -match '[*?]' -or -not (Test-CEIsWindows)) { return [long]-1 }
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
        Write-Verbose "Could not read the reparse tag of ${Path}: $($_.Exception.Message)"
        return [long]-1
    }
}

function Test-CELinkItem {
    <#
        Whether a file or folder (a FileSystemInfo) is a link: a reparse point whose tag is a name
        surrogate (bit 0x20000000), such as a junction (0xA0000003) or symbolic link (0xA000000C).
        Other reparse points are not links: OneDrive and other cloud files keep theirs once they are
        downloaded, and deduplicated or compressed files have one too. A tag that can't be read
        counts as a link. Attributes only: nothing is opened.
    #>
    param($Item)
    if ($null -eq $Item -or ([int]($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)) -eq 0) { return $false }
    $tag = [long](Get-CEReparseTag -Path ([string]$Item.FullName))
    if ($tag -lt 0) { return $true }
    return (($tag -band 0x20000000) -ne 0)
}

function Test-CEPlainDirectory {
    <#
        True when Path is an existing directory that is not a junction or symbolic link
        (Test-CELinkItem). With -FollowLinks, any existing directory.
    #>
    param([string]$Path, [switch]$FollowLinks)
    if (-not $Path) { return $false }
    try {
        $d = New-Object IO.DirectoryInfo $Path
        return ($d.Exists -and ($FollowLinks -or -not (Test-CELinkItem $d)))
    }
    catch { return $false }
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

function Test-CEPlainDirectoryChain {
    <#
        Base exists as a directory (it may itself be a link: profile containers and moved profiles
        are; callers check Base with Test-CELocalFilePath) and every folder of Relative below it is
        a plain directory. With -FollowLinks (an audit in the user's own session), every folder of
        Relative only has to exist.
    #>
    param([string]$Base, [string]$Relative, [switch]$FollowLinks)
    if (-not $Base) { return $false }
    try { if (-not (New-Object IO.DirectoryInfo $Base).Exists) { return $false } } catch { return $false }
    if (-not (Test-CERelativePathText $Relative)) { return $false }
    $p = $Base
    foreach ($seg in ($Relative -split '[\\/]')) {
        $p = Join-Path $p $seg
        if (-not (Test-CEPlainDirectory $p -FollowLinks:$FollowLinks)) { return $false }
    }
    return $true
}

function Test-CEPlainProfileItem {
    <#
        Whether Relative names a file or folder below ProfilePath that is reached through plain
        folders only. The last part may itself be a junction or symbolic link (a folder moved to
        another drive, say): its own attributes are read, and the link is not followed. With
        -NoLink the last part must not be a link either, for callers that go on to use the path.
        -FollowLinks (an audit in the user's own session) drops both link rules. Reads attributes
        only: nothing is opened. ProfilePath must be on a local fixed drive.
    #>
    param([string]$ProfilePath, [string]$Relative, [switch]$NoLink, [switch]$FollowLinks)
    if (-not $ProfilePath -or -not (Test-CELocalFilePath $ProfilePath)) { return $false }
    if (-not (Test-CERelativePathText $Relative)) { return $false }
    $parent = Split-Path -Parent $Relative
    if ($parent -and -not (Test-CEPlainDirectoryChain -Base $ProfilePath -Relative $parent -FollowLinks:$FollowLinks)) { return $false }
    try {
        $full = Join-Path $ProfilePath $Relative
        $item = New-Object IO.DirectoryInfo $full
        if (-not $item.Exists) { $item = New-Object IO.FileInfo $full }
        if (-not $item.Exists) { return $false }
        return ($FollowLinks -or -not $NoLink -or -not (Test-CELinkItem $item))
    }
    catch { return $false }
}

function Get-CEProfileFileLinkProblem {
    <#
        For a file Relative below ProfilePath, as an audit with more rights than the user sees it:
        '' when it is there, every folder on the way to it is a plain folder and the file is not a
        link; 'missing' when it (or a folder on the way) is not there; otherwise why it is not
        looked at. Stops at the first link, so nothing below a link is looked up. Attributes only:
        nothing is opened. Callers report a reason other than 'missing' as found, not read.
    #>
    param([string]$ProfilePath, [string]$Relative)
    if (-not $ProfilePath -or -not (Test-CELocalFilePath $ProfilePath)) { return 'the profile folder is not on a local fixed drive' }
    if (-not (Test-CERelativePathText $Relative)) { return 'missing' }
    try {
        $parts = @($Relative -split '[\\/]')
        $p = $ProfilePath
        for ($i = 0; $i -lt $parts.Count - 1; $i++) {
            $p = Join-Path $p $parts[$i]
            $d = New-Object IO.DirectoryInfo $p
            if (-not $d.Exists) { return 'missing' }
            if (Test-CELinkItem $d) { return "the folder $(@($parts[0..$i]) -join '\') on the way to it is a junction or symbolic link, which an elevated or SYSTEM audit does not follow" }
        }
        $f = New-Object IO.FileInfo (Join-Path $p $parts[$parts.Count - 1])
        if (-not $f.Exists) { return 'missing' }
        if (Test-CELinkItem $f) { return 'it is a junction or symbolic link, which an elevated or SYSTEM audit does not follow' }
        return ''
    }
    catch { return "its path could not be checked: $($_.Exception.Message)" }
}

function Get-CEProgramFilesPath {
    <#
        The Program Files folder for an 'installed' base: programFiles is the 64-bit one, even in a
        32-bit PowerShell (where ProgramFiles names the x86 folder), and programFilesX86 the 32-bit one.
    #>
    param([string]$Base)
    if ($Base -eq 'programFiles') {
        if ($env:ProgramW6432) { return [string]$env:ProgramW6432 }
        return [string]$env:ProgramFiles
    }
    if ($Base -eq 'programFilesX86') { return [string]${env:ProgramFiles(x86)} }
    return ''
}

function Get-CEPlainChildName {
    <#
        Names of the plain (non-link) child directories of Path, or of its files ending in
        -Extension. Looks at no more than -Max entries. Names only: nothing is opened. Never
        descends into a child. Leaves out names ending in '.' or a space: Windows drops that
        character when the name is used in a path, so 'Profile 1.' would lead into a link
        called 'Profile 1' that was skipped here. -IncludeLinks keeps links too, for callers
        that use the names only and never the paths, and for an audit in the user's own session.
    #>
    param([string]$Path, [int]$Max, [string]$Extension, [switch]$IncludeLinks)
    $names = New-Object System.Collections.ArrayList
    $seen = 0
    try {
        $di = New-Object IO.DirectoryInfo $Path
        # Assign the enumerable directly: routing it through 'if' in an expression would read the whole folder first.
        if ($Extension) { $items = $di.EnumerateFiles('*' + $Extension) } else { $items = $di.EnumerateDirectories() }
        foreach ($i in $items) {
            if (++$seen -gt $Max) { Write-Verbose "Stopped listing $Path at $Max entries"; break }
            if (-not $IncludeLinks -and (Test-CELinkItem $i)) { continue }
            if ($i.Name -match '[. ]$') { continue }
            [void]$names.Add($i.Name)
        }
    }
    catch { Write-Verbose "Could not list ${Path}: $($_.Exception.Message)" }
    return , $names.ToArray()
}

function Test-CEFirefoxAddonId {
    <# A Firefox add-on id: {GUID} or name@domain, at most 128 characters. #>
    param([string]$Id)
    if (-not $Id -or $Id.Length -gt 128) { return $false }
    if ($Id -match '^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$') { return $true }
    return ($Id -match '^[A-Za-z0-9._+-]{1,80}@[A-Za-z0-9.-]{1,80}$')
}

function ConvertTo-CEBoundedInt {
    <# Value as an int clamped to Min..Max, or Default when it isn't a whole number. #>
    param($Value, [int]$Default, [int]$Min, [int]$Max)
    if ($null -eq $Value -or $Value -is [bool] -or "$Value" -notmatch '^\s*\d{1,9}\s*$') { return $Default }
    $n = [int]"$Value"
    if ($n -lt $Min) { return $Min }
    if ($n -gt $Max) { return $Max }
    return $n
}

function Get-CEBrowserProfileRoot {
    <#
        Validated Windows entries from browser-profiles.json plus the caps (defaults 64 / 2000,
        clamped to 1..10000). Drops, with Write-Verbose, entries with no name, an engine other than
        chromium/firefox, a bad root, and installed items with a base other than programFiles,
        programFilesX86 or profile, or a bad path, or an appx name that is not a Store package name.
        A missing file, a missing 'windows' key or missing caps are not errors.
    #>
    $cfg = (Get-CEConfig)['browser-profiles']
    $browsers = New-Object System.Collections.ArrayList
    foreach ($b in @(Get-CEObjectValue $cfg 'windows' @())) {
        if ($null -eq $b) { continue }
        $name = [string](Get-CEObjectValue $b 'name' '')
        $engine = ([string](Get-CEObjectValue $b 'engine' '')).ToLowerInvariant()
        $root = [string](Get-CEObjectValue $b 'root' '')
        if (-not $name -or @('chromium', 'firefox') -notcontains $engine -or -not (Test-CERelativePathText $root)) {
            Write-Verbose "browser-profiles.json: ignoring entry '$name' (needs a name, engine chromium or firefox, and a relative root)"
            continue
        }
        $installed = New-Object System.Collections.ArrayList
        foreach ($item in @(Get-CEObjectValue $b 'installed' @())) {
            if ($null -eq $item) { continue }
            $appx = [string](Get-CEObjectValue $item 'appx' '')
            if ($appx) {
                # A Store (MSIX) package installed for the user, by package name.
                if ($appx -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$') { Write-Verbose "browser-profiles.json: ignoring an installed item of '$name' (appx '$appx')"; continue }
                [void]$installed.Add([pscustomobject]@{ Base = 'appx'; Path = $appx })
                continue
            }
            $base = [string](Get-CEObjectValue $item 'base' '')
            $path = [string](Get-CEObjectValue $item 'path' '')
            if (@('programFiles', 'programFilesX86', 'profile') -notcontains $base -or -not (Test-CERelativePathText $path)) {
                Write-Verbose "browser-profiles.json: ignoring an installed item of '$name' (base '$base', path '$path')"
                continue
            }
            [void]$installed.Add([pscustomobject]@{ Base = $base; Path = $path })
        }
        [void]$browsers.Add([pscustomobject]@{
            Name          = $name
            Engine        = $engine
            Root          = $root
            RootIsProfile = [bool](Get-CEObjectValue $b 'rootIsProfile' $false)
            Installed     = $installed.ToArray()
        })
    }
    return [pscustomobject]@{
        Browsers    = $browsers.ToArray()
        MaxProfiles = ConvertTo-CEBoundedInt (Get-CEObjectValue $cfg 'maxProfilesPerBrowser') -Default 64 -Min 1 -Max 10000
        MaxEntries  = ConvertTo-CEBoundedInt (Get-CEObjectValue $cfg 'maxEntriesPerFolder') -Default 2000 -Min 1 -Max 10000
    }
}

function Get-CEBrowserExtensionIdSet {
    <# Catalog extension ids by engine: Chromium (lower-case, 32 letters a-p) and Firefox (valid add-on ids). Malformed ids are ignored. #>
    param([object[]]$Catalog)
    $chromium = @{}
    $firefox = @{}
    foreach ($entry in @($Catalog)) {
        if ($null -eq $entry) { continue }
        foreach ($ext in @(Get-CEObjectValue $entry.Tool 'browserExtensions' @())) {
            if ($null -eq $ext) { continue }
            $store = ([string](Get-CEObjectValue $ext 'store' '')).ToLowerInvariant()
            $id = [string](Get-CEObjectValue $ext 'id' '')
            if (@('chrome', 'edge', 'opera') -contains $store) {
                $lid = $id.ToLowerInvariant()
                if ($lid -cmatch '^[a-p]{32}$') { $chromium[$lid] = $true } else { Write-Verbose "ai-tools.json: ignoring $store extension id '$id'" }
            }
            elseif ($store -eq 'firefox') {
                if (Test-CEFirefoxAddonId $id) { $firefox[$id] = $true } else { Write-Verbose "ai-tools.json: ignoring firefox add-on id '$id'" }
            }
            else { Write-Verbose "ai-tools.json: ignoring extension id '$id' from unknown store '$store'" }
        }
    }
    return [pscustomobject]@{ Chromium = $chromium; Firefox = $firefox }
}

function Get-CEBrowserProfileLabel {
    <# Profile label that never shows a name the person chose. #>
    param([string]$Engine, [string]$Folder, [switch]$Root)
    if ($Root) { return 'main' }
    if ($Engine -eq 'firefox') {
        if ($Folder -match '^[a-z0-9]{8}\.(default|default-release|default-esr|dev-edition-default|default-nightly)$') { return $Matches[1].ToLowerInvariant() }
        return 'other'
    }
    if ($Folder -eq 'Default' -or $Folder -match '^Profile \d{1,4}$') { return $Folder }
    return 'other'
}

function Get-CEChromiumExtensionVersion {
    <# Highest '<version>_<n>' child folder name, as the version; '' when there is none. #>
    param([string]$Folder, [switch]$FollowLinks)
    $best = $null
    $bestText = ''
    $names = Get-CEPlainChildName -Path $Folder -Max 32 -IncludeLinks:$FollowLinks   # assign first: it returns ,array
    foreach ($n in $names) {
        if ($n -notmatch '^(\d{1,5}(\.\d{1,5}){0,3})_\d{1,3}$') { continue }
        $text = $Matches[1]
        $parse = if ($text.Contains('.')) { $text } else { "$text.0" }
        try { $v = [version]$parse } catch { continue }
        if ($null -eq $best -or $v -gt $best) { $best = $v; $bestText = $text }
    }
    return $bestText
}

function Test-CEBrowserInstalled {
    <#
        Whether any of the browser's 'installed' files exists, or any of its Store packages
        (appx) is among -StorePackages, the user's Store package names; $true when it lists none.
        Program Files paths come from the machine; profile paths must be a link-free chain below
        the profile unless -FollowLinks. Existence only: FileInfo.Exists reads attributes, it does
        not open the file.
    #>
    param($Browser, [string]$ProfilePath, [string[]]$StorePackages, [switch]$FollowLinks)
    $items = @($Browser.Installed)
    if ($items.Count -eq 0) { return $true }
    foreach ($item in $items) {
        if ($item.Base -eq 'appx') {
            if (@($StorePackages) -contains $item.Path) { return $true }
            continue
        }
        $base = if ($item.Base -eq 'profile') { $ProfilePath } else { Get-CEProgramFilesPath $item.Base }
        if (-not $base -or -not (Test-CELocalFilePath $base)) { continue }
        if ($item.Base -eq 'profile') {
            $parent = Split-Path -Parent $item.Path
            if ($parent -and -not (Test-CEPlainDirectoryChain -Base $base -Relative $parent -FollowLinks:$FollowLinks)) { continue }
        }
        try {
            $fi = New-Object IO.FileInfo (Join-Path $base $item.Path)
            if ($fi.Exists -and ($FollowLinks -or -not (Test-CELinkItem $fi))) { return $true }
        }
        catch { Write-Verbose "Could not check $($item.Path): $($_.Exception.Message)" }
    }
    return $false
}

function Get-CEBrowserExtensionList {
    <#
        AI browser extensions installed in the user's browser profiles, from folder and file NAMES:
          Chromium: <root>\<profile>\Extensions\<id>\<version>_<n>
          Firefox:  <root>\<profile>\extensions\<id>.xpi
        Returns only ids in -ChromiumIds / -FirefoxIds. Catalog ids are compared, never used to build
        a path. Links below the profile folder are skipped unless -FollowLinks (an audit in the
        user's own session, see Test-CEAboveUserRights). -StorePackages: the user's Store package
        names, for browsers installed from the Store. Tests mock this.
    #>
    param([string]$ProfilePath, [hashtable]$ChromiumIds, [hashtable]$FirefoxIds, [string[]]$StorePackages, [switch]$FollowLinks)
    $list = New-Object System.Collections.ArrayList
    if (-not $ChromiumIds) { $ChromiumIds = @{} }
    if (-not $FirefoxIds) { $FirefoxIds = @{} }
    if (-not $ProfilePath -or -not (Test-CELocalFilePath $ProfilePath)) { return , $list.ToArray() }
    if ($ChromiumIds.Count -eq 0 -and $FirefoxIds.Count -eq 0) { return , $list.ToArray() }
    $roots = Get-CEBrowserProfileRoot
    $skip = @('System Profile', 'Guest Profile', 'Snapshots')
    foreach ($b in @($roots.Browsers)) {
        $ids = if ($b.Engine -eq 'firefox') { $FirefoxIds } else { $ChromiumIds }
        if ($ids.Count -eq 0) { continue }
        if (-not (Test-CEPlainDirectoryChain -Base $ProfilePath -Relative $b.Root -FollowLinks:$FollowLinks)) { continue }
        $root = Join-Path $ProfilePath $b.Root
        $found = $null   # whether the browser is installed; worked out on the first match only
        $candidates = New-Object System.Collections.ArrayList
        if ($b.Engine -eq 'chromium' -and $b.RootIsProfile) { [void]$candidates.Add([pscustomobject]@{ Path = $root; Label = 'main' }) }
        $children = Get-CEPlainChildName -Path $root -Max $roots.MaxEntries -IncludeLinks:$FollowLinks   # assign first: it returns ,array
        foreach ($n in $children) {
            if ($b.Engine -eq 'chromium' -and $skip -contains $n) { continue }
            [void]$candidates.Add([pscustomobject]@{ Path = (Join-Path $root $n); Label = (Get-CEBrowserProfileLabel -Engine $b.Engine -Folder $n) })
        }
        $profiles = 0
        foreach ($c in $candidates) {
            # The profile folder as a path: Windows normalises it the same way the reads below will.
            if (-not (Test-CEPlainDirectory $c.Path -FollowLinks:$FollowLinks)) { continue }
            $extDir = Join-Path $c.Path $(if ($b.Engine -eq 'firefox') { 'extensions' } else { 'Extensions' })
            if (-not (Test-CEPlainDirectory $extDir -FollowLinks:$FollowLinks)) { continue }
            if (++$profiles -gt $roots.MaxProfiles) { Write-Verbose "Stopped at $($roots.MaxProfiles) $($b.Name) profiles"; break }
            if ($b.Engine -eq 'firefox') {
                $files = Get-CEPlainChildName -Path $extDir -Max $roots.MaxEntries -Extension '.xpi' -IncludeLinks:$FollowLinks
                foreach ($n in $files) {
                    # On Windows PowerShell 5.1, *.xpi also matches .xpix (the short-name rule).
                    if ($n -notmatch '\.xpi$') { continue }
                    $id = $n -replace '\.xpi$', ''
                    if (-not (Test-CEFirefoxAddonId $id) -or -not $FirefoxIds.ContainsKey($id)) { continue }
                    if ($null -eq $found) { $found = Test-CEBrowserInstalled -Browser $b -ProfilePath $ProfilePath -StorePackages $StorePackages -FollowLinks:$FollowLinks }
                    [void]$list.Add([pscustomobject]@{ Browser = $b.Name; Engine = $b.Engine; Profile = $c.Label; Id = $id; Version = ''; BrowserFound = [bool]$found })
                }
            }
            else {
                $folders = Get-CEPlainChildName -Path $extDir -Max $roots.MaxEntries -IncludeLinks:$FollowLinks
                foreach ($n in $folders) {
                    $lid = $n.ToLowerInvariant()
                    if ($lid -cnotmatch '^[a-p]{32}$' -or -not $ChromiumIds.ContainsKey($lid)) { continue }
                    if ($null -eq $found) { $found = Test-CEBrowserInstalled -Browser $b -ProfilePath $ProfilePath -StorePackages $StorePackages -FollowLinks:$FollowLinks }
                    $version = Get-CEChromiumExtensionVersion -Folder (Join-Path $extDir $n) -FollowLinks:$FollowLinks
                    [void]$list.Add([pscustomobject]@{ Browser = $b.Name; Engine = $b.Engine; Profile = $c.Label; Id = $lid; Version = $version; BrowserFound = [bool]$found })
                }
            }
        }
    }
    return , $list.ToArray()
}

function Format-CEBrowserExtensionEvidence {
    <# One evidence line for a match from Get-CEBrowserExtensionList. #>
    param($Match)
    $kind = if ($Match.Engine -eq 'firefox') { 'add-on' } else { 'extension' }
    $version = if ($Match.Version) { " $($Match.Version)" } else { '' }
    $where = "profile: $($Match.Profile)"
    if (-not $Match.BrowserFound) { $where += "; leftover: $($Match.Browser) is not installed" }
    return "$($Match.Browser) ${kind}: $($Match.Id)$version ($where)"
}
