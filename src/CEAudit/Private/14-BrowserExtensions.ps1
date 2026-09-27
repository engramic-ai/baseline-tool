# ---------------------------------------------------------------------------
# AI browser extensions in the user's browser profiles (config/browser-profiles.json),
# for the catalog in config/ai-tools.json. Folder and file NAMES only: no file in a
# browser profile is opened, so history, cookies, settings and extension data are never
# read. Runs the same way as SYSTEM over a standard user's profile: listings are capped,
# only catalog ids are returned, and everything is read through the profile read
# layer (15-ProfileReads.ps1), which records what it could not look at.
# ---------------------------------------------------------------------------

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
    <#
        Highest '<version>_<n>' child folder name of the extension folder ProfilePath\Relative, as the
        version; '' when there is none. Listed through the profile read layer (topic
        extension-version, which no check depends on); -Location is how a skip is shown.
    #>
    param([string]$ProfilePath, [string]$Relative, $Log, [bool]$Above = $true, [string]$Location)
    $best = $null
    $bestText = ''
    $names = Get-CEProfileChildName -ProfilePath $ProfilePath -Relative $Relative -Max 32 -Log $Log -Above $Above -Topic 'extension-version' -Location $Location   # assign first: it returns ,array
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
        Whether the browser is installed: $true when any of its 'installed' files exists, or any of
        its Store packages (appx) is among -StorePackages, the user's Store package names; $true when
        it lists none; $null when none was found and a file below the profile could not be checked
        (a folder on the way was not passed, see Test-CEProfileItem); otherwise $false. Program
        Files paths come from the machine, and a link there is not counted. Existence only:
        attributes are read, no file is opened.
    #>
    param($Browser, [string]$ProfilePath, [string[]]$StorePackages, $Log, [bool]$Above = $true)
    $items = @($Browser.Installed)
    if ($items.Count -eq 0) { return $true }
    $unknown = $false
    foreach ($item in $items) {
        if ($item.Base -eq 'appx') {
            if (@($StorePackages) -contains $item.Path) { return $true }
            continue
        }
        if ($item.Base -eq 'profile') {
            $r = Test-CEProfileItem -ProfilePath $ProfilePath -Relative $item.Path -Log $Log -Above $Above -Topic 'browser-installed'
            if ($r -eq $true) { return $true }
            if ($null -eq $r) { $unknown = $true }
            continue
        }
        $base = Get-CEProgramFilesPath $item.Base
        if (-not $base -or -not (Test-CELocalFilePath $base)) { continue }
        try {
            $fi = New-Object IO.FileInfo (Join-Path $base $item.Path)
            if ($fi.Exists -and (-not $Above -or @('none', 'reparse') -contains (Get-CEReparseKind -Item $fi))) { return $true }
        }
        catch { Write-Verbose "Could not check $($item.Path): $(Get-CEErrorTypeName $_)" }
    }
    if ($unknown) { return $null }
    return $false
}

function Get-CEBrowserExtensionList {
    <#
        AI browser extensions installed in the user's browser profiles, from folder and file NAMES:
          Chromium: <root>\<profile>\Extensions\<id>\<version>_<n>
          Firefox:  <root>\<profile>\extensions\<id>.xpi
        Returns only ids in -ChromiumIds / -FirefoxIds. Catalog ids are compared, never used to build
        a path. Everything below the profile is read through the profile read layer: -Above says the
        audit has more rights than the user (Test-CEAboveUserRights), and what could not be looked at
        is written to -Log. Records show a browser profile by its label, never by a name the person
        chose. BrowserFound is $true, $false, or $null when that could not be checked.
        -StorePackages: the user's Store package names, for browsers installed from the Store.
    #>
    param([string]$ProfilePath, [hashtable]$ChromiumIds, [hashtable]$FirefoxIds, [string[]]$StorePackages, $Log, [bool]$Above = $true)
    $list = New-Object System.Collections.ArrayList
    if (-not $ChromiumIds) { $ChromiumIds = @{} }
    if (-not $FirefoxIds) { $FirefoxIds = @{} }
    if (-not (Test-CEProfileReady $ProfilePath)) { return , $list.ToArray() }
    if ($ChromiumIds.Count -eq 0 -and $FirefoxIds.Count -eq 0) { return , $list.ToArray() }
    $roots = Get-CEBrowserProfileRoot
    $skip = @('System Profile', 'Guest Profile', 'Snapshots')
    foreach ($b in @($roots.Browsers)) {
        $ids = if ($b.Engine -eq 'firefox') { $FirefoxIds } else { $ChromiumIds }
        if ($ids.Count -eq 0) { continue }
        $rootLoc = Get-CEProfileLocation $b.Root
        $found = 'unset'   # whether the browser is installed; worked out on the first match only
        $candidates = New-Object System.Collections.ArrayList
        if ($b.Engine -eq 'chromium' -and $b.RootIsProfile) { [void]$candidates.Add([pscustomobject]@{ Rel = $b.Root; Label = 'main' }) }
        $exclude = if ($b.Engine -eq 'chromium') { $skip } else { @() }
        # Each profile folder is gone into, so each one is judged as a folder on the way.
        $children = Get-CEProfileChildName -ProfilePath $ProfilePath -Relative $b.Root -Max $roots.MaxEntries -Descend -Label $b.Engine -Exclude $exclude `
            -Log $Log -Above $Above -Topic 'browser' -Location $rootLoc -CapRemedy 'Raise maxEntriesPerFolder in browser-profiles.json, or check the rest by hand.'   # assign first: it returns ,array
        foreach ($n in $children) {
            [void]$candidates.Add([pscustomobject]@{ Rel = "$($b.Root)\$n"; Label = (Get-CEBrowserProfileLabel -Engine $b.Engine -Folder $n) })
        }
        $profiles = 0
        $extName = if ($b.Engine -eq 'firefox') { 'extensions' } else { 'Extensions' }
        foreach ($c in $candidates) {
            $extRel = "$($c.Rel)\$extName"
            $extLoc = "$rootLoc\$($c.Label)\$extName"
            if ((Test-CEProfileItem -ProfilePath $ProfilePath -Relative $extRel -Log $Log -Above $Above -Topic 'browser' -Location $extLoc) -ne $true) { continue }
            if (++$profiles -gt $roots.MaxProfiles) {
                Add-CENotRead -Log $Log -Location $rootLoc -Kind 'folder-listing' -Reason "the audit reads at most $($roots.MaxProfiles) browser profiles here" -Topic 'browser' `
                    -Remedy 'Raise maxProfilesPerBrowser in browser-profiles.json, or check the rest by hand.'
                break
            }
            if ($b.Engine -eq 'firefox') {
                $files = Get-CEProfileChildName -ProfilePath $ProfilePath -Relative $extRel -Max $roots.MaxEntries -Extension '.xpi' -Log $Log -Above $Above -Topic 'browser' -Location $extLoc `
                    -CapRemedy 'Raise maxEntriesPerFolder in browser-profiles.json, or check the rest by hand.'
                foreach ($n in $files) {
                    # On Windows PowerShell 5.1, *.xpi also matches .xpix (the short-name rule).
                    if ($n -notmatch '\.xpi$') { continue }
                    $id = $n -replace '\.xpi$', ''
                    if (-not (Test-CEFirefoxAddonId $id) -or -not $FirefoxIds.ContainsKey($id)) { continue }
                    if ($found -is [string]) { $found = Test-CEBrowserInstalled -Browser $b -ProfilePath $ProfilePath -StorePackages $StorePackages -Log $Log -Above $Above }
                    [void]$list.Add([pscustomobject]@{ Browser = $b.Name; Engine = $b.Engine; Profile = $c.Label; Id = $id; Version = ''; BrowserFound = $found })
                }
            }
            else {
                # Names only: a folder named like a catalog id counts whatever it is. Its version is read by going into it.
                $folders = Get-CEProfileChildName -ProfilePath $ProfilePath -Relative $extRel -Max $roots.MaxEntries -Log $Log -Above $Above -Topic 'browser' -Location $extLoc `
                    -CapRemedy 'Raise maxEntriesPerFolder in browser-profiles.json, or check the rest by hand.'
                foreach ($n in $folders) {
                    $lid = $n.ToLowerInvariant()
                    if ($lid -cnotmatch '^[a-p]{32}$' -or -not $ChromiumIds.ContainsKey($lid)) { continue }
                    if ($found -is [string]) { $found = Test-CEBrowserInstalled -Browser $b -ProfilePath $ProfilePath -StorePackages $StorePackages -Log $Log -Above $Above }
                    $version = Get-CEChromiumExtensionVersion -ProfilePath $ProfilePath -Relative "$extRel\$n" -Log $Log -Above $Above -Location "$extLoc\$lid"
                    [void]$list.Add([pscustomobject]@{ Browser = $b.Name; Engine = $b.Engine; Profile = $c.Label; Id = $lid; Version = $version; BrowserFound = $found })
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
    if ($Match.BrowserFound -eq $false) { $where += "; leftover: $($Match.Browser) is not installed" }
    elseif ($null -eq $Match.BrowserFound) { $where += "; whether $($Match.Browser) is installed could not be checked" }
    return "$($Match.Browser) ${kind}: $($Match.Id)$version ($where)"
}
