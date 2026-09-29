# ---------------------------------------------------------------------------
# Generic helpers. Everything that touches the OS goes through a small wrapper
# so the Pester tests can mock it on non-Windows hosts.
# ---------------------------------------------------------------------------

function Test-CEIsWindows {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if ($PSVersionTable.PSVersion.Major -lt 6) { return $true }
    return [bool]$IsWindows
}

function Test-CEIsAdmin {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if (-not (Test-CEIsWindows)) { return $false }
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CERegistryValue {
    <#
        Returns the value of a registry value, or $Default when the key/value
        does not exist. Path uses PowerShell provider syntax (HKLM:\...).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $Default }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $Default
    }
}

function Test-CERegistryValueExists {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $false }
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        return ($key.GetValueNames() -contains $Name)
    }
    catch {
        return $false
    }
}

function Invoke-CENative {
    <#
        Runs a native executable and returns its stdout as a string array.
        Wrapped so tests can mock it (net.exe, auditpol.exe, dsregcmd.exe, winget.exe ...).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )
    $output = & $FilePath @ArgumentList 2>&1
    $exitCode = $LASTEXITCODE
    return [pscustomobject]@{
        ExitCode = $exitCode
        Output   = @($output | ForEach-Object { "$_" })
    }
}

function Get-CEConfig {
    <#
        Loads JSON configuration from <repo>\config. Results are cached.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [switch]$Force
    )
    if ($script:CEConfig -and -not $Force) { return $script:CEConfig }
    if (-not $ConfigPath) { $ConfigPath = Join-Path $script:RepoRoot 'config' }

    # Shipped defaults first, then per-device overrides from the data folder
    # (e.g. %ProgramData%\EngramicBaseline\config\cloud-services.json).
    # An override replaces the whole file of the same name.
    $folders = @($ConfigPath)
    # Pack config comes after the shipped files (packs can't reuse their names) and before overrides.
    if ($script:CEPackConfigPaths) { $folders += @($script:CEPackConfigPaths) }
    $dataRoot = Get-CEDataRoot
    $overrideDir = Join-Path $dataRoot 'config'
    if ((Test-Path -LiteralPath $overrideDir) -and ($overrideDir -ne $ConfigPath)) {
        # An elevated audit must not load overrides a standard user could have planted or could
        # change: the data folder (whose owner could replace config), the config folder, and then
        # each file below (a file keeps the owner who created it, even in a folder locked later).
        if ((Test-CEDataPathTrusted -Path $dataRoot) -and (Test-CEDataPathTrusted -Path $overrideDir)) { $folders += $overrideDir }
        else { Write-Warning "Ignoring config overrides in $overrideDir : standard users can change it." }
    }

    $config = @{}
    foreach ($folder in $folders) {
        foreach ($file in (Get-ChildItem -Path $folder -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
            if ($file.Extension -ne '.json') { continue }
            if ($folder -eq $overrideDir -and -not (Test-CEDataPathTrusted -Path $file.FullName)) {
                Write-Warning "Ignoring the config override $($file.FullName) : a standard user owns it or can change it."
                continue
            }
            $key = [IO.Path]::GetFileNameWithoutExtension($file.Name)
            $config[$key] = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        }
    }
    $script:CEConfig = $config
    return $config
}

function Get-CEEnvironmentHook {
    <#
        Value of a development environment variable (CE_CHECKER_DATA, CE_CHECKER_PACKS),
        or $null. Ignored when elevated: an elevated process started from a user's session
        inherits that session's environment, so a standard user could otherwise point an
        administrator's audit at folders they control and switch off the data-folder
        permission checks. Elevated callers pass Import-Module -ArgumentList instead.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Name)
    $value = [Environment]::GetEnvironmentVariable($Name)
    if (-not $value) { return $null }
    if (-not (Test-CEIsAdmin)) { return $value }
    if (-not $script:CEIgnoredEnvHooks.ContainsKey($Name)) {
        $script:CEIgnoredEnvHooks[$Name] = $true
        Write-Warning "Ignoring the $Name environment variable because this audit is running as administrator. It is for development only; pass the folder with Import-Module -ArgumentList instead."
    }
    return $null
}

function Get-CEDataRoot {
    <#
        Machine-wide data folder used by the scheduled audit and Intune scripts.
        Moved by the module's import argument (tests, the scheduled audit's -DataRoot)
        or, when not elevated, by CE_CHECKER_DATA.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if ($script:CEDataRootOverride) { return $script:CEDataRootOverride }
    $fromEnv = Get-CEEnvironmentHook -Name 'CE_CHECKER_DATA'
    if ($fromEnv) { return $fromEnv }
    $base = $env:ProgramData
    if (-not $base) { $base = [IO.Path]::GetTempPath() }
    return (Join-Path $base 'EngramicBaseline')
}

function ConvertTo-CEFullPath {
    <#
        $Path as a full path spelled one way, so that two spellings of one place compare equal: a
        relative path is taken from PowerShell's current location (not the process directory), '.' and
        '..' names and repeated separators are collapsed (UNC paths included), '/' becomes '\' on
        Windows, and no separator is left at the end except on a root such as C:\. Only the spelling
        changes: nothing on disk is read, so a link is not followed and a short (8.3) name is not
        expanded. ([IO.Path]::GetFullPath expands one only where the rest of the path exists, so it
        could spell a folder and a folder not yet made inside it differently.) A \\?\ or \\.\ path is
        kept as written, as Windows keeps it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    $full = $Path
    # A drive PowerShell does not know (X: with no X: drive) cannot be resolved: keep it as written.
    try { $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path) } catch { $full = $Path }
    $separator = [string][IO.Path]::DirectorySeparatorChar
    if ($separator -eq '\') {
        if ($full -match '^[\\/]{2}[?.][\\/]') { return $full.TrimEnd('\', '/') }
        $m = [regex]::Match($full, '^(?:([A-Za-z]:)|[\\/]{2}([^\\/]+)[\\/]+([^\\/]+))(.*)$')
        if (-not $m.Success) { return $full }
        $root = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { '\\' + $m.Groups[2].Value + '\' + $m.Groups[3].Value }
        $names = $m.Groups[4].Value -split '[\\/]+'
    }
    else {
        if (-not $full.StartsWith('/')) { return $full }
        $root = ''
        $names = $full -split '/+'
    }
    $kept = New-Object System.Collections.ArrayList
    foreach ($name in $names) {
        if ($name -eq '' -or $name -eq '.') { continue }
        if ($name -eq '..') { if ($kept.Count) { $kept.RemoveAt($kept.Count - 1) }; continue }
        [void]$kept.Add($name)
    }
    return $root + $separator + ($kept.ToArray() -join $separator)
}

function Resolve-CEDataPath {
    <#
        Where $Path stands against the machine data folder (Get-CEDataRoot, including one moved on the
        Import-Module line, as the scheduled audit's -DataRoot and the tests do). Returns Path and Root,
        both as normalised full paths (ConvertTo-CEFullPath); InDataRoot, true only when Path is the data
        folder itself or strictly inside it; and Relative, Path relative to Root ('' for the data folder
        itself). Compared ignoring case once '.' and '..' are collapsed, so '..' never climbs out of the
        data folder and a look-alike sibling (EngramicBaseline2, EngramicBaseline.untrusted-<id>) is not
        in it. A path that cannot be parsed is not in it. Only paths in the data folder are ever created
        locked or moved aside (Initialize-CEDataFolder, Move-CEDataItemAside): any other folder belongs
        to whoever named it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $result = [pscustomobject]@{ Path = $Path; Root = ''; InDataRoot = $false; Relative = '' }
    try {
        $result.Root = ConvertTo-CEFullPath -Path (Get-CEDataRoot)
        $result.Path = ConvertTo-CEFullPath -Path $Path
    }
    catch { return $result }
    $separator = [string][IO.Path]::DirectorySeparatorChar
    $prefix = if ($result.Root.EndsWith($separator)) { $result.Root } else { $result.Root + $separator }
    if ($result.Path.Equals($result.Root, [StringComparison]::OrdinalIgnoreCase)) { $result.InDataRoot = $true }
    elseif ($result.Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        $result.InDataRoot = $true
        $result.Relative = $result.Path.Substring($prefix.Length)
    }
    return $result
}

function New-CELockedDirectorySecurity {
    <#
        The locked security descriptor a machine data folder is born with: owner Administrators, and a
        protected DACL (no inheritance from %ProgramData%) granting only SYSTEM and Administrators full
        control, inherited by the folder's children. -UsersRead also grants Users read and execute.
        SIDs keep it locale independent. The owner is in the descriptor so it is applied in the one
        call that creates the folder, never afterwards: an elevated or SYSTEM token may name
        BUILTIN\Administrators as owner (that group carries SE_GROUP_OWNER). Kept identical to the
        installer's New-CEDataDirectorySecurity.
    #>
    param([switch]$UsersRead)
    $sddl = 'O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    if ($UsersRead) { $sddl += '(A;OICI;0x1200A9;;;BU)' }
    $sec = New-Object Security.AccessControl.DirectorySecurity
    $sec.SetSecurityDescriptorSddlForm($sddl)
    return $sec
}

function Get-CELockedFolderProblem {
    <#
        '' when the folder at $Path is one the tool may keep in place (created locked at birth, or an
        admin-only folder an administrator has since read or granted a helpdesk group read), or the
        reason it is not. Read only: never changes owner or permissions. Judged by trust, not by SDDL
        equality (design rule 1): accepted only when it is not a link, is owned by SYSTEM,
        Administrators or TrustedInstaller (a standard user can set none of these), grants no SID
        outside those (and CREATOR OWNER) any write, add, delete, change-permissions or take-ownership
        right, and carries no deny entry against a trusted SID. So a read-only ACE an admin added is
        kept (no data loss), while a folder a standard user made or could write - which they could hold
        a handle on that keeps add-file/WRITE_DAC access after any later lock - is rejected and moved
        aside. Exact SDDL equality was too strict: it also rejected a folder locked with icacls (which
        reads back D:PAI, not D:P) and any benign read ACE. Delegates to Get-CEDataPathProblem so the
        module and the installer's Test-CELockedFolder judge trust the same way.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    $problems = @(Get-CEDataPathProblem -Path $Path)
    if ($problems.Count) { return [string]$problems[0] }
    return ''
}

function Get-CEDataAsidePath {
    <#
        Where an untrusted item at $Path is moved to: always OUT of the data folder, to a sibling of it
        - <data folder>.untrusted-<id> for the data folder itself, <data folder>.untrusted-<id>-<name>
        for an item inside it (say ...-reports) - never a name inside the data folder. A moved-aside
        item is a tree a standard user may control, so it must be outside every tree the tool reads,
        walks or deletes as SYSTEM; the uninstaller leaves every EngramicBaseline.untrusted-* folder for
        an administrator. Same volume, so the move is a rename. Throws for anything that is not the data
        folder or in it (Resolve-CEDataPath): nothing else is ever moved aside, so a folder someone
        named for another purpose (Write-CEStatus -Path elsewhere, say) is never renamed. Kept in step
        with the installer's Get-CEAsidePath.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    $target = Resolve-CEDataPath -Path $Path
    if (-not $target.InDataRoot) { throw "$Path is not in the data folder $(Get-CEDataRoot), so it is never moved aside." }
    $id = [guid]::NewGuid().ToString('n')
    if (-not $target.Relative) { return "$($target.Root).untrusted-$id" }
    return "$($target.Root).untrusted-$id-" + ($target.Relative -replace '[\\/]+', '-')
}

function Move-CEDataItemAside {
    <#
        Renames a file or folder in the data folder out of it, to a quarantine sibling of it
        (Get-CEDataAsidePath, which refuses anything not in the data folder), without opening its
        contents or following a link, so nothing later reads or walks it. Retries a few times with a
        short back-off: an old-version audit, an admin with a report open, or any process with a handle
        in the tree can make the first [IO.Directory]::Move fail with a sharing violation, and Intune
        would then just report the install failed with no hint why. Returns the new path; throws with a
        clear reason if every attempt fails.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    $aside = Get-CEDataAsidePath -Path $Path
    # The full path Get-CEDataAsidePath judged, not a relative $Path .NET would take from the process directory.
    $item = (Resolve-CEDataPath -Path $Path).Path
    $isDir = [bool]([IO.File]::GetAttributes($item) -band [IO.FileAttributes]::Directory)
    $lastErr = $null
    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        try {
            if ($isDir) { [IO.Directory]::Move($item, $aside) } else { [IO.File]::Move($item, $aside) }
            return $aside
        }
        catch {
            $lastErr = $_
            Start-Sleep -Milliseconds (200 * ($attempt + 1))
        }
    }
    throw "Could not move $Path aside to $aside - a process may have a file or folder open under the data folder ($($lastErr.Exception.Message)). Close it and try again."
}

function Initialize-CEDataFolder {
    <#
        Makes sure a folder exists, creating a machine data folder the same way the installer does, so a
        data root is never born user-writable even when an elevated audit (the GUI, Invoke-CEAudit or the
        scheduled audit) runs before the installer. Returns $Path.

        Only the data folder (Get-CEDataRoot, including one moved on the Import-Module line or by the
        scheduled audit's -DataRoot) and folders strictly inside it are ever created locked or moved
        aside, judged on normalised full paths ignoring case (Resolve-CEDataPath), so '..' or a
        look-alike name such as EngramicBaseline2 does not count. Any other folder - the one
        Write-CEStatus -Path names elsewhere, say - belongs to whoever named it: it is created plainly,
        with its parent's permissions, if it is missing, and otherwise left exactly as it is, whoever
        runs this. Callers that are not elevated or not on Windows get the same plain folder everywhere:
        they only affect their own user, whose data lives in their own profile.

        In the data folder, an elevated caller on Windows gets the folder with its locked,
        administrator-owned descriptor applied in the one call that makes it, then VERIFIES the result
        and never repairs it: anything already in its place that a standard user made, took over or
        could write - or a link - is moved aside, out of the data folder (Get-CEDataAsidePath), and the
        create retried, never written into or taken back in place (its creator may hold a handle that
        kept add-file or WRITE_DAC access after any later lock). Each move-aside is a warning and an
        Application event (ID 1003) naming where it went. An existing folder that is trusted -
        admin-owned, not a link, with no non-admin write, delete, DAC or owner right and no deny
        against a trusted SID - is kept, so status.json and reports survive; a benign read-only ACE an
        administrator added does not force it aside.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path, [switch]$UsersRead)
    $target = $null
    if ((Test-CEIsWindows) -and (Test-CEIsAdmin)) { $target = Resolve-CEDataPath -Path $Path }
    if (-not $target -or -not $target.InDataRoot) {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
        return $Path
    }
    # From here on, the full path that was judged to be in the data folder, never a relative spelling
    # .NET would resolve against the process directory instead.
    $folder = $target.Path
    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        if (Test-CEReparsePoint -Path $folder) {
            if ([IO.File]::GetAttributes($folder) -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete($folder, $false) } else { [IO.File]::Delete($folder) }
            continue
        }
        if (Test-Path -LiteralPath $folder) {
            $problem = Get-CELockedFolderProblem -Path $folder
            if (-not $problem) { return $Path }
            Move-CEDataItemAsideWithNotice -Path $folder -Reason $problem
            continue
        }
        $security = New-CELockedDirectorySecurity -UsersRead:$UsersRead
        if ($PSVersionTable.PSVersion.Major -ge 6) { [void][IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($folder), $security) }
        else { [void][IO.Directory]::CreateDirectory($folder, $security) }
        # Verify what is now on disk; never repair it. A silent no-op over a pre-existing folder is
        # rejected here (wrong owner, or a non-admin write/DAC/owner right) instead of being re-owned in place.
        $problem = Get-CELockedFolderProblem -Path $folder
        if (-not $problem) { return $Path }
        if (Test-Path -LiteralPath $folder) { Move-CEDataItemAsideWithNotice -Path $folder -Reason $problem }
    }
    throw "Could not create a locked, administrator-owned data folder at $Path."
}

function Move-CEDataItemAsideWithNotice {
    <#
        Moves an untrusted data-folder item aside (Move-CEDataItemAside) and says so where it will be
        seen: a warning (the scheduled audit writes it into its log) and an Application event, ID 1003,
        naming the quarantine path, so nothing is lost silently.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [string]$Reason)
    $aside = Move-CEDataItemAside -Path $Path
    $notice = "Moved an untrusted $Path aside to $aside ($Reason) and made a fresh, locked one in its place. Nothing in it is used again; check it, then delete it."
    Write-Warning $notice
    Write-CEEventEntry -Id 1003 -Type Warning -Message "Engramic Baseline - data folder: $notice"
}

function Remove-CEDataTree {
    <#
        Deletes a folder and everything in it without ever following a junction or symbolic link: each
        link is removed as a link, each real subfolder is recursed into, each file is deleted. Used for
        deletes as SYSTEM or administrator under the data folder (old report folders, and the deployment
        rehearsal's own folder). Remove-Item -Recurse is not used because Windows PowerShell 5.1 follows
        links and would empty what they point at.

        When elevated, a folder is listed only if it is trusted at that moment (Get-CELockedFolderProblem:
        not a link, admin-owned, no non-administrator write, add, delete, change-permissions or
        take-ownership right, no deny against administrators), so no non-administrator can swap an
        entry in it for a junction before it is acted on. A folder that fails is left in place, never
        listed or walked, with a warning; so is anything named *.untrusted-* (a quarantine is for an
        administrator to check). A standard user's own delete needs no check: it can only remove what
        that user could remove anyway. Returns $true when the whole tree was removed.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path)
    $attrs = $null
    try { $attrs = [IO.File]::GetAttributes($Path) }
    catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] { return $true }
    if ($attrs -band [IO.FileAttributes]::ReparsePoint) {
        if ($attrs -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete($Path, $false) } else { [IO.File]::Delete($Path) }
        return $true
    }
    if (-not ($attrs -band [IO.FileAttributes]::Directory)) { [IO.File]::Delete($Path); return $true }
    if (Test-CEIsAdmin) {
        $problem = Get-CELockedFolderProblem -Path $Path
        if ($problem) {
            Write-Warning "Left $Path in place, unread ($problem): a standard user may control it, so it is not walked as administrator or SYSTEM. Check it, then delete it by hand."
            return $false
        }
    }
    $complete = $true
    foreach ($child in @([IO.Directory]::GetFileSystemEntries($Path))) {
        if ((Split-Path -Leaf $child) -like '*.untrusted-*') {
            Write-Warning "Left the quarantine $child in place for an administrator to check and delete."
            $complete = $false
            continue
        }
        try { if (-not (Remove-CEDataTree -Path $child)) { $complete = $false } }
        catch {
            Write-Warning "Could not remove $child ($($_.Exception.Message)); left it in place."
            $complete = $false
        }
    }
    if ($complete) { [IO.Directory]::Delete($Path, $false) }
    return $complete
}

function Write-CEEventEntry {
    <#
        Writes one entry to the Application event log under the EngramicBaseline source. Uses the
        low-level RegisterEventSource / ReportEvent API: the managed EventLog.WriteEntry and
        SourceExists enumerate every event log to find the source's log and throw when Security/State
        are inaccessible (hosted CI runners, restricted images), even to SYSTEM. RegisterEventSource
        opens the source directly and never enumerates. A failure is only a warning.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint32]$Id,
        [ValidateSet('Error', 'Warning', 'Information')][string]$Type = 'Information',
        [Parameter(Mandatory)][string]$Message
    )
    $typeMap = @{ Error = [uint16]1; Warning = [uint16]2; Information = [uint16]4 }
    if ($Message.Length -gt 31000) { $Message = $Message.Substring(0, 31000) }
    try {
        if (-not ('CEAudit.EventReporter' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CEAudit {
    public static class EventReporter {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr RegisterEventSource(string server, string source);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ReportEvent(IntPtr handle, ushort type, ushort category, uint eventId, IntPtr sid, ushort numStrings, uint dataSize, string[] strings, IntPtr rawData);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DeregisterEventSource(IntPtr handle);
        public static int Write(string source, ushort type, uint eventId, string message) {
            IntPtr handle = RegisterEventSource(null, source);
            if (handle == IntPtr.Zero) { return Marshal.GetLastWin32Error(); }
            try {
                bool ok = ReportEvent(handle, type, 0, eventId, IntPtr.Zero, 1, 0, new string[] { message }, IntPtr.Zero);
                return ok ? 0 : Marshal.GetLastWin32Error();
            }
            finally { DeregisterEventSource(handle); }
        }
    }
}
'@ -ErrorAction Stop
        }
        $rc = [CEAudit.EventReporter]::Write('EngramicBaseline', $typeMap[$Type], $Id, $Message)
        if ($rc -ne 0) { Write-Warning "Event write failed for source 'EngramicBaseline' id $Id (Win32 error $rc)" }
    }
    catch { Write-Warning "Could not write event: $_" }
}

function Get-CEUserRegistryRoot {
    <#
        Registry root for per-user settings of the person using the device.
        Normally HKCU:. When running as SYSTEM (Intune, scheduled task) it maps to
        the signed-in user's loaded hive under HKEY_USERS, or $null if nobody is
        signed in.
    #>
    [CmdletBinding()]
    param()
    $ctx = Get-CEDeviceContext
    if (-not $ctx.IsSystem) { return 'HKCU:' }
    $sid = $ctx.ConsoleUserSid
    if (-not $sid) { return $null }
    $root = "Registry::HKEY_USERS\$sid"
    if (Test-Path -LiteralPath $root) { return $root }
    return $null
}

function ConvertTo-CEDate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Value)
    # PowerShell 7's ConvertFrom-Json may already have turned ISO dates into DateTime.
    if ($Value -is [datetime]) { return $Value.Date }
    return [datetime]::ParseExact([string]$Value, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-CEUninstallKey {
    <#
        The values Get-CEInstalledSoftware uses from each subkey of an open Uninstall key (a
        RegistryKey, or an object with the same methods in tests). A subkey that can't be read is
        skipped on its own: RegistryKey.OpenSubKey throws SecurityException, rather than returning
        $null, for a key whose ACL denies this account, and that must not hide the programs after it.
    #>
    param([Parameter(Mandatory)]$Key, [string]$View)
    $out = New-Object System.Collections.ArrayList
    foreach ($name in @($Key.GetSubKeyNames())) {
        try {
            $sub = $Key.OpenSubKey($name)
            if (-not $sub) { continue }
            try {
                $entry = [ordered]@{ PSChildName = $name }
                foreach ($v in 'DisplayName', 'DisplayVersion', 'Publisher', 'InstallDate', 'SystemComponent') {
                    $value = $sub.GetValue($v)
                    if ($null -ne $value) { $entry[$v] = $value }
                }
                [void]$out.Add([pscustomobject]$entry)
            }
            finally { $sub.Close() }
        }
        catch { Write-Verbose "Could not read the $View Uninstall subkey ${name}: $($_.Exception.Message)" }
    }
    return , $out.ToArray()
}

function Get-CEUninstallRegistryEntry {
    <#
        The values Get-CEInstalledSoftware uses from each subkey of the machine's Uninstall key in one
        registry view: Registry64 (64-bit programs) or Registry32 (32-bit programs, WOW6432Node). The
        view is opened explicitly, so a 32-bit PowerShell, whose HKLM:\SOFTWARE is redirected to
        WOW6432Node, still sees 64-bit programs. On 32-bit Windows both views are the same key.
        Tests mock this.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('Registry64', 'Registry32')][string]$View)
    $entries = @()
    try {
        $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]$View)
        try {
            $key = $hive.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($key) {
                try { $entries = ConvertFrom-CEUninstallKey -Key $key -View $View }
                finally { $key.Close() }
            }
        }
        finally { $hive.Close() }
    }
    catch { Write-Verbose "Could not read the $View Uninstall key: $($_.Exception.Message)" }
    return , $entries
}

function Get-CEInstalledSoftware {
    <#
        Installed programs from the uninstall registry keys (machine, in both the 64-bit and 32-bit
        registry views whatever the bitness of this PowerShell, and the current user).
        Deliberately avoids Win32_Product, which triggers MSI self-repair.
    #>
    [CmdletBinding()]
    param()
    $raw = New-Object System.Collections.ArrayList
    foreach ($view in 'Registry64', 'Registry32') {
        $entries = Get-CEUninstallRegistryEntry -View $view   # assign first: it returns ,array
        foreach ($e in $entries) { [void]$raw.Add($e) }
    }
    # Per-user installs for the signed-in user (their hive when running as SYSTEM). HKCU\Software is
    # not redirected for 32-bit processes, so one path covers both.
    $userRoot = Get-CEUserRegistryRoot
    if ($userRoot) {
        foreach ($e in @(Get-ItemProperty -Path "$userRoot\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue)) { [void]$raw.Add($e) }
    }
    $items = foreach ($r in $raw) {
        if (-not ($r.PSObject.Properties['DisplayName'] -and $r.DisplayName) -or ($r.PSObject.Properties['SystemComponent'] -and $r.SystemComponent -eq 1)) { continue }
        [pscustomobject]@{
            Name        = [string]$r.DisplayName
            Version     = if ($r.PSObject.Properties['DisplayVersion']) { [string]$r.DisplayVersion } else { '' }
            Publisher   = if ($r.PSObject.Properties['Publisher']) { [string]$r.Publisher } else { '' }
            InstallDate = if ($r.PSObject.Properties['InstallDate']) { [string]$r.InstallDate } else { '' }
            KeyName     = [string]$r.PSChildName
        }
    }
    return @($items | Sort-Object Name, Version -Unique)
}

function Test-CESignedBy {
    <#
        Whether a file has a valid Authenticode signature from one of $Publisher (the
        signing certificate's common name). Anything unreadable counts as unsigned.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string[]]$Publisher)
    try { $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop }
    catch { return $false }
    if (-not $sig -or "$($sig.Status)" -ne 'Valid' -or -not $sig.SignerCertificate) { return $false }
    $m = [regex]::Match([string]$sig.SignerCertificate.Subject, '(?:^|,)\s*CN=(?:"([^"]*)"|([^,]*))')
    if (-not $m.Success) { return $false }
    $cn = ($m.Groups[1].Value + $m.Groups[2].Value).Trim()
    return [bool]($Publisher -contains $cn)
}

function Resolve-CETrustedTool {
    <#
        The first candidate that exists and is signed by one of $Publisher, so a program
        planted in a folder on PATH is never run, least of all by an elevated or SYSTEM
        audit. List known install locations first and PATH last. Returns Path ($null if
        none could be verified) and Refused (candidates found that failed the check).
    #>
    [CmdletBinding()]
    param([string[]]$Candidate, [Parameter(Mandatory)][string[]]$Publisher)
    $refused = New-Object System.Collections.ArrayList
    foreach ($c in @($Candidate | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $c -PathType Leaf)) { continue }
        if (Test-CESignedBy -Path $c -Publisher $Publisher) { return [pscustomobject]@{ Path = $c; Refused = $refused.ToArray() } }
        Write-Verbose "Not running $c : it is not validly signed by $($Publisher -join ' or ')"
        [void]$refused.Add($c)
    }
    return [pscustomobject]@{ Path = $null; Refused = $refused.ToArray() }
}

function Get-CEWingetCandidate {
    <#
        Places winget.exe may be, most trusted first. winget is a per-user app, so it isn't
        on PATH for SYSTEM: use the machine-wide App Installer package, then the current
        user's. The PATH entry is usually an app execution alias under the user's
        %LOCALAPPDATA%, which can't be verified, so it comes last.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    $candidates = @()
    if ($env:ProgramFiles) {
        $pattern = Join-Path $env:ProgramFiles 'WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe'
        $candidates += @(Resolve-Path -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object { $_.Path } | Sort-Object -Descending)
    }
    if (Get-Command 'Get-AppxPackage' -ErrorAction SilentlyContinue) {
        try {
            $candidates += @(Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' -ErrorAction Stop |
                Where-Object { $_.InstallLocation } | ForEach-Object { Join-Path $_.InstallLocation 'winget.exe' })
        }
        catch { Write-Verbose "Could not list the App Installer package: $_" }
    }
    $candidates += @(Get-Command 'winget.exe' -CommandType Application -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    return $candidates
}

function Resolve-CEWingetPath {
    <# winget.exe signed by Microsoft: Path, or $null with Refused listing any copies that weren't. #>
    [CmdletBinding()]
    param()
    return (Resolve-CETrustedTool -Candidate @(Get-CEWingetCandidate) -Publisher 'Microsoft Corporation')
}
