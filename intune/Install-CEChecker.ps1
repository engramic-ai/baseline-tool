#Requires -Version 5.1
<#
.SYNOPSIS
    Installs Engramic Baseline machine-wide. Built to run as the
    install command of an Intune Win32 app, and also runnable by hand.

.DESCRIPTION
    - Copies the tool to Program Files, locked down so only administrators and
      SYSTEM can change it (the scheduled task runs these scripts as SYSTEM)
    - Creates %ProgramData%\EngramicBaseline for status, reports and logs
    - Copies any config overrides staged in the package's data\config folder
      into %ProgramData%\EngramicBaseline\config
    - Registers the Application event log source EngramicBaseline
    - Registers the scheduled task \EngramicBaseline\Audit (SYSTEM,
      daily with a random delay, plus shortly after start-up)
    - Adds a Start menu shortcut for the desktop app
    - Writes HKLM\SOFTWARE\EngramicBaseline (Version, InstallPath) for
      Intune detection

    Safe to run again: re-running upgrades in place. Never downgrades: if a
    newer version is already installed, changes nothing and exits 0, unless
    run with -AllowDowngrade. Relaunches itself in 64-bit PowerShell if started
    from a 32-bit host (as Intune may do).

    Exit codes: 0 success, 1 failure.

.PARAMETER InstallPath
    Default: %ProgramFiles%\EngramicBaseline

.PARAMETER DailyAt
    Time of the daily audit, HH:mm, local time. Default 11:00 (when laptops
    are usually on).

.PARAMETER RandomDelayMinutes
    Spreads audits across the fleet. Default 120.

.PARAMETER RunNow
    Start the first audit straight after installing.

.PARAMETER AllowDowngrade
    Install even when a newer version is already installed. Without it, an
    older package left assigned in Intune could put an old version back.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\intune\Install-CEChecker.ps1 -RunNow
#>
[CmdletBinding()]
param(
    [string]$InstallPath,
    [ValidatePattern('^\d{2}:\d{2}$')][string]$DailyAt = '11:00',
    [ValidateRange(0, 720)][int]$RandomDelayMinutes = 120,
    [switch]$NoScheduledTask,
    [switch]$NoUserProbeTask,
    [switch]$NoShortcut,
    [switch]$RunNow,
    [switch]$AllowDowngrade
)

$ErrorActionPreference = 'Stop'

# --- 64-bit relaunch --------------------------------------------------------
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v) { $argList += "-$k" } }
        else { $argList += @("-$k", "`"$v`"") }
    }
    $p = Start-Process -FilePath $ps64 -ArgumentList $argList -Wait -PassThru -NoNewWindow
    exit $p.ExitCode
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this as an administrator (Intune runs it as SYSTEM).'
    exit 1
}

$packageRoot = Split-Path -Parent $PSScriptRoot
if (-not $InstallPath) { $InstallPath = Join-Path $env:ProgramFiles 'EngramicBaseline' }
$dataRoot = Join-Path $env:ProgramData 'EngramicBaseline'
$regPath = 'HKLM:\SOFTWARE\EngramicBaseline'
# The sealed-at-birth marker lives in a SEPARATE key, so uninstall (which deletes $regPath) leaves it
# unless -RemoveData is given: an uninstall/reinstall or a supersede-with-uninstall then keeps the
# locked data folder in place instead of moving it aside and losing config overrides, packs and
# reports. It is a sibling, not a value under $regPath, so Discover-CECompliance does not read it as
# 'installed' (it treats the mere existence of SOFTWARE\EngramicBaseline as installed).
$sealRegPath = 'HKLM:\SOFTWARE\EngramicBaseline.DataRoot'
$taskPath = '\EngramicBaseline\'
$taskName = 'Audit'
$userTaskName = 'User probe'

$log = Join-Path $dataRoot ("logs\install-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
# Native tools by full path, never through PATH.
$system32 = [Environment]::GetFolderPath('System')
$icacls = Join-Path $system32 'icacls.exe'

$transcribing = $false

function Set-CELockedAcl {
    <# SYSTEM and Administrators: full control. Users: read (optional). SIDs keep this locale independent. #>
    param([string]$Path, [switch]$UsersRead)
    $grants = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    if ($UsersRead) { $grants += '*S-1-5-32-545:(OI)(CI)RX' }
    $icaclsArgs = @($Path, '/inheritance:r', '/grant:r') + $grants + @('/Q')
    & $icacls @icaclsArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path (exit $LASTEXITCODE)" }
}

function Test-CENewerInstalled {
    <# Whether the installed version (the detection value) is newer than this package's. Unreadable counts as not newer. #>
    param([string]$Installed, [string]$Package)
    $installedVersion = $null
    $packageVersion = $null
    if (-not [version]::TryParse($Installed, [ref]$installedVersion)) { return $false }
    if (-not [version]::TryParse($Package, [ref]$packageVersion)) { return $false }
    return $installedVersion -gt $packageVersion
}

function New-CEDataDirectorySecurity {
    <#
        The locked security descriptor a data folder is born with: owner Administrators, and a
        protected DACL (no inheritance from %ProgramData%) granting only SYSTEM and Administrators
        full control, inherited by the folder's children. -UsersRead also grants Users read and
        execute (the config folder, which the desktop app reads). SIDs keep this locale independent.
        The owner is in the descriptor so it is set in the one call that creates the folder, never
        afterwards: an elevated or SYSTEM token may name BUILTIN\Administrators as owner (that group
        carries SE_GROUP_OWNER), so no separate ownership step - which could land on a folder a
        standard user made in a race - is needed.
    #>
    param([switch]$UsersRead)
    $sddl = 'O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    if ($UsersRead) { $sddl += '(A;OICI;0x1200A9;;;BU)' }
    $sec = New-Object Security.AccessControl.DirectorySecurity
    $sec.SetSecurityDescriptorSddlForm($sddl)
    return $sec
}

function New-CEDataFileSecurity {
    <#
        The security descriptor a config file this install deploys is born with: owner Administrators
        and a protected DACL granting SYSTEM and Administrators full control and Users read (the desktop
        app reads config), as the locked config folder would. The owner is set in the call that creates
        the file: a file otherwise takes its creator's default owner, which for an administrator's
        elevated session on a Windows client is their own account, and the SYSTEM audit ignores a
        config file that is not owned by SYSTEM or Administrators.
    #>
    $sec = New-Object Security.AccessControl.FileSecurity
    $sec.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200A9;;;BU)')
    return $sec
}

function Test-CELockedFolder {
    <#
        '' when the folder (or file) at $Path is one this install may keep in place, or the reason it is not.
        Read only: it never changes owner or permissions. Judged by trust, not by SDDL equality
        (design rule 1): a folder is accepted only when it is not a link, is owned by SYSTEM,
        Administrators or TrustedInstaller (a standard user can set none of these, so a folder they
        made or took over is rejected here), grants no SID outside those (and CREATOR OWNER) any
        write, add, delete, change-permissions or take-ownership right, and carries no deny entry
        against a trusted SID. So a folder a user made or could write - on which they may hold an
        add-file or WRITE_DAC handle that still works after a later lock - is rejected, while a
        read-only ACE an administrator added (browsing the folder, or granting a helpdesk group read)
        is kept, and so is a folder locked with icacls (which reads back D:PAI, not D:P). Exact SDDL
        equality was stricter than design rule 1 and caused silent data loss. Kept identical in intent
        to the module's Get-CELockedFolderProblem / Get-CEDataPathProblem.
    #>
    param([string]$Path)
    # SYSTEM, Administrators, TrustedInstaller.
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    # Rights that let a principal change, delete or re-permission it, incl. GENERIC_WRITE / GENERIC_ALL.
    $writeRights = 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288 -bor 0x40000000 -bor 0x10000000
    if (Test-CEReparsePoint -Path $Path) { return "$Path is a link (junction or symbolic link)" }
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $Path } catch { return "the permissions of $Path could not be read" }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($trusted -notcontains $owner) { return "$Path is owned by $owner, not SYSTEM or Administrators" }
    foreach ($rule in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        $sid = "$($rule.IdentityReference)"
        if ("$($rule.AccessControlType)" -ne 'Allow') {
            # A deny against SYSTEM/Administrators/TrustedInstaller could stop the tool replacing a
            # forged file, so treat it as tampering.
            if ($trusted -contains $sid) { return "$Path denies $sid, so the tool may be unable to replace it" }
            continue
        }
        # CREATOR OWNER only applies to new items, which only administrators can create in a locked folder.
        if ($trusted -contains $sid -or $sid -eq 'S-1-3-0') { continue }
        $rights = [long]0
        try { $rights = [long]$rule.FileSystemRights } catch { $rights = [long]::MaxValue }
        if ($rights -band $writeRights) { return "$Path can be changed by $sid, not only administrators" }
    }
    return ''
}

function Test-CEReparsePoint {
    <# Whether a path is a junction or symbolic link. Reads the link itself, never its target. #>
    param([string]$Path)
    try { return [bool]([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) }
    catch { return $false }
}

function Remove-CELink {
    <#
        Removes a junction or symbolic link, never what it points at. A standard user can plant a
        junction in %ProgramData% without any special right; left in place it would send the audit's
        output to a folder the user controls. Remove-Item -Recurse is not used: Windows PowerShell
        5.1 follows links and would empty the target.
    #>
    param([string]$Path)
    Write-Warning "$Path is a link (junction or symbolic link), not a folder. A standard user may have made it to redirect the audit's data, so the link is removed; what it points at is left alone."
    if ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete($Path, $false) }
    else { [IO.File]::Delete($Path) }
    if (Test-CEReparsePoint -Path $Path) { throw "Could not remove the link at $Path" }
}

function Get-CEAsidePath {
    <#
        Where an untrusted item at $Path is moved to: always a sibling of the data folder, never a
        name inside it - %ProgramData%\EngramicBaseline.untrusted-<id> for the data folder itself,
        and EngramicBaseline.untrusted-<id>-<name> for an item inside it (say ...-packs). A
        moved-aside item is a tree a standard user may control, so it must be outside every tree the
        tool keeps, reads or deletes as SYSTEM; the uninstaller leaves every
        EngramicBaseline.untrusted-* folder for an administrator. Same volume, so the move is a rename.
    #>
    param([string]$Path, [string]$DataRoot)
    $root = $DataRoot.TrimEnd('\')
    $item = $Path.TrimEnd('\')
    $id = [guid]::NewGuid().ToString('n')
    if ($item -eq $root) { return "$root.untrusted-$id" }
    if (-not $item.StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase)) { throw "$Path is not in the data folder $DataRoot" }
    return "$root.untrusted-$id-" + ($item.Substring($root.Length + 1) -replace '\\', '-')
}

function Move-CEItemAside {
    <#
        Renames a file or folder out of the data folder to a quarantine sibling of it
        (Get-CEAsidePath), so nothing later reads or walks it. The rename touches only the item
        itself, never what is inside it, and never follows a link. Nothing ever reads the moved-aside
        item; it is for an administrator to check by hand and delete. Retries a few times with a
        short back-off: an old-version audit, or any process with a handle open under the data
        folder, can make the first rename fail with a sharing violation, and Intune would then just
        report the install failed with no hint why. Returns the new path; throws with a clear reason
        on final failure.
    #>
    param([string]$Path, [string]$DataRoot)
    $aside = Get-CEAsidePath -Path $Path -DataRoot $DataRoot
    $isDir = [bool]([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::Directory)
    $lastErr = $null
    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        try {
            if ($isDir) { [IO.Directory]::Move($Path, $aside) } else { [IO.File]::Move($Path, $aside) }
            return $aside
        }
        catch {
            $lastErr = $_
            Start-Sleep -Milliseconds (200 * ($attempt + 1))
        }
    }
    throw "Could not move $Path aside to $aside - a process may have a file or folder open under the data folder ($($lastErr.Exception.Message)). Close it (or wait for a running audit to finish) and reinstall."
}

function Get-CERegistryString {
    <# A registry string value under $Path, or '' when the key or value is missing or unreadable. #>
    param([string]$Path, [string]$Name)
    try { return [string](Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return '' }
}

function New-CELockedDirectory {
    <#
        Creates a data folder with its locked, administrator-owned descriptor already applied, in the
        one call that makes it (CreateDirectory with a DirectorySecurity on 5.1,
        FileSystemAclExtensions.Create on pwsh 7), so there is never a moment when a standard user can
        write it or add to it, and the owner is never changed afterwards. Both calls return silently
        if the folder already exists, leaving the existing descriptor untouched, so after creating it
        this VERIFIES the result with Test-CELockedFolder and never repairs it. Anything already there
        that a user made, took over or could write - or a link - is moved aside (out of the data
        folder, Get-CEAsidePath) and the create retried a bounded number of times, then the install
        fails. A folder is never taken back in place: its creator may hold a handle opened while they
        owned it, which keeps add-file or WRITE_DAC access even after takeown and icacls (verified
        Windows behaviour). An existing folder that is trusted (admin-owned, not a link, no non-admin
        write/DAC/owner right) is kept, so a re-run preserves reports; a benign read-only ACE an admin
        added does not force it aside. Each move-aside is a warning naming where it went, which the
        install collects and writes to its log and the Application event log.
    #>
    [CmdletBinding()]
    param([string]$Path, [string]$DataRoot, [switch]$UsersRead)
    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        if (Test-CEReparsePoint -Path $Path) { Remove-CELink -Path $Path }
        if (Test-Path -LiteralPath $Path) {
            $problem = Test-CELockedFolder -Path $Path
            if (-not $problem) { return }
            $aside = Move-CEItemAside -Path $Path -DataRoot $DataRoot
            Write-Warning "$problem, so a standard user may control it. It was moved aside to $aside (check it, then delete it) and a fresh, locked folder made in its place."
            continue
        }
        $security = New-CEDataDirectorySecurity -UsersRead:$UsersRead
        if ($PSVersionTable.PSVersion.Major -ge 6) { [void][IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path), $security) }
        else { [void][IO.Directory]::CreateDirectory($Path, $security) }
        # Verify what is now on disk; never repair it. If the folder pre-existed, the create was a
        # silent no-op and this rejects it (wrong owner, or a non-admin write right) rather than re-owning it.
        $problem = Test-CELockedFolder -Path $Path
        if (-not $problem) { return }
        $aside = Move-CEItemAside -Path $Path -DataRoot $DataRoot
        Write-Warning "The folder at $Path is not the one this install created ($problem). It was moved aside to $aside (check it, then delete it) and the create retried."
    }
    throw "Could not create a locked, administrator-owned folder at $Path; a standard user may be interfering with the install."
}

function Initialize-CEDataRoot {
    <#
        Establishes the data folder as a locked, administrator-owned folder.

        A link found in its place is removed as a link. An existing real folder is KEPT in place only
        when a locked-at-birth version sealed it: the marker HKLM\SOFTWARE\EngramicBaseline.DataRoot
        \DataRootSealed (which only administrators can write, and which uninstall leaves in place
        unless -RemoveData is given, so an uninstall/reinstall or supersede does not lose the data)
        records that a locked root was created, and Test-CELockedFolder confirms it is still trusted
        (admin-owned, not a link, no non-admin write/DAC/owner right). Such a root was never writable
        by a standard user, so no one holds a handle to it, and keeping it preserves the admin's config
        overrides, installed packs and report history across upgrades.

        Anything else - a folder a standard user made or could write, one an older version re-owned in
        place (which left no marker, so its creator may hold a handle), one a script made before this
        install ran, or one whose owner is wrong - is moved aside whole (to a sibling of the data
        folder, never inside it), never taken back in place, and a fresh locked folder made instead.
        Nothing in a moved-aside folder is carried over, not even a file that now looks admin-owned
        and locked: while a standard user controlled the folder, they could give themselves write and
        change-permissions rights on a file an administrator then put there, change it, and lock it
        again, and a handle they opened keeps working after any later lock (verified Windows
        behaviour). Nothing about a file's current state shows that never happened. The next audit
        rebuilds status and reports; config overrides staged in the package are copied in by this
        install (Copy-CEStagedConfig), and anything else is redeployed after it.
    #>
    [CmdletBinding()]
    param([string]$Path, [string]$RegPath)
    if (Test-CEReparsePoint -Path $Path) { Remove-CELink -Path $Path }
    if (Test-Path -LiteralPath $Path) {
        $sealed = Get-CERegistryString -Path $RegPath -Name 'DataRootSealed'
        $problem = Test-CELockedFolder -Path $Path
        if ($sealed -and -not $problem) {
            Write-Host "Keeping the existing locked data folder at $Path (config overrides, packs and reports are preserved)."
            return
        }
        $reason = if (-not $sealed) { 'this version''s install did not create it locked, so it may have been writable by a standard user' } else { $problem }
        $aside = Move-CEItemAside -Path $Path -DataRoot $Path
        Write-Warning "An existing $Path was moved aside to $aside ($reason) and a fresh, locked data folder made. Its reports, logs, config overrides and packs are not carried over: stage config overrides in the package's data\config folder, or redeploy them and any packs after this install. Check the moved-aside folder, then delete it."
    }
    New-CELockedDirectory -Path $Path -DataRoot $Path
}

function Copy-CEStagedConfig {
    <#
        Copies the config overrides staged in the package ($Source, the package's data\config folder)
        into the data folder's locked config folder, replacing a file of the same name. This is the
        supported way to deploy config overrides with the app: the package is as trusted as the code
        it installs. Only *.json files directly in $Source are copied, each into a new file born
        administrator-owned and locked (New-CEDataFileSecurity), whoever runs the install. An existing
        file of the same name is replaced only when it is admin-owned and no non-administrator can
        change it; a link is removed as a link, and anything else (a folder, or a file a standard user
        owns or can change) is moved aside out of the data folder with a warning, never written into or
        re-permissioned in place.
    #>
    [CmdletBinding()]
    param([string]$Source, [string]$ConfigDir, [string]$DataRoot)
    if (-not (Test-Path -LiteralPath $Source -PathType Container)) { return }
    foreach ($file in @(Get-ChildItem -LiteralPath $Source -Filter '*.json' -File)) {
        # -Filter '*.json' also matches longer extensions through 8.3 names, so check it exactly.
        if ($file.Extension -ne '.json') { continue }
        $dest = Join-Path $ConfigDir $file.Name
        $tmp = '{0}.{1}.tmp' -f $dest, [guid]::NewGuid().ToString('n')
        $bytes = [IO.File]::ReadAllBytes($file.FullName)
        try {
            # A new file, born with its owner and locked DACL (New-CEDataFileSecurity), never a copy of
            # the source's attributes: a read-only copy could not be replaced by the next upgrade.
            $security = New-CEDataFileSecurity
            $stream = if ($PSVersionTable.PSVersion.Major -ge 6) {
                [IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($tmp), [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $security)
            }
            else { [IO.File]::Create($tmp, 4096, [IO.FileOptions]::None, $security) }
            try { $stream.Write($bytes, 0, $bytes.Length) }
            finally { $stream.Dispose() }
            if (Test-CEReparsePoint -Path $dest) { Remove-CELink -Path $dest }
            if (Test-Path -LiteralPath $dest) {
                $problem = if (Test-Path -LiteralPath $dest -PathType Container) { "$dest is a folder" } else { Test-CELockedFolder -Path $dest }
                if ($problem) {
                    $aside = Move-CEItemAside -Path $dest -DataRoot $DataRoot
                    Write-Warning "$problem, so it was not overwritten in place. It was moved aside to $aside (check it, then delete it) and replaced by the copy staged in the package."
                }
                else {
                    [IO.File]::SetAttributes($dest, [IO.FileAttributes]::Normal)
                    [IO.File]::Delete($dest)
                }
            }
            [IO.File]::Move($tmp, $dest)
        }
        finally {
            if (Test-Path -LiteralPath $tmp) { [IO.File]::Delete($tmp) }
        }
        Write-Host "Deployed the config override $($file.Name) staged in the package"
    }
}

function Write-CEInstallEvent {
    <#
        Writes a warning to the Application event log under the EngramicBaseline source, with the same
        RegisterEventSource / ReportEvent calls the audit uses: EventLog.WriteEntry enumerates every
        log and throws where Security is unreadable. A failure here is only a warning.
    #>
    param([string]$Message, [int]$Id = 1003)
    try {
        if (-not ('CEInstall.EventWriter' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CEInstall {
    public static class EventWriter {
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
        # 2 = EVENTLOG_WARNING_TYPE
        $rc = [CEInstall.EventWriter]::Write('EngramicBaseline', [uint16]2, [uint32]$Id, $Message)
        if ($rc -ne 0) { Write-Warning "Could not write event $Id to the Application log (Win32 error $rc)" }
    }
    catch { Write-Warning "Could not write event $Id to the Application log: $($_.Exception.Message)" }
}

function Write-CESetupNotice {
    <#
        Records each data-folder notice (a link removed, or something moved aside, naming where it
        went) in the install log and the Application event log (ID 1003), so a move-aside is never
        silent: Intune shows none of an install's console output, and the notices are raised before
        the log can start (the log lives in the folder being set up). Call it once logging has started.
    #>
    param([object[]]$Notice)
    foreach ($n in @($Notice)) {
        $text = "$n"
        if (-not $text) { continue }
        Write-Warning "Data folder: $text"
        Write-CEInstallEvent -Message "Engramic Baseline install - data folder: $text" -Id 1003
    }
}

$auditMutex = $null
$haveMutex = $false
$disabledAudit = $false
# Data-folder notices (a link removed, something moved aside) are raised before the install log can
# start, since the log lives in the folder being set up. They are written to the log and the
# Application event log as soon as logging starts, or from the catch if it never does.
$setupNotices = @()
$noticesWritten = $false

try {
    $manifest = Import-PowerShellDataFile -Path (Join-Path $packageRoot 'src\CEAudit\CEAudit.psd1')
    $version = [string]$manifest.ModuleVersion

    # --- Never downgrade, before touching the data folder --------------------
    # An older package still assigned (say, to All Devices while a newer one goes to a pilot
    # group) must not put its version back over a newer install. Check this FIRST, so an older
    # package that "changes nothing and exits 0" never moves the data folder aside.
    $installedVersion = ''
    $installedItem = Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue
    if ($installedItem -and $installedItem.PSObject.Properties['Version']) { $installedVersion = [string]$installedItem.Version }
    if (-not $AllowDowngrade -and (Test-CENewerInstalled -Installed $installedVersion -Package $version)) {
        Write-Warning "Engramic Baseline $installedVersion is installed, which is newer than this package ($version), so it is left as it is. Run with -AllowDowngrade to install $version over it."
        exit 0
    }

    # --- Event log source, before the data folder ----------------------------
    # Registered first so that anything the data-folder set-up moves aside can be recorded in the
    # Application event log. Register the source by writing its registry key directly. The managed
    # [Diagnostics.EventLog]::CreateEventSource calls SourceExists, which
    # enumerates every event log and throws when Security/State are inaccessible
    # (hosted CI runners, restricted images) - so the source was never created
    # and the audit's event was silently dropped. Creating the key is all that
    # RegisterEventSource (used by the audit) needs; the full message text still
    # shows in Event Viewer as the event's insertion string.
    $sourceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\EngramicBaseline'
    $registeredSource = $false
    if (-not (Test-Path -LiteralPath $sourceKey)) {
        New-Item -Path $sourceKey -Force | Out-Null
        New-ItemProperty -Path $sourceKey -Name 'EventMessageFile' -PropertyType ExpandString -Value '%SystemRoot%\System32\EventCreate.exe' -Force | Out-Null
        New-ItemProperty -Path $sourceKey -Name 'TypesSupported' -PropertyType DWord -Value 7 -Force | Out-Null
        $registeredSource = $true
    }

    # --- Don't set up the data folder underneath a running audit -------------
    # An old-version audit that starts while the installer waits (start-up trigger, StartWhenAvailable
    # catch-up, a restart retry) would take its working directory in the data root and block the rename
    # with a sharing violation. Stopping the task does not prevent a new start, so DISABLE it first,
    # then stop any running instance, then take the audit mutex - which also blocks a manual run or the
    # Remediations audit - and hold it until the folders are locked. The task is re-registered (enabled)
    # at the end, or re-enabled in the finally if the install fails first. The audit takes the same
    # mutex before it writes anything under the data folder.
    $running = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
    if ($running) {
        try { $running | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null; $disabledAudit = $true } catch { $null = $_ }
        if ($running.State -eq 'Running') { $running | Stop-ScheduledTask -ErrorAction SilentlyContinue }
    }
    $auditMutex = New-Object System.Threading.Mutex($false, 'Global\EngramicBaselineAudit')
    try { $haveMutex = $auditMutex.WaitOne([TimeSpan]::FromMinutes(5)) }
    catch [System.Threading.AbandonedMutexException] { $haveMutex = $true }
    if (-not $haveMutex) { throw 'An Engramic Baseline audit is still running (could not take the Global\EngramicBaselineAudit mutex within 5 minutes). Try the install again once it has finished.' }

    # --- Data folder: born locked, before anything is written there ----------
    # %ProgramData% lets standard users create files and folders, and the data folder holds config
    # overrides and a status.json that the SYSTEM audit and Intune trust. Make the folder and every
    # subfolder the tool keeps with their locked, administrator-owned descriptor applied in the one
    # call that creates them, so there is never a moment when a standard user can write them or add
    # to them. An existing root this version sealed is kept (config, packs and reports preserved);
    # anything else is moved aside out of the data folder, never taken back in place
    # (Initialize-CEDataRoot says why). Their warnings, which name where anything went, are collected
    # for the log and the event log.
    Initialize-CEDataRoot -Path $dataRoot -RegPath $sealRegPath -WarningVariable +setupNotices -WarningAction SilentlyContinue
    # Users may read config overrides (the desktop app uses them); status, reports and the rest stay admin-only.
    foreach ($name in @('logs', 'reports', 'cache', 'packs')) { New-CELockedDirectory -Path (Join-Path $dataRoot $name) -DataRoot $dataRoot -WarningVariable +setupNotices -WarningAction SilentlyContinue }
    New-CELockedDirectory -Path (Join-Path $dataRoot 'config') -DataRoot $dataRoot -UsersRead -WarningVariable +setupNotices -WarningAction SilentlyContinue
    # Record that a locked root was sealed at birth, so a later install keeps it in place instead of
    # moving it aside. Only administrators can write here, so a standard user cannot forge it; it is a
    # key separate from $regPath so uninstall can leave it unless -RemoveData is given.
    if (-not (Test-Path -LiteralPath $sealRegPath)) { New-Item -Path $sealRegPath -Force | Out-Null }
    New-ItemProperty -Path $sealRegPath -Name 'DataRootSealed' -Value $version -PropertyType String -Force | Out-Null
    # Log only once the data folder is locked, so no one else can read or plant the log.
    Start-Transcript -LiteralPath $log | Out-Null
    $transcribing = $true
    Write-Host "Installing Engramic Baseline $version to $InstallPath"
    if ($registeredSource) { Write-Host 'Registered event log source EngramicBaseline' }
    # Every link removed and everything moved aside above goes in this log and the Application event log.
    $noticesWritten = $true
    Write-CESetupNotice -Notice $setupNotices

    # --- Config overrides staged in the package -------------------------------
    # The supported way to deploy config overrides with the app (docs/INTUNE.md): copied into the
    # locked config folder on every install, so they survive a moved-aside data folder and reach a
    # device where a script made the folder before this install ran.
    $stagedNotices = @()
    Copy-CEStagedConfig -Source (Join-Path $packageRoot 'data\config') -ConfigDir (Join-Path $dataRoot 'config') -DataRoot $dataRoot -WarningVariable +stagedNotices -WarningAction SilentlyContinue
    Write-CESetupNotice -Notice $stagedNotices

    # --- Copy payload into a staging folder, then swap -----------------------
    $payload = @('src', 'config', 'intune', 'docs', 'app', 'README.md')
    $staging = "$InstallPath.staging"
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    foreach ($item in $payload) {
        $src = Join-Path $packageRoot $item
        if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $staging -Recurse -Force }
        elseif ($item -ne 'docs') { throw "Package is missing $item" }
    }
    Get-ChildItem -LiteralPath $staging -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

    $swapped = $false
    if (Test-Path -LiteralPath $InstallPath) {
        try {
            Remove-Item -LiteralPath $InstallPath -Recurse -Force
        }
        catch {
            # Something (e.g. an open desktop app) is holding the folder: update it in place instead.
            Write-Warning "Could not replace $InstallPath ($($_.Exception.Message)); updating files in place."
            Get-ChildItem -LiteralPath $staging | Copy-Item -Destination $InstallPath -Recurse -Force
            Remove-Item -LiteralPath $staging -Recurse -Force
            $swapped = $true
        }
    }
    if (-not $swapped) { Move-Item -LiteralPath $staging -Destination $InstallPath }
    Set-CELockedAcl -Path $InstallPath -UsersRead

    # --- Scheduled task ------------------------------------------------------
    if (-not $NoScheduledTask) {
        $ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $script = Join-Path $InstallPath 'app\Invoke-CEScheduledAudit.ps1'
        # Working directory is the install folder, not the data folder: an audit's open working
        # directory would otherwise block an upgrade from renaming the data root.
        $action = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`"" -WorkingDirectory $InstallPath
        $daily = New-ScheduledTaskTrigger -Daily -At $DailyAt
        if ($RandomDelayMinutes -gt 0) { $daily.RandomDelay = "PT$($RandomDelayMinutes)M" }
        $startup = New-ScheduledTaskTrigger -AtStartup
        $startup.Delay = 'PT15M'
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew `
            -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 30)
        Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger @($daily, $startup) `
            -Principal $taskPrincipal -Settings $settings `
            -Description 'Engramic Baseline: read-only daily audit. Writes %ProgramData%\EngramicBaseline\status.json for Intune compliance.' `
            -Force | Out-Null
        Write-Host "Registered scheduled task $taskPath$taskName (daily at $DailyAt + up to $RandomDelayMinutes min, and 15 min after start-up)"
    }

    # --- Per-user probe task (shadow AI / WSL, runs as each signed-in user) ---
    if (-not $NoUserProbeTask) {
        $ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $probe = Join-Path $InstallPath 'app\Invoke-CEUserProbe.ps1'
        $uAction = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$probe`""
        $uLogon = New-ScheduledTaskTrigger -AtLogOn
        $uLogon.Delay = 'PT2M'
        $uDaily = New-ScheduledTaskTrigger -Daily -At $DailyAt
        if ($RandomDelayMinutes -gt 0) { $uDaily.RandomDelay = "PT$($RandomDelayMinutes)M" }
        # BUILTIN\Users, non-elevated: each signed-in user runs their own instance in
        # their own session, so the probe sees their agents and their WSL VM. SYSTEM
        # cannot, which is why shadow-AI checks are User-scope.
        $uPrincipal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
        $uSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $userTaskName -TaskPath $taskPath -Action $uAction -Trigger @($uLogon, $uDaily) `
            -Principal $uPrincipal -Settings $uSettings `
            -Description 'Engramic Baseline: per-user shadow-AI and WSL probe. Runs as each signed-in user; writes %LOCALAPPDATA%\EngramicBaseline\user-status.json.' `
            -Force | Out-Null
        Write-Host "Registered scheduled task $taskPath$userTaskName (per signed-in user, at logon + daily at $DailyAt)"
    }

    # --- Start menu shortcut -------------------------------------------------
    $lnk = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Engramic Baseline.lnk'
    if (-not $NoShortcut) {
        $shell = New-Object -ComObject WScript.Shell
        $sc = $shell.CreateShortcut($lnk)
        $sc.TargetPath = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $sc.Arguments = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$(Join-Path $InstallPath 'app\Start-CEAuditGui.ps1')`""
        # Not the install folder, so an open app never blocks an upgrade.
        $sc.WorkingDirectory = '%USERPROFILE%'
        $sc.IconLocation = "$env:WINDIR\System32\shell32.dll,47"
        $sc.Description = 'Check this device against Cyber Essentials'
        $sc.Save()
        Write-Host "Created Start menu shortcut"
    }
    elseif (Test-Path -LiteralPath $lnk) {
        Remove-Item -LiteralPath $lnk -Force
    }

    # --- Detection key -------------------------------------------------------
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    New-ItemProperty -Path $regPath -Name 'Version' -Value $version -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name 'InstallPath' -Value $InstallPath -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name 'DataRoot' -Value $dataRoot -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name 'InstalledAt' -Value ((Get-Date).ToUniversalTime().ToString('o')) -PropertyType String -Force | Out-Null

    if ($RunNow -and -not $NoScheduledTask) {
        Start-ScheduledTask -TaskPath $taskPath -TaskName $taskName
        Write-Host 'First audit started in the background.'
    }
    Write-Host "Installed $version."
    $exit = 0
}
catch {
    Write-Error "Install failed: $($_.Exception.Message)" -ErrorAction Continue
    # A failure before logging started must not lose a move-aside: record it in the event log.
    if (-not $noticesWritten) { Write-CESetupNotice -Notice $setupNotices }
    $exit = 1
}
finally {
    if ($transcribing) { Stop-Transcript | Out-Null }
    if ($haveMutex) { try { $auditMutex.ReleaseMutex() } catch { $null = $_ } }
    if ($auditMutex) { $auditMutex.Dispose() }
    # Re-enable the audit task if we disabled it. Re-registration above already left it enabled; this
    # covers -NoScheduledTask and a failure before re-registration, so the device keeps auditing.
    if ($disabledAudit) {
        try { Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue | Enable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null } catch { $null = $_ }
    }
}
exit $exit
