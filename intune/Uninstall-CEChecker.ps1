#Requires -Version 5.1
<#
.SYNOPSIS
    Removes Engramic Baseline. Intune Win32 app uninstall command.

.DESCRIPTION
    Removes the scheduled task, Start menu shortcut, program folder, event log
    source and detection key. Audit history in %ProgramData% is kept unless
    -RemoveData is given, so evidence isn't lost by accident, and so is the
    sealed-at-birth marker, so a reinstall keeps the existing locked data folder
    rather than moving it aside.

    With -RemoveData, the data folder is removed only when the install sealed it at
    birth (the DataRootSealed marker) and it is still the locked, admin-owned folder
    the tool created, and even then every folder is checked again just before it is
    listed: a folder that is a link, not admin-owned or changeable by a
    non-administrator is left in place and reported, never walked, so a SYSTEM
    recursive delete never walks a tree a standard user could control. Any
    EngramicBaseline.untrusted-* quarantine folder is left for an administrator to
    check and delete by hand, because it is a user-owned tree; only a quarantine entry
    that is itself a link is removed.

    Exit codes: 0 success, 1 failure.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\intune\Uninstall-CEChecker.ps1
#>
[CmdletBinding()]
param(
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'

if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($RemoveData) { $argList += '-RemoveData' }
    $p = Start-Process -FilePath $ps64 -ArgumentList $argList -Wait -PassThru -NoNewWindow
    exit $p.ExitCode
}

function Remove-CETreeNoFollow {
    <#
        Deletes a folder and everything in it without ever following a junction or symbolic link (each
        link is removed as a link), and without ever listing a folder it does not trust. This runs as
        SYSTEM under the data folder, and Remove-Item -Recurse follows links on Windows PowerShell 5.1,
        which could empty a folder a link points at.

        Each folder is checked with Get-CEFolderTrustProblem immediately before it is listed: not a
        link, owned by SYSTEM, Administrators or TrustedInstaller, no non-administrator write, add,
        delete, change-permissions or take-ownership right, no deny against those. A folder that fails
        is left in place, with everything in it, and reported; it is never listed or walked. So every
        folder that is walked is one no non-administrator can add to, rename in or delete from, and an
        entry listed there cannot be swapped for a junction before it is acted on. Anything named
        *.untrusted-* is a quarantine an administrator has to check, so it is left in place too.
        Returns $true when the whole tree was removed, $false when something was left.
    #>
    param([string]$Path)
    $attrs = $null
    try { $attrs = [IO.File]::GetAttributes($Path) }
    catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] { return $true }
    if ($attrs -band [IO.FileAttributes]::ReparsePoint) {
        if ($attrs -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete($Path, $false) } else { [IO.File]::Delete($Path) }
        return $true
    }
    if (-not ($attrs -band [IO.FileAttributes]::Directory)) { [IO.File]::Delete($Path); return $true }
    $problem = Get-CEFolderTrustProblem -Path $Path
    if ($problem) {
        Write-Warning "Left $Path in place, unread ($problem). A standard user may control it, so SYSTEM does not walk it. Check it, then remove it by hand."
        return $false
    }
    $complete = $true
    foreach ($child in @([IO.Directory]::GetFileSystemEntries($Path))) {
        if ((Split-Path -Leaf $child) -like '*.untrusted-*') {
            Write-Warning "Left the quarantine folder $child in place for an administrator to check and delete by hand."
            $complete = $false
            continue
        }
        try { if (-not (Remove-CETreeNoFollow -Path $child)) { $complete = $false } }
        catch {
            Write-Warning "Could not remove $child ($($_.Exception.Message)); left it in place."
            $complete = $false
        }
    }
    if ($complete) { [IO.Directory]::Delete($Path, $false) }
    return $complete
}

function Get-CEFolderTrustProblem {
    <#
        '' when the folder at $Path is admin-owned and no non-administrator can change it - safe for a
        SYSTEM recursive delete to list - or the reason it is not. Read only. A link, an owner outside
        SYSTEM / Administrators / TrustedInstaller, any Allow entry giving another SID (bar CREATOR
        OWNER) a write, add, delete, change-permissions or take-ownership right, or a deny entry against
        SYSTEM, Administrators or TrustedInstaller is a problem. This is the same trust test the
        installer (Test-CELockedFolder) and the module (Get-CELockedFolderProblem) apply to the data
        folder; it is what tells a user-owned tree apart from the locked folders the tool created.
    #>
    param([string]$Path)
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $writeRights = 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288 -bor 0x40000000 -bor 0x10000000
    $attrs = $null
    try { $attrs = [IO.File]::GetAttributes($Path) } catch { return "the attributes of $Path could not be read" }
    if ($attrs -band [IO.FileAttributes]::ReparsePoint) { return "$Path is a link (junction or symbolic link)" }
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $Path } catch { return "the permissions of $Path could not be read" }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($trusted -notcontains $owner) { return "$Path is owned by $owner, not an administrator" }
    foreach ($rule in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        $sid = "$($rule.IdentityReference)"
        if ("$($rule.AccessControlType)" -ne 'Allow') {
            # A deny against SYSTEM or Administrators is tampering: it could stop the delete part-way.
            if ($trusted -contains $sid) { return "$Path denies $sid" }
            continue
        }
        if ($trusted -contains $sid -or $sid -eq 'S-1-3-0') { continue }
        $rights = [long]0
        try { $rights = [long]$rule.FileSystemRights } catch { $rights = [long]::MaxValue }
        if ($rights -band $writeRights) { return "$Path can be changed by $sid, not only administrators" }
    }
    return ''
}

function Get-CERegistryString {
    <# A registry string value under $Path, or '' when the key or value is missing or unreadable. #>
    param([string]$Path, [string]$Name)
    try { return [string](Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return '' }
}

function Remove-CEDataFolders {
    <#
        The -RemoveData folder clean-up. Removes the data root as a link if it is one. Otherwise walks
        and deletes it only when the install sealed it at birth (DataRootSealed under $SealRegPath) and
        it is still the locked, admin-owned folder the tool created. A root without the marker is left
        and reported: it may be a folder an older version locked after a standard user made it, whose
        creator can still hold a handle that lets them change it. Even in a sealed root,
        Remove-CETreeNoFollow checks every folder again just before listing it and leaves any it does
        not trust, so a SYSTEM recursive delete never walks a tree a standard user could change. Leaves
        every EngramicBaseline.untrusted-* quarantine folder beside the data root for an administrator
        to check and delete by hand, because those are user-owned trees SYSTEM must not recurse into;
        only one that is itself a link is removed. In a function so the tests can drive it.
    #>
    param([Parameter(Mandatory)][string]$DataRoot, [Parameter(Mandatory)][string]$ProgramData, [Parameter(Mandatory)][string]$SealRegPath)
    if (Test-Path -LiteralPath $DataRoot) {
        if ([IO.File]::GetAttributes($DataRoot) -band [IO.FileAttributes]::ReparsePoint) {
            if ([IO.File]::GetAttributes($DataRoot) -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete($DataRoot, $false) } else { [IO.File]::Delete($DataRoot) }
            Write-Host "Removed the link at $DataRoot (left what it pointed at alone)"
        }
        elseif (-not (Get-CERegistryString -Path $SealRegPath -Name 'DataRootSealed')) {
            Write-Warning "Not deleting $DataRoot as SYSTEM: this version's install did not create it locked (no DataRootSealed marker), so a standard user may still be able to change it. Check it, then remove it by hand."
        }
        else {
            $problem = Get-CEFolderTrustProblem -Path $DataRoot
            if ($problem) {
                Write-Warning "Not deleting $DataRoot as SYSTEM ($problem). A standard user may control it, so removing it recursively is unsafe. Remove it by hand after checking it."
            }
            elseif (Remove-CETreeNoFollow -Path $DataRoot) { Write-Host "Removed $DataRoot" }
            else { Write-Warning "Removed what could safely be removed from $DataRoot; what is left is listed above. Check it, then remove it by hand." }
        }
    }
    # EngramicBaseline.untrusted-<guid> quarantine folders are BY DESIGN trees a standard user owns and
    # may still hold handles to (that is why they were moved aside). SYSTEM must never recurse into them:
    # a junction swapped in mid-walk would redirect the delete outside the folder. Remove one only if it
    # is itself a link; otherwise leave it for an administrator to check and delete.
    foreach ($aside in @(Get-ChildItem -LiteralPath $ProgramData -Directory -Force -Filter 'EngramicBaseline.untrusted-*' -ErrorAction SilentlyContinue)) {
        if ((Get-Item -LiteralPath $aside.FullName -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            [IO.Directory]::Delete($aside.FullName, $false)
            Write-Host "Removed the link $($aside.FullName)"
        }
        else {
            Write-Warning "Left the quarantine folder $($aside.FullName) in place for an administrator to check and delete by hand (it holds a tree a standard user may own)."
        }
    }
}

$regPath = 'HKLM:\SOFTWARE\EngramicBaseline'
# The sealed-at-birth marker (written by the installer) lives in a separate key. Removing it is what
# lets a later install move the data folder aside, so it is deleted only under -RemoveData; a plain
# uninstall leaves it, so a reinstall keeps the data folder (config overrides, packs, reports) in place.
$sealRegPath = 'HKLM:\SOFTWARE\EngramicBaseline.DataRoot'
$dataRoot = Join-Path $env:ProgramData 'EngramicBaseline'
$installPath = Join-Path $env:ProgramFiles 'EngramicBaseline'
if (Test-Path $regPath) {
    $saved = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).InstallPath
    if ($saved) { $installPath = $saved }
}

$exit = 0
try {
    $task = Get-ScheduledTask -TaskPath '\EngramicBaseline\' -ErrorAction SilentlyContinue
    if ($task) {
        $task | Stop-ScheduledTask -ErrorAction SilentlyContinue
        $task | Unregister-ScheduledTask -Confirm:$false
        Write-Host 'Removed scheduled task'
    }
    try {
        $svc = New-Object -ComObject 'Schedule.Service'
        $svc.Connect()
        $svc.GetFolder('\').DeleteFolder('EngramicBaseline', 0)
    }
    catch {
        Write-Verbose "Task folder not removed: $_"
    }

    $lnk = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Engramic Baseline.lnk'
    Remove-Item -LiteralPath $lnk -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $installPath) {
        Remove-Item -LiteralPath $installPath -Recurse -Force
        Write-Host "Removed $installPath"
    }
    Remove-Item -LiteralPath "$installPath.staging" -Recurse -Force -ErrorAction SilentlyContinue

    # Remove the source by deleting its registry key directly.
    # [Diagnostics.EventLog]::DeleteEventSource calls SourceExists, which
    # enumerates every event log and throws when Security/State are inaccessible
    # (hosted CI runners, restricted images); the install registers it the same
    # registry-only way.
    Remove-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\EngramicBaseline' -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue

    if ($RemoveData) {
        Remove-CEDataFolders -DataRoot $dataRoot -ProgramData $env:ProgramData -SealRegPath $sealRegPath
        # The data has been removed (or is being left for an admin), so drop the sealed-at-birth marker:
        # a fresh install then starts clean.
        Remove-Item -Path $sealRegPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host 'Uninstalled.'
}
catch {
    Write-Error "Uninstall failed: $($_.Exception.Message)" -ErrorAction Continue
    $exit = 1
}
exit $exit
