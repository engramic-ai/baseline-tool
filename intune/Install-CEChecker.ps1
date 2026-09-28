#Requires -Version 5.1
<#
.SYNOPSIS
    Installs Engramic Baseline machine-wide. Built to run as the
    install command of an Intune Win32 app, and also runnable by hand.

.DESCRIPTION
    - Copies the tool to Program Files, locked down so only administrators and
      SYSTEM can change it (the scheduled task runs these scripts as SYSTEM)
    - Creates %ProgramData%\EngramicBaseline for status, reports and logs
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
$taskPath = '\EngramicBaseline\'
$taskName = 'Audit'
$userTaskName = 'User probe'

$log = Join-Path $dataRoot ("logs\install-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
# Native tools by full path, never through PATH.
$system32 = [Environment]::GetFolderPath('System')
$icacls = Join-Path $system32 'icacls.exe'
$takeown = Join-Path $system32 'takeown.exe'
# SYSTEM, Administrators, TrustedInstaller.
$trustedOwners = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
# Rights that let someone change, delete or re-permission a file or folder, including GENERIC_WRITE and GENERIC_ALL.
$writeRights = 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288 -bor 0x40000000 -bor 0x10000000
# The folders the tool keeps in the data folder; the install deletes any other folder a user made there.
$dataFolders = @('logs', 'reports', 'config', 'cache', 'packs')

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

function Reset-CEFolderOwner {
    <#
        Makes Administrators the owner of a folder (not its contents) and drops any permission
        set on the folder itself, so it only inherits from its parent. A standard user who created
        the folder first keeps no control over it. Files inside keep their owner, which is how an
        elevated audit recognises ones a user planted (Get-CEConfig refuses them).
    #>
    param([string]$Path)
    & $takeown /F $Path /A | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "takeown failed on $Path (exit $LASTEXITCODE)" }
    & $icacls $Path /reset /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path (exit $LASTEXITCODE)" }
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
        junction in %ProgramData% without any special right; takeown and icacls would then lock the
        link while the audit's output went to a folder the user owns. Remove-Item -Recurse is not
        used: Windows PowerShell 5.1 follows links and would empty the target.
    #>
    param([string]$Path)
    Write-Warning "$Path is a link (junction or symbolic link), not a folder. A standard user may have made it to redirect the audit's data, so the link is removed; what it points at is left alone."
    if ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete($Path, $false) }
    else { [IO.File]::Delete($Path) }
    if (Test-CEReparsePoint -Path $Path) { throw "Could not remove the link at $Path" }
}

function Get-CEItemTrustProblem {
    <#
        Why a file or folder in the data folder might be under a standard user's control, or '' when
        it isn't: it is owned by someone other than SYSTEM, Administrators or TrustedInstaller, or its
        permissions let anyone else change, delete or re-permission it. The owner alone is not enough:
        a hard link, or a file a user moved in, keeps an administrator owner while the user can still
        write to it (every profile has such files, such as ntuser.ini).
    #>
    param([string]$Path)
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $Path } catch { return "the permissions of $Path could not be read" }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($trustedOwners -notcontains $owner) { return "$Path is owned by $owner, not an administrator" }
    foreach ($rule in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        if ("$($rule.AccessControlType)" -ne 'Allow') { continue }
        $sid = "$($rule.IdentityReference)"
        # CREATOR OWNER only applies to new items, which only administrators can create in a locked folder.
        if ($trustedOwners -contains $sid -or $sid -eq 'S-1-3-0') { continue }
        $rights = [long]0
        try { $rights = [long]$rule.FileSystemRights } catch { $rights = [long]::MaxValue }
        if ($rights -band $writeRights) { return "$Path can be changed by $sid, not only administrators" }
    }
    return ''
}

function Assert-CEInDataRoot {
    <#
        Throws unless a path is the data folder or inside it, and neither it nor any folder between
        it and the data folder is a link. A link anywhere on the way would make every step after it
        act on the folder it points at: Test-CEReparsePoint only reads the last part of a path.
    #>
    param([string]$Path, [string]$Root)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $current = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not ($current -eq $rootFull -or $current.StartsWith("$rootFull\", [StringComparison]::OrdinalIgnoreCase))) {
        throw "$Path is not in the data folder $Root"
    }
    while ($true) {
        if (Test-CEReparsePoint -Path $current) { throw "$current is a link (junction or symbolic link); a standard user may be interfering with the install." }
        if ($current.Length -le $rootFull.Length) { break }
        $current = Split-Path -Parent $current
    }
}

function Remove-CEPlantedFile {
    <# Deletes a file a user left in the data folder. Deleting a hard link removes only that name. #>
    param([string]$Path)
    try { Remove-Item -LiteralPath $Path -Force }
    catch {
        # The owner may have denied administrators access: take it back, then delete it.
        & $takeown /F $Path /A | Out-Null
        & $icacls $Path /reset /Q | Out-Null
        Remove-Item -LiteralPath $Path -Force
    }
}

function Remove-CEFolderTree {
    <#
        Deletes a folder a standard user made, and everything in it, without following links. Each
        link is removed as a link, and each folder is taken back before it is listed, so the user can
        no longer add to it, or put a link in place of anything in it, while it is emptied. Remove-Item
        -Recurse is not used: Windows PowerShell 5.1 follows links and would empty what they point at.
    #>
    param([string]$Path)
    if (Test-CEReparsePoint -Path $Path) { Remove-CELink -Path $Path; return }
    Reset-CEFolderOwner -Path $Path
    if (Test-CEReparsePoint -Path $Path) { throw "$Path became a link while it was being taken back; a standard user may be interfering with the install." }
    foreach ($child in @([IO.Directory]::GetFileSystemEntries($Path))) {
        $attributes = $null
        # Gone already: the user moved it out, which they can still do but can't undo.
        try { $attributes = [IO.File]::GetAttributes($child) } catch { continue }
        if ($attributes -band [IO.FileAttributes]::ReparsePoint) { Remove-CELink -Path $child }
        elseif ($attributes -band [IO.FileAttributes]::Directory) { Remove-CEFolderTree -Path $child }
        else { Remove-CEPlantedFile -Path $child }
    }
    [IO.Directory]::Delete($Path, $false)
}

function Repair-CEDataFolder {
    <#
        Takes back what a standard user left in a data folder before the install locked it: removes
        links and deletes files and folders that anyone but administrators owns or can change (the
        audit writes them again). The folders named in -KeepFolders are taken back instead, and are
        repaired on their own. An item keeps the owner who created it even in a locked folder, and an
        owner can always change its permissions, so a user-owned status.json would stay forgeable.
        -WarnOnly (config overrides and packs) removes links and only warns about the rest: audits
        running as administrator or SYSTEM already ignore those.
        Refuses to run through a link, and on anything outside -Root, the data folder.
    #>
    param([string]$Path, [string]$Root, [switch]$WarnOnly, [string[]]$KeepFolders = @())
    Assert-CEInDataRoot -Path $Path -Root $Root
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    $prefix = [IO.Path]::GetFullPath($Path).TrimEnd('\') + '\'
    foreach ($item in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)) {
        $full = $item.FullName
        if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "$full is not in $Path" }
        if (Test-CEReparsePoint -Path $full) { Remove-CELink -Path $full; continue }
        $problem = Get-CEItemTrustProblem -Path $full
        if (-not $problem) { continue }
        if ($WarnOnly) {
            Write-Warning "$problem, so audits running as administrator or SYSTEM ignore it. Check it, then save it again as administrator or delete it."
        }
        elseif ($item.PSIsContainer -and $KeepFolders -contains $item.Name) {
            Write-Warning "$problem. Taking the folder back; what a user left in it is dealt with next."
            Reset-CEFolderOwner -Path $full
        }
        elseif ($item.PSIsContainer) {
            Write-Warning "Deleting the folder $full, which a standard user may have left in the data folder ($problem)."
            Remove-CEFolderTree -Path $full
        }
        else {
            Write-Warning "Deleting $full, which a standard user may have left in the data folder ($problem)."
            Remove-CEPlantedFile -Path $full
        }
    }
}

function Initialize-CEDataRoot {
    <#
        Makes the data folder and locks it. A folder that anyone but administrators owns or can change
        is moved aside, never taken back in place: its owner could swap it for a junction while it was
        being locked, and every step after that would act on wherever the junction led. A folder this
        install makes can't be renamed or deleted by standard users. Checks again once it is locked,
        after which only administrators can rename or replace it.
    #>
    param([string]$Path)
    if (Test-CEReparsePoint -Path $Path) { Remove-CELink -Path $Path }
    if (Test-Path -LiteralPath $Path) {
        $problem = if (Test-Path -LiteralPath $Path -PathType Container) { Get-CEItemTrustProblem -Path $Path } else { "$Path is a file" }
        if ($problem) {
            $aside = '{0}.untrusted-{1}' -f $Path, [guid]::NewGuid().ToString('n')
            Write-Warning "$problem, so a standard user may have made it. Moving it to $aside and making a new data folder; check what is in it, then delete it."
            # Renames the item itself (a link too), and never opens what is inside.
            if ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::Directory) { [IO.Directory]::Move($Path, $aside) }
            else { [IO.File]::Move($Path, $aside) }
        }
    }
    # No -Force: if a user made the folder again since, this fails rather than use theirs.
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
    Reset-CEFolderOwner -Path $Path
    Set-CELockedAcl -Path $Path
    if (Test-CEReparsePoint -Path $Path) {
        Remove-CELink -Path $Path
        throw "$Path became a link while it was being locked; a standard user may be interfering with the install."
    }
    $problem = Get-CEItemTrustProblem -Path $Path
    if ($problem) { throw "$problem after it was locked; a standard user may be interfering with the install." }
}

try {
    # --- Data folder: lock it before anything is written there -------------
    # %ProgramData% lets standard users create files and folders, and the data
    # folder holds config overrides that the SYSTEM audit trusts. Lock it before
    # creating anything inside. A link a user planted there (a junction needs no
    # special right) is removed, and a folder a user made is moved aside rather than
    # taken back (Initialize-CEDataRoot says why).
    Initialize-CEDataRoot -Path $dataRoot
    # Only administrators can add to the data folder from here on.
    foreach ($name in @('logs', 'reports', 'config')) {
        $d = Join-Path $dataRoot $name
        if (Test-CEReparsePoint -Path $d) { Remove-CELink -Path $d }
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        Reset-CEFolderOwner -Path $d
    }
    # Users may read config overrides (the desktop app uses them); status and reports stay admin-only.
    & $icacls (Join-Path $dataRoot 'config') /grant '*S-1-5-32-545:(OI)(CI)RX' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on the config folder (exit $LASTEXITCODE)" }
    # Log only once the data folder is locked, so no one else can read or plant the log.
    Start-Transcript -LiteralPath $log | Out-Null
    $transcribing = $true
    # Then take back what a user left there: status.json (which Intune reads), cache, packs and the rest.
    Repair-CEDataFolder -Path $dataRoot -Root $dataRoot -KeepFolders $dataFolders
    foreach ($name in @('logs', 'reports', 'cache')) { Repair-CEDataFolder -Path (Join-Path $dataRoot $name) -Root $dataRoot }
    foreach ($name in @('config', 'packs')) { Repair-CEDataFolder -Path (Join-Path $dataRoot $name) -Root $dataRoot -WarnOnly }

    $manifest = Import-PowerShellDataFile -Path (Join-Path $packageRoot 'src\CEAudit\CEAudit.psd1')
    $version = [string]$manifest.ModuleVersion

    # --- Never downgrade -----------------------------------------------------
    # An older package still assigned (say, to All Devices while a newer one goes to a pilot
    # group) must not put its version back over a newer install.
    $installedVersion = ''
    $installedItem = Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue
    if ($installedItem -and $installedItem.PSObject.Properties['Version']) { $installedVersion = [string]$installedItem.Version }
    if (-not $AllowDowngrade -and (Test-CENewerInstalled -Installed $installedVersion -Package $version)) {
        Write-Warning "Engramic Baseline $installedVersion is installed, which is newer than this package ($version), so it is left as it is. Run with -AllowDowngrade to install $version over it."
        exit 0
    }
    Write-Host "Installing Engramic Baseline $version to $InstallPath"

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

    # Don't upgrade underneath a running audit.
    $running = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
    if ($running -and $running.State -eq 'Running') { $running | Stop-ScheduledTask -ErrorAction SilentlyContinue }

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

    # --- Event log source ----------------------------------------------------
    # Register the source by writing its registry key directly. The managed
    # [Diagnostics.EventLog]::CreateEventSource calls SourceExists, which
    # enumerates every event log and throws when Security/State are inaccessible
    # (hosted CI runners, restricted images) - so the source was never created
    # and the audit's event was silently dropped. Creating the key is all that
    # RegisterEventSource (used by the audit) needs; the full message text still
    # shows in Event Viewer as the event's insertion string.
    $sourceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\EngramicBaseline'
    if (-not (Test-Path -LiteralPath $sourceKey)) {
        New-Item -Path $sourceKey -Force | Out-Null
        New-ItemProperty -Path $sourceKey -Name 'EventMessageFile' -PropertyType ExpandString -Value '%SystemRoot%\System32\EventCreate.exe' -Force | Out-Null
        New-ItemProperty -Path $sourceKey -Name 'TypesSupported' -PropertyType DWord -Value 7 -Force | Out-Null
        Write-Host 'Registered event log source EngramicBaseline'
    }

    # --- Scheduled task ------------------------------------------------------
    if (-not $NoScheduledTask) {
        $ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $script = Join-Path $InstallPath 'app\Invoke-CEScheduledAudit.ps1'
        $action = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`"" -WorkingDirectory $dataRoot
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
    $exit = 1
}
finally {
    if ($transcribing) { Stop-Transcript | Out-Null }
}
exit $exit
