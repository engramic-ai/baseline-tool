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

function Move-CEDataItemAside {
    <#
        Renames a file or folder out of the data root to a quarantine sibling (<path>.untrusted-<guid>)
        without opening its contents or following a link, so nothing later reads it. Retries a few
        times with a short back-off: an old-version audit, an admin with a report open, or any process
        with a handle in the tree can make the first [IO.Directory]::Move fail with a sharing violation,
        and Intune would then just report the install failed with no hint why. Returns the new path;
        throws with a clear reason if every attempt fails.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    $aside = '{0}.untrusted-{1}' -f $Path, [guid]::NewGuid().ToString('n')
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
    throw "Could not move $Path aside to $aside - a process may have a file or folder open under the data folder ($($lastErr.Exception.Message)). Close it and try again."
}

function Initialize-CEDataFolder {
    <#
        Creates a machine data folder the same way the installer does, so a data root is never born
        user-writable even when an elevated audit (the GUI, Invoke-CEAudit or the scheduled audit)
        runs before the installer. Non-elevated or non-Windows callers only affect their own user and
        their data lives in their own profile, so they get a plain folder. An elevated caller on
        Windows gets the folder with its locked, administrator-owned descriptor applied in the one
        call that makes it, then VERIFIES the result and never repairs it: anything already in its
        place that a standard user made, took over or could write - or a link - is moved aside and the
        create retried, never written into or taken back in place (its creator may hold a handle that
        kept add-file or WRITE_DAC access after any later lock). An existing folder that is trusted -
        admin-owned, not a link, with no non-admin write, delete, DAC or owner right and no deny
        against a trusted SID - is kept, so status.json and reports survive; a benign read-only ACE an
        administrator added does not force it aside. Returns the path.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path, [switch]$UsersRead)
    if (-not (Test-CEIsWindows) -or -not (Test-CEIsAdmin)) {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
        return $Path
    }
    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        if (Test-CEReparsePoint -Path $Path) {
            if ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete($Path, $false) } else { [IO.File]::Delete($Path) }
            continue
        }
        if (Test-Path -LiteralPath $Path) {
            if (-not (Get-CELockedFolderProblem -Path $Path)) { return $Path }
            $aside = Move-CEDataItemAside -Path $Path
            Write-Warning "Moved an untrusted $Path aside to $aside and will make a fresh, locked one."
            continue
        }
        $security = New-CELockedDirectorySecurity -UsersRead:$UsersRead
        if ($PSVersionTable.PSVersion.Major -ge 6) { [void][IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path), $security) }
        else { [void][IO.Directory]::CreateDirectory($Path, $security) }
        # Verify what is now on disk; never repair it. A silent no-op over a pre-existing folder is
        # rejected here (wrong owner, or a non-admin write/DAC/owner right) instead of being re-owned in place.
        if (-not (Get-CELockedFolderProblem -Path $Path)) { return $Path }
        if (Test-Path -LiteralPath $Path) { Move-CEDataItemAside -Path $Path | Out-Null }
    }
    throw "Could not create a locked, administrator-owned data folder at $Path."
}

function Remove-CEDataTree {
    <#
        Deletes a folder and everything in it without ever following a junction or symbolic link: each
        link is removed as a link, each real subfolder is recursed into, each file is deleted. Used for
        SYSTEM deletes under the data folder (report and log housekeeping). Remove-Item -Recurse is not
        used because Windows PowerShell 5.1 follows links and would empty what they point at.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (Test-CEReparsePoint -Path $Path) {
        if ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete($Path, $false) } else { [IO.File]::Delete($Path) }
        return
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { [IO.File]::Delete($Path); return }
    foreach ($child in @([IO.Directory]::GetFileSystemEntries($Path))) {
        $attrs = $null
        try { $attrs = [IO.File]::GetAttributes($child) } catch { continue }
        if ($attrs -band [IO.FileAttributes]::ReparsePoint) {
            if ($attrs -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete($child, $false) } else { [IO.File]::Delete($child) }
        }
        elseif ($attrs -band [IO.FileAttributes]::Directory) { Remove-CEDataTree -Path $child }
        else { [IO.File]::Delete($child) }
    }
    [IO.Directory]::Delete($Path, $false)
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

function Get-CEInstalledSoftware {
    <#
        Installed programs from the uninstall registry keys (machine + current user).
        Deliberately avoids Win32_Product, which triggers MSI self-repair.
    #>
    [CmdletBinding()]
    param()
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    # Per-user installs for the signed-in user (their hive when running as SYSTEM).
    $userRoot = Get-CEUserRegistryRoot
    if ($userRoot) { $paths += "$userRoot\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" }
    $items = foreach ($p in $paths) {
        Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
            Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -and -not ($_.PSObject.Properties['SystemComponent'] -and $_.SystemComponent -eq 1) } |
            ForEach-Object {
                [pscustomobject]@{
                    Name        = [string]$_.DisplayName
                    Version     = if ($_.PSObject.Properties['DisplayVersion']) { [string]$_.DisplayVersion } else { '' }
                    Publisher   = if ($_.PSObject.Properties['Publisher']) { [string]$_.Publisher } else { '' }
                    InstallDate = if ($_.PSObject.Properties['InstallDate']) { [string]$_.InstallDate } else { '' }
                    KeyName     = [string]$_.PSChildName
                }
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
