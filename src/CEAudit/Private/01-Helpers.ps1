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
    $overrideDir = Join-Path (Get-CEDataRoot) 'config'
    if ((Test-Path -LiteralPath $overrideDir) -and ($overrideDir -ne $ConfigPath)) {
        # An elevated audit must not load overrides a standard user could have planted.
        if (Test-CEDataPathTrusted -Path $overrideDir) { $folders += $overrideDir }
        else { Write-Warning "Ignoring config overrides in $overrideDir : standard users can change it." }
    }

    $config = @{}
    foreach ($folder in $folders) {
        foreach ($file in (Get-ChildItem -Path $folder -Filter '*.json' -ErrorAction SilentlyContinue)) {
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
