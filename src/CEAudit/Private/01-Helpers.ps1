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

function Get-CEDataRoot {
    <#
        Machine-wide data folder used by the scheduled audit and Intune scripts.
        CE_CHECKER_DATA overrides it (used by tests).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if ($env:CE_CHECKER_DATA) { return $env:CE_CHECKER_DATA }
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

function Get-CEWingetPath {
    <#
        Path to winget.exe, or $null. winget is a per-user app, so it isn't on
        PATH for SYSTEM; in that case use the machine-wide App Installer package.
    #>
    [CmdletBinding()]
    param()
    $cmd = Get-Command 'winget.exe' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    if (-not $env:ProgramFiles) { return $null }
    $pattern = Join-Path $env:ProgramFiles 'WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe'
    $found = @(Resolve-Path -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object { $_.Path } | Sort-Object -Descending)
    if ($found.Count) { return $found[0] }
    return $null
}
