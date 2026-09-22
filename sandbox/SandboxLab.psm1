#Requires -Version 5.1
<#
    SandboxLab: helpers that run INSIDE a disposable Windows Sandbox to bootstrap winget,
    install tools from tools.json, and start or stop them. No dependency on anything else
    in this repository; Engramic Baseline is one consumer of the environments this builds.
#>
Set-StrictMode -Version 2.0

$script:CatalogPath = Join-Path $PSScriptRoot 'tools.json'

function Get-SandboxTool {
    <# Catalogue entries from tools.json; one by -Id, or all. #>
    param([string]$Id)
    $catalog = Get-Content -LiteralPath $script:CatalogPath -Raw | ConvertFrom-Json
    if ($Id) {
        $t = @($catalog.tools | Where-Object { $_.id -eq $Id })
        if ($t.Count -eq 0) { throw "No tool '$Id' in $($script:CatalogPath)" }
        return $t[0]
    }
    return @($catalog.tools)
}

function Get-SandboxField {
    # PSObject property or default, without tripping strict mode.
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($p -and $null -ne $p.Value) { return $p.Value }
    return $Default
}

function Update-SandboxPath {
    <# Pick up PATH entries written by installers without opening a new console. #>
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = (@($machine, $user, $env:Path) | Where-Object { $_ }) -join ';'
}

function Test-SandboxWinget {
    Update-SandboxPath
    return [bool](Get-Command winget.exe -ErrorAction SilentlyContinue)
}

function Install-Winget {
    <#
        Windows Sandbox ships without App Installer. Microsoft's supported bootstrap is the
        Microsoft.WinGet.Client module's Repair-WinGetPackageManager; fall back to installing the
        App Installer bundle and its two dependencies by hand.
    #>
    [CmdletBinding()]
    param()
    if (Test-SandboxWinget) { Write-Host 'winget already present'; return $true }
    Write-Host 'Bootstrapping winget...'
    $ErrorActionPreference = 'Continue'   # see Install-SandboxTool: native stderr must not be terminating
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        # Get-PackageProvider reports a stub even when the real NuGet provider is absent, and Install-Module then
        # prompts to fetch it. Install it unconditionally so nothing asks.
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -Confirm:$false | Out-Null
        Import-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue | Out-Null
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        if (-not (Get-Module -ListAvailable Microsoft.WinGet.Client)) { Install-Module Microsoft.WinGet.Client -Force -Scope CurrentUser -AllowClobber -Confirm:$false }
        Import-Module Microsoft.WinGet.Client
        Repair-WinGetPackageManager -AllUsers -Force -Latest
    }
    catch { Write-Warning "Repair-WinGetPackageManager failed: $($_.Exception.Message). Trying the App Installer bundle." }
    if (-not (Test-SandboxWinget)) {
        $tmp = Join-Path $env:TEMP 'winget-bootstrap'
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        $files = @(
            @{ Url = 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx'; Name = 'vclibs.appx' }
            @{ Url = 'https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx'; Name = 'uixaml.appx' }
            @{ Url = 'https://aka.ms/getwinget'; Name = 'appinstaller.msixbundle' }
        )
        foreach ($f in $files) {
            $dest = Join-Path $tmp $f.Name
            Invoke-WebRequest -Uri $f.Url -OutFile $dest -UseBasicParsing
            Add-AppxPackage -Path $dest -ErrorAction Stop
        }
    }
    # The alias can take a moment to appear after the package registers.
    for ($i = 0; $i -lt 10 -and -not (Test-SandboxWinget); $i++) { Start-Sleep -Seconds 3 }
    if (-not (Test-SandboxWinget)) { throw 'winget is still not available after bootstrap' }
    # First use of the msstore source asks to accept its terms; answer up front, never prompt.
    & winget.exe source update --accept-source-agreements --disable-interactivity | Out-Null
    & winget.exe list --accept-source-agreements --disable-interactivity --count 1 2>&1 | Out-Null
    Write-Host "winget $(& winget.exe --version)"
    return $true
}

function Invoke-SandboxAsStandardUser {
    <#
        Runs a command line under a restricted token (runas /trustlevel:0x20000 - no password), for
        installers whose manifest prohibits elevation. runas returns at once, so the command writes its
        own exit code and output to a scratch folder that this function waits on.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CommandLine, [int]$TimeoutSeconds = 900)
    $dir = Join-Path $env:TEMP ('deelev-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $cmd = Join-Path $dir 'run.cmd'
    $out = Join-Path $dir 'out.txt'
    $exit = Join-Path $dir 'exit.txt'
    Set-Content -LiteralPath $cmd -Value "@echo off`r`n$CommandLine > `"$out`" 2>&1`r`necho %ERRORLEVEL% > `"$exit`"" -Encoding ASCII
    & runas.exe /trustlevel:0x20000 "cmd.exe /c `"$cmd`"" | Out-Null
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path -LiteralPath $exit) -and $sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) { Start-Sleep -Seconds 2 }
    if (-not (Test-Path -LiteralPath $exit)) { return [pscustomobject]@{ ExitCode = -1; Output = "timed out after $TimeoutSeconds s" } }
    Start-Sleep -Seconds 1
    $code = [int]((Get-Content -LiteralPath $exit -Raw).Trim())
    $text = if (Test-Path -LiteralPath $out) { Get-Content -LiteralPath $out -Raw } else { '' }
    return [pscustomobject]@{ ExitCode = $code; Output = $text }
}

function Get-SandboxWingetError {
    # The few winget exit codes a lab is likely to meet, so the summary says what happened in words.
    param([int]$Code)
    switch ($Code) {
        -1978335189 { 'already installed / no applicable update' }
        -1978335212 { 'no package found with that id' }
        -1978335216 { 'no applicable installer for this machine' }
        -1978335215 { 'installer hash mismatch' }
        -1978335224 { 'download failed' }
        -1978335210 { 'multiple packages matched' }
        -1978335173 { 'a source could not be searched (usually msstore); the result was ambiguous' }
        -1978335226 { 'the installer failed' }
        -1978335170 { 'the installer needs a restart' }
        default { "winget exit $Code" }
    }
}

function Install-SandboxTool {
    <#
        Installs one catalogue tool (and its dependsOn first). Returns a result object rather than
        throwing, so a lab run can report per tool: Id, Installed, Method, Message, Seconds.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Id)
    $tool = Get-SandboxTool -Id $Id
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $result = [pscustomobject]@{ Id = $Id; Installed = $false; Method = ''; Message = ''; Seconds = 0 }
    if (Get-SandboxField $tool 'manual' $false) {
        $result.Method = 'manual'; $result.Message = [string](Get-SandboxField $tool 'reason' 'not installable unattended')
        return $result
    }
    if ($env:SANDBOX_ONLINE -eq '0') {
        $result.Method = 'offline'; $result.Message = 'the sandbox has no network'
        return $result
    }
    foreach ($dep in @(Get-SandboxField $tool 'dependsOn' @())) {
        $d = Install-SandboxTool -Id $dep
        if (-not $d.Installed) { $result.Message = "dependency $dep failed: $($d.Message)"; $result.Seconds = [int]$sw.Elapsed.TotalSeconds; return $result }
    }
    $install = Get-SandboxField $tool 'install'
    $type = [string](Get-SandboxField $install 'type' '')
    $result.Method = $type
    # Callers run with ErrorActionPreference = Stop. Under Windows PowerShell 5.1 that turns any stderr line
    # from a native command captured with 2>&1 (a Node deprecation warning, a winget notice) into a
    # terminating error before the exit code can be read. Judge native commands by exit code and output.
    $ErrorActionPreference = 'Continue'
    try {
        switch ($type) {
            'winget' {
                if (-not (Test-SandboxWinget)) { Install-Winget | Out-Null }
                $wgArgs = @('install', '--id', [string]$install.id, '--exact', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
                # Always name the source: with both sources searched, an msstore REST failure (usual inside a
                # sandbox) makes winget refuse an otherwise unambiguous result.
                $source = [string](Get-SandboxField $install 'source' 'winget')
                $wgArgs += @('--source', $source)
                $wgArgs += @(Get-SandboxField $install 'args' @())
                $out = & winget.exe @wgArgs 2>&1 | Out-String
                $code = $LASTEXITCODE
                $log = if ($env:SANDBOX_RESULTS) { Join-Path $env:SANDBOX_RESULTS "install-$Id.log" } else { $null }
                if ($log) { Set-Content -LiteralPath $log -Value $out -Encoding UTF8 }
                if ($code -ne 0 -and $out -match 'administrator context|prohibits elevation|cannot be run from an administrator') {
                    # The package's installer refuses an elevated context (user-scope installers). Retry under a
                    # restricted token.
                    $result.Method = 'winget (as standard user)'
                    $r = Invoke-SandboxAsStandardUser -CommandLine ('winget.exe ' + (($wgArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '))
                    $code = $r.ExitCode
                    if ($log) { Add-Content -LiteralPath $log -Value "`r`n--- retry as standard user ---`r`n$($r.Output)" -Encoding UTF8 }
                    $out = $r.Output
                }
                # 0 = installed, -1978335189 (0x8A15002B) = already installed / no applicable upgrade
                if ($code -ne 0 -and $code -ne -1978335189) { throw "$(Get-SandboxWingetError $code) ($code)" }
            }
            'script' {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                & ([scriptblock]::Create([string]$install.command)) | Out-Null
            }
            'npm' {
                Update-SandboxPath
                $out = & npm.cmd install -g ([string]$install.package) 2>&1 | Out-String
                if ($LASTEXITCODE -ne 0) { throw "npm exit $LASTEXITCODE`: $(($out -split "`n" | Select-Object -Last 2) -join ' ')" }
            }
            'vscode' {
                Update-SandboxPath
                $code = Get-Command code.cmd -ErrorAction SilentlyContinue
                if (-not $code) { $code = Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'Programs\Microsoft VS Code\bin') -Filter code.cmd -ErrorAction SilentlyContinue | Select-Object -First 1 }
                if (-not $code) { throw 'code.cmd not found; is the vscode tool installed?' }
                $codePath = if ($code -is [System.IO.FileInfo]) { $code.FullName } else { $code.Source }
                foreach ($ext in @($install.extensions)) {
                    $out = & $codePath --install-extension $ext --force 2>&1 | Out-String
                    $code = $LASTEXITCODE
                    if ($env:SANDBOX_RESULTS) { Add-Content -LiteralPath (Join-Path $env:SANDBOX_RESULTS "install-$Id.log") -Value "--- code --install-extension $ext (exit $code) ---`r`n$out" -Encoding UTF8 }
                    # VS Code prints Node deprecation warnings on stderr and can exit non-zero after a successful
                    # install; trust its own success line, and report the informative lines when it fails.
                    # Since VS Code 1.13x Copilot Chat ships built in; asking for it (or a dependency pulling it) is
                    # refused as a downgrade. Present is present, so that counts as installed.
                    if ($out -notmatch 'was successfully installed|is already installed|is a built-in extension') {
                        $why = @($out -split "`n" | Where-Object { $_.Trim() -and $_ -notmatch 'DeprecationWarning|Use `node --trace|url.parse|CVEs are not issued' } | Select-Object -Last 3) -join ' '
                        throw "code --install-extension $ext (exit $code): $why"
                    }
                }
            }
            default { throw "unknown install type '$type'" }
        }
        Update-SandboxPath
        $result.Installed = $true
    }
    catch { $result.Message = $_.Exception.Message }
    $result.Seconds = [int]$sw.Elapsed.TotalSeconds
    return $result
}

function Find-SandboxToolExe {
    <# Locate a tool's executable after install: app-execution alias first, then the usual install roots. #>
    param([Parameter(Mandatory)][string]$Name)
    $alias = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\$Name"
    if (Test-Path -LiteralPath $alias) { return $alias }
    # Per-user installers, the Store, npm globals, and vendor CLIs that install under ~\.local\bin (Claude Code).
    $roots = @((Join-Path $env:USERPROFILE '.local\bin'), (Join-Path $env:LOCALAPPDATA 'Programs'), $env:LOCALAPPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path $env:ProgramFiles 'WindowsApps'), (Join-Path $env:APPDATA 'npm'))
    foreach ($root in ($roots | Where-Object { $_ -and (Test-Path -LiteralPath $_) })) {
        $hit = Get-ChildItem -LiteralPath $root -Filter $Name -Recurse -Depth 4 -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

function Start-SandboxTool {
    <# Starts a catalogue tool so its process can be observed. Returns the process, or $null with a warning. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Id, [int]$SettleSeconds = 8)
    $tool = Get-SandboxTool -Id $Id
    $exe = [string](Get-SandboxField $tool 'exe' '')
    if (-not $exe) { Write-Warning "$Id has no exe in the catalogue"; return $null }
    $path = Find-SandboxToolExe -Name $exe
    if (-not $path) { Write-Warning "$Id`: $exe not found after install"; return $null }
    $p = Start-Process -FilePath $path -PassThru -WindowStyle Minimized -ErrorAction Stop
    Start-Sleep -Seconds $SettleSeconds
    return $p
}

function Stop-SandboxTool {
    <# Stops every process running the tool's image (Electron apps fan out into several). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Id)
    $tool = Get-SandboxTool -Id $Id
    $exe = [string](Get-SandboxField $tool 'exe' '')
    if (-not $exe) { return }
    $name = [IO.Path]::GetFileNameWithoutExtension($exe)
    Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

Export-ModuleMember -Function Get-SandboxTool, Install-Winget, Test-SandboxWinget, Install-SandboxTool, Find-SandboxToolExe, Start-SandboxTool, Stop-SandboxTool, Update-SandboxPath, Invoke-SandboxAsStandardUser, Get-SandboxWingetError
