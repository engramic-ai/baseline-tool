# ---------------------------------------------------------------------------
# AI assistants and agents on the device (config/ai-tools.json), used by
# UA-07 (MFA on their accounts), SC-09 (agents as remote access), SC-14 (whether
# the organisation has approved them) and UA-10 (agents running with
# administrator rights). Read-only: installed programs, the user's Store
# packages, profile folders, VS Code extensions, the names of browser extension
# folders in the user's browser profiles (no file there is opened) and processes.
# ---------------------------------------------------------------------------

function Get-CEAIToolSignal {
    <#
        How to detect a catalog tool on Windows: its 'windows' block, or $null when it has none (a
        tool that only runs elsewhere). An override written before signals were grouped by operating
        system keeps them at the top level; those are read as the Windows signals.
    #>
    param($Tool)
    $block = Get-CEObjectValue $Tool 'windows'
    if ($null -ne $block) { return $block }
    foreach ($name in 'programs', 'uninstallKeys', 'appx', 'processes', 'paths', 'vscodeExtensions', 'mcpConfigs') {
        if ($null -ne $Tool.PSObject.Properties[$name]) { return $Tool }
    }
    return $null
}

function Get-CEAIToolCatalog {
    <#
        Catalog tools looked for on Windows, each with its Windows signals as .Signals. A tool found
        only by its browser extensions (shared by every operating system) has an empty .Signals.
        enabled: false in the windows block turns off every Windows signal, extensions included.
    #>
    $out = New-Object System.Collections.ArrayList
    foreach ($t in @(Get-CEObjectValue (Get-CEConfig).'ai-tools' 'tools' @())) {
        $signals = Get-CEAIToolSignal -Tool $t
        if ($null -eq $signals) {
            if (@(Get-CEObjectValue $t 'browserExtensions' @()).Count -eq 0) { continue }
            $signals = [pscustomobject]@{}
        }
        elseif ((Get-CEObjectValue $signals 'enabled' $true) -eq $false) { continue }
        [void]$out.Add([pscustomobject]@{ Tool = $t; Signals = $signals })
    }
    return , $out.ToArray()
}

function Get-CEVsCodeBuiltInExtensionDir {
    <#
        Folders holding the extensions VS Code ships with (Copilot Chat since 1.13x). The user
        installer puts them under the profile; the machine installer, which winget picks when
        elevated, under Program Files. Only folders that exist are returned; under the profile,
        only those reached through plain folders (no junctions or symbolic links). Tests mock this.
    #>
    param([string]$ProfilePath)
    $dirs = @()
    # The user's own install: through plain folders only, since the user controls their profile.
    if ($ProfilePath -and (Test-CELocalFilePath $ProfilePath)) {
        foreach ($name in 'Microsoft VS Code', 'Microsoft VS Code Insiders') {
            $rel = "AppData\Local\Programs\$name"
            if (-not (Test-CEPlainDirectoryChain -Base $ProfilePath -Relative $rel)) { continue }
            $install = Join-Path $ProfilePath $rel
            $subs = Get-CEPlainChildName -Path $install -Max 64   # assign first: it returns ,array
            foreach ($sub in @('resources\app\extensions') + @($subs | ForEach-Object { "$_\resources\app\extensions" })) {
                if (Test-CEPlainDirectoryChain -Base $install -Relative $sub) { $dirs += Join-Path $install $sub }
            }
        }
    }
    $installs = @()
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)} | Where-Object { $_ })) {
        $installs += @('Microsoft VS Code', 'Microsoft VS Code Insiders' | ForEach-Object { Join-Path $root $_ })
    }
    foreach ($install in ($installs | Where-Object { Test-Path -LiteralPath $_ })) {
        # Older layouts: <install>\resources\app\extensions. Since 1.13x the app lives in a
        # commit-hash subfolder: <install>\<hash>\resources\app\extensions.
        $candidates = @((Join-Path $install 'resources\app\extensions'))
        $candidates += @(Get-ChildItem -LiteralPath $install -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'resources\app\extensions' })
        $dirs += @($candidates | Where-Object { Test-Path -LiteralPath $_ })
    }
    return , @($dirs)
}

function Get-CEVsCodeBuiltInExtensionId {
    <#
        Identity of a built-in extension folder: publisher.name from its package.json (the folder
        itself is just "copilot" for GitHub Copilot Chat), falling back to the folder name.
    #>
    param([Parameter(Mandatory)][string]$Folder)
    $pkg = Join-Path $Folder 'package.json'
    if (Test-Path -LiteralPath $pkg) {
        try {
            $j = Get-Content -LiteralPath $pkg -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $publisher = [string](Get-CEObjectValue $j 'publisher' '')
            $name = [string](Get-CEObjectValue $j 'name' '')
            if ($publisher -and $name) { return "$publisher.$name".ToLowerInvariant() }
        }
        catch { Write-Verbose "Could not read $pkg`: $($_.Exception.Message)" }
    }
    return (Split-Path -Leaf $Folder).ToLowerInvariant()
}

function Get-CEStorePackageName {
    <# Store (MSIX) package names installed for the signed-in user, from their registry hive. #>
    $root = Get-CEUserRegistryRoot
    if (-not $root) { return ,@() }
    $key = "$root\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
    $names = @(Get-ChildItem -Path $key -ErrorAction SilentlyContinue | ForEach-Object { ($_.PSChildName -split '_')[0] } | Sort-Object -Unique)
    return ,$names
}

function Get-CEProcessList {
    <# Running processes with path and command line (blank when they can't be read, e.g. elevated processes in a non-elevated audit). #>
    try {
        $list = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name        = [string]$_.Name
                ProcessId   = [int]$_.ProcessId
                Path        = [string](Get-CEObjectValue $_ 'ExecutablePath' '')
                CommandLine = [string](Get-CEObjectValue $_ 'CommandLine' '')
                Cim         = $_
            }
        })
        return ,$list
    }
    catch { return ,@() }
}

function Get-CEProcessOwner {
    param($Process)
    try {
        $o = Invoke-CimMethod -InputObject $Process.Cim -MethodName GetOwner -ErrorAction Stop
        if ($o.User) { return "$($o.Domain)\$($o.User)" }
    }
    catch { Write-Verbose "Owner of $($Process.ProcessId) not readable: $_" }
    return ''
}

function Get-CEProcessElevation {
    <#
        1 when the process token is elevated, 0 when it isn't, -1 when it can't be read.
        Reads the token with query-only access (PROCESS_QUERY_LIMITED_INFORMATION, TOKEN_QUERY).
    #>
    param([Parameter(Mandatory)][int]$ProcessId)
    if (-not (Test-CEIsWindows)) { return -1 }
    try {
        if (-not ('CEAudit.TokenElevation' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CEAudit {
    public static class TokenElevation {
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int processId);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int infoClass, out int info, int length, out int returned);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        public static int IsElevated(int processId) {
            IntPtr process = OpenProcess(0x1000, false, processId);
            if (process == IntPtr.Zero) { return -1; }
            try {
                IntPtr token;
                if (!OpenProcessToken(process, 0x0008, out token)) { return -1; }
                try {
                    int elevated; int returned;
                    if (!GetTokenInformation(token, 20, out elevated, 4, out returned)) { return -1; }
                    return elevated != 0 ? 1 : 0;
                }
                finally { CloseHandle(token); }
            }
            finally { CloseHandle(process); }
        }
    }
}
'@ -ErrorAction Stop
        }
        return [CEAudit.TokenElevation]::IsElevated($ProcessId)
    }
    catch {
        Write-Verbose "Could not check elevation of $ProcessId : $_"
        return -1
    }
}

function Get-CEAIToolState {
    <# AI tools found on this device, gathered once per audit. #>
    param($Context)
    $cacheKey = "$($Context.ComputerName)|$($Context.AuditTime.Ticks)|$($Context.IsElevated)"
    if ($script:CEAIToolCache -and $script:CEAIToolCache.Key -eq $cacheKey) { return $script:CEAIToolCache.State }
    $state = Get-CEAIToolStateUncached -Context $Context
    $script:CEAIToolCache = @{ Key = $cacheKey; State = $state }
    return $state
}

function Get-CEAIToolStateUncached {
    param($Context)
    $catalog = Get-CEAIToolCatalog   # assign first: it returns ,array
    $software = @(Get-CEInstalledSoftware)
    $store = Get-CEStorePackageName
    $profilePath = Get-CEUserProfilePath -Context $Context
    $extensions = @()
    $builtIn = @()
    if ($profilePath -and (Test-CELocalFilePath $profilePath)) {
        foreach ($folder in '.vscode\extensions', '.vscode-insiders\extensions') {
            # Only through plain folders: the profile belongs to the user, and a SYSTEM audit must not follow their links.
            if (-not (Test-CEPlainDirectoryChain -Base $profilePath -Relative $folder)) { continue }
            # Names only: listing a folder does not go into its children.
            $extensions += @(Get-ChildItem -LiteralPath (Join-Path $profilePath $folder) -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        }
    }
    # Extensions VS Code ships with (Copilot Chat since 1.13x) live under the install, not the user's
    # extensions folder, in unversioned directories such as github.copilot-chat.
    $builtInDirs = Get-CEVsCodeBuiltInExtensionDir -ProfilePath $profilePath   # assign first: it returns ,array and @(...) would nest it
    foreach ($folder in $builtInDirs) {
        $builtIn += @(Get-ChildItem -LiteralPath $folder -Directory -ErrorAction SilentlyContinue |
            Where-Object { ([int]($_.Attributes -band [IO.FileAttributes]::ReparsePoint)) -eq 0 } |
            ForEach-Object { Get-CEVsCodeBuiltInExtensionId -Folder $_.FullName })
    }
    # AI browser extensions: folder and file names in the user's browser profiles, only for ids in the catalog.
    $extIds = Get-CEBrowserExtensionIdSet -Catalog $catalog
    $browserExt = Get-CEBrowserExtensionList -ProfilePath $profilePath -ChromiumIds $extIds.Chromium -FirefoxIds $extIds.Firefox   # assign first: it returns ,array
    $processes = Get-CEProcessList
    $like = { param($value, $pattern) (-not $pattern) -or ("$value" -like $pattern) }
    $programText = { param($sw) if ($sw.Version -and $sw.Name -notlike "*$($sw.Version)*") { "Installed program: $($sw.Name) $($sw.Version)" } else { "Installed program: $($sw.Name)" } }

    $tools = New-Object System.Collections.ArrayList
    $claimed = @{}
    foreach ($entry in $catalog) {
        $t = $entry.Tool
        $w = $entry.Signals
        $signals = @()
        $extAll = @()
        foreach ($p in @(Get-CEObjectValue $w 'programs' @())) {
            $signals += @($software | Where-Object { $_.Name -like [string]$p.name -and (& $like $_.Publisher ([string](Get-CEObjectValue $p 'publisher' ''))) } |
                ForEach-Object { & $programText $_ })
        }
        $keys = @(Get-CEObjectValue $w 'uninstallKeys' @())
        if ($keys.Count) { $signals += @($software | Where-Object { $keys -contains $_.KeyName } | ForEach-Object { & $programText $_ }) }
        foreach ($a in @(Get-CEObjectValue $w 'appx' @())) { if ($store -contains $a) { $signals += "Store app: $a" } }
        if ($profilePath) {
            foreach ($rel in @(Get-CEObjectValue $w 'paths' @())) {
                # Attributes only, through plain folders: a link the user made is never followed.
                if (Test-CEPlainProfileItem -ProfilePath $profilePath -Relative $rel) { $signals += "Found %USERPROFILE%\$rel" }
            }
        }
        foreach ($pattern in @(Get-CEObjectValue $w 'vscodeExtensions' @())) {
            $signals += @($extensions | Where-Object { $_ -like $pattern } | ForEach-Object { "VS Code extension: $_" })
            # Built-in folders carry no version suffix; match them as if they had one so patterns like
            # "github.copilot-chat-*" cover both.
            $signals += @($builtIn | Where-Object { $_ -like $pattern -or "$_-builtin" -like $pattern } | ForEach-Object { "VS Code built-in extension: $_" })
        }
        foreach ($ext in @(Get-CEObjectValue $t 'browserExtensions' @())) {
            $extId = [string](Get-CEObjectValue $ext 'id' '')
            if ($extId) { $extAll += @($browserExt | Where-Object { $_.Id -eq $extId }) }
        }
        $signals += @($extAll | ForEach-Object { Format-CEBrowserExtensionEvidence $_ })
        $running = @()
        foreach ($spec in @(Get-CEObjectValue $w 'processes' @())) {
            $pathPattern = [string](Get-CEObjectValue $spec 'path' '')
            $cmdPattern = [string](Get-CEObjectValue $spec 'commandLine' '')
            $image = [string](Get-CEObjectValue $spec 'image' '')
            if (-not $image) { continue }
            foreach ($proc in @($processes | Where-Object { $_.Name -eq $image })) {
                if ($claimed.ContainsKey($proc.ProcessId)) { continue }
                if ($pathPattern -and -not ($proc.Path -and $proc.Path -like $pathPattern)) { continue }
                if ($cmdPattern -and -not ($proc.CommandLine -and $proc.CommandLine -like $cmdPattern)) { continue }
                $claimed[$proc.ProcessId] = $true
                $running += $proc
            }
        }
        # Found only in the profile of a browser that is no longer installed. Counted before duplicates
        # are dropped, so each match stands for one signal.
        $leftoverOnly = ($extAll.Count -gt 0 -and @($extAll | Where-Object { $_.BrowserFound }).Count -eq 0 -and $signals.Count -eq $extAll.Count -and $running.Count -eq 0)
        $signals = @($signals | Select-Object -Unique)
        if ($signals.Count -eq 0 -and $running.Count -eq 0) { continue }
        $canAct = [bool](Get-CEObjectValue $t 'canActOnDevice' $false)
        $procInfo = @($running | ForEach-Object {
            # Owner and token are only needed for agents that can act on the device (UA-10), and are the slow part.
            $owner = if ($canAct) { Get-CEProcessOwner -Process $_ } else { '' }
            $elevation = if ($canAct) { Get-CEProcessElevation -ProcessId $_.ProcessId } else { -1 }
            [pscustomobject]@{
                ProcessId = $_.ProcessId
                Image     = $_.Name
                Path      = $_.Path
                Owner     = $owner
                AsSystem  = ($owner -match '^NT AUTHORITY\\SYSTEM$')
                Elevated  = $(switch ($elevation) { 1 { $true } 0 { $false } default { $null } })
            }
        })
        if ($procInfo.Count) {
            # Agents keep every pid (UA-10 names them). A browser or chat app runs many processes of one
            # image, so those are counted instead.
            $runText = if ($canAct) { @($procInfo | ForEach-Object { "$($_.Image) (pid $($_.ProcessId))" }) }
            else {
                @(foreach ($g in @($procInfo | Group-Object -Property Image)) {
                    if ($g.Count -eq 1) { "$($g.Name) (pid $($g.Group[0].ProcessId))" } else { "$($g.Name) ($($g.Count) processes)" }
                })
            }
            $signals += "Running: $(@($runText) -join ', ')"
        }
        [void]$tools.Add([pscustomobject]@{
            Id             = [string](Get-CEObjectValue $t 'id' '')
            Name           = [string](Get-CEObjectValue $t 'name' '')
            Service        = [string](Get-CEObjectValue $t 'service' '')
            CanActOnDevice = $canAct
            Notes          = [string](Get-CEObjectValue $t 'notes' '')
            Signals        = $signals
            Processes      = $procInfo
            LeftoverOnly   = $leftoverOnly
        })
    }

    # Agent images whose path and command line couldn't be read: they may belong to an agent that can
    # act on the device running elevated or as another user. Only those tools count; browsers and chat
    # apps are not agents UA-10 looks for. node.exe is too common to report this way.
    $agentImages = @($catalog | Where-Object { [bool](Get-CEObjectValue $_.Tool 'canActOnDevice' $false) } |
        ForEach-Object { @(Get-CEObjectValue $_.Signals 'processes' @()) | Where-Object { (Get-CEObjectValue $_ 'path' '') -or (Get-CEObjectValue $_ 'commandLine' '') } | ForEach-Object { [string]$_.image } } |
        Where-Object { $_ -and $_ -ne 'node.exe' } | Sort-Object -Unique)
    $hidden = @($processes | Where-Object { $agentImages -contains $_.Name -and -not $_.Path -and -not $_.CommandLine -and -not $claimed.ContainsKey($_.ProcessId) } |
        ForEach-Object { "$($_.Name) (pid $($_.ProcessId))" })
    return [pscustomobject]@{ Tools = $tools.ToArray(); UninspectedProcesses = $hidden; ProfileChecked = [bool]$profilePath }
}

function Get-CEAiPosture {
    <#
        Per-user AI inventory for user-status.json: which agents are present,
        whether the organisation has approved them (ai-approvals.json), whether
        they are contained, and where they run (WSL, containers). A deviation is
        an agent running as administrator/SYSTEM or a distribution that logs in
        as root; approval is counted separately, since it is a decision rather
        than containment. Read-only; only meaningful in the user's own session
        (Invoke-CEUserProbe.ps1).
    #>
    [CmdletBinding()]
    param($Context)
    if (-not $Context) { $Context = Get-CEDeviceContext }
    $ai = Get-CEAIToolState -Context $Context
    $virt = Get-CEVirtualisationState -Context $Context
    $register = Get-CEAIApprovalRegister
    $today = if ($Context.PSObject.Properties['AuditTime'] -and $Context.AuditTime) { ([datetime]$Context.AuditTime).Date } else { (Get-Date).Date }

    $agents = @(foreach ($t in @($ai.Tools)) {
        $procs = @(Get-CEObjectValue $t 'Processes' @())
        $approval = Get-CEAIApproval -ToolId ([string]$t.Id) -Register $register -Today $today
        [ordered]@{
            id             = [string]$t.Id
            name           = [string]$t.Name
            canActOnDevice = [bool]$t.CanActOnDevice
            running        = ($procs.Count -gt 0)
            elevated       = [bool](@($procs | Where-Object { $_.Elevated -eq $true }).Count)
            asSystem       = [bool](@($procs | Where-Object { $_.AsSystem }).Count)
            approval       = [string]$approval.State
            approvalDetail = [string]$approval.Detail
        }
    })

    $wslEnvs = @(foreach ($d in @($virt.Wsl)) {
        [ordered]@{
            type           = 'wsl'
            name           = [string]$d.Name
            wslVersion     = [int]$d.Version
            running        = $(if ($null -eq $d.Running) { $null } else { [bool]$d.Running })
            autoMount      = $(if ($null -eq $d.Automount) { $null } else { [bool]$d.Automount })
            defaultUidRoot = ([int](Get-CEObjectValue $d 'DefaultUid' 1000) -eq 0)
            networking     = [string]$virt.WslNetworking
        }
    })
    $containerEnvs = @(foreach ($c in @($virt.Containers)) {
        [ordered]@{ type = 'container'; name = [string]$c.Name; image = [string]$c.Image }
    })
    $environments = @($wslEnvs) + @($containerEnvs)

    $mcp = Get-CEMcpInventory -Context $Context
    $plaintext = [int]$mcp.credentialsPlaintext
    # A plaintext credential is a containment failure in its own right, so it folds
    # into deviations; credentialsPlaintext is also exposed on its own so admins can
    # key rules off it deliberately.
    $agentDeviations = @($agents | Where-Object { $_.elevated -or $_.asSystem }).Count + @($wslEnvs | Where-Object { $_.defaultUidRoot }).Count
    $deviations = [int]$agentDeviations + $plaintext

    $countApproval = { param($state) @($agents | Where-Object { $_.approval -eq $state }).Count }

    return [ordered]@{
        agentsFound          = @($agents).Count
        contained            = ([int]$deviations -eq 0)
        deviations           = [int]$deviations
        approved             = & $countApproval 'approved'
        approvalStale        = & $countApproval 'stale'
        unapproved           = & $countApproval 'not-approved'
        unreviewed           = & $countApproval 'unreviewed'
        agents               = $agents
        environments         = $environments
        mcpServers           = @($mcp.mcpServers)
        mcpConfigsFound      = [int]$mcp.mcpConfigsFound
        mcpConfigsParsed     = [int]$mcp.mcpConfigsParsed
        mcpConfigsUnreadable = @($mcp.mcpConfigsUnreadable)
        credentialsFound     = [int]$mcp.credentialsFound
        credentialsPlaintext = $plaintext
        scanBounds           = [string]$mcp.scanBounds
    }
}
