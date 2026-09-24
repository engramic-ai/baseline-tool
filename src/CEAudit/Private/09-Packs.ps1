# ---------------------------------------------------------------------------
# Feature packs: separately installed folders that add checks, remediations,
# categories and config. The module loads them at import (CEAudit.psm1) from:
#   <repo>\packs\*                               next to the module
#   Import-Module -ArgumentList $null, <folders>  development and tests
#   $env:CE_CHECKER_PACKS (path list)             development, ignored when elevated
#   %ProgramData%\EngramicBaseline\packs\*  installed copies
# Audits run elevated or as SYSTEM, so packs under the data folder are refused
# if anyone other than administrators could change them.
#
# pack.json: { "id": "ai-agents", "name": "AI agent coverage", "version": "0.1.0",
#              "minCoreVersion": "0.2.0", "categories": [ { "id": "AIAgents", "label": "AI agents" } ] }
# Folders: Checks\*.ps1, Remediations\*.ps1, config\*.json (all optional).
# ---------------------------------------------------------------------------

# SYSTEM, Administrators, TrustedInstaller.
$script:CETrustedSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
# Rights that let a principal change a file or folder, including GENERIC_WRITE and GENERIC_ALL.
$script:CEWriteRightsMask = 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288 -bor 0x40000000 -bor 0x10000000

function Test-CEAdminOnlyAcl {
    <#
        Returns problems (nothing when fine) for an owner SID and access rules
        (objects with IdentityReference SID, FileSystemRights, AccessControlType).
        Returns a plain list: callers wrap the call in @().
    #>
    param([string]$Owner, [object[]]$Rules, [string]$Path = '')
    $problems = @()
    if ($script:CETrustedSids -notcontains $Owner) { $problems += "$Path is owned by $Owner" }
    foreach ($r in @($Rules)) {
        if ("$($r.AccessControlType)" -ne 'Allow') { continue }
        $sid = "$($r.IdentityReference)"
        # CREATOR OWNER only applies to new items, which need create rights checked here anyway.
        if ($script:CETrustedSids -contains $sid -or $sid -eq 'S-1-3-0') { continue }
        $rights = [long]0
        try { $rights = [long]$r.FileSystemRights } catch { $rights = [long]::MaxValue }
        if ($rights -band $script:CEWriteRightsMask) { $problems += "$Path is writable by $sid" }
    }
    return $problems
}

function Get-CEPathAclProblem {
    <# Problems with the permissions on a file or folder (Windows only). Plain list: wrap the call in @(). #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-CEIsWindows)) { return }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
            [pscustomobject]@{ IdentityReference = $_.IdentityReference.Value; FileSystemRights = [long]$_.FileSystemRights; AccessControlType = "$($_.AccessControlType)" }
        })
        return (Test-CEAdminOnlyAcl -Owner $owner -Rules $rules -Path $Path)
    }
    catch {
        return "$Path permissions could not be read: $($_.Exception.Message)"
    }
}

function Test-CEDataPathTrusted {
    <#
        Whether an elevated audit may read from a data-root path. The risk is the
        predictable default %ProgramData% location, which a standard user could
        pre-create or tamper with before an administrator runs the tool; a forged
        config override or firmware cache there would control the verdict. A
        non-elevated audit can only affect its own user, so it trusts any path.
        There is deliberately no bypass for a moved data folder: an elevated audit
        checks the permissions wherever the folder is.
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-CEIsAdmin)) { return $true }
    return (@(Get-CEPathAclProblem -Path $Path).Count -eq 0)
}

function Get-CEPackSearchPath {
    <#
        Folders that contain pack folders, with whether their permissions must be locked down.
        Folders passed to Import-Module are trusted like the repo's own packs folder: they come
        from the code importing the module. CE_CHECKER_PACKS is ignored when elevated
        (Get-CEEnvironmentHook), since it could come from a standard user's environment.
    #>
    $paths = New-Object System.Collections.ArrayList
    [void]$paths.Add([pscustomobject]@{ Path = (Join-Path $script:RepoRoot 'packs'); RequireLockedAcl = $false })
    $devPaths = @($script:CEPackPathOverride)
    $fromEnv = Get-CEEnvironmentHook -Name 'CE_CHECKER_PACKS'
    if ($fromEnv) { $devPaths += @($fromEnv -split [regex]::Escape([IO.Path]::PathSeparator)) }
    foreach ($p in $devPaths) {
        if ($p) { [void]$paths.Add([pscustomobject]@{ Path = $p; RequireLockedAcl = $false }) }
    }
    [void]$paths.Add([pscustomobject]@{ Path = (Join-Path (Get-CEDataRoot) 'packs'); RequireLockedAcl = $true })
    return ,$paths.ToArray()
}

function Get-CEPackCandidate {
    <#
        Pack folders found on the search path, validated but not loaded.
        Status is Ready, or Skipped with a Reason.
    #>
    $coreConfigNames = @(Get-ChildItem -Path (Join-Path $script:RepoRoot 'config') -Filter '*.json' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name.ToLowerInvariant() })
    $coreVersion = [version](Get-CEToolVersion)
    $seenIds = @{}
    $seenConfig = @{}
    $found = New-Object System.Collections.ArrayList
    # Assign first: the function returns ,@() and looping over the call would give one nested array.
    $searchPaths = Get-CEPackSearchPath
    foreach ($root in $searchPaths) {
        if (-not (Test-Path -LiteralPath $root.Path -PathType Container)) { continue }
        foreach ($dir in @(Get-ChildItem -LiteralPath $root.Path -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $pack = [pscustomobject]@{
                Id = $dir.Name; Name = $dir.Name; Version = ''; Path = $dir.FullName; Status = 'Skipped'; Reason = ''
                Files = @(); ConfigPath = $null; Categories = @(); Checks = @(); Remediations = @()
            }
            [void]$found.Add($pack)
            $manifestPath = Join-Path $dir.FullName 'pack.json'
            if (-not (Test-Path -LiteralPath $manifestPath)) { $pack.Reason = 'No pack.json'; continue }
            try { $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
            catch { $pack.Reason = "pack.json is not valid JSON: $($_.Exception.Message)"; continue }

            $id = [string](Get-CEObjectValue $manifest 'id' '')
            $version = [string](Get-CEObjectValue $manifest 'version' '')
            if ($id -notmatch '^[a-z0-9][a-z0-9-]{1,39}$') { $pack.Reason = "Invalid pack id '$id' (lower-case letters, digits and hyphens)"; continue }
            $pack.Id = $id
            $pack.Name = [string](Get-CEObjectValue $manifest 'name' $id)
            if ($version -notmatch '^\d+\.\d+\.\d+$') { $pack.Reason = "Invalid version '$version' (use major.minor.patch)"; continue }
            $pack.Version = $version
            if ($seenIds.ContainsKey($id)) { $pack.Reason = "Pack '$id' is already loaded from $($seenIds[$id])"; continue }
            $minCore = [string](Get-CEObjectValue $manifest 'minCoreVersion' '')
            if ($minCore) {
                if ($minCore -notmatch '^\d+\.\d+\.\d+$') { $pack.Reason = "Invalid minCoreVersion '$minCore'"; continue }
                if ([version]$minCore -gt $coreVersion) { $pack.Reason = "Needs Engramic Baseline $minCore or later (this is $coreVersion)"; continue }
            }
            $categories = @(@(Get-CEObjectValue $manifest 'categories' @()) | ForEach-Object { [pscustomobject]@{ Id = [string](Get-CEObjectValue $_ 'id' ''); Label = [string](Get-CEObjectValue $_ 'label' '') } })
            $pack.Categories = $categories

            if ($root.RequireLockedAcl) {
                # Also check the parent (%ProgramData%\EngramicBaseline): if a user could write
                # there, they could replace the packs folder itself, so its own ACL isn't enough.
                $parent = Split-Path -Parent $root.Path
                $problems = @(Get-CEPathAclProblem -Path $parent) + @(Get-CEPathAclProblem -Path $root.Path)
                foreach ($item in @(@(Get-Item -LiteralPath $dir.FullName) + @(Get-ChildItem -LiteralPath $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue))) {
                    $problems += @(Get-CEPathAclProblem -Path $item.FullName)
                }
                if ($problems.Count) { $pack.Reason = "Not loaded because non-administrators could change it: $(@($problems | Select-Object -First 3) -join '; ')"; continue }
            }

            $configDir = Join-Path $dir.FullName 'config'
            if (Test-Path -LiteralPath $configDir -PathType Container) {
                $names = @(Get-ChildItem -LiteralPath $configDir -Filter '*.json' -File | ForEach-Object { $_.Name.ToLowerInvariant() })
                $clash = @($names | Where-Object { $coreConfigNames -contains $_ -or $seenConfig.ContainsKey($_) })
                if ($clash.Count) { $pack.Reason = "Config file name already used: $($clash -join ', ')"; continue }
                foreach ($n in $names) { $seenConfig[$n] = $id }
                $pack.ConfigPath = $configDir
            }

            $files = @()
            foreach ($sub in 'Checks', 'Remediations') {
                $subDir = Join-Path $dir.FullName $sub
                if (Test-Path -LiteralPath $subDir -PathType Container) {
                    $files += @(Get-ChildItem -LiteralPath $subDir -Filter '*.ps1' -File | Sort-Object Name | ForEach-Object { $_.FullName })
                }
            }
            $pack.Files = $files
            $seenIds[$id] = $dir.FullName
            $pack.Status = 'Ready'
        }
    }
    return ,$found.ToArray()
}

function Start-CEPackLoad {
    <# Records the module state before a pack's scripts run, and registers its categories and config. #>
    param([Parameter(Mandatory)]$Pack)
    $snapshot = [pscustomobject]@{
        Checks       = @($script:CEChecks | ForEach-Object { $_.Id })
        Remediations = @($script:CERemediations.Keys)
        Categories   = @($script:CEValidCategory)
        Functions    = @{}
    }
    foreach ($name in $script:CECoreFunctionNames) {
        $fn = Get-Item -LiteralPath "function:$name" -ErrorAction SilentlyContinue
        if ($fn) { $snapshot.Functions[$name] = $fn.ScriptBlock }
    }
    $script:CECurrentPack = $Pack.Id
    foreach ($c in $Pack.Categories) { Register-CECategory -Id $c.Id -Label $c.Label }
    if ($Pack.ConfigPath) { [void]$script:CEPackConfigPaths.Add($Pack.ConfigPath); $script:CEConfig = $null }
    return $snapshot
}

function Complete-CEPackLoad {
    <# Checks the pack left the core intact, then records what it added. Throws if it replaced a core function. #>
    param([Parameter(Mandatory)]$Pack, [Parameter(Mandatory)]$Snapshot)
    foreach ($name in @($Snapshot.Functions.Keys)) {
        $now = Get-Item -LiteralPath "function:$name" -ErrorAction SilentlyContinue
        if (-not $now -or -not [object]::ReferenceEquals($now.ScriptBlock, $Snapshot.Functions[$name])) {
            throw "it redefines the built-in function $name"
        }
    }
    $Pack.Checks = @($script:CEChecks | Where-Object { $Snapshot.Checks -notcontains $_.Id } | ForEach-Object { $_.Id })
    $Pack.Remediations = @($script:CERemediations.Keys | Where-Object { $Snapshot.Remediations -notcontains $_ })
    $Pack.Status = 'Loaded'
    $Pack.Reason = ''
    $script:CECurrentPack = $null
}

function Undo-CEPackLoad {
    <# Removes everything a failed pack registered and puts back any built-in function it replaced. #>
    param([Parameter(Mandatory)]$Pack, [Parameter(Mandatory)]$Snapshot, [string]$Reason)
    foreach ($c in @($script:CEChecks | Where-Object { $Snapshot.Checks -notcontains $_.Id })) { $script:CEChecks.Remove($c) }
    foreach ($k in @($script:CERemediations.Keys | Where-Object { $Snapshot.Remediations -notcontains $_ })) { $script:CERemediations.Remove($k) }
    foreach ($cat in @($script:CEValidCategory | Where-Object { $Snapshot.Categories -notcontains $_ })) {
        $script:CEValidCategory.Remove($cat)
        $script:CECategoryLabels.Remove($cat)
        $script:CECategoryPack.Remove($cat)
    }
    if ($Pack.ConfigPath) { $script:CEPackConfigPaths.Remove($Pack.ConfigPath); $script:CEConfig = $null }
    foreach ($name in @($Snapshot.Functions.Keys)) {
        $now = Get-Item -LiteralPath "function:$name" -ErrorAction SilentlyContinue
        if (-not $now -or -not [object]::ReferenceEquals($now.ScriptBlock, $Snapshot.Functions[$name])) {
            Set-Item -LiteralPath "function:script:$name" -Value $Snapshot.Functions[$name]
        }
    }
    $Pack.Status = 'Skipped'
    $Pack.Reason = "Failed to load: $Reason"
    $script:CECurrentPack = $null
    Write-Warning "Engramic Baseline: pack '$($Pack.Id)' was not loaded. $($Pack.Reason)"
}

function Get-CEPack {
    <# Packs found at import: Loaded, or Skipped with the reason. #>
    [CmdletBinding()]
    param()
    return @($script:CEPacks | ForEach-Object {
        [pscustomobject]@{ Id = $_.Id; Name = $_.Name; Version = $_.Version; Status = $_.Status; Reason = $_.Reason; Path = $_.Path; Checks = @($_.Checks); Remediations = @($_.Remediations) }
    })
}
