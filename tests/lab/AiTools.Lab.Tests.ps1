#Requires -Modules Pester
<#
    AI-tool detection lab. Runs ONLY inside Windows Sandbox (CE_LAB=1, set by tests\lab\Invoke-Lab.ps1);
    everywhere else every block is skipped. It installs real software and runs elevated.

    Ladder, per tool in CE_LAB_TOOLS (ids from sandbox\tools.json, matching config\ai-tools.json):
      0  clean image      : nothing detected, SC-13 not applicable
      1  installed        : detected, and which signal fired
      1b no cross-detection: installing it lit up no other tool
      2  running          : its process is seen; UA-10 flags it (the sandbox user is an administrator)
      3  MCP config       : a seeded config at the tool's documented path is found, parsed, and its
                            plaintext credential classified; SC-13 reports it
#>

# Evaluated at discovery (for -Skip) and again in BeforeAll: top-level variables do not survive into the run phase.
$script:lab = ($env:CE_LAB -eq '1' -and $env:USERNAME -eq 'WDAGUtilityAccount')

BeforeAll {
    $script:lab = ($env:CE_LAB -eq '1' -and $env:USERNAME -eq 'WDAGUtilityAccount')
    if (-not $script:lab) { return }
    Import-Module 'C:\sandbox\SandboxLab.psm1' -Force
    Import-Module 'C:\baseline-tool\src\CEAudit\CEAudit.psd1' -Force
    $script:catalog = (Get-Content 'C:\baseline-tool\config\ai-tools.json' -Raw | ConvertFrom-Json).tools
    $global:LabContext = Get-CEDeviceContext

    function global:Clear-LabCaches {
        # The module memoises tool state and the MCP inventory for the life of the process (one audit
        # reads once). The lab changes the machine between reads, so every read must start cold.
        & (Get-Module CEAudit) { $script:CEAIToolCache = $null; $script:CEMcpCache = $null }
    }
    function global:Get-LabToolState {
        # Every recognised tool with the detection signals that fired (private module function, needs a context).
        Clear-LabCaches
        $state = & (Get-Module CEAudit) { param($c) Get-CEAIToolState -Context $c } $global:LabContext
        $map = @{}
        foreach ($t in @($state.Tools)) { $map[[string]$t.Id] = $t }
        return $map
    }
    function global:Get-LabDetectedIds { param($State) @($State.Keys | Where-Object { @($State[$_].Signals).Count -gt 0 } | Sort-Object) }
    function global:Get-LabCheck {
        param([string]$Id)
        Clear-LabCaches
        $f = @(Invoke-CEAuditCore -Id $Id) | Select-Object -First 1
        if (-not $f) { return [pscustomobject]@{ Status = 'Missing'; Actual = "check $Id returned no finding" } }
        return $f
    }
    function global:Add-LabRow {
        param([string]$Tool, [string]$Install, [string]$Detected, [string]$Signal, [string]$Running, [string]$Elevated, [string]$Mcp, [string]$Note)
        [void]$global:LabMatrix.Add([pscustomobject]@{ Tool = $Tool; Install = $Install; Detected = $Detected; Signal = $Signal; Running = $Running; Elevated = $Elevated; Mcp = $Mcp; Note = $Note })
    }
    function global:New-LabMcpFixture {
        # Two servers: one with a plaintext Anthropic key, one referencing an environment variable.
        param([string]$Root, [string]$Format)
        $body = @"
{
  "$Root": {
    "leaky": { "command": "npx", "args": ["-y", "@example/server"], "env": { "ANTHROPIC_API_KEY": "sk-ant-api03-LABFIXTURE0000000000000000000000000000000000000000" } },
    "safe":  { "command": "npx", "args": ["-y", "@example/server"], "env": { "OPENAI_API_KEY": "`${env:OPENAI_API_KEY}" } }
  }
}
"@
        if ($Format -eq 'jsonc') { $body = "// lab fixture with a comment, as VS Code writes them`r`n" + $body }
        return $body
    }
    if (-not (Get-Variable -Name LabMatrix -Scope Global -ErrorAction SilentlyContinue)) { $global:LabMatrix = New-Object System.Collections.ArrayList }
    $script:toolIds = @(($env:CE_LAB_TOOLS -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $script:baseline = Get-LabToolState
}

Describe 'Layer 0: clean image' -Tag Lab -Skip:(-not $script:lab) {
    It 'loads the AI tool catalogue inside the module (otherwise "nothing detected" is vacuous)' {
        $diag = & (Get-Module CEAudit) {
            $cfgDir = Join-Path $script:RepoRoot 'config'
            [pscustomobject]@{
                RepoRoot = $script:RepoRoot
                ConfigFiles = @(Get-ChildItem -Path $cfgDir -Filter '*.json' -ErrorAction SilentlyContinue).Count
                Tools = @((Get-CEConfig)['ai-tools'].tools).Count
                McpEntries = @(Get-CEMcpConfigCatalogue | ForEach-Object { $_ }).Count   # unwraps the ,array return
            }
        }
        Write-Host "    module RepoRoot=$($diag.RepoRoot) configFiles=$($diag.ConfigFiles) tools=$($diag.Tools) mcpEntries=$($diag.McpEntries)"
        $diag.Tools | Should -Be $script:catalog.Count -Because 'the module must see the same ai-tools.json the lab reads directly'
        $diag.McpEntries | Should -BeGreaterThan 0
    }
    It 'detects no AI tools on a fresh sandbox' {
        $ids = Get-LabDetectedIds $script:baseline
        $ids -join ', ' | Should -BeNullOrEmpty
    }
    It 'reports SC-13 as not applicable with no MCP configuration' {
        (Get-LabCheck 'SC-13').Status | Should -Be 'NotApplicable'
    }
}

Describe 'Tool: <_>' -Tag Lab -Skip:(-not $script:lab) -ForEach @(($env:CE_LAB_TOOLS -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) {
    BeforeAll {
        $script:id = $_
        $script:rule = @($script:catalog | Where-Object { $_.id -eq $script:id })
        $script:row = @{ Tool = $script:id; Install = '-'; Detected = '-'; Signal = '-'; Running = '-'; Elevated = '-'; Mcp = '-'; Note = '' }
        $script:before = Get-LabDetectedIds (Get-LabToolState)
        $script:install = Install-SandboxTool -Id $script:id
        $script:row.Install = if ($script:install.Installed) { $script:install.Method } else { "FAILED ($($script:install.Method)): $($script:install.Message)" }
        $script:ready = [bool]$script:install.Installed
    }
    AfterAll {
        Stop-SandboxTool -Id $script:id
        Add-LabRow @script:row
    }

    It 'has a detection rule in config/ai-tools.json' {
        $script:rule.Count | Should -Be 1 -Because "sandbox\tools.json and config\ai-tools.json must agree on tool ids"
    }

    It 'installs unattended' {
        if ($script:install.Method -eq 'manual') { Set-ItResult -Skipped -Because "not installable unattended: $($script:install.Message)"; return }
        $script:install.Installed | Should -BeTrue -Because $script:install.Message
    }

    It 'is detected after install (layer 1)' {
        if (-not $script:ready) { Set-ItResult -Skipped -Because 'install failed'; return }
        $state = Get-LabToolState
        # Only tools with at least one signal are in the state; absent means not detected.
        $signals = @(if ($state.ContainsKey($script:id)) { $state[$script:id].Signals } else { @() })   # @(if ...): a one-item result would otherwise unwrap to a string
        $script:row.Detected = if ($signals.Count) { 'yes' } else { 'NO' }
        $script:row.Signal = if ($signals.Count) { [string]$signals[0] } else { '-' }
        Write-Host "    signals: $($signals -join ' | ')"
        if ($signals.Count -eq 0 -and @($script:rule[0].vscodeExtensions).Count) {
            # Say what is actually on disk for extension-based rules: user extensions and VS Code's built-ins.
            $userExt = @(Get-ChildItem -LiteralPath (Join-Path $env:USERPROFILE '.vscode\extensions') -Directory -ErrorAction SilentlyContinue | ForEach-Object Name)
            $builtIn = @(Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'Programs\Microsoft VS Code') -Recurse -Depth 4 -Directory -Filter '*copilot*' -ErrorAction SilentlyContinue | ForEach-Object FullName)
            $script:row.Note += "ext diag: user=[$($userExt -join ',')] builtin=[$($builtIn -join ',')]. "
            Write-Host "    $($script:row.Note)"
        }
        $signals.Count | Should -BeGreaterThan 0 -Because "none of the rules for $($script:id) matched the installed tool"
    }

    It 'lights up no other tool (layer 1b)' {
        if (-not $script:ready) { Set-ItResult -Skipped -Because 'install failed'; return }
        $after = Get-LabDetectedIds (Get-LabToolState)
        $new = @($after | Where-Object { $script:before -notcontains $_ -and $_ -ne $script:id })
        if ($new.Count) { $script:row.Note += "also detected: $($new -join ', '). " }
        $new -join ', ' | Should -BeNullOrEmpty -Because "installing $($script:id) should not make other tools appear"
    }

    It 'is seen running, and UA-10 flags it as elevated (layer 2)' {
        if (-not $script:ready) { Set-ItResult -Skipped -Because 'install failed'; return }
        $proc = Start-SandboxTool -Id $script:id
        if (-not $proc) { $script:row.Running = 'could not launch'; Set-ItResult -Skipped -Because 'executable not found after install'; return }
        $state = Get-LabToolState
        $running = $state.ContainsKey($script:id) -and @($state[$script:id].Processes).Count -gt 0
        $script:row.Running = if ($running) { 'yes' } else { 'NO' }
        $ua10 = Get-LabCheck 'UA-10'
        $canAct = [bool]$script:rule[0].canActOnDevice
        # UA-10 reports an agent running with administrator rights as Warn (its design), with the process named.
        $flagged = ($ua10.Status -in @('Warn', 'Fail')) -and ([string]$ua10.Actual -match 'administrator rights')
        $script:row.Elevated = if (-not $canAct) { 'n/a (cannot act on device)' } elseif ($flagged) { "yes ($($ua10.Status))" } else { "NO ($($ua10.Status): $($ua10.Actual))" }
        $running | Should -BeTrue -Because "the process rules for $($script:id) did not match the running tool"
        if ($canAct) { $flagged | Should -BeTrue -Because "the sandbox user is an administrator, so UA-10 must report the running agent; it said $($ua10.Status): $($ua10.Actual)" }
    }

    It 'finds a seeded MCP config and classifies its credentials (layer 3)' {
        # ($null | ForEach-Object) still runs once, so test for the property before enumerating it.
        $mcpProp = $script:rule[0].PSObject.Properties['mcpConfigs']
        $mcp = @(if ($mcpProp -and $null -ne $mcpProp.Value) { $mcpProp.Value } else { @() })
        if ($mcp.Count -eq 0) { $script:row.Mcp = 'n/a (no config rule)'; Set-ItResult -Skipped -Because 'tool has no mcpConfigs rule'; return }
        $cfg = $mcp[0]
        $path = Join-Path $env:USERPROFILE ([string]$cfg.path)
        $existed = Test-Path -LiteralPath $path
        $backup = $null
        if ($existed) { $backup = Get-Content -LiteralPath $path -Raw }
        try {
            New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
            Set-Content -LiteralPath $path -Value (New-LabMcpFixture -Root ([string]$cfg.root) -Format ([string]$cfg.format)) -Encoding UTF8
            Clear-LabCaches
            $posture = Get-CEAiPosture -Context $global:LabContext
            $servers = @($posture['mcpServers'] | Where-Object { $_.toolId -eq $script:id })
            $sc13 = Get-LabCheck 'SC-13'
            $script:row.Mcp = "$($servers.Count) servers, $([int]$posture['credentialsPlaintext']) plaintext, SC-13 $($sc13.Status)"
            if ($servers.Count -ne 2) {
                $profDir = & (Get-Module CEAudit) { param($c) Get-CEUserProfilePath -Context $c } $global:LabContext
                $script:row.Note += "mcp diag: fixture=$path exists=$(Test-Path -LiteralPath $path) profile=$profDir found=$($posture['mcpConfigsFound']) parsed=$($posture['mcpConfigsParsed']) unreadable=$(@($posture['mcpConfigsUnreadable']) -join ';') bounds=$($posture['scanBounds']). "
                Write-Host "    $($script:row.Note)"
            }
            $servers.Count | Should -Be 2 -Because "the config at $($cfg.path) should parse as $($cfg.format) with root $($cfg.root)"
            [int]$posture['credentialsPlaintext'] | Should -BeGreaterOrEqual 1
            $sc13.Status | Should -BeIn @('Warn', 'Fail')
            $sc13.Actual | Should -Not -Match 'LABFIXTURE' -Because 'credential values must never be recorded'
        }
        finally {
            if ($existed) { Set-Content -LiteralPath $path -Value $backup -Encoding UTF8 } else { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
        }
    }
}
