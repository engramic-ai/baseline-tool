#Requires -Version 5.1
<#
.SYNOPSIS
    Runs inside Windows Sandbox: the same jobs as .github/workflows/ci.yml, on a throwaway Windows.
.DESCRIPTION
    Started by the ci environment (tools\sandbox\environments\ci.json). Mirrors ci.yml job for job:

      Tests (powershell) and Tests (pwsh): lint, unit tests, load the desktop app layout
      Intune deployment rehearsal: config override, Test-IntuneDeployment.ps1, Build-IntunePackage.ps1

    Each step is judged the way GitHub judges it (exit code / thrown error), and the unit tests
    additionally by Pester's Result and failed containers, so a discovery error cannot pass as
    "0 failed". Writes ci-summary.md and per-step logs to the run's results folder on the host.
    Keep the steps in sync with ci.yml; the runner image differs (preinstalled tools, account
    model), so a green here is strong evidence, not proof.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:USERNAME -ne 'WDAGUtilityAccount' -or -not (Test-Path 'C:\baseline-tool\src\CEAudit\CEAudit.psd1')) {
    throw 'This mirrors CI on a disposable machine (it installs, runs as SYSTEM and uninstalls). Use tools\sandbox\New-SandboxRun.ps1 -Environment ci on the host.'
}
$results = if ($env:SANDBOX_RESULTS) { $env:SANDBOX_RESULTS } else { Join-Path 'C:\results' (Get-Date -Format 'yyyyMMdd-HHmmss') }
New-Item -ItemType Directory -Path $results -Force | Out-Null

$work = 'C:\work\baseline-tool'
New-Item -ItemType Directory -Path $work -Force | Out-Null
& robocopy.exe 'C:\baseline-tool' $work /E /NFL /NDL /NJH /NJS /XD .git output build .playwright-mcp | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed with exit code $LASTEXITCODE" }

$modules = if (Test-Path 'C:\ps-modules') { 'C:\ps-modules' } else { '' }
$steps = New-Object System.Collections.ArrayList
function Invoke-Step {
    # Runs one CI step in a child shell; a step passes when the child exits 0.
    param([string]$Job, [string]$Name, [string]$Shell, [string]$Script)
    $log = Join-Path $results ("{0}-{1}.log" -f ($Job -replace '[^\w]+', '-').Trim('-'), ($Name -replace '[^\w]+', '-').Trim('-'))
    $file = Join-Path $results ("step-{0}.ps1" -f [guid]::NewGuid().ToString('N'))
    # The sandbox user is an administrator; the suite refuses to run elevated unless told the machine is
    # disposable (GitHub's runners are elevated too, and are let through by CI=true).
    $prelude = "`$ErrorActionPreference = 'Stop'`r`n`$ProgressPreference = 'SilentlyContinue'`r`n`$env:CE_TESTS_ALLOW_ELEVATED = '1'`r`nSet-Location '$work'`r`n"
    if ($modules) { $prelude += "`$env:PSModulePath = '$modules;' + `$env:PSModulePath`r`n" }
    Set-Content -LiteralPath $file -Value ($prelude + $Script) -Encoding UTF8
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Write-Host ("==> [{0}] {1}" -f $Job, $Name) -ForegroundColor Cyan
    & $Shell -NoProfile -ExecutionPolicy Bypass -File $file 2>&1 | Tee-Object -FilePath $log | Out-Host
    $code = $LASTEXITCODE
    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    $ok = ($code -eq 0)
    [void]$steps.Add([pscustomobject]@{ Job = $Job; Step = $Name; Ok = $ok; ExitCode = $code; Seconds = [int]$sw.Elapsed.TotalSeconds; Log = (Split-Path -Leaf $log) })
    Write-Host ("    {0} ({1}s)" -f $(if ($ok) { 'passed' } else { "FAILED exit $code" }), [int]$sw.Elapsed.TotalSeconds) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
}

# --- Tests (powershell) and Tests (pwsh): the same three steps as ci.yml --------------------------
$lint = @'
$issues = Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./.github/PSScriptAnalyzerSettings.psd1
$issues | Format-Table -AutoSize
if ($issues) { throw "$($issues.Count) analyzer issue(s)" }
'@
$unit = @'
Import-Module Pester -MinimumVersion 5.5.0
$c = New-PesterConfiguration
$c.Run.Path = './tests'
$c.Run.PassThru = $true
$c.Output.Verbosity = 'Normal'
$c.Output.RenderMode = 'Plaintext'
$r = Invoke-Pester -Configuration $c
$failedContainers = @($r.Containers | Where-Object { $_.Result -eq 'Failed' })
"Result=$($r.Result) Passed=$($r.PassedCount) Failed=$($r.FailedCount) Skipped=$($r.SkippedCount) FailedContainers=$($failedContainers.Count)"
foreach ($fc in $failedContainers) { "container failed: $($fc.Item) :: $(@($fc.ErrorRecord | ForEach-Object { $_.Exception.Message }) -join ' | ')" }
if ($r.Result -ne 'Passed') { exit 1 }
'@
$xaml = @'
Add-Type -AssemblyName PresentationFramework
$src = Get-Content ./app/Start-CEAuditGui.ps1 -Raw
foreach ($tag in @("[xml]`$xaml = @'", "`$chooserXaml = @'")) {
    $start = $src.IndexOf($tag) + $tag.Length
    $end = $src.IndexOf("'@", $start)
    [xml]$x = $src.Substring($start, $end - $start).Trim()
    $null = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $x))
}
'XAML loaded OK (main window and check chooser)'
'@
$shells = @(@{ Job = 'Tests (powershell)'; Exe = 'powershell.exe' })
$pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
if ($pwsh) { $shells += @{ Job = 'Tests (pwsh)'; Exe = $pwsh.Source } }
else { [void]$steps.Add([pscustomobject]@{ Job = 'Tests (pwsh)'; Step = '(all)'; Ok = $false; ExitCode = -1; Seconds = 0; Log = 'pwsh.exe not found: is the pwsh tool in the environment?' }) }
foreach ($s in $shells) {
    Invoke-Step -Job $s.Job -Name 'Lint' -Shell $s.Exe -Script $lint
    Invoke-Step -Job $s.Job -Name 'Unit tests' -Shell $s.Exe -Script $unit
    Invoke-Step -Job $s.Job -Name 'Load the desktop app layout' -Shell $s.Exe -Script $xaml
}

# --- Intune deployment rehearsal ------------------------------------------------------------------
$override = @'
$dir = Join-Path $env:ProgramData 'EngramicBaseline\config'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
'{ "excludeCheckIds": ["SU-03"] }' | Set-Content (Join-Path $dir 'scheduled-audit.json')
'skipping the online Windows Update search, as ci.yml does'
'@
Invoke-Step -Job 'Intune deployment rehearsal' -Name 'Skip the online Windows Update search' -Shell 'powershell.exe' -Script $override
Invoke-Step -Job 'Intune deployment rehearsal' -Name 'Install, audit as SYSTEM, discovery, rules, uninstall' -Shell 'powershell.exe' -Script './intune/Test-IntuneDeployment.ps1 -TimeoutMinutes 20'
Invoke-Step -Job 'Intune deployment rehearsal' -Name 'Build the Intune package' -Shell 'powershell.exe' -Script './intune/Build-IntunePackage.ps1 -DownloadTool'

# --- summary, the way the PR checks page would show it --------------------------------------------
$jobs = @($steps | Group-Object Job | ForEach-Object { [pscustomobject]@{ Job = $_.Name; Ok = -not @($_.Group | Where-Object { -not $_.Ok }).Count; Seconds = ($_.Group | Measure-Object Seconds -Sum).Sum } })
$verdict = if (@($jobs | Where-Object { -not $_.Ok }).Count) { 'FAILED' } else { 'PASSED' }
$lines = @("# Local CI mirror $(Split-Path -Leaf $results)", '', "Verdict: **$verdict**", '', '| Job | Result | Seconds |', '|---|---|---|')
foreach ($j in $jobs) { $lines += "| $($j.Job) | $(if ($j.Ok) { 'passed' } else { '**failed**' }) | $($j.Seconds) |" }
$lines += @('', '| Job | Step | Result | Exit | Seconds | Log |', '|---|---|---|---|---|---|')
foreach ($s in $steps) { $lines += "| $($s.Job) | $($s.Step) | $(if ($s.Ok) { 'passed' } else { '**failed**' }) | $($s.ExitCode) | $($s.Seconds) | $($s.Log) |" }
$lines += @('', 'Mirrors .github/workflows/ci.yml on a Windows Sandbox image, not the GitHub runner image: a pass here is strong evidence, not proof.')
Set-Content -LiteralPath (Join-Path $results 'ci-summary.md') -Value ($lines -join "`r`n") -Encoding UTF8
$steps | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $results 'ci-summary.json') -Encoding UTF8

Write-Host ''
$steps | Format-Table Job, Step, Ok, ExitCode, Seconds -AutoSize | Out-String | Write-Host
Write-Host "CI mirror: $verdict" -ForegroundColor $(if ($verdict -eq 'PASSED') { 'Green' } else { 'Red' })
Write-Host "Results are on the host under build\sandbox\results\ci\$(Split-Path -Leaf $results). Close this window to destroy the sandbox." -ForegroundColor Cyan
