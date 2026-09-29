#Requires -Version 5.1
<#
.SYNOPSIS
    The one check to run before pushing: what CI runs, on the working tree, with one verdict at the end.
.DESCRIPTION
    Runs every step below, even after one fails, then prints a table of them all and a verdict:

      .NET                the SDK that global.json names, the locked restore, the build with warnings as
                          errors and the tests: the "Build and test (.NET)" job of .github/workflows/dotnet.yml
      Hygiene             ASCII text, and only public hosts and repository names (tools\hygiene\Test-Hygiene.ps1):
                          the Hygiene job of dotnet.yml
      Workflows           actionlint on .github/workflows. CI does not run it, so this is where a workflow
                          change is linted.
      Tests (powershell)  PSScriptAnalyzer, the Pester unit tests and the desktop app layout: the "Tests" jobs
      Tests (pwsh)        of ci.yml, on Windows PowerShell 5.1 and on pwsh 7 when it is installed. The unit
                          tests are judged by Pester's Result and failed containers, since a discovery error is
                          a failed container with zero failed tests.

    A step that needs what came before it, such as the build after the restore, is not run when that
    failed. A step that cannot run here, such as actionlint when it is not installed, is reported as skipped
    with the reason. The verdict is FAILED, and the exit code 1, when any step failed.

    Runs as the current user, so it never changes the device. What needs a disposable machine does not run
    here: the Intune rehearsal (tools\sandbox\New-SandboxRun.ps1 -Environment ci), and the contract and
    parity runs as SYSTEM, which the Contracts and Parity jobs of dotnet.yml do.
.PARAMETER ModulePath
    A folder containing Pester (and PSScriptAnalyzer) modules, e.g. the parent of Pester\<version>.
    Prepended to PSModulePath for every shell. Optional when the modules are installed normally.
.PARAMETER PesterVersion
    Use this Pester version specifically (CI resolves -MinimumVersion 5.5.0 to the newest, 6.x).
.PARAMETER SkipLint
    Leave out PSScriptAnalyzer.
.PARAMETER SkipDotNet
    Leave out the .NET steps, on a machine without the SDK. CI still runs them.
.PARAMETER ActionlintPath
    actionlint.exe, when it is not on PATH.
.EXAMPLE
    .\tools\Invoke-PreFlight.ps1 -ModulePath C:\modules -PesterVersion 6.2.0
#>
[CmdletBinding()]
param(
    [string]$ModulePath,
    [string]$PesterVersion,
    [switch]$SkipLint,
    [switch]$SkipDotNet,
    [string]$ActionlintPath
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repo

$rows = New-Object System.Collections.ArrayList
function Add-Row {
    param([string]$Job, [string]$Step, [string]$Result, [int]$Seconds = 0, [string]$Detail = '')
    [void]$rows.Add([pscustomobject]@{ Job = $Job; Step = $Step; Result = $Result; Seconds = $Seconds; Detail = $Detail })
    $colour = if ($Result -eq 'passed') { 'Green' } elseif ($Result -eq 'skipped') { 'Yellow' } else { 'Red' }
    Write-Host ("    {0}{1}" -f $Result, $(if ($Detail) { " - $Detail" } else { '' })) -ForegroundColor $colour
}

function Invoke-Program {
    # Runs a program in this console, showing its output as it comes, and returns its exit code. A line
    # on stderr must not stop this script, as it would under 'Stop' in Windows PowerShell 5.1.
    param([string]$FilePath, [string[]]$ArgumentList = @())
    $ErrorActionPreference = 'Continue'
    & $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" } | Out-Host
    return $LASTEXITCODE
}

function Invoke-Step {
    # Runs one step, which returns an exit code or throws, and records whether it passed.
    param([string]$Job, [string]$Step, [scriptblock]$Action)
    Write-Host ("==> [{0}] {1}" -f $Job, $Step) -ForegroundColor Cyan
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $ok = $false
    $detail = ''
    try {
        $code = & $Action
        $ok = ($code -eq 0)
        if (-not $ok) { $detail = "exit code $code" }
    }
    catch { $detail = $_.Exception.Message }
    Add-Row -Job $Job -Step $Step -Result $(if ($ok) { 'passed' } else { 'FAILED' }) -Seconds ([int]$clock.Elapsed.TotalSeconds) -Detail $detail
    return $ok
}

# --- .NET: the "Build and test (.NET)" job of dotnet.yml ------------------------------------------
if ($SkipDotNet) { Add-Row -Job '.NET' -Step '(all)' -Result 'skipped' -Detail '-SkipDotNet: CI still runs them' }
else {
    $sdk = [string](Get-Content -LiteralPath (Join-Path $repo 'global.json') -Raw | ConvertFrom-Json).sdk.version
    $dotnetCommand = Get-Command dotnet -ErrorAction SilentlyContinue
    $dotnet = if ($dotnetCommand) { $dotnetCommand.Source } else { '' }
    $ready = Invoke-Step -Job '.NET' -Step "SDK $sdk, as global.json names" -Action {
        if (-not $dotnet) { throw "dotnet is not on PATH: install SDK $sdk." }
        $actual = ([string](& $dotnet --version)).Trim()
        # A newer patch fails the locked restore: some implicit packages follow the SDK (docs/DOTNET.md).
        if ($actual -ne $sdk) { throw "dotnet --version is ${actual}: install SDK $sdk, as CI does." }
        0
    }
    $dotnetSteps = @(
        @{ Name = 'Restore (locked)'; Arguments = @('restore', 'Baseline.slnx', '--locked-mode') }
        @{ Name = 'Build (warnings as errors)'; Arguments = @('build', 'Baseline.slnx', '--configuration', 'Release', '--no-restore', '-warnaserror') }
        @{ Name = 'Test'; Arguments = @('test', '--solution', 'Baseline.slnx', '--configuration', 'Release', '--no-build') }
    )
    foreach ($dotnetStep in $dotnetSteps) {
        if (-not $ready) { Add-Row -Job '.NET' -Step $dotnetStep.Name -Result 'not run' -Detail 'a step before it failed'; continue }
        $ready = Invoke-Step -Job '.NET' -Step $dotnetStep.Name -Action { Invoke-Program -FilePath $dotnet -ArgumentList $dotnetStep.Arguments }
    }
}

# --- Hygiene: the Hygiene job of dotnet.yml -------------------------------------------------------
$pwshCommand = Get-Command pwsh.exe -ErrorAction SilentlyContinue
$hygieneShell = if ($pwshCommand) { $pwshCommand.Source } else { 'powershell.exe' }
[void](Invoke-Step -Job 'Hygiene' -Step 'ASCII text, and only public hosts and repository names' -Action {
        Invoke-Program -FilePath $hygieneShell -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $repo 'tools\hygiene\Test-Hygiene.ps1'))
    })

# --- Workflows: actionlint, which no CI job runs --------------------------------------------------
$actionlint = $ActionlintPath
if (-not $actionlint) {
    $actionlintCommand = Get-Command actionlint -ErrorAction SilentlyContinue
    if ($actionlintCommand) { $actionlint = $actionlintCommand.Source }
}
if ($actionlint) { [void](Invoke-Step -Job 'Workflows' -Step 'actionlint' -Action { Invoke-Program -FilePath $actionlint }) }
else { Add-Row -Job 'Workflows' -Step 'actionlint' -Result 'skipped' -Detail 'actionlint is not on PATH: install it, or pass -ActionlintPath' }

# --- Tests (powershell) and Tests (pwsh): the "Tests" jobs of ci.yml ------------------------------
$import = if ($PesterVersion) { "Import-Module Pester -RequiredVersion $PesterVersion" } else { 'Import-Module Pester -MinimumVersion 5.5.0' }
$prelude = "`$ErrorActionPreference = 'Stop'`r`n`$ProgressPreference = 'SilentlyContinue'`r`nSet-Location '$repo'`r`n"
if ($ModulePath) { $prelude += "`$env:PSModulePath = '$((Resolve-Path -LiteralPath $ModulePath).Path);' + `$env:PSModulePath`r`n" }

$steps = @(
    @{ Name = 'Lint'; Skip = [bool]$SkipLint; Script = @'
$issues = Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./.github/PSScriptAnalyzerSettings.psd1
$issues | Format-Table -AutoSize
if ($issues) { throw "$($issues.Count) analyzer issue(s)" }
'@ }
    @{ Name = 'Unit tests'; Skip = $false; Script = $import + @'

$c = New-PesterConfiguration
$c.Run.Path = './tests'
$c.Run.PassThru = $true
$c.Output.Verbosity = 'None'
$r = Invoke-Pester -Configuration $c
$failedContainers = @($r.Containers | Where-Object { $_.Result -eq 'Failed' })
"Pester $((Get-Module Pester).Version): Result=$($r.Result) Passed=$($r.PassedCount) Failed=$($r.FailedCount) Skipped=$($r.SkippedCount) FailedContainers=$($failedContainers.Count)"
foreach ($t in $r.Failed) { "  [-] $($t.ExpandedPath): $($t.ErrorRecord.Exception.Message)" }
foreach ($fc in $failedContainers) { "  container failed: $($fc.Item) :: $(@($fc.ErrorRecord | ForEach-Object { $_.Exception.Message }) -join ' | ')" }
if ($r.Result -ne 'Passed') { exit 1 }
'@ }
    @{ Name = 'Load the desktop app layout'; Skip = $false; Script = @'
Add-Type -AssemblyName PresentationFramework
$src = Get-Content ./app/Start-CEAuditGui.ps1 -Raw
foreach ($tag in @("[xml]`$xaml = @'", "`$chooserXaml = @'")) {
    $start = $src.IndexOf($tag) + $tag.Length
    $end = $src.IndexOf("'@", $start)
    [xml]$x = $src.Substring($start, $end - $start).Trim()
    $null = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $x))
}
'XAML loaded OK (main window and check chooser)'
'@ }
)
$shells = @(@{ Job = 'Tests (powershell)'; Exe = 'powershell.exe' })
if ($pwshCommand) { $shells += @{ Job = 'Tests (pwsh)'; Exe = $pwshCommand.Source } }
else { Add-Row -Job 'Tests (pwsh)' -Step '(all)' -Result 'skipped' -Detail 'pwsh 7 is not installed here; CI also runs the tests on it' }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('preflight-' + [guid]::NewGuid().ToString('N') + '.ps1')
try {
    foreach ($shell in $shells) {
        foreach ($step in $steps) {
            if ($step.Skip) { Add-Row -Job $shell.Job -Step $step.Name -Result 'skipped' -Detail '-SkipLint'; continue }
            Set-Content -LiteralPath $tmp -Value ($prelude + $step.Script) -Encoding UTF8
            [void](Invoke-Step -Job $shell.Job -Step $step.Name -Action {
                    Invoke-Program -FilePath $shell.Exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $tmp)
                })
        }
    }
}
finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

# --- the verdict ----------------------------------------------------------------------------------
Write-Host ''
$rows | Format-Table Job, Step, Result, Seconds, Detail -AutoSize -Wrap | Out-String -Width 160 | Write-Host
$failed = @($rows | Where-Object { $_.Result -ne 'passed' -and $_.Result -ne 'skipped' })
$skipped = @($rows | Where-Object { $_.Result -eq 'skipped' })
if ($failed.Count) {
    Write-Host ("Pre-flight: FAILED - {0} step(s) did not pass: {1}. Do not push." -f $failed.Count, (@($failed | ForEach-Object { "$($_.Job) / $($_.Step)" }) -join ', ')) -ForegroundColor Red
    exit 1
}
if ($skipped.Count) {
    Write-Host ("Pre-flight: passed, but {0} step(s) did not run here: {1}." -f $skipped.Count, (@($skipped | ForEach-Object { "$($_.Job) / $($_.Step)" }) -join ', ')) -ForegroundColor Yellow
}
else { Write-Host 'Pre-flight: passed. For the Intune rehearsal, run the ci sandbox environment.' -ForegroundColor Green }
exit 0
