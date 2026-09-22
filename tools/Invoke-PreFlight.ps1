#Requires -Version 5.1
<#
.SYNOPSIS
    The quick pre-push check on the host: lint, the unit tests on every PowerShell here, the app layout.
.DESCRIPTION
    Runs the "Tests" jobs of .github/workflows/ci.yml against the working tree, on Windows
    PowerShell 5.1 and on pwsh 7 when it is installed, judging the unit tests by Pester's Result and
    failed containers (a discovery error is a failed container with zero failed tests). Runs as the
    current user, so it never changes the device; the Intune rehearsal needs a disposable machine:
    use tools\sandbox\New-SandboxRun.ps1 -Environment ci for the full mirror.
.PARAMETER ModulePath
    A folder containing Pester (and PSScriptAnalyzer) modules, e.g. the parent of Pester\<version>.
    Prepended to PSModulePath for every shell. Optional when the modules are installed normally.
.PARAMETER PesterVersion
    Use this Pester version specifically (CI resolves -MinimumVersion 5.5.0 to the newest, 6.x).
.EXAMPLE
    .\tools\Invoke-PreFlight.ps1 -ModulePath C:\modules -PesterVersion 6.2.0
#>
[CmdletBinding()]
param(
    [string]$ModulePath,
    [string]$PesterVersion,
    [switch]$SkipLint
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repo

$import = if ($PesterVersion) { "Import-Module Pester -RequiredVersion $PesterVersion" } else { 'Import-Module Pester -MinimumVersion 5.5.0' }
$prelude = "`$ErrorActionPreference = 'Stop'`r`n`$ProgressPreference = 'SilentlyContinue'`r`nSet-Location '$repo'`r`n"
if ($ModulePath) { $prelude += "`$env:PSModulePath = '$((Resolve-Path -LiteralPath $ModulePath).Path);' + `$env:PSModulePath`r`n" }

$steps = @(
    @{ Name = 'Lint'; Skip = [bool]$SkipLint; Script = @'
$issues = Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./.github/PSScriptAnalyzerSettings.psd1
$issues | Format-Table -AutoSize
if ($issues) { throw "$($issues.Count) analyzer issue(s)" }
'@ }
    @{ Name = 'Unit tests'; Script = $import + @'

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
    @{ Name = 'Load the desktop app layout'; Script = @'
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
$pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
if ($pwsh) { $shells += @{ Job = 'Tests (pwsh)'; Exe = $pwsh.Source } } else { Write-Warning 'pwsh 7 is not installed here; CI also runs the tests on it.' }

$rows = New-Object System.Collections.ArrayList
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('preflight-' + [guid]::NewGuid().ToString('N') + '.ps1')
try {
    foreach ($s in $shells) {
        foreach ($step in $steps) {
            if ($step.Skip) { continue }
            Set-Content -LiteralPath $tmp -Value ($prelude + $step.Script) -Encoding UTF8
            $sw = [Diagnostics.Stopwatch]::StartNew()
            Write-Host ("==> [{0}] {1}" -f $s.Job, $step.Name) -ForegroundColor Cyan
            & $s.Exe -NoProfile -ExecutionPolicy Bypass -File $tmp 2>&1 | Out-Host
            $ok = ($LASTEXITCODE -eq 0)
            [void]$rows.Add([pscustomobject]@{ Job = $s.Job; Step = $step.Name; Result = $(if ($ok) { 'passed' } else { 'FAILED' }); Seconds = [int]$sw.Elapsed.TotalSeconds })
        }
    }
}
finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

Write-Host ''
$rows | Format-Table -AutoSize | Out-String | Write-Host
$failed = @($rows | Where-Object { $_.Result -ne 'passed' }).Count
if ($failed) { Write-Host "Pre-flight: $failed step(s) FAILED - do not push." -ForegroundColor Red; exit 1 }
Write-Host 'Pre-flight: passed. For the Intune rehearsal, run the ci sandbox environment.' -ForegroundColor Green
