#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the tests of one trait in a test assembly as SYSTEM, explicit ones included, and fails unless every one
    of them ran and passed.

.DESCRIPTION
    For CI runners and other machines that are there to be changed. Some tests hold only as SYSTEM, the account
    the scheduled audit runs as, and some of those change the machine, such as its WinHTTP proxy or its hosts
    file, putting each change back afterwards. Those are explicit, so they never run with the other tests, and
    they skip unless they run as SYSTEM.

    This runs them: dotnet runs the xUnit test assembly as SYSTEM through tools\ci\Invoke-AsSystem.ps1, a
    temporary scheduled task, with the tests of -Trait selected, explicit ones included, and a skipped test
    counted as a failure. It prints what the run printed and each test's result, with what the test wrote to
    its output, then exits 1 unless the run succeeded, at least -MinimumTests tests ran, and every one passed.
    The results file stays in -WorkPath.

    It needs an elevated administrator, registers a scheduled task, and runs tests that change the machine: run
    it only where that is meant.

.PARAMETER TestAssembly
    The test assembly, the .dll the build writes, by its full path.

.PARAMETER Trait
    The trait that selects the tests, as name=value, such as Context=System.

.PARAMETER WorkPath
    The folder for the run's files, which only SYSTEM and Administrators may change: Invoke-AsSystem.ps1 makes it
    so if it does not exist, and refuses it otherwise.

.PARAMETER MinimumTests
    How many tests must run, so that a filter that matches too few cannot pass. Default: 1.

.PARAMETER TimeoutSeconds
    How long the run may take. Default: 900.

.EXAMPLE
    .\tools\ci\Test-AsSystem.ps1 -TestAssembly "$PWD\artifacts\bin\Engramic.Baseline.Windows.Tests\release\Engramic.Baseline.Windows.Tests.dll" -Trait Context=System -WorkPath C:\ci-system -MinimumTests 5
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TestAssembly,
    [Parameter(Mandatory = $true)][ValidatePattern('^[^=]+=[^=]+$')][string]$Trait,
    [Parameter(Mandatory = $true)][string]$WorkPath,
    [ValidateRange(1, 10000)][int]$MinimumTests = 1,
    [ValidateRange(60, 7200)][int]$TimeoutSeconds = 900
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if (-not [IO.Path]::IsPathRooted($TestAssembly) -or -not (Test-Path -LiteralPath $TestAssembly -PathType Leaf)) {
    throw "Give the test assembly by its full path; $TestAssembly is not a file."
}

# The dotnet that built the tests, by its full path, since the task runs as SYSTEM with SYSTEM's own PATH.
$dotnet = @(Get-Command -Name 'dotnet' -CommandType Application -ErrorAction Stop)[0].Source
$results = Join-Path $WorkPath ('results-{0}.xml' -f [guid]::NewGuid().ToString('n'))
$arguments = @($TestAssembly, '-trait', $Trait, '-explicit', 'only', '-failSkips', '-noColor', '-noLogo', '-xml', $results)
Write-Host "Running the tests with $Trait as SYSTEM: $dotnet $($arguments -join ' ')"
$run = & (Join-Path $PSScriptRoot 'Invoke-AsSystem.ps1') -FilePath $dotnet -ArgumentList $arguments -WorkPath $WorkPath -TimeoutSeconds $TimeoutSeconds
$run.Output | ForEach-Object { Write-Host $_ }
$run.Errors | ForEach-Object { Write-Host "error: $_" }

$problems = New-Object System.Collections.ArrayList
if ($run.TimedOut) { [void]$problems.Add("The run timed out after $TimeoutSeconds seconds.") }
elseif ($run.ExitCode -ne 0) { [void]$problems.Add("The test run exited with $($run.ExitCode).") }

if (-not (Test-Path -LiteralPath $results -PathType Leaf)) {
    [void]$problems.Add("The run wrote no results to $results.")
}
else {
    [xml]$document = [IO.File]::ReadAllText($results)
    $assemblies = @($document.SelectNodes('/assemblies/assembly'))
    if ($assemblies.Count -ne 1) { [void]$problems.Add("The results name $($assemblies.Count) test assemblies, not one.") }
    foreach ($test in @($document.SelectNodes('//test'))) {
        $line = '{0,-5} {1}' -f $test.GetAttribute('result'), $test.GetAttribute('name')
        Write-Host $line
        foreach ($output in @($test.SelectNodes('output'))) {
            $output.InnerText.Trim() -split "`r?`n" | ForEach-Object { Write-Host "      $_" }
        }
        if ($test.GetAttribute('result') -ne 'Pass') {
            $why = @($test.SelectNodes('failure/message | reason') | ForEach-Object { $_.InnerText.Trim() }) -join ' '
            [void]$problems.Add("$line $why".Trim())
        }
    }

    foreach ($assembly in $assemblies) {
        $counts = @{}
        foreach ($name in 'total', 'passed', 'failed', 'skipped', 'errors', 'not-run') { $counts[$name] = [int]$assembly.GetAttribute($name) }
        Write-Host ('{0} ran: {1} passed, {2} failed, {3} skipped, {4} not run, {5} errors.' -f $counts['total'], $counts['passed'], $counts['failed'], $counts['skipped'], $counts['not-run'], $counts['errors'])
        if ($counts['passed'] -lt $MinimumTests) { [void]$problems.Add("Only $($counts['passed']) tests passed; at least $MinimumTests must run and pass.") }
        if ($counts['passed'] -ne $counts['total']) { [void]$problems.Add("$($counts['total'] - $counts['passed']) of $($counts['total']) tests did not pass.") }
        if ($counts['errors'] -ne 0) { [void]$problems.Add("The run reported $($counts['errors']) errors outside the tests.") }
    }
}

if ($problems.Count) {
    $problems | ForEach-Object { Write-Host "FAIL: $_" }
    exit 1
}
Write-Host "PASS: every test with $Trait ran as SYSTEM and passed."
