#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the attack suite of the .NET tests with a throwaway standard user as the attacker.

.DESCRIPTION
    For CI runners and other machines that are there to be changed: it creates a local account. The Security job
    in .github\workflows\dotnet.yml runs this twice, as the elevated administrator the runner is and, through
    tools\ci\Invoke-AsSystem.ps1, as SYSTEM.

    The attack suite is the tests with the trait Suite=Security (docs\DOTNET.md). Some of them need a real
    standard user to act as the attacker, which they do by impersonating a logon of it. This script makes one: a
    local account with a random name and password and no group of its own beyond Users, so its token carries
    Users and not Administrators. It runs the built test assembly directly with the suite's trait, with the
    account's name and password in BASELINE_TEST_ATTACKER_USER and BASELINE_TEST_ATTACKER_PASSWORD, which only
    that run sees, and deletes the account afterwards, whatever happened. Without the account, those tests skip.

    It runs the assembly, as tools\ci\Test-AsSystem.ps1 does, rather than dotnet test: run as SYSTEM, dotnet
    test took the project for a VSTest one and refused to run it. So the test platform's hang dump does not
    apply; the SYSTEM run's task has its own time limit. A run in which no test ran fails.

.PARAMETER Dotnet
    The full path of dotnet.exe, from the SDK the tests were built with (global.json).

.PARAMETER TestAssembly
    The test assembly, built in Release. Default: Engramic.Baseline.Windows.Tests.dll under artifacts\bin.

.PARAMETER ResultsPath
    The folder the results file, security.xml, is written into.

.OUTPUTS
    The test runner's output and a summary. The exit code is 0 when tests ran and every one passed or skipped.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\Invoke-SecurityTests.ps1 -Dotnet 'C:\Program Files\dotnet\dotnet.exe' -ResultsPath C:\security
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Dotnet,
    # No default here: Windows PowerShell 5.1 leaves $PSScriptRoot empty in an advanced script's parameter
    # defaults when it is run with -File, as the SYSTEM run is. It is filled in below.
    [string]$TestAssembly,
    [Parameter(Mandatory = $true)][string]$ResultsPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $TestAssembly) { $TestAssembly = Join-Path $repoRoot 'artifacts\bin\Engramic.Baseline.Windows.Tests\release\Engramic.Baseline.Windows.Tests.dll' }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this as an elevated administrator or SYSTEM: it creates a local account, and the tests act as it.'
}
foreach ($file in @($Dotnet, $TestAssembly)) {
    if (-not [IO.Path]::IsPathRooted($file) -or -not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "$file is not a file given by its full path." }
}

# A name no other account has, and a password random enough for any policy, with every kind of character.
$name = 'bl-sec-' + [guid]::NewGuid().ToString('n').Substring(0, 12)
$bytes = New-Object byte[] 24
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($bytes) } finally { $random.Dispose() }
$password = 'Aa1!' + [Convert]::ToBase64String($bytes)
$secure = New-Object Security.SecureString
foreach ($character in $password.ToCharArray()) { $secure.AppendChar($character) }

$code = 1
# Windows allows an account description of at most 48 characters.
New-LocalUser -Name $name -Password $secure -Description 'Baseline attack suite user, deleted after run' -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
try {
    # Authenticated users are in Users already; adding the account says so plainly, and changes nothing if so.
    try { Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $name -ErrorAction Stop }
    catch { if ("$($_.FullyQualifiedErrorId)" -notlike 'MemberExists*') { throw } }
    Write-Output "Made the standard user $name to act as the attacker."

    $env:BASELINE_TEST_ATTACKER_USER = $name
    $env:BASELINE_TEST_ATTACKER_PASSWORD = $password
    # As SYSTEM too: no first-run text or telemetry.
    $env:DOTNET_NOLOGO = 'true'
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = 'true'

    [void](New-Item -ItemType Directory -Path $ResultsPath -Force)
    $results = Join-Path $ResultsPath 'security.xml'
    $arguments = @($TestAssembly, '-trait', 'Suite=Security', '-noColor', '-noLogo', '-result-xml', $results)
    # Windows PowerShell turns each line a native program writes to standard error into an error record,
    # which would stop the script; they are the test runner's output like any other.
    $ErrorActionPreference = 'Continue'
    & $Dotnet @arguments 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'

    if (-not (Test-Path -LiteralPath $results -PathType Leaf)) {
        Write-Output "The run wrote no results to $results."
        $code = 1
    }
    else {
        $assembly = ([xml][IO.File]::ReadAllText($results)).SelectSingleNode('/assemblies/assembly')
        $total = 0
        if ($assembly) {
            $total = [int]$assembly.GetAttribute('total')
            Write-Output ('{0} ran: {1} passed, {2} failed, {3} skipped, {4} errors.' -f $total, $assembly.GetAttribute('passed'), $assembly.GetAttribute('failed'), $assembly.GetAttribute('skipped'), $assembly.GetAttribute('errors'))
        }
        if ($total -eq 0) {
            Write-Output 'No test ran, so the trait matched nothing.'
            $code = 1
        }
    }
}
finally {
    Remove-Item -LiteralPath Env:\BASELINE_TEST_ATTACKER_USER, Env:\BASELINE_TEST_ATTACKER_PASSWORD -ErrorAction SilentlyContinue
    Remove-LocalUser -Name $name -ErrorAction SilentlyContinue
    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { Write-Warning "Could not delete the account $name; delete it by hand." }
    else { Write-Output "Deleted the standard user $name." }
}
exit $code
