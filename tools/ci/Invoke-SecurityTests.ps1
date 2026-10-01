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
    Users and not Administrators. It runs the built tests with dotnet test, as CI's other jobs do, filtered to the
    suite, with the account's name and password in BASELINE_TEST_ATTACKER_USER and
    BASELINE_TEST_ATTACKER_PASSWORD, which only that run sees, and deletes the account afterwards, whatever
    happened. Without the account, those tests skip.

    The test project's own settings apply, as in any run of it: the hang dump, so a hung test fails the run, and
    at least one test expected, so a filter that matches nothing fails it too.

.PARAMETER Dotnet
    The full path of dotnet.exe, from the SDK the tests were built with (global.json).

.PARAMETER Project
    The test project, built in Release. Default: tests\Engramic.Baseline.Windows.Tests.

.PARAMETER ResultsPath
    The folder the test platform writes its results, and any hang dump, into.

.OUTPUTS
    The test platform's output. The exit code is dotnet test's: 0 when every test passed or skipped.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\Invoke-SecurityTests.ps1 -Dotnet 'C:\Program Files\dotnet\dotnet.exe' -ResultsPath C:\security
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Dotnet,
    # No default here: Windows PowerShell 5.1 leaves $PSScriptRoot empty in an advanced script's parameter
    # defaults when it is run with -File, as the SYSTEM run is. It is filled in below.
    [string]$Project,
    [Parameter(Mandatory = $true)][string]$ResultsPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $Project) { $Project = Join-Path $repoRoot 'tests\Engramic.Baseline.Windows.Tests\Engramic.Baseline.Windows.Tests.csproj' }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this as an elevated administrator or SYSTEM: it creates a local account, and the tests act as it.'
}
foreach ($file in @($Dotnet, $Project)) {
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
    # As SYSTEM too: no first-run text or telemetry, and no build node left running once the run ends.
    $env:DOTNET_NOLOGO = 'true'
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = 'true'
    $env:TESTINGPLATFORM_TELEMETRY_OPTOUT = '1'
    $env:MSBUILDDISABLENODEREUSE = '1'

    # From the repository's root, where global.json names the SDK and the test runner.
    Push-Location -LiteralPath $repoRoot
    try {
        $arguments = @('test', '--project', $Project, '--configuration', 'Release', '--no-build', '--results-directory', $ResultsPath,
            '--', '--filter-trait', 'Suite=Security')
        # Windows PowerShell turns each line a native program writes to standard error into an error record,
        # which would stop the script; they are the test platform's output like any other.
        $ErrorActionPreference = 'Continue'
        & $Dotnet @arguments 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
    }
    finally { Pop-Location }
}
finally {
    Remove-Item -LiteralPath Env:\BASELINE_TEST_ATTACKER_USER, Env:\BASELINE_TEST_ATTACKER_PASSWORD -ErrorAction SilentlyContinue
    Remove-LocalUser -Name $name -ErrorAction SilentlyContinue
    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { Write-Warning "Could not delete the account $name; delete it by hand." }
    else { Write-Output "Deleted the standard user $name." }
}
exit $code
