#Requires -Version 5.1
<#
.SYNOPSIS
    Fails unless a release tag is "v" and the version of what it releases, exactly.
.DESCRIPTION
    Two things are released from this repository, each with one version:

      the PowerShell module  ModuleVersion in src/CEAudit/CEAudit.psd1, such as 0.3.2 (tag v0.3.2)
      baseline.exe           VersionPrefix and VersionSuffix in Directory.Build.props together, such as
                             1.0.0 and alpha.0 (tag v1.0.0-alpha.0), which every assembly and
                             baseline.exe --version carry

    The tag must equal one of them with the "v" in front, prefix and suffix alike: v1.0.0 does not
    release 1.0.0-alpha.0. A tag for the module is judged as it always was, whatever
    Directory.Build.props holds, and where the repository has none, the module's is the only version.
    .github/workflows/release.yml runs this on every v* tag; it outputs what the tag releases, 'module'
    or 'baseline.exe'.
.PARAMETER Tag
    The tag, such as v0.3.2 or v1.0.0-alpha.0 (GITHUB_REF_NAME in the workflow).
.PARAMETER Root
    The repository. Defaults to the one this script is in.
.EXAMPLE
    .\tools\Test-ReleaseTag.ps1 -Tag v1.0.0-alpha.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Tag,
    [string]$Root
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 leaves $PSScriptRoot empty in parameter defaults, so the default is set here.
if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }
Import-Module (Join-Path $PSScriptRoot 'Release.psm1')

$moduleVersion = [string](Import-PowerShellDataFile -LiteralPath (Join-Path $Root 'src\CEAudit\CEAudit.psd1')).ModuleVersion
$releases = @()
if ($Tag -ceq "v$moduleVersion") {
    Write-Host "Tag $Tag matches the PowerShell module's version, $moduleVersion in src/CEAudit/CEAudit.psd1."
    $releases += 'module'
}

# baseline.exe's version, when there is a .NET solution. A version that cannot be trusted fails a tag for
# baseline.exe, and never one for the module.
$props = Join-Path $Root 'Directory.Build.props'
$dotnetVersion = ''
$dotnetProblem = ''
if (Test-Path -LiteralPath $props -PathType Leaf) {
    try { $dotnetVersion = Get-ReleaseDotNetVersion -Path $props }
    catch { $dotnetProblem = $_.Exception.Message }
}
if ($dotnetVersion -and $Tag -ceq "v$dotnetVersion") {
    Write-Host "Tag $Tag matches baseline.exe's version, $dotnetVersion in Directory.Build.props."
    $releases += 'baseline.exe'
}

if (-not $releases.Count) {
    $versions = "the module's $moduleVersion (src/CEAudit/CEAudit.psd1)"
    if ($dotnetVersion) { $versions += " or baseline.exe's $dotnetVersion (Directory.Build.props)" }
    if ($dotnetProblem) { $versions += ", and baseline.exe's version cannot be read: $dotnetProblem" }
    throw "Tag $Tag does not match $versions. A release tag is v and the version it releases, exactly."
}
$releases
