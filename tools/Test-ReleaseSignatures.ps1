#Requires -Version 5.1
<#
.SYNOPSIS
    Fails unless every PE file in a folder carries a valid, timestamped Authenticode signature: ours on what
    this repository built, Microsoft's on everything else.
.DESCRIPTION
    Run on the published baseline.exe folder, where every .exe and .dll, and any other file with a PE header,
    must be signed in the file itself and timestamped, so the signature outlives the certificate:

      ours         the files this repository built, as the publish's .deps.json names them (the assemblies of
                   its own projects, and the launcher, baseline.exe). Signed by -Publisher or -Thumbprint.
      Microsoft's  everything else: the .NET runtime and the package assemblies, exactly as Microsoft signed
                   them. A file of ours signed a second time, or signed by anyone else, fails.

    Every problem is reported, one line per file, before it throws. tools\New-SignedRelease.ps1 -DotNet runs it
    on the signed build, CI runs it with -Unsigned on what it publishes, and the sign-test sandbox runs both.
.PARAMETER Path
    The published folder.
.PARAMETER Publisher
    Who our files are signed by: the organisation (O=) in the signing certificate's subject, or its common
    name (CN=) when it has no organisation. Artifact Signing issues a new certificate every few days, so a
    release names the publisher rather than a certificate.
.PARAMETER Thumbprint
    Instead of -Publisher: the certificate our files are signed with, such as a throwaway test certificate.
.PARAMETER AllowUntrustedChain
    Accept a chain that ends in a root this machine does not trust on our files, as a self-signed test
    certificate or an Artifact Signing test profile gives. Microsoft's files must verify as Valid regardless.
.PARAMETER Unsigned
    The folder is not signed yet, as CI publishes it: our files must carry no signature at all, and every other
    PE file must still carry Microsoft's. This is what makes signing ours enough for a release.
.PARAMETER PassThru
    Also return one row for each PE file.
.EXAMPLE
    .\tools\Test-ReleaseSignatures.ps1 -Path .\build\release-dotnet\payload -Publisher 'Engramic Ltd'
.EXAMPLE
    .\tools\Test-ReleaseSignatures.ps1 -Path $env:RUNNER_TEMP\baseline -Unsigned
#>
[CmdletBinding(DefaultParameterSetName = 'Publisher')]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(ParameterSetName = 'Publisher', Mandatory)][string]$Publisher,
    [Parameter(ParameterSetName = 'Thumbprint', Mandatory)][string[]]$Thumbprint,
    [Parameter(ParameterSetName = 'Publisher')]
    [Parameter(ParameterSetName = 'Thumbprint')]
    [switch]$AllowUntrustedChain,
    [Parameter(ParameterSetName = 'Unsigned', Mandatory)][switch]$Unsigned,
    [switch]$PassThru
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Release.psm1')

if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "There is no folder '$Path' to check." }
$root = (Resolve-Path -LiteralPath $Path).ProviderPath

$reportArgs = @{ Path = $root }
switch ($PSCmdlet.ParameterSetName) {
    'Publisher' { $reportArgs['Publisher'] = $Publisher }
    'Thumbprint' { $reportArgs['Thumbprint'] = $Thumbprint }
    'Unsigned' { $reportArgs['Unsigned'] = $true }
}
if ($AllowUntrustedChain) { $reportArgs['AllowUntrustedChain'] = $true }
$rows = @(Get-ReleaseSignatureReport @reportArgs)
if (-not $rows.Count) { throw "There are no PE files under '$root'. Point at the folder dotnet publish wrote." }

$ours = @($rows | Where-Object { $_.Owner -eq 'ours' })
$theirs = @($rows | Where-Object { $_.Owner -ne 'ours' })
$bad = @($rows | Where-Object { $_.Problems.Count })
Write-Host ("Checked {0} PE file(s) under {1}" -f $rows.Count, $root)
if ($Unsigned) { Write-Host ("  ours      : {0}, which must not be signed yet" -f $ours.Count) }
else {
    $signers = @($ours | Where-Object { $_.Thumbprint } | ForEach-Object { '{0} ({1})' -f $_.Signer, $_.Thumbprint } | Sort-Object -Unique)
    Write-Host ("  ours      : {0}, signed by {1}" -f $ours.Count, $(if ($signers.Count) { $signers -join '; ' } else { '(nobody)' }))
}
Write-Host ("  Microsoft : {0}" -f $theirs.Count)
foreach ($row in $bad) {
    Write-Host ("  [{0}] {1}: {2}" -f $row.Owner, $row.File, ($row.Problems -join '; ')) -ForegroundColor Red
}
if ($PassThru) { $rows }
if ($bad.Count) {
    throw ("{0} of {1} PE file(s) under {2} are not signed as a release needs." -f $bad.Count, $rows.Count, $root)
}
if ($Unsigned) {
    Write-Host ("None of the {0} file(s) this repository built is signed yet, and the other {1} carry Microsoft's valid, timestamped signature." -f $ours.Count, $theirs.Count) -ForegroundColor Green
}
elseif ($AllowUntrustedChain) {
    Write-Host ("All {0} PE file(s) carry a timestamped signature: ours on the {1} this repository built, Microsoft's valid one on the other {2}." -f $rows.Count, $ours.Count, $theirs.Count) -ForegroundColor Green
    Write-Warning 'Accepted a chain this machine does not trust on our files (-AllowUntrustedChain). Do not publish this build.'
}
else {
    Write-Host ("All {0} PE file(s) carry a valid, timestamped signature: ours on the {1} this repository built, Microsoft's on the other {2}." -f $rows.Count, $ours.Count, $theirs.Count) -ForegroundColor Green
}
