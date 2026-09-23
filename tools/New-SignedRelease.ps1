#Requires -Version 5.1
<#
.SYNOPSIS
    Builds a signed release on this machine, ready to upload.
.DESCRIPTION
    Release signing happens here rather than in GitHub Actions because the signing identity is a
    maintainer's own Azure login. Wiring it into CI needs a federated credential and a decision
    about who may trigger a signed build; until then this script is the whole release path.

    It assembles the payload, signs every shipped .ps1, .psm1 and .psd1 in it, packs the Intune
    and zip artefacts from the signed files, then verifies the result and records a checksum for
    each artefact. It does not publish anything: it prints the command that would, so the person
    running it decides.

    A release is only publishable when every signature verifies as Valid. An Artifact Signing
    Public Trust Test profile cannot reach that, by design, so -AllowUntrustedChain produces a
    build marked DO-NOT-PUBLISH and refuses to print a publish command.
.PARAMETER AzureMetadata
    The Artifact Signing metadata JSON naming the account, region endpoint and certificate
    profile. Keep it out of the repository; it identifies the signing setup.
.PARAMETER AllowUntrustedChain
    Accept a chain that does not reach a trusted root, which is what a test profile issues. The
    output is marked DO-NOT-PUBLISH.
.PARAMETER SkipPreFlight
    Skip lint and tests. Only for iterating on this script itself.
.PARAMETER ModulePath
    A folder holding Pester and PSScriptAnalyzer, passed to Invoke-PreFlight.ps1.
.EXAMPLE
    .\tools\New-SignedRelease.ps1 -AzureMetadata C:\keys\artifact-signing.json -ModulePath C:\modules
.EXAMPLE
    .\tools\New-SignedRelease.ps1 -AzureMetadata .\build\test-profile.json -AllowUntrustedChain
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AzureMetadata,
    [string]$OutputPath,
    [switch]$AllowUntrustedChain,
    [switch]$SkipPreFlight,
    # Passed straight to Invoke-PreFlight.ps1. Needed when Pester and PSScriptAnalyzer are kept in
    # a folder of their own rather than installed, which is how this repo pins the versions CI uses.
    [string]$ModulePath,
    [string]$PesterVersion,
    [switch]$AllowDirtyTree
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repo
if (-not $OutputPath) { $OutputPath = Join-Path $repo 'build\release' }
if (-not (Test-Path -LiteralPath $AzureMetadata)) { throw "Artifact Signing metadata not found: $AzureMetadata" }
$AzureMetadata = (Resolve-Path -LiteralPath $AzureMetadata).Path

function Write-Step { param([string]$Text) Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }

# --- what exactly is being released ---------------------------------------------------------
$version = (Import-PowerShellDataFile (Join-Path $repo 'src\CEAudit\CEAudit.psd1')).ModuleVersion
$commit = (& git rev-parse --short HEAD 2>$null)
$dirty = @(& git status --porcelain 2>$null | Where-Object { $_ })
if ($dirty.Count -and -not $AllowDirtyTree) {
    throw ("The working tree has $($dirty.Count) uncommitted change(s), so this build could not be " +
        'reproduced from any commit. Commit them, or pass -AllowDirtyTree for a throwaway build.')
}
Write-Host ("Version   : {0}" -f $version)
Write-Host ("Commit    : {0}{1}" -f $commit, $(if ($dirty.Count) { ' (DIRTY)' } else { '' }))
Write-Host ("Signing   : {0}" -f $AzureMetadata)
Write-Host ("Output    : {0}" -f $OutputPath)

# The Azure CLI credential shells out to az, and a shell whose PATH predates installing the CLI
# fails with "Azure CLI not installed", which signtool reports only as an internal error.
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Warning 'az is not on PATH for this process. If signing fails with an internal error, that is why: open a new shell.'
}

# --- the same checks CI would run -------------------------------------------------------------
if (-not $SkipPreFlight) {
    Write-Step 'Lint and tests'
    $preFlightArgs = @{}
    if ($ModulePath) { $preFlightArgs['ModulePath'] = $ModulePath }
    if ($PesterVersion) { $preFlightArgs['PesterVersion'] = $PesterVersion }
    & (Join-Path $repo 'tools\Invoke-PreFlight.ps1') @preFlightArgs
    if ($LASTEXITCODE -ne 0) { throw 'Pre-flight failed, so nothing was built. Fix that before releasing.' }
}

# --- build, signing the payload before anything wraps it ---------------------------------------
Write-Step 'Build and sign'
if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Recurse -Force }
$buildArgs = @{
    OutputPath        = $OutputPath
    DownloadTool      = $true
    SignAzureMetadata = $AzureMetadata
    RequireSignature  = $true
}
if ($AllowUntrustedChain) { $buildArgs['AllowUntrustedChain'] = $true }
& (Join-Path $repo 'intune\Build-IntunePackage.ps1') @buildArgs | Out-Host

$uploadDir = Join-Path $OutputPath 'upload'
$uploadZip = Join-Path $OutputPath 'intune-upload-files.zip'
Compress-Archive -Path (Join-Path $uploadDir '*') -DestinationPath $uploadZip -Force

# --- verify what is actually going out ----------------------------------------------------------
Write-Step 'Verify every shipped signature'
$signed = @(Get-ChildItem -LiteralPath (Join-Path $OutputPath 'payload') -Recurse -File |
        Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1' })
$signed += @(Get-ChildItem -LiteralPath $uploadDir -File | Where-Object { $_.Extension -eq '.ps1' })
$states = @($signed | ForEach-Object { Get-AuthenticodeSignature -LiteralPath $_.FullName })
$valid = @($states | Where-Object { $_.Status -eq 'Valid' }).Count
$stamped = @($states | Where-Object { $_.TimeStamperCertificate }).Count
$unsigned = @($states | Where-Object { $_.Status -eq 'NotSigned' }).Count
$signer = if ($states.Count) { [string]$states[0].SignerCertificate.Subject } else { '(none)' }
Write-Host ("  files signed : {0}" -f $states.Count)
Write-Host ("  verify Valid : {0}" -f $valid)
Write-Host ("  timestamped  : {0}" -f $stamped)
Write-Host ("  unsigned     : {0}" -f $unsigned)
if ($unsigned -or -not $states.Count) { throw "$unsigned file(s) went unsigned; this is not releasable." }
if ($stamped -ne $states.Count) {
    throw ("$($states.Count - $stamped) signature(s) have no timestamp. They stop verifying when the " +
        'certificate expires, which for Artifact Signing is three days.')
}
$publishable = ($valid -eq $states.Count)
if (-not $publishable -and -not $AllowUntrustedChain) {
    throw "Only $valid of $($states.Count) file(s) verify as Valid, so this build is not releasable."
}

# --- artefacts and their checksums ----------------------------------------------------------------
Write-Step 'Artefacts'
$artefacts = @(Get-ChildItem -LiteralPath $OutputPath -File |
        Where-Object { $_.Extension -in '.intunewin', '.zip', '.md' } | Sort-Object Name)
$sums = foreach ($a in $artefacts) {
    $h = (Get-FileHash -LiteralPath $a.FullName -Algorithm SHA256).Hash
    Write-Host ("  {0,-42} {1,10:N0} bytes" -f $a.Name, $a.Length)
    '{0}  {1}' -f $h, $a.Name
}
Set-Content -LiteralPath (Join-Path $OutputPath 'SHA256SUMS.txt') -Value $sums -Encoding ASCII

# The certificate subject carries the registered address. That belongs in the signature, where
# anyone who wants it can read it, not on a public release page. Name the organisation instead.
$org = if ($signer -match 'O=([^,]+)') { $matches[1].Trim() } else { $signer }
$issuer = if ($states.Count) { [string]$states[0].SignerCertificate.Issuer } else { '' }
$issuerCn = if ($issuer -match 'CN=([^,]+)') { $matches[1].Trim() } else { $issuer }
$thumb = if ($states.Count) { [string]$states[0].SignerCertificate.Thumbprint } else { '' }

# What changed, taken from the commits since the last tag. Merges are left out: their subjects name
# a branch, while the commits themselves say what was done.
$prevTag = @(& git tag --list 'v*' --sort=-v:refname 2>$null |
        Where-Object { $_ -and $_ -ne "v$version" }) | Select-Object -First 1
$changes = @()
if ($prevTag) { $changes = @(& git log "$prevTag..HEAD" --no-merges --format=%s 2>$null | Where-Object { $_ }) }

$notes = New-Object System.Collections.ArrayList
function Add-Note { param([string[]]$Lines) foreach ($l in $Lines) { [void]$notes.Add($l) } }

Add-Note @("# Engramic Baseline $version", '')
if ($changes.Count) {
    Add-Note @("## What changed since $prevTag", '')
    foreach ($c in $changes) { Add-Note @("- $c") }
    Add-Note @('')
}
Add-Note @('## What to download', '',
    '| File | Use |', '|---|---|',
    '| `EngramicBaseline-VERSION.intunewin` | Intune Win32 app. Follow `INTUNE-SETTINGS.md` for the exact values to enter. |'.Replace('VERSION', $version),
    '| `EngramicBaseline.zip` | The same payload for RMM, Group Policy or a manual install. |',
    '| `intune-upload-files.zip` | The scripts and JSON that Intune takes as separate uploads. |',
    '| `INTUNE-SETTINGS.md` | Detection rules, install commands and requirements. |',
    '| `SHA256SUMS.txt` | Checksums for everything above. |', '')
# An installer is only described when one was actually built, so the notes never promise a file
# that is not attached.
$msi = @($artefacts | Where-Object { $_.Extension -eq '.msi' }) | Select-Object -First 1
$intuneName = [string](@($artefacts | Where-Object { $_.Extension -eq '.intunewin' }) |
        Select-Object -First 1 -ExpandProperty Name)
Add-Note @('## Installing', '')
Add-Note @('### On your own PC', '')
if ($msi) {
    Add-Note @("Download ``$($msi.Name)`` and run it. It installs to Program Files and adds a Start menu",
        'entry. Windows will show Engramic Ltd as the publisher.', '')
}
else {
    Add-Note @('Download `EngramicBaseline.zip`. Before extracting it, right-click the file, choose Properties,',
        'and tick Unblock, or Windows treats everything inside as downloaded from the internet.', '',
        'Extract it somewhere of your choosing and run `app\Start-EB.cmd` to open the desktop app. Auditing',
        'reads only; nothing is changed until you apply a fix, and every fix can be rolled back.', '')
}
Add-Note @('### Across a fleet', '',
    "Use ``$(if ($intuneName) { $intuneName } else { 'the .intunewin package' })`` with Intune as a Win32 app.",
    '`INTUNE-SETTINGS.md` lists the exact values to enter, including the detection rules. Upload the',
    'scripts in `intune-upload-files.zip` separately for compliance and remediation.', '',
    'Because everything is signed, you can set **Enforce script signature check** to Yes.', '')
Add-Note @('### From PowerShell', '',
    'Extract the zip and import the module directly:', '',
    '```powershell',
    'Import-Module .\src\CEAudit\CEAudit.psd1',
    'Invoke-CEAudit',
    '```', '')
Add-Note @('## Verifying what you downloaded', '',
    "Every one of the $($states.Count) PowerShell files in this release is Authenticode signed and timestamped,",
    'so the signatures keep verifying after the signing certificate expires.', '',
    "- Signed by **$org**", "- Issued by $issuerCn", ('- Certificate thumbprint `{0}`' -f $thumb), '',
    'Unpack the zip and check any script for yourself:', '',
    '```powershell',
    'Get-AuthenticodeSignature .\src\CEAudit\CEAudit.psm1 | Format-List Status, SignerCertificate',
    '```', '',
    'A trustworthy copy reports `Valid`. Anything else means the file was altered after signing, or',
    'did not come from us.', '')
Add-Note @('## Checksums', '', '```')
foreach ($line in $sums) { Add-Note @($line) }
Add-Note @('```', '', "Built from commit $commit on $(Get-Date -Format 'yyyy-MM-dd').")

if (-not $publishable) {
    Add-Note @('', '## DO NOT PUBLISH', '',
        'Signed with a certificate whose chain does not reach a trusted root, which is what an',
        'Artifact Signing Public Trust Test profile issues. This build proves the pipeline. It is',
        'not a release: Windows will report the signature as untrusted on every customer machine.')
}
# ASCII, not UTF8: Windows PowerShell writes a byte order mark with -Encoding UTF8, and this file
# gets uploaded as release notes where the mark shows up as stray characters.
Set-Content -LiteralPath (Join-Path $OutputPath 'RELEASE-NOTES.md') -Value ($notes.ToArray() -join "`r`n") -Encoding ASCII

# --- what to do next -------------------------------------------------------------------------------
Write-Host ''
if (-not $publishable) {
    Write-Host 'DO NOT PUBLISH: signed by an untrusted chain (a test profile).' -ForegroundColor Yellow
    Write-Host 'The pipeline is proven. Re-run against a Public Trust profile to make a real release.' -ForegroundColor Yellow
    return
}
Write-Host ("Signed release ready in {0}" -f $OutputPath) -ForegroundColor Green
Write-Host 'Nothing has been published. To publish it, tag the commit and upload these artefacts:' -ForegroundColor Cyan
Write-Host ''
# Not "git tag ... && git push ...": && is a parse error in Windows PowerShell 5.1, which this
# repo still supports, so the printed commands have to run in either shell.
Write-Host ("  git tag v$version")
Write-Host ("  git push origin v$version")
Write-Host ("  gh release create v$version --title `"Engramic Baseline $version`" --notes-file `"$OutputPath\RELEASE-NOTES.md`" ``")
foreach ($a in $artefacts) { Write-Host ("      `"$($a.FullName)`" ``") }
Write-Host ("      `"$OutputPath\SHA256SUMS.txt`"")
Write-Host ''
Write-Host 'Pushing the tag publishes nothing: release.yml only checks the tag against the module' -ForegroundColor Yellow
Write-Host 'version. The release is created from the files above, by you, with the command above.' -ForegroundColor Yellow
Write-Host 'Tag the commit these artefacts were built from, not whatever main has moved on to.' -ForegroundColor Yellow
