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

    With -DotNet it releases baseline.exe, the .NET port, instead: it publishes it self-contained
    from this commit, checks that none of our files is signed yet and every other PE file carries
    Microsoft's signature, signs only the .exe and .dll files this repository built (never the
    runtime's), and fails unless every PE file then carries a valid, timestamped signature, ours or
    Microsoft's (tools\Test-ReleaseSignatures.ps1). The signed folder is left in build\release-dotnet,
    where the sign-test sandbox finds it and runs the slice from it.
.PARAMETER AzureMetadata
    The Artifact Signing metadata JSON naming the account, region endpoint and certificate
    profile. Keep it out of the repository; it identifies the signing setup. The login it leaves
    (usually the Azure CLI's, so az login first) is checked before the tests and the build.
.PARAMETER AllowUntrustedChain
    Accept a chain that does not reach a trusted root, which is what a test profile issues. The
    output is marked DO-NOT-PUBLISH.
.PARAMETER SkipPreFlight
    Skip lint and tests. Only for iterating on this script itself.
.PARAMETER ModulePath
    A folder holding Pester and PSScriptAnalyzer, passed to Invoke-PreFlight.ps1.
.PARAMETER DotNet
    Release baseline.exe, whose version is the one in Directory.Build.props, instead of the
    PowerShell module.
.PARAMETER Publisher
    With -DotNet: who our files must be signed by, the organisation in the signing certificate.
.EXAMPLE
    .\tools\New-SignedRelease.ps1 -AzureMetadata C:\keys\artifact-signing.json -ModulePath C:\modules
.EXAMPLE
    .\tools\New-SignedRelease.ps1 -AzureMetadata .\build\test-profile.json -AllowUntrustedChain
.EXAMPLE
    .\tools\New-SignedRelease.ps1 -AzureMetadata C:\keys\artifact-signing.json -DotNet -ModulePath C:\modules
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
    [switch]$AllowDirtyTree,
    [switch]$SkipInstaller,
    [switch]$DotNet,
    [string]$Publisher = 'Engramic Ltd'
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repo
Import-Module (Join-Path $repo 'tools\Release.psm1')
if (-not $OutputPath) { $OutputPath = Join-Path $repo $(if ($DotNet) { 'build\release-dotnet' } else { 'build\release' }) }
if (-not (Test-Path -LiteralPath $AzureMetadata)) { throw "Artifact Signing metadata not found: $AzureMetadata" }
$AzureMetadata = (Resolve-Path -LiteralPath $AzureMetadata).Path

function Write-Step { param([string]$Text) Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }

# --- what exactly is being released ---------------------------------------------------------
$version = if ($DotNet) { Get-ReleaseDotNetVersion -Path (Join-Path $repo 'Directory.Build.props') }
else { (Import-PowerShellDataFile (Join-Path $repo 'src\CEAudit\CEAudit.psd1')).ModuleVersion }
$commit = (& git rev-parse --short HEAD 2>$null)
$dirty = @(& git status --porcelain 2>$null | Where-Object { $_ })
if ($dirty.Count -and -not $AllowDirtyTree) {
    throw ("The working tree has $($dirty.Count) uncommitted change(s), so this build could not be " +
        'reproduced from any commit. Commit them, or pass -AllowDirtyTree for a throwaway build.')
}
# data\config holds config overrides an organisation stages for its own package (docs/INTUNE.md),
# which the build would pack. A release must never carry them, not even a throwaway one.
if (-not $DotNet -and @(Get-ChildItem -LiteralPath (Join-Path $repo 'data') -Recurse -File -Force -ErrorAction SilentlyContinue).Count) {
    throw 'The data folder holds files (config overrides staged for a package), which the build would ship. Move them out of the tree before building a release.'
}
Write-Host ("Product   : {0}" -f $(if ($DotNet) { 'baseline.exe (Directory.Build.props)' } else { 'the PowerShell module' }))
Write-Host ("Version   : {0}" -f $version)
Write-Host ("Commit    : {0}{1}" -f $commit, $(if ($dirty.Count) { ' (DIRTY)' } else { '' }))
Write-Host ("Signing   : {0}" -f $AzureMetadata)
Write-Host ("Output    : {0}" -f $OutputPath)

# Signing comes after the tests and the build, and a login that cannot work fails there only as
# signtool's "internal error". Find that out now, in seconds.
$loginProblem = Get-ReleaseAzureLoginProblem -Path $AzureMetadata
if ($loginProblem) { throw $loginProblem }

# --- the same checks CI would run -------------------------------------------------------------
if (-not $SkipPreFlight) {
    Write-Step 'Lint and tests'
    $preFlightArgs = @{}
    if ($ModulePath) { $preFlightArgs['ModulePath'] = $ModulePath }
    if ($PesterVersion) { $preFlightArgs['PesterVersion'] = $PesterVersion }
    & (Join-Path $repo 'tools\Invoke-PreFlight.ps1') @preFlightArgs
    if ($LASTEXITCODE -ne 0) { throw 'Pre-flight failed, so nothing was built. Fix that before releasing.' }
}

if ($DotNet) {
    # --- baseline.exe, published from this commit ---------------------------------------------------
    # CI is to publish and attest this folder, and this script to verify the attestation before signing
    # it. Until CI attests anything, the folder is published here from the committed tree, with the SDK
    # global.json names and the locked packages, as CI publishes it.
    Write-Step 'Publish baseline.exe'
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw 'dotnet is not on PATH. Install the SDK that global.json names.' }
    $sdk = [string](Get-Content -LiteralPath (Join-Path $repo 'global.json') -Raw | ConvertFrom-Json).sdk.version
    $actualSdk = [string](& dotnet --version)
    if ($actualSdk.Trim() -ne $sdk) { throw "dotnet --version is '$actualSdk', but global.json names $sdk. Install that SDK, as CI does." }
    if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Recurse -Force }
    $payload = Join-Path $OutputPath 'payload'
    & dotnet restore (Join-Path $repo 'Baseline.slnx') --locked-mode | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "The locked restore failed with exit code $LASTEXITCODE, so nothing was built." }
    & dotnet publish (Join-Path $repo 'src\Engramic.Baseline.Cli\Engramic.Baseline.Cli.csproj') --configuration Release --runtime win-x64 `
        --no-restore --output $payload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE." }

    # Before one signature is spent: nothing of ours is signed yet, and every other PE file carries
    # Microsoft's signature already, so signing ours is all this release needs.
    Write-Step 'Check the unsigned build'
    & (Join-Path $repo 'tools\Test-ReleaseSignatures.ps1') -Path $payload -Unsigned

    Write-Step 'Sign the .exe and .dll files this repository built'
    $signArgs = @{ Path = $payload; AzureMetadata = $AzureMetadata; IncludeExtensions = @('.exe', '.dll') }
    if ($AllowUntrustedChain) { $signArgs['AllowUntrustedChain'] = $true }
    & (Join-Path $repo 'tools\Sign-Release.ps1') @signArgs | Out-Host

    # Every PE file, not only the ones just signed: ours by the publisher, the rest by Microsoft, all
    # valid and timestamped.
    Write-Step 'Verify every PE file'
    $checkArgs = @{ Path = $payload; Publisher = $Publisher; PassThru = $true }
    if ($AllowUntrustedChain) { $checkArgs['AllowUntrustedChain'] = $true }
    $rows = @(& (Join-Path $repo 'tools\Test-ReleaseSignatures.ps1') @checkArgs)
    $ours = @($rows | Where-Object { $_.Owner -eq 'ours' })
    $publishable = -not @($ours | Where-Object { $_.Status -ne 'Valid' }).Count
    if (-not $publishable -and -not $AllowUntrustedChain) { throw 'Not every file of ours verifies as Valid, so this build is not releasable.' }

    # The signed build starts, and reports the version it was built as.
    $printed = [string](& (Join-Path $payload 'baseline.exe') --version)
    if ($LASTEXITCODE -ne 0 -or $printed.Trim() -ne $version) {
        throw "The signed baseline.exe --version printed '$printed' with exit code $LASTEXITCODE, not $version."
    }
    Write-Host ("  baseline.exe --version: {0}" -f $printed.Trim())

    Write-Step 'Artefacts'
    $zip = Join-Path $OutputPath "EngramicBaseline-$version-win-x64.zip"
    Compress-Archive -Path (Join-Path $payload '*') -DestinationPath $zip -Force
    $zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    Set-Content -LiteralPath (Join-Path $OutputPath 'SHA256SUMS.txt') -Value ('{0}  {1}' -f $zipHash, (Split-Path -Leaf $zip)) -Encoding ASCII
    Write-Host ("  {0,-42} {1,10:N0} bytes" -f (Split-Path -Leaf $zip), (Get-Item -LiteralPath $zip).Length)
    $signer = [string]$ours[0].Signer
    $org = if ($signer -match 'O=([^,]+)') { $matches[1].Trim() } else { $signer }
    # What the sign-test sandbox reads to check this build on a clean Windows and run it there.
    [ordered]@{
        product        = 'baseline.exe'
        version        = $version
        commit         = [string]$commit
        publisher      = $Publisher
        untrustedChain = (-not $publishable)
        payload        = 'payload'
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputPath 'release.json') -Encoding ASCII
    $notes = @("# Engramic Baseline $version (baseline.exe)", '',
        'baseline.exe is the .NET port of Engramic Baseline, released for testing beside the PowerShell module,',
        'which stays the one to deploy. It audits only the checks ported so far.', '',
        '## Verifying what you downloaded', '',
        "Every one of the $($rows.Count) .exe and .dll files in the zip is Authenticode signed and timestamped: the",
        "$($ours.Count) this repository built by **$org**, and the .NET runtime and package files by Microsoft, as",
        'Microsoft signed them.', '',
        '```powershell',
        'Get-AuthenticodeSignature .\baseline.exe | Format-List Status, SignerCertificate',
        '```', '',
        '## Checksums', '', '```', ('{0}  {1}' -f $zipHash, (Split-Path -Leaf $zip)), '```', '',
        "Built from commit $commit on $(Get-Date -Format 'yyyy-MM-dd').")
    if (-not $publishable) {
        $notes += @('', '## DO NOT PUBLISH', '',
            'Signed with a certificate whose chain does not reach a trusted root. This build proves the pipeline;',
            'it is not a release.')
    }
    Set-Content -LiteralPath (Join-Path $OutputPath 'RELEASE-NOTES.md') -Value ($notes -join "`r`n") -Encoding ASCII

    Write-Host ''
    Write-Host 'To check this build on a clean Windows and run baseline.exe audit --id SU-01 from it:' -ForegroundColor Cyan
    Write-Host '  .\tools\sandbox\New-SandboxRun.ps1 -Environment sign-test'
    Write-Host ''
    if (-not $publishable) {
        Write-Host 'DO NOT PUBLISH: signed by an untrusted chain (a test profile).' -ForegroundColor Yellow
        return
    }
    Write-Host ("Signed build ready in {0}. Nothing has been published. To publish it:" -f $OutputPath) -ForegroundColor Green
    Write-Host ("  git tag v$version")
    Write-Host ("  git push origin v$version")
    Write-Host ("  gh release create v$version{0} --title `"Engramic Baseline $version (baseline.exe)`" --notes-file `"$OutputPath\RELEASE-NOTES.md`" ``" -f $(if ($version -match '-') { ' --prerelease' } else { '' }))
    Write-Host ("      `"$zip`" `"$OutputPath\SHA256SUMS.txt`"")
    return
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

$script:AcceptableInstallerStatus = if ($AllowUntrustedChain) { @('Valid', 'UnknownError', 'NotTrusted') } else { @('Valid') }

# --- the desktop installer ------------------------------------------------------------------------
# Built from the signed payload, so the files inside carry the same signatures a customer can check.
# The MSI is then signed itself: that signature is what Windows shows at the elevation prompt, and
# it is the only thing most people will ever look at.
if (-not $SkipInstaller) {
    Write-Step 'Desktop installer'
    & (Join-Path $repo 'installer\Build-Msi.ps1') -PayloadPath (Join-Path $OutputPath 'payload') `
        -Version $version -OutputPath $OutputPath | Out-Host
    $msiArgs = @{ AzureMetadata = $AzureMetadata; IncludeExtensions = @('.msi') }
    if ($AllowUntrustedChain) { $msiArgs['AllowUntrustedChain'] = $true }
    & (Join-Path $repo 'tools\Sign-Release.ps1') -Path $OutputPath @msiArgs | Out-Host
    $msiFile = @(Get-ChildItem -LiteralPath $OutputPath -Filter '*.msi')
    if ($msiFile.Count -ne 1) { throw "Expected one .msi in $OutputPath, found $($msiFile.Count)." }
    $msiSig = Get-AuthenticodeSignature -LiteralPath $msiFile[0].FullName
    if ($script:AcceptableInstallerStatus -notcontains [string]$msiSig.Status) {
        throw "The installer is not signed acceptably: $($msiSig.Status)."
    }
    if (-not $msiSig.TimeStamperCertificate) { throw 'The installer signature has no timestamp.' }
}

# --- artefacts and their checksums ----------------------------------------------------------------
Write-Step 'Artefacts'
$artefacts = @(Get-ChildItem -LiteralPath $OutputPath -File |
        Where-Object { $_.Extension -in '.intunewin', '.zip', '.md', '.msi' } | Sort-Object Name)
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

# An installer is only described when one was actually built, so the notes never promise a file
# that is not attached.
$msi = @($artefacts | Where-Object { $_.Extension -eq '.msi' }) | Select-Object -First 1
$intuneName = [string](@($artefacts | Where-Object { $_.Extension -eq '.intunewin' }) |
        Select-Object -First 1 -ExpandProperty Name)
Add-Note @("# Engramic Baseline $version", '')
if ($changes.Count) {
    Add-Note @("## What changed since $prevTag", '')
    foreach ($c in $changes) { Add-Note @("- $c") }
    Add-Note @('')
}
Add-Note @('## What to download', '', '| File | Use |', '|---|---|')
if ($msi) {
    Add-Note @(('| `{0}` | Installer for a single PC. Start here if you are installing on your own machine. |' -f $msi.Name))
}
Add-Note @(
    '| `EngramicBaseline-VERSION.intunewin` | Intune Win32 app. Follow `INTUNE-SETTINGS.md` for the exact values to enter. |'.Replace('VERSION', $version),
    '| `EngramicBaseline.zip` | The same payload for RMM, Group Policy or a manual install. |',
    '| `intune-upload-files.zip` | The scripts and JSON that Intune takes as separate uploads. |',
    '| `INTUNE-SETTINGS.md` | Detection rules, install commands and requirements. |',
    '| `SHA256SUMS.txt` | Checksums for everything above. |', '')
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
