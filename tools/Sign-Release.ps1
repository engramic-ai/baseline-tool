#Requires -Version 5.1
<#
.SYNOPSIS
    Authenticode-signs the PowerShell a customer actually runs, and fails if any of it is unsigned.
.DESCRIPTION
    Signing happens on an assembled payload, never on the repository working tree, and always
    before IntuneWinAppUtil wraps it: an .intunewin is an encrypted container, so a signature on
    the wrapper proves nothing. Windows and Intune verify the payload.

    PowerShell only checks the file it is launched with, but WDAC and AllSigned tenants need the
    whole engine signed, so every .ps1, .psm1 and .psd1 under -Path is signed, not just the entry
    points. Config, reports and markdown are not signed; they carry no code.

    Every signature is SHA256 and timestamped, so signatures stay valid after the certificate
    expires. Verification is part of signing: the script exits non-zero unless every file it
    signed reports Valid.

    Three ways to supply a certificate:
      -Thumbprint     a certificate already in CurrentUser\My or LocalMachine\My
      -PfxPath        a .pfx, with -PfxPassword as a SecureString
      -AzureMetadata  Azure Artifact Signing, via signtool and the signing dlib. Needs the
                      Artifact Signing Certificate Profile Signer role, and an Endpoint in the
                      metadata matching the account's region or every sign returns 403. Those
                      certificates are valid for three days, so the timestamp is what keeps a
                      signature verifying afterwards.

    A self-signed certificate is for developing and testing this pipeline only. It is refused
    unless -AllowSelfSigned is given, because a self-signed release is worse than an unsigned
    one: it looks signed while being trusted by nobody, and no customer should ever be asked to
    import a .cer.
.PARAMETER Path
    The assembled payload to sign. Mandatory and never defaulted, so this cannot accidentally
    sign your working tree and leave signature blocks in files you then commit.
.PARAMETER VerifyOnly
    Check signatures without signing. Used by Build-IntunePackage.ps1 -RequireSignature.
.EXAMPLE
    .\tools\Sign-Release.ps1 -Path .\build\payload -Thumbprint A1B2C3...
.EXAMPLE
    .\tools\Sign-Release.ps1 -Path .\build\payload -VerifyOnly
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Verify')]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(ParameterSetName = 'Thumbprint', Mandatory)][string]$Thumbprint,
    [Parameter(ParameterSetName = 'Pfx', Mandatory)][string]$PfxPath,
    [Parameter(ParameterSetName = 'Pfx')][SecureString]$PfxPassword,
    [Parameter(ParameterSetName = 'Azure', Mandatory)][string]$AzureMetadata,
    [Parameter(ParameterSetName = 'Azure')][string]$SignToolPath,
    [Parameter(ParameterSetName = 'Azure')][string]$DlibPath,
    [Parameter(ParameterSetName = 'Verify')][switch]$VerifyOnly,
    [string]$TimestampUrl,
    [switch]$AllowSelfSigned
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path)) { throw "Nothing to sign: '$Path' does not exist. Run intune\Build-IntunePackage.ps1 first." }
$root = (Resolve-Path -LiteralPath $Path).Path

# What a customer runs. Tests, sandbox helpers and developer tooling are not shipped and are not
# signed; if one ever ships, add it here deliberately rather than by a wildcard.
# -Include is silently ignored alongside -LiteralPath -Recurse, which would hand every file in the
# payload to the signer, icons and JSON included. Filter on the extension instead.
$signable = @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1' -and $_.FullName -notmatch '\\(tests|sandbox|tools)\\' })
if (-not $signable.Count) { throw "No PowerShell files found under '$root'." }

# A real build must verify as Valid. A declared self-signed test build cannot: nothing chains to a
# trusted root, and installing one needs a consent dialog that no automated run can answer. So for
# -AllowSelfSigned an untrusted chain is the expected result and passes, while a missing signature
# or a tampered file still fails.
$script:AcceptableStatus = if ($AllowSelfSigned) { @('Valid', 'UnknownError', 'NotTrusted') } else { @('Valid') }

function Get-SignatureState {
    param([string]$File)
    $sig = Get-AuthenticodeSignature -LiteralPath $File
    [pscustomobject]@{
        File        = $File
        Status      = [string]$sig.Status
        Signer      = [string]$sig.SignerCertificate.Subject
        Timestamped = [bool]$sig.TimeStamperCertificate
    }
}

# --- verify only -----------------------------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Verify') {
    $states = @($signable | ForEach-Object { Get-SignatureState -File $_.FullName })
    $bad = @($states | Where-Object { $script:AcceptableStatus -notcontains $_.Status })
    $unstamped = @($states | Where-Object { -not $_.Timestamped })
    Write-Host ("Checked {0} file(s) under {1}" -f $states.Count, $root)
    foreach ($b in $bad) { Write-Host ("  {0}: {1}" -f $b.Status, $b.File.Substring($root.Length + 1)) -ForegroundColor Red }
    foreach ($u in $unstamped) { Write-Warning ("not timestamped: " + $u.File.Substring($root.Length + 1)) }
    if ($bad.Count) { throw "$($bad.Count) of $($states.Count) file(s) are not validly signed." }
    Write-Host ("All {0} file(s) signed by {1}" -f $states.Count, ($states[0].Signer)) -ForegroundColor Green
    if ($AllowSelfSigned) { Write-Warning 'Accepted an untrusted chain because -AllowSelfSigned was given. Do not publish this build.' }
    return
}

# --- resolve the certificate ------------------------------------------------------------------
$cert = $null
switch ($PSCmdlet.ParameterSetName) {
    'Thumbprint' {
        $clean = ($Thumbprint -replace '[^0-9A-Fa-f]', '')
        $cert = @(Get-ChildItem -Path 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $clean }) | Select-Object -First 1
        if (-not $cert) { throw "No certificate with thumbprint '$clean' in CurrentUser\My or LocalMachine\My." }
    }
    'Pfx' {
        if (-not (Test-Path -LiteralPath $PfxPath)) { throw "PFX not found: $PfxPath" }
        $cert = if ($PfxPassword) { Get-PfxCertificate -FilePath $PfxPath -Password $PfxPassword } else { Get-PfxCertificate -FilePath $PfxPath }
    }
}

if ($cert) {
    if (-not $cert.HasPrivateKey) { throw "Certificate $($cert.Thumbprint) has no private key, so it cannot sign." }
    $selfSigned = ($cert.Subject -eq $cert.Issuer)
    if ($selfSigned -and -not $AllowSelfSigned) {
        throw ("Refusing to sign with a self-signed certificate ($($cert.Subject)). Windows trusts it nowhere, " +
            'and a release that looks signed but is trusted by nobody is worse than an unsigned one. ' +
            'Pass -AllowSelfSigned only to develop or test this pipeline, never to publish.')
    }
    if ($selfSigned) {
        Write-Warning ('Signing with a SELF-SIGNED certificate. This build is for testing the signing pipeline ' +
            'and must not be published or given to anyone.')
    }
    if ($cert.NotAfter -lt (Get-Date)) { throw "Certificate expired on $($cert.NotAfter)." }
}

if (-not $TimestampUrl) {
    # Azure Artifact Signing has its own timestamp authority; otherwise a public one.
    $TimestampUrl = if ($PSCmdlet.ParameterSetName -eq 'Azure') { 'http://timestamp.acs.microsoft.com' } else { 'http://timestamp.digicert.com' }
}

# --- sign ---------------------------------------------------------------------------------------
Write-Host ("Signing {0} file(s) under {1}" -f $signable.Count, $root)
$failed = New-Object System.Collections.ArrayList

if ($PSCmdlet.ParameterSetName -eq 'Azure') {
    # Artifact Signing signs through signtool and a dlib; the private key never leaves the service.
    # Untested here until a certificate profile exists - the identity validation gates it.
    if (-not $SignToolPath) {
        $SignToolPath = (Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1).FullName
    }
    if (-not $SignToolPath -or -not (Test-Path -LiteralPath $SignToolPath)) { throw 'signtool.exe not found; pass -SignToolPath.' }
    if (-not (Test-Path -LiteralPath $AzureMetadata)) { throw "Artifact Signing metadata not found: $AzureMetadata" }
    # The dlib ships in its own package and does not sit beside metadata.json. The Artifact Signing
    # Client Tools installer (winget Microsoft.Azure.ArtifactSigningClientTools) is the easy route;
    # the NuGet package Microsoft.ArtifactSigning.Client extracted by hand also works. Either way the
    # architecture must match the signtool above, which is x64.
    $dlib = $DlibPath
    if (-not $dlib) {
        $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $PWD.Path) | Where-Object { $_ }
        $found = New-Object System.Collections.ArrayList
        foreach ($r in $roots) {
            $hits = @(Get-ChildItem -LiteralPath $r -Recurse -Filter 'Azure.CodeSigning.Dlib.dll' -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -match '\\x64\\' })
            foreach ($h in $hits) { [void]$found.Add($h.FullName) }
        }
        $dlib = [string](@($found | Sort-Object -Descending) | Select-Object -First 1)
    }
    if (-not $dlib -or -not (Test-Path -LiteralPath $dlib)) {
        throw ('Azure.CodeSigning.Dlib.dll (x64) not found. Install the client tools with ' +
            '"winget install -e --id Microsoft.Azure.ArtifactSigningClientTools", or pass -DlibPath.')
    }
    foreach ($f in $signable) {
        if (-not $PSCmdlet.ShouldProcess($f.FullName, 'Authenticode sign')) { continue }
        & $SignToolPath sign /v /fd SHA256 /tr $TimestampUrl /td SHA256 /dlib $dlib /dmdf $AzureMetadata $f.FullName | Out-Null
        if ($LASTEXITCODE -ne 0) { [void]$failed.Add("signtool exit $LASTEXITCODE for $($f.FullName)") }
    }
}
else {
    foreach ($f in $signable) {
        if (-not $PSCmdlet.ShouldProcess($f.FullName, 'Authenticode sign')) { continue }
        $r = Set-AuthenticodeSignature -LiteralPath $f.FullName -Certificate $cert -HashAlgorithm SHA256 `
            -TimestampServer $TimestampUrl -IncludeChain NotRoot -ErrorAction Continue
        # Same rule as the verification below: a declared test build cannot chain to a trusted root.
        if ($script:AcceptableStatus -notcontains $r.Status) { [void]$failed.Add("$($r.Status) for $($f.FullName)") }
    }
}

if ($WhatIfPreference) { return }

# --- verify what we just did --------------------------------------------------------------------
$states = @($signable | ForEach-Object { Get-SignatureState -File $_.FullName })
$bad = @($states | Where-Object { $script:AcceptableStatus -notcontains $_.Status })
$unstamped = @($states | Where-Object { -not $_.Timestamped })
foreach ($b in $bad) { Write-Host ("  {0}: {1}" -f $b.Status, $b.File.Substring($root.Length + 1)) -ForegroundColor Red }
foreach ($u in $unstamped) { Write-Warning ('not timestamped: ' + $u.File.Substring($root.Length + 1)) }
if ($failed.Count -or $bad.Count) {
    throw ("Signing failed for {0} file(s); {1} do not verify. " -f $failed.Count, $bad.Count) + ($failed | Select-Object -First 3 | Out-String)
}
Write-Host ("Signed and verified {0} file(s) as {1}" -f $states.Count, $states[0].Signer) -ForegroundColor Green
if ($AllowSelfSigned) { Write-Warning 'This build is signed by an untrusted self-signed certificate and must not be published.' }
if ($unstamped.Count) { Write-Warning "$($unstamped.Count) signature(s) have no timestamp and will stop verifying when the certificate expires." }
