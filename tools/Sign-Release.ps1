#Requires -Version 5.1
<#
.SYNOPSIS
    Authenticode-signs what a customer actually runs, and fails if any of it is unsigned.
.DESCRIPTION
    Signing happens on an assembled payload, never on the repository working tree, and always
    before IntuneWinAppUtil wraps it: an .intunewin is an encrypted container, so a signature on
    the wrapper proves nothing. Windows and Intune verify the payload.

    PowerShell only checks the file it is launched with, but WDAC and AllSigned tenants need the
    whole engine signed, so every .ps1, .psm1 and .psd1 under -Path is signed, not just the entry
    points. Config, reports and markdown are not signed; they carry no code.

    With .exe and .dll in -IncludeExtensions it signs a published .NET folder, but only the PE files
    this repository built: the assemblies of its own projects and the launcher, as the .deps.json
    that dotnet publish wrote names them (tools\Release.psm1). The .NET runtime and the package
    assemblies keep Microsoft's signature and are never signed again: a PE file chosen for signing
    that already carries any signature is refused, not overwritten. A PE signature must also be
    timestamped, or signing fails. tools\Test-ReleaseSignatures.ps1 then checks every PE file in
    the folder, ours and Microsoft's.

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
                      signature verifying afterwards. Unless the metadata carries an AccessToken
                      or excludes AzureCliCredential, sign in with az login first: this checks
                      the login before signing anything.

    -Thumbprint and -PfxPath sign scripts and PE files with Set-AuthenticodeSignature. An installer
    (.msi) needs the Azure path, which signs everything with signtool.

    A self-signed certificate is for developing and testing this pipeline only. It is refused
    unless -AllowSelfSigned is given, because a self-signed release is worse than an unsigned
    one: it looks signed while being trusted by nobody, and no customer should ever be asked to
    import a .cer.
.PARAMETER Path
    The assembled payload to sign. Mandatory and never defaulted, so this cannot accidentally
    sign your working tree and leave signature blocks in files you then commit.
.PARAMETER AllowUntrustedChain
    Accept a signature whose chain does not reach a trusted root. An Artifact Signing Public
    Trust Test profile issues exactly that, so use it to exercise this pipeline against the real
    service without producing a release anyone should install.
.PARAMETER VerifyOnly
    Check signatures without signing. Used by Build-IntunePackage.ps1 -RequireSignature.
.PARAMETER IncludeExtensions
    What to sign: .ps1, .psm1 and .psd1 by default. Add .exe and .dll for a published .NET folder,
    of which only this repository's files are signed, or .msi for the installer (Azure only).
.EXAMPLE
    .\tools\Sign-Release.ps1 -Path .\build\payload -Thumbprint A1B2C3...
.EXAMPLE
    .\tools\Sign-Release.ps1 -Path .\build\payload -VerifyOnly
.EXAMPLE
    .\tools\Sign-Release.ps1 -Path .\build\release-dotnet\payload -AzureMetadata C:\keys\artifact-signing.json -IncludeExtensions .exe, .dll
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
    [switch]$AllowSelfSigned,
    [switch]$AllowUntrustedChain,
    # Defaults to the PowerShell a customer runs. An installer is signed by adding '.msi', which
    # only the Azure path can do: signtool handles MSI, Set-AuthenticodeSignature does not. '.exe'
    # and '.dll' sign the PE files of a published .NET folder that this repository built.
    [string[]]$IncludeExtensions = @('.ps1', '.psm1', '.psd1')
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Release.psm1')

if (-not (Test-Path -LiteralPath $Path)) { throw "Nothing to sign: '$Path' does not exist. Run intune\Build-IntunePackage.ps1 first." }
$root = (Resolve-Path -LiteralPath $Path).ProviderPath.TrimEnd('\')
$scriptExtensions = @('.ps1', '.psm1', '.psd1')
$peExtensions = @('.exe', '.dll')

# What a customer runs. Tests, sandbox helpers and developer tooling are not shipped and are not
# signed; if one ever ships, add it here deliberately rather than by a wildcard.
# -Include is silently ignored alongside -LiteralPath -Recurse, which would hand every file in the
# payload to the signer, icons and JSON included. Filter on the extension instead.
$signable = @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in $IncludeExtensions -and $_.FullName.Substring($root.Length) -notmatch '\\(tests|sandbox|tools)\\' })

# PE files are signed only when this repository built them, as the publish's .deps.json says. The rest,
# the .NET runtime and the package assemblies, ship with Microsoft's signature, which must never be
# replaced by ours: tools\Test-ReleaseSignatures.ps1 fails a release where it is.
$leftAlone = @()
if (@($IncludeExtensions | Where-Object { $peExtensions -contains $_ }).Count) {
    $own = @{}
    foreach ($file in @(Get-ReleaseOwnFile -Path $root)) { $own[$file] = $true }
    $leftAlone = @($signable | Where-Object { $peExtensions -contains $_.Extension -and -not $own.ContainsKey($_.FullName) })
    $signable = @($signable | Where-Object { $peExtensions -notcontains $_.Extension -or $own.ContainsKey($_.FullName) })
}
if (-not $signable.Count) { throw ("No files matching {0} found under '{1}'." -f ($IncludeExtensions -join ', '), $root) }
$signToolOnly = @($signable | Where-Object { ($scriptExtensions + $peExtensions) -notcontains $_.Extension })
if ($signToolOnly.Count -and $PSCmdlet.ParameterSetName -notin 'Azure', 'Verify') {
    throw ('Only the Azure path can sign ' + ((@($signToolOnly | ForEach-Object { $_.Extension }) | Sort-Object -Unique) -join ', ') +
        ": signtool handles them and Set-AuthenticodeSignature does not.")
}

# A real build must verify as Valid. A declared self-signed test build cannot: nothing chains to a
# trusted root, and installing one needs a consent dialog that no automated run can answer. So for
# -AllowSelfSigned an untrusted chain is the expected result and passes, while a missing signature
# or a tampered file still fails.
$script:AcceptableStatus = if ($AllowSelfSigned -or $AllowUntrustedChain) { @('Valid', 'UnknownError', 'NotTrusted') } else { @('Valid') }

function Get-SignatureState {
    param([string]$File)
    $sig = Get-ReleaseSignature -LiteralPath $File
    [pscustomobject]@{
        File        = $File
        Status      = $sig.Status
        Signer      = $sig.Subject
        Timestamped = $sig.Timestamped
        # A PE signature without a timestamp fails: it would stop verifying when the certificate expires.
        IsPE        = ($peExtensions -contains [IO.Path]::GetExtension($File))
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
    $unstampedPE = @($unstamped | Where-Object { $_.IsPE })
    if ($unstampedPE.Count) { throw "$($unstampedPE.Count) PE file(s) are signed without a timestamp, so their signatures stop verifying when the certificate expires." }
    Write-Host ("All {0} file(s) signed by {1}" -f $states.Count, ($states[0].Signer)) -ForegroundColor Green
    if ($AllowSelfSigned -or $AllowUntrustedChain) { Write-Warning 'Accepted an untrusted chain because -AllowSelfSigned was given. Do not publish this build.' }
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
# A PE file of ours comes straight from the build, unsigned. One that carries a signature is not what
# this run built, or was signed already; either way it is left as it is rather than signed over.
foreach ($f in @($signable | Where-Object { $peExtensions -contains $_.Extension })) {
    $existing = Get-ReleaseSignature -LiteralPath $f.FullName
    if ($existing.Status -ne 'NotSigned') {
        throw ("Refusing to sign {0}: it already carries a signature ({1}, by {2}). Only a file this repository has " +
            'just built is signed, so no signature is ever replaced; publish the folder again.') -f $f.FullName, $existing.Status, $existing.Subject
    }
}
if ($leftAlone.Count) {
    Write-Host ("Leaving {0} PE file(s) as their publisher signed them: the .NET runtime and the package assemblies." -f $leftAlone.Count)
}
Write-Host ("Signing {0} file(s) under {1}" -f $signable.Count, $root)
$failed = New-Object System.Collections.ArrayList

if ($PSCmdlet.ParameterSetName -eq 'Azure') {
    # Artifact Signing signs through signtool and a dlib; the private key never leaves the service.
    # Untested here until a certificate profile exists - the identity validation gates it.
    if (-not $SignToolPath) {
        $newest = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
        if ($newest) { $SignToolPath = $newest.FullName }
    }
    if (-not $SignToolPath -or -not (Test-Path -LiteralPath $SignToolPath)) { throw 'signtool.exe not found; pass -SignToolPath.' }
    if (-not (Test-Path -LiteralPath $AzureMetadata)) { throw "Artifact Signing metadata not found: $AzureMetadata" }
    # signtool does not necessarily share our working directory, so hand it a full path.
    $AzureMetadata = (Resolve-Path -LiteralPath $AzureMetadata).Path
    # DefaultAzureCredential walks a chain of credential types and some of them block for a long
    # time off-Azure: the managed identity probe waits on an endpoint that only exists in Azure,
    # and the interactive one waits with no window. That looks exactly like a hung signtool. Name
    # the ones to skip in the metadata's ExcludeCredentials so only the intended login is tried.
    $meta = Get-Content -LiteralPath $AzureMetadata -Raw
    # A login that cannot work - az missing from this window's PATH, or signed out - fails in
    # signtool only as an internal error, once for every file. Say it plainly, before signing any.
    $loginProblem = Get-ReleaseAzureLoginProblem -Path $AzureMetadata
    if ($loginProblem) { throw $loginProblem }
    if ($meta -notmatch 'ExcludeCredentials') {
        Write-Warning ("$AzureMetadata has no ExcludeCredentials list. If signing hangs with no output, " +
            "that is the credential chain blocking, not the service.")
    }
    # The dlib ships in its own package and does not sit beside metadata.json. The Artifact Signing
    # Client Tools installer (winget Microsoft.Azure.ArtifactSigningClientTools) is the easy route;
    # the NuGet package Microsoft.ArtifactSigning.Client extracted by hand also works. Either way the
    # architecture must match the signtool above, which is x64.
    $dlib = $DlibPath
    if (-not $dlib) {
        # The client tools MSI installs a flat folder under LocalAppData; only the NuGet package has
        # x64\ and x86\ subfolders. Look in the MSI location first so this does not sweep Program
        # Files on every run, and stop at the first root that has a copy.
        $roots = @((Join-Path $env:LOCALAPPDATA 'Microsoft\MicrosoftArtifactSigningClientTools'),
            $PWD.Path, $env:ProgramFiles, ${env:ProgramFiles(x86)}) |
            Where-Object { $_ -and (Test-Path -LiteralPath $_) }
        $found = New-Object System.Collections.ArrayList
        foreach ($r in $roots) {
            $hits = @(Get-ChildItem -LiteralPath $r -Recurse -Filter 'Azure.CodeSigning.Dlib.dll' -ErrorAction SilentlyContinue)
            foreach ($h in $hits) { [void]$found.Add($h.FullName) }
            if ($found.Count) { break }
        }
        # Match the x64 signtool chosen above when the layout offers a choice.
        $x64 = @($found | Where-Object { $_ -match '\\x64\\' })
        $pick = @(if ($x64.Count) { $x64 } else { $found })
        $dlib = [string](@($pick | Sort-Object -Descending) | Select-Object -First 1)
    }
    if (-not $dlib -or -not (Test-Path -LiteralPath $dlib)) {
        throw ('Azure.CodeSigning.Dlib.dll (x64) not found. Install the client tools with ' +
            '"winget install -e --id Microsoft.Azure.ArtifactSigningClientTools", or pass -DlibPath.')
    }
    foreach ($f in $signable) {
        if (-not $PSCmdlet.ShouldProcess($f.FullName, 'Authenticode sign')) { continue }
        $run = Invoke-ReleaseSignTool -SignToolPath $SignToolPath -ArgumentList @(
            'sign', '/v', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256', '/dlib', $dlib, '/dmdf', $AzureMetadata, $f.FullName)
        if ($run.ExitCode -ne 0) {
            [void]$failed.Add(("signtool exit {0} for {1}: {2}" -f $run.ExitCode, $f.FullName, (@($run.Output | Select-Object -Last 3) -join ' ')))
        }
    }
}
else {
    foreach ($f in $signable) {
        if (-not $PSCmdlet.ShouldProcess($f.FullName, 'Authenticode sign')) { continue }
        $r = Set-AuthenticodeSignature -LiteralPath $f.FullName -Certificate $cert -HashAlgorithm SHA256 `
            -TimestampServer $TimestampUrl -IncludeChain NotRoot -ErrorAction Continue
        # Same rule as the verification below: a declared test build cannot chain to a trusted root.
        $status = if ($r) { [string]$r.Status } else { 'no result' }
        if ($script:AcceptableStatus -notcontains $status) { [void]$failed.Add("$status for $($f.FullName)") }
    }
}

if ($WhatIfPreference) { return }

# --- verify what we just did --------------------------------------------------------------------
$states = @($signable | ForEach-Object { Get-SignatureState -File $_.FullName })
$bad = @($states | Where-Object { $script:AcceptableStatus -notcontains $_.Status })
$unstamped = @($states | Where-Object { -not $_.Timestamped })
$unstampedPE = @($unstamped | Where-Object { $_.IsPE })
foreach ($b in $bad) { Write-Host ("  {0}: {1}" -f $b.Status, $b.File.Substring($root.Length + 1)) -ForegroundColor Red }
foreach ($u in $unstamped) { Write-Warning ('not timestamped: ' + $u.File.Substring($root.Length + 1)) }
if ($failed.Count -or $bad.Count -or $unstampedPE.Count) {
    throw (("Signing failed for {0} file(s); {1} do not verify; {2} PE file(s) have no timestamp. " -f $failed.Count, $bad.Count, $unstampedPE.Count) +
        ($failed | Select-Object -First 3 | Out-String))
}
Write-Host ("Signed and verified {0} file(s) as {1}" -f $states.Count, $states[0].Signer) -ForegroundColor Green
if ($AllowSelfSigned -or $AllowUntrustedChain) { Write-Warning 'This build is signed by an untrusted self-signed certificate and must not be published.' }
if ($unstamped.Count) { Write-Warning "$($unstamped.Count) signature(s) have no timestamp and will stop verifying when the certificate expires." }
