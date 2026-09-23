#Requires -Version 5.1
<#
.SYNOPSIS
    Builds everything an admin uploads to Intune, in one step.

.DESCRIPTION
    Creates build\ with:
      payload\                          What gets installed (no tests or dev tools)
      EngramicBaseline.intunewin  Win32 app package (needs IntuneWinAppUtil.exe)
      EngramicBaseline.zip        Same payload for RMM / GPO / manual installs
      upload\                           Scripts and JSON uploaded separately in Intune
      INTUNE-SETTINGS.md                Exact values to type into the Intune portal

    IntuneWinAppUtil.exe (Microsoft Win32 Content Prep Tool) is found via
    -IntuneWinAppUtilPath, PATH, or build\tools. Use -DownloadTool to fetch it
    from Microsoft's GitHub repository.

.EXAMPLE
    .\intune\Build-IntunePackage.ps1 -DownloadTool
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$IntuneWinAppUtilPath,
    [switch]$DownloadTool,
    # Sign the assembled payload before packing. The .intunewin is an encrypted container, so a
    # signature on it proves nothing; Windows and Intune verify what is inside.
    [string]$SignThumbprint,
    [string]$SignPfxPath,
    [SecureString]$SignPfxPassword,
    [string]$SignAzureMetadata,
    [switch]$AllowSelfSigned,
    # An Artifact Signing Public Trust Test profile chains to a root Windows does not trust, so a
    # package built with one can be proven but must never be published.
    [switch]$AllowUntrustedChain,
    # Refuse to produce a package from unsigned scripts. Release builds set this; a local
    # rehearsal leaves it off so Test-IntuneDeployment.ps1 still works on an unsigned tree.
    [switch]$RequireSignature
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) { $OutputPath = Join-Path $repo 'build' }
$version = [string](Import-PowerShellDataFile -Path (Join-Path $repo 'src\CEAudit\CEAudit.psd1')).ModuleVersion

# Keep the detection script's minimum version in step with the module.
$detect = Join-Path $PSScriptRoot 'Detect-CEChecker.ps1'
$detectText = Get-Content -LiteralPath $detect -Raw
$pinned = [regex]::Match($detectText, "\`$required = \[version\]'([^']+)'").Groups[1].Value
if ($pinned -ne $version) { throw "Detect-CEChecker.ps1 requires $pinned but the module is $version. Update `$required in Detect-CEChecker.ps1." }

Write-Host "Building Engramic Baseline $version into $OutputPath"
if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Recurse -Force }
$payload = Join-Path $OutputPath 'payload'
$upload = Join-Path $OutputPath 'upload'
New-Item -ItemType Directory -Path $payload, $upload -Force | Out-Null

$items = @('src', 'config', 'intune', 'docs', 'app', 'README.md')
foreach ($i in $items) { Copy-Item -LiteralPath (Join-Path $repo $i) -Destination $payload -Recurse -Force }

foreach ($f in @('Discover-CECompliance.ps1', 'compliance-rules.json', 'compliance-rules-autofail-only.json',
        'Detect-CECompliance.ps1', 'Remediate-CECompliance.ps1', 'Detect-CEChecker.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $f) -Destination $upload
}

# Signing goes here: after the payload and upload folders are assembled, before the zip is made
# and before IntuneWinAppUtil wraps anything.
$signer = Join-Path $repo 'tools\Sign-Release.ps1'
$signArgs = @{}
if ($SignThumbprint) { $signArgs['Thumbprint'] = $SignThumbprint }
elseif ($SignPfxPath) { $signArgs['PfxPath'] = $SignPfxPath; if ($SignPfxPassword) { $signArgs['PfxPassword'] = $SignPfxPassword } }
elseif ($SignAzureMetadata) { $signArgs['AzureMetadata'] = $SignAzureMetadata }
if ($signArgs.Count) {
    if ($AllowSelfSigned) { $signArgs['AllowSelfSigned'] = $true }
    if ($AllowUntrustedChain) { $signArgs['AllowUntrustedChain'] = $true }
    foreach ($dir in @($payload, $upload)) { & $signer -Path $dir @signArgs }
}
if ($RequireSignature) {
    $verifyArgs = @{ VerifyOnly = $true }
    if ($AllowSelfSigned) { $verifyArgs['AllowSelfSigned'] = $true }
    if ($AllowUntrustedChain) { $verifyArgs['AllowUntrustedChain'] = $true }
    foreach ($dir in @($payload, $upload)) { & $signer -Path $dir @verifyArgs }
}

# Zip for non-Intune deployment
$zip = Join-Path $OutputPath 'EngramicBaseline.zip'
Compress-Archive -Path (Join-Path $payload '*') -DestinationPath $zip -Force

# .intunewin
$tool = $IntuneWinAppUtilPath
if (-not $tool) {
    $cmd = Get-Command 'IntuneWinAppUtil.exe' -ErrorAction SilentlyContinue
    if ($cmd) { $tool = $cmd.Source }
}
$toolDir = Join-Path $repo 'build-tools'
if (-not $tool -and (Test-Path (Join-Path $toolDir 'IntuneWinAppUtil.exe'))) { $tool = Join-Path $toolDir 'IntuneWinAppUtil.exe' }
if (-not $tool -and $DownloadTool) {
    New-Item -ItemType Directory -Path $toolDir -Force | Out-Null
    $tool = Join-Path $toolDir 'IntuneWinAppUtil.exe'
    # Pinned to a release tag and verified by hash, not tracking a moving 'master',
    # so the build can't silently pick up a changed binary. The Authenticode check
    # below is kept as a second, independent guarantee.
    $toolVersion = 'v1.8.7'
    $toolSha256 = 'C1BA45B5CB939E84AF064BB7FF4B38FB3DFE33C8DC1078FD9B157672EAE671F6'
    $url = "https://raw.githubusercontent.com/microsoft/Microsoft-Win32-Content-Prep-Tool/$toolVersion/IntuneWinAppUtil.exe"
    Write-Host "Downloading IntuneWinAppUtil.exe ($toolVersion) from $url"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $tool -UseBasicParsing
    $hash = (Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash
    if ($hash -ne $toolSha256) {
        Remove-Item -LiteralPath $tool -Force -ErrorAction SilentlyContinue
        throw "IntuneWinAppUtil.exe SHA256 $hash does not match the pinned $toolSha256 for $toolVersion."
    }
    Write-Host "  verified SHA256 $toolSha256"
    $sig = Get-AuthenticodeSignature -FilePath $tool
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') {
        Remove-Item -LiteralPath $tool -Force
        throw "Downloaded IntuneWinAppUtil.exe is not validly signed by Microsoft ($($sig.Status))."
    }
}

$intunewin = $null
if ($tool) {
    & $tool -c $payload -s (Join-Path $payload 'intune\Install-CEChecker.ps1') -o $OutputPath -q | Out-Host
    $built = Join-Path $OutputPath 'Install-CEChecker.intunewin'
    if (-not (Test-Path -LiteralPath $built)) { throw 'IntuneWinAppUtil did not produce a package.' }
    $intunewin = Join-Path $OutputPath "EngramicBaseline-$version.intunewin"
    Move-Item -LiteralPath $built -Destination $intunewin -Force
}
else {
    Write-Warning 'IntuneWinAppUtil.exe not found, so no .intunewin was built. Re-run with -DownloadTool or -IntuneWinAppUtilPath.'
}

$settings = @"
# Intune settings for Engramic Baseline $version

Generated by intune/Build-IntunePackage.ps1. See docs/INTUNE.md for the walkthrough.

## 1. Win32 app

| Field | Value |
|---|---|
| Package file | ``$(if ($intunewin) { Split-Path -Leaf $intunewin } else { '(build with IntuneWinAppUtil.exe)' })`` |
| Name | Engramic Baseline |
| Version | $version |
| Install command | ``powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\intune\Install-CEChecker.ps1 -RunNow`` |
| Uninstall command | ``powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\intune\Uninstall-CEChecker.ps1`` |
| Install behaviour | System |
| Device restart behaviour | No specific action |
| Return codes | 0 = Success, 1 = Failed |
| Operating system architecture | x64 |
| Minimum operating system | Windows 10 22H2 (Windows 11 recommended) |
| Detection rule | Use a custom detection script: ``upload/Detect-CEChecker.ps1``. Run as 32-bit process on 64-bit clients: **No**. Enforce signature check: **No** (unless you sign it) |
| Assignment | Required, to your device group |

## 2. Custom compliance

1. **Devices > Compliance > Scripts > Add > Windows 10 and later**
   - Script: ``upload/Discover-CECompliance.ps1``
   - Run this script using the logged on credentials: **No**
   - Enforce script signature check: **No**
   - Run script in 64 bit PowerShell Host: **Yes**
2. **Devices > Compliance > Create policy > Windows 10 and later**, then **Custom Compliance: Require**
   - Discovery script: the one above
   - Rules file: ``upload/compliance-rules.json`` (full Cyber Essentials) or ``upload/compliance-rules-autofail-only.json`` (softer first rollout)
   - Actions for non-compliance: start with "Mark device non-compliant" after a grace period (e.g. 3 days) before using it in Conditional Access.

## 3. Remediations (optional, gives per-device detail in one report)

**Devices > Scripts and remediations > Remediations > Create**

| Field | Value |
|---|---|
| Detection script | ``upload/Detect-CECompliance.ps1`` |
| Remediation script | ``upload/Remediate-CECompliance.ps1`` |
| Run this script using the logged-on credentials | No |
| Enforce script signature check | No |
| Run script in 64-bit PowerShell | Yes |
| Schedule | Daily |

With the default ``config/auto-remediation.json`` the remediation only refreshes the audit. Enable automatic fixes there before building if you want them.
"@
Set-Content -LiteralPath (Join-Path $OutputPath 'INTUNE-SETTINGS.md') -Value $settings -Encoding UTF8

Write-Host ''
Write-Host 'Done:' -ForegroundColor Green
Get-ChildItem -LiteralPath $OutputPath | ForEach-Object { Write-Host "  $($_.Name)" }
Write-Host ''
Write-Host "Next: follow $(Join-Path $OutputPath 'INTUNE-SETTINGS.md')"
