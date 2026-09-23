#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the desktop installer from an already-signed payload.
.DESCRIPTION
    This is the install path for a person putting Baseline on their own PC. A fleet is deployed with
    the .intunewin package instead, so this deliberately does not register the scheduled audit tasks:
    on a personal machine a daily SYSTEM task nobody asked for is a surprise, not a feature.

    It builds from a payload that is already signed, never from the repository, so the files inside
    the MSI carry the same signatures a customer can verify. The MSI itself is signed afterwards,
    which is what Windows shows the user at the User Account Control prompt.

    WiX is fetched on first use and pinned by SHA256. The WiX 3.14 binaries are not themselves
    Authenticode signed, so unlike IntuneWinAppUtil they cannot be checked by publisher. The hash
    below was taken from the official wixtoolset/wix3 release and pins every later build to that
    exact archive.
.PARAMETER PayloadPath
    The signed payload to package. Mandatory: this must never be pointed at the working tree.
.PARAMETER Version
    Product version, normally the module version.
.EXAMPLE
    .\installer\Build-Msi.ps1 -PayloadPath .\build\release\payload -Version 0.3.2
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PayloadPath,
    [Parameter(Mandatory)][string]$Version,
    [string]$OutputPath,
    [string]$WixPath
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

$wixUrl = 'https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip'
$wixSha = '6AC824E1642D6F7277D0ED7EA09411A508F6116BA6FAE0AA5F2C7DAA2FF43D31'

if (-not (Test-Path -LiteralPath $PayloadPath)) { throw "Payload not found: $PayloadPath" }
$payload = (Resolve-Path -LiteralPath $PayloadPath).Path
if (-not $OutputPath) { $OutputPath = Split-Path -Parent $payload }
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# An MSI ProductVersion is three parts at most, and the installer ignores anything beyond the third.
$v = [version]$Version
$msiVersion = '{0}.{1}.{2}' -f $v.Major, $v.Minor, [Math]::Max($v.Build, 0)

# --- WiX ------------------------------------------------------------------------------------------
if (-not $WixPath) { $WixPath = Join-Path $repo 'build-tools\wix' }
if (-not (Test-Path -LiteralPath (Join-Path $WixPath 'candle.exe'))) {
    Write-Host 'Fetching the WiX toolset'
    $zip = Join-Path ([IO.Path]::GetTempPath()) ('wix314-' + [guid]::NewGuid().ToString('N') + '.zip')
    try {
        $old = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $wixUrl -OutFile $zip -UseBasicParsing
        $ProgressPreference = $old
        $got = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
        if ($got -ne $wixSha) {
            throw ("WiX download does not match the pinned hash. Expected $wixSha, got $got. " +
                'Refusing to build an installer with a build tool that changed underneath us.')
        }
        New-Item -ItemType Directory -Path $WixPath -Force | Out-Null
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $WixPath)
    }
    finally { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
}
$candle = Join-Path $WixPath 'candle.exe'
$light = Join-Path $WixPath 'light.exe'
$heat = Join-Path $WixPath 'heat.exe'
foreach ($t in $candle, $light, $heat) {
    if (-not (Test-Path -LiteralPath $t)) { throw "WiX is incomplete: $t is missing. Delete $WixPath and run again." }
}

# --- harvest, compile, link -------------------------------------------------------------------------
$obj = Join-Path $OutputPath 'msi-obj'
if (Test-Path -LiteralPath $obj) { Remove-Item -LiteralPath $obj -Recurse -Force }
New-Item -ItemType Directory -Path $obj -Force | Out-Null

$harvested = Join-Path $obj 'Payload.wxs'
# -gg  stable component GUIDs, so an upgrade replaces files rather than doubling them
# -sfrag / -srd  one fragment, and do not invent a root directory above the payload
& $heat dir $payload -nologo -gg -sfrag -srd -scom -sreg -dr INSTALLFOLDER -cg PayloadFiles `
    -var var.PayloadDir -out $harvested | Out-Null
if ($LASTEXITCODE -ne 0) { throw "heat.exe failed with exit code $LASTEXITCODE" }

$wxs = Join-Path $PSScriptRoot 'EngramicBaseline.wxs'
$candleArgs = @('-nologo', '-arch', 'x64', "-dVersion=$msiVersion", "-dPayloadDir=$payload",
    '-out', ($obj + '\'), $wxs, $harvested)
& $candle @candleArgs | Out-Host
if ($LASTEXITCODE -ne 0) { throw "candle.exe failed with exit code $LASTEXITCODE" }

$msi = Join-Path $OutputPath ("EngramicBaseline-$Version.msi")
& $light -nologo -sval -b $payload -out $msi (Join-Path $obj 'EngramicBaseline.wixobj') (Join-Path $obj 'Payload.wixobj') | Out-Host
if ($LASTEXITCODE -ne 0) { throw "light.exe failed with exit code $LASTEXITCODE" }
Remove-Item -LiteralPath $obj -Recurse -Force -ErrorAction SilentlyContinue

$size = (Get-Item -LiteralPath $msi).Length
Write-Host ("Built {0} ({1:N0} bytes)" -f (Split-Path -Leaf $msi), $size) -ForegroundColor Green
Write-Host 'Not signed yet. The release script signs it; a hand-built MSI needs signing separately.' -ForegroundColor Yellow
return $msi
