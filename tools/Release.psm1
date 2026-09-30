#Requires -Version 5.1
<#
.SYNOPSIS
    What the release scripts share: which PE files in a published folder this repository built, what their
    signatures say, the version of baseline.exe, running signtool, and checking its Azure login first.
.DESCRIPTION
    Used by tools\Sign-Release.ps1, tools\Test-ReleaseSignatures.ps1, tools\Test-ReleaseTag.ps1 and
    tools\New-SignedRelease.ps1. Nothing here changes a file, except the signtool that
    Invoke-ReleaseSignTool is told to run.

    "Ours" is decided by the publish's own manifest, never by a name pattern: the .deps.json that dotnet
    publish writes lists each library with its kind, and only libraries of kind "project" are built from
    this repository. Everything else in the folder, the .NET runtime and the package assemblies, is
    someone else's and keeps their signature.
#>
Set-StrictMode -Version 2.0

# The extensions of the PE files a published folder carries. A PE file with any other extension is found
# by its header, so nothing that holds code escapes the checks by its name.
$script:PEExtensions = @('.exe', '.dll')

function Test-ReleasePEFile {
    <#
    .SYNOPSIS
        Whether a file is a PE image: "MZ" at the start, and "PE" and two zero bytes where the DOS header points.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$LiteralPath)
    $stream = [IO.File]::Open($LiteralPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 64) { return $false }
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { return $false }
        $stream.Position = 0x3C
        $offset = $reader.ReadInt32()
        if ($offset -lt 64 -or $offset -gt ($stream.Length - 4)) { return $false }
        $stream.Position = $offset
        return ($reader.ReadUInt32() -eq 0x4550)
    }
    finally { $stream.Dispose() }
}

function Get-ReleasePEFile {
    <#
    .SYNOPSIS
        Every PE file under a folder, hidden ones included: .exe and .dll files, and any other file with a PE header.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $root = (Resolve-Path -LiteralPath $Path).ProviderPath
    foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force)) {
        if ($script:PEExtensions -contains $file.Extension -or (Test-ReleasePEFile -LiteralPath $file.FullName)) { $file }
    }
}

function Get-ReleaseJsonValue {
    <# A property of an object ConvertFrom-Json made, or $null when it has none (strict mode throws on a missing one). #>
    param($InputObject, [string]$Name)
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Get-ReleaseOwnFile {
    <#
    .SYNOPSIS
        The full paths of the PE files in a published folder that this repository built.
    .DESCRIPTION
        For each .deps.json under the folder, as dotnet publish writes it: the assets (runtime, native and
        resource assemblies) of every library whose kind is "project", and the application's launcher,
        <name>.exe beside <name>.deps.json, when <name> is one of those projects. The runtime pack's files and
        the packages' assemblies are someone else's and are never returned.

        Throws when there is no .deps.json, when one is not what dotnet publish writes, or when it names a file
        that is not in the folder or lies outside it, so nothing is ever signed or judged on a guess.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $root = (Resolve-Path -LiteralPath $Path).ProviderPath.TrimEnd('\', '/')
    $manifests = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -Filter '*.deps.json')
    if (-not $manifests.Count) {
        throw ("There is no .deps.json under '$root', so which of its PE files this repository built cannot be told. " +
            'Point at the folder dotnet publish wrote.')
    }
    $seen = @{}
    foreach ($manifest in $manifests) {
        $deps = Get-Content -LiteralPath $manifest.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $targetName = [string](Get-ReleaseJsonValue (Get-ReleaseJsonValue $deps 'runtimeTarget') 'name')
        $libraries = Get-ReleaseJsonValue $deps 'libraries'
        $target = $null
        if ($targetName) { $target = Get-ReleaseJsonValue (Get-ReleaseJsonValue $deps 'targets') $targetName }
        if ($null -eq $libraries -or $null -eq $target) {
            throw "$($manifest.FullName) is not a .deps.json as dotnet publish writes it: it has no runtimeTarget with targets and libraries."
        }
        $folder = $manifest.DirectoryName
        $appName = $manifest.Name.Substring(0, $manifest.Name.Length - '.deps.json'.Length)
        $appIsProject = $false
        foreach ($library in @($target.PSObject.Properties)) {
            $kind = [string](Get-ReleaseJsonValue (Get-ReleaseJsonValue $libraries $library.Name) 'type')
            if ($kind -ne 'project') { continue }
            if ($library.Name.Split('/')[0] -eq $appName) { $appIsProject = $true }
            foreach ($group in @('runtime', 'native', 'resources', 'runtimeTargets')) {
                $assets = Get-ReleaseJsonValue $library.Value $group
                if ($null -eq $assets) { continue }
                foreach ($asset in @($assets.PSObject.Properties)) {
                    $relative = $asset.Name.Replace('/', [IO.Path]::DirectorySeparatorChar)
                    $full = [IO.Path]::GetFullPath([IO.Path]::Combine($folder, $relative))
                    if (-not $full.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                        throw "$($manifest.FullName) names '$($asset.Name)', which is outside '$root'."
                    }
                    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
                        throw "$($manifest.FullName) names '$($asset.Name)' of project $($library.Name), which is not in '$folder'."
                    }
                    if (-not $seen.ContainsKey($full)) { $seen[$full] = $true; $full }
                }
            }
        }
        $launcher = Join-Path $folder "$appName.exe"
        if ($appIsProject -and (Test-Path -LiteralPath $launcher -PathType Leaf)) {
            $full = [IO.Path]::GetFullPath($launcher)
            if (-not $seen.ContainsKey($full)) { $seen[$full] = $true; $full }
        }
    }
}

function Get-ReleaseNamePart {
    <#
    .SYNOPSIS
        The value of one attribute of a distinguished name, such as O in "CN=Contoso, O=Contoso Ltd, C=GB", or ''.
    .DESCRIPTION
        Splits only on commas outside quotes and escapes, so a quoted value cannot pose as another attribute.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Name, [Parameter(Mandatory)][string]$Attribute)
    if (-not $Name) { return '' }
    $parts = New-Object System.Collections.ArrayList
    $current = New-Object System.Text.StringBuilder
    $quoted = $false
    for ($i = 0; $i -lt $Name.Length; $i++) {
        $c = $Name[$i]
        if ($c -eq '\' -and $i + 1 -lt $Name.Length) { [void]$current.Append($c).Append($Name[$i + 1]); $i++; continue }
        if ($c -eq '"') { $quoted = -not $quoted }
        if (($c -eq ',' -or $c -eq '+') -and -not $quoted) { [void]$parts.Add($current.ToString()); [void]$current.Clear(); continue }
        [void]$current.Append($c)
    }
    [void]$parts.Add($current.ToString())
    foreach ($part in $parts) {
        $equals = $part.IndexOf('=')
        if ($equals -lt 1) { continue }
        if ($part.Substring(0, $equals).Trim() -ne $Attribute) { continue }
        $value = $part.Substring($equals + 1).Trim()
        if ($value.Length -ge 2 -and $value.StartsWith('"') -and $value.EndsWith('"')) { $value = $value.Substring(1, $value.Length - 2).Replace('""', '"') }
        return $value
    }
    return ''
}

function Get-ReleaseSignature {
    <#
    .SYNOPSIS
        What a file's Authenticode signature says, in the terms the release checks use.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath)
    $signature = Get-AuthenticodeSignature -LiteralPath $LiteralPath
    $signer = $signature.SignerCertificate
    $subject = ''
    $issuer = ''
    $thumbprint = ''
    if ($null -ne $signer) {
        $subject = [string]$signer.Subject
        $issuer = [string]$signer.Issuer
        $thumbprint = [string]$signer.Thumbprint
    }
    # Authenticode (in the file) or Catalog (in a catalog on this machine, which does not travel with the file).
    $type = ''
    if ($signature.PSObject.Properties['SignatureType']) { $type = [string]$signature.SignatureType }
    [pscustomobject]@{
        Path               = $LiteralPath
        Status             = [string]$signature.Status
        StatusMessage      = [string]$signature.StatusMessage
        SignatureType      = $type
        Subject            = $subject
        CommonName         = Get-ReleaseNamePart -Name $subject -Attribute 'CN'
        Organisation       = Get-ReleaseNamePart -Name $subject -Attribute 'O'
        IssuerOrganisation = Get-ReleaseNamePart -Name $issuer -Attribute 'O'
        Thumbprint         = $thumbprint
        Timestamped        = ($null -ne $signature.TimeStamperCertificate)
    }
}

function ConvertTo-ReleaseThumbprint {
    <# A certificate thumbprint as hex digits alone, upper case, whatever spaces or case it was given with. #>
    param([string]$Thumbprint)
    return ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
}

function Test-ReleaseMicrosoftSignature {
    <#
    .SYNOPSIS
        Whether a signature (from Get-ReleaseSignature) is Microsoft's: made by a certificate issued to
        Microsoft Corporation by one of Microsoft's own certification authorities.
    .DESCRIPTION
        Whether it verifies is a separate question: Status says that.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Signature)
    return ($Signature.Organisation -eq 'Microsoft Corporation' -and $Signature.IssuerOrganisation -eq 'Microsoft Corporation')
}

function Get-ReleaseSignatureReport {
    <#
    .SYNOPSIS
        One row for each PE file under a folder: whose signature it must carry, what it carries, and every problem.
    .DESCRIPTION
        A file this repository built (Get-ReleaseOwnFile) must be signed in the file itself by our certificate
        (-Thumbprint) or publisher (-Publisher, the O= of the certificate's subject, or its CN= when it has no
        O=), verify as Valid (or, with -AllowUntrustedChain, end in a root this machine does not trust, as a test
        certificate does) and be timestamped. With -Unsigned it must carry no signature at all, as CI builds it.

        Every other PE file must be signed in the file itself by Microsoft, verify as Valid and be timestamped,
        whatever the switches say: the runtime and the packages ship exactly as their publisher signed them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Publisher,
        [string[]]$Thumbprint = @(),
        [switch]$AllowUntrustedChain,
        [switch]$Unsigned
    )
    $ourThumbprints = @($Thumbprint | Where-Object { $_ } | ForEach-Object { ConvertTo-ReleaseThumbprint $_ })
    if (-not $Unsigned -and -not $Publisher -and -not $ourThumbprints.Count) {
        throw 'Say whose signature this repository''s files carry, with -Publisher or -Thumbprint, or check a folder not yet signed with -Unsigned.'
    }
    $root = (Resolve-Path -LiteralPath $Path).ProviderPath.TrimEnd('\', '/')
    $own = @{}
    foreach ($file in @(Get-ReleaseOwnFile -Path $root)) { $own[$file] = $true }
    $acceptedForOurs = @('Valid')
    if ($AllowUntrustedChain) { $acceptedForOurs += @('NotTrusted', 'UnknownError') }
    $expectedSigner = if ($ourThumbprints.Count) { 'certificate ' + ($ourThumbprints -join ' or ') } else { $Publisher }

    foreach ($file in @(Get-ReleasePEFile -Path $root)) {
        $ours = $own.ContainsKey([IO.Path]::GetFullPath($file.FullName))
        $signature = Get-ReleaseSignature -LiteralPath $file.FullName
        $signer = if ($signature.Subject) { $signature.Subject } else { '(none)' }
        $bySigner = $false
        if ($signature.Thumbprint) {
            if ($ourThumbprints.Count) { $bySigner = $ourThumbprints -contains (ConvertTo-ReleaseThumbprint $signature.Thumbprint) }
            elseif ($Publisher) {
                $name = if ($signature.Organisation) { $signature.Organisation } else { $signature.CommonName }
                $bySigner = ($name -eq $Publisher)
            }
        }
        $problems = New-Object System.Collections.ArrayList
        if ($ours -and $Unsigned) {
            if ($signature.Status -ne 'NotSigned') {
                [void]$problems.Add("already signed ($($signature.Status), by $signer): what the build publishes must carry no signature until a release signs it")
            }
        }
        elseif ($signature.Status -eq 'NotSigned') {
            if ($ours) { [void]$problems.Add('not signed') }
            else {
                [void]$problems.Add('not signed, and not built by this repository. A package assembly compiled with ReadyToRun loses ' +
                    "its publisher's signature: keep it out with PublishReadyToRunExclude")
            }
        }
        else {
            if ($signature.Status -eq 'HashMismatch') { [void]$problems.Add('changed since it was signed (HashMismatch)') }
            elseif ($ours -and $acceptedForOurs -notcontains $signature.Status) {
                [void]$problems.Add("the signature does not verify: $($signature.Status). $($signature.StatusMessage)".Trim())
            }
            elseif (-not $ours -and $signature.Status -ne 'Valid') {
                [void]$problems.Add("the signature does not verify: $($signature.Status). $($signature.StatusMessage)".Trim())
            }
            if ($signature.SignatureType -eq 'Catalog') {
                [void]$problems.Add('signed only in a catalog on this machine, which does not travel with the file')
            }
            if ($ours) {
                if (-not $bySigner) { [void]$problems.Add("signed by $signer, not $expectedSigner") }
            }
            elseif (-not (Test-ReleaseMicrosoftSignature -Signature $signature)) {
                if ($bySigner) { [void]$problems.Add("signed by us ($signer), but this repository did not build it: someone else's file was signed again") }
                else { [void]$problems.Add("signed by $signer, which is neither this repository's publisher nor Microsoft") }
            }
            if (-not $signature.Timestamped) {
                [void]$problems.Add('not timestamped, so the signature stops verifying when the certificate expires')
            }
        }
        [pscustomobject]@{
            File        = $file.FullName.Substring($root.Length + 1)
            Owner       = $(if ($ours) { 'ours' } else { 'Microsoft' })
            Status      = $signature.Status
            Signer      = $signer
            Thumbprint  = $signature.Thumbprint
            Timestamped = $signature.Timestamped
            Problems    = @($problems)
        }
    }
}

function Get-ReleaseDotNetVersion {
    <#
    .SYNOPSIS
        The version of baseline.exe: VersionPrefix, then a hyphen and VersionSuffix when there is one, from
        Directory.Build.props.
    .DESCRIPTION
        Throws unless each is written once and under no condition, the prefix is three numbers and the suffix is
        dot-separated letters, digits and hyphens: the tag check compares a tag with it exactly, so it must be
        the one version every assembly carries.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    $props = New-Object System.Xml.XmlDocument
    $props.Load((Resolve-Path -LiteralPath $Path).ProviderPath)
    $prefix = @($props.SelectNodes('//*[local-name()="VersionPrefix"]'))
    $suffix = @($props.SelectNodes('//*[local-name()="VersionSuffix"]'))
    if ($prefix.Count -ne 1) { throw "$Path must set VersionPrefix exactly once, not $($prefix.Count) time(s)." }
    if ($suffix.Count -gt 1) { throw "$Path must set VersionSuffix at most once, not $($suffix.Count) times." }
    foreach ($node in @($prefix + $suffix)) {
        for ($element = $node; $null -ne $element -and $element -is [System.Xml.XmlElement]; $element = $element.ParentNode) {
            if ($element.HasAttribute('Condition')) { throw "$Path sets $($node.LocalName) under a condition, so the version would depend on how it is built." }
        }
    }
    $versionPrefix = $prefix[0].InnerText.Trim()
    if ($versionPrefix -notmatch '^\d+\.\d+\.\d+$') { throw "$Path has VersionPrefix '$versionPrefix', which is not three numbers such as 1.0.0." }
    $versionSuffix = ''
    if ($suffix.Count) { $versionSuffix = $suffix[0].InnerText.Trim() }
    if (-not $versionSuffix) { return $versionPrefix }
    if ($versionSuffix -notmatch '^[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*$') { throw "$Path has VersionSuffix '$versionSuffix', which is not a prerelease label such as alpha.0." }
    return "$versionPrefix-$versionSuffix"
}

function Invoke-ReleaseSignTool {
    <#
    .SYNOPSIS
        Runs signtool.exe with the arguments given, in this console, and returns its exit code and what it printed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SignToolPath,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )
    # signtool writes its errors to stderr; in Windows PowerShell 5.1 a redirected line of it would stop the
    # script under 'Stop', before the exit code could say what happened.
    $ErrorActionPreference = 'Continue'
    $output = @(& $SignToolPath @ArgumentList 2>&1 | ForEach-Object { [string]$_ })
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

function Invoke-ReleaseAzCli {
    <#
    .SYNOPSIS
        Runs the Azure CLI with the arguments given and returns its exit code and what it printed, or $null when az
        is not on this process's PATH.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$ArgumentList)
    $az = Get-Command az -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $az) { return $null }
    # az writes its errors to stderr, which under 'Stop' would end the script in Windows PowerShell 5.1.
    $ErrorActionPreference = 'Continue'
    $output = @(& $az.Source @ArgumentList 2>&1 | ForEach-Object { [string]$_ })
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

function Get-ReleaseAzureLoginProblem {
    <#
    .SYNOPSIS
        Why Artifact Signing could not sign in with the metadata given, or $null when nothing stops it.
    .DESCRIPTION
        The signing dlib signs in with DefaultAzureCredential, less the credential types the metadata's
        ExcludeCredentials names. With no AccessToken in the metadata and no service principal in AZURE_CLIENT_ID,
        the login it reaches is the Azure CLI's. When that fails, signtool says only "SignerSign() failed", once
        for every file and after the whole build. So this asks az for an Artifact Signing token the way the dlib
        will, and a missing or signed-out CLI stops a release in seconds. The token is never printed.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    try { $metadata = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { return "$Path is not readable JSON, so signtool could not read it either." }
    if ([string](Get-ReleaseJsonValue $metadata 'AccessToken')) { return $null }
    if ($env:AZURE_CLIENT_ID) { return $null }
    $excluded = @(Get-ReleaseJsonValue $metadata 'ExcludeCredentials' | ForEach-Object { [string]$_ })
    if ($excluded -contains 'AzureCliCredential') { return $null }
    $otherLogin = 'If you sign in some other way, name AzureCliCredential in the metadata''s ExcludeCredentials.'
    $result = Invoke-ReleaseAzCli -ArgumentList @('account', 'get-access-token', '--resource', 'https://codesigning.azure.net', '--output', 'none')
    if ($null -eq $result) {
        return ('The Azure CLI (az) is not on PATH in this window, and it is the login the signing metadata leaves. ' +
            'A window keeps the PATH it started with, so one opened before the CLI was installed cannot find it: ' +
            'open a new one (closing the terminal app first if it has been open since), or reload PATH in this one. ' + $otherLogin)
    }
    if ($result.ExitCode -ne 0) {
        return ('The Azure CLI could not get an Artifact Signing token, so signing would fail. az said: ' +
            ((@($result.Output) | Where-Object { $_ }) -join ' ') + ' Run az login, then try again. ' + $otherLogin)
    }
    return $null
}

Export-ModuleMember -Function Test-ReleasePEFile, Get-ReleasePEFile, Get-ReleaseOwnFile, Get-ReleaseNamePart, Get-ReleaseSignature,
    Test-ReleaseMicrosoftSignature, Get-ReleaseSignatureReport, Get-ReleaseDotNetVersion, Invoke-ReleaseSignTool,
    Get-ReleaseAzureLoginProblem
