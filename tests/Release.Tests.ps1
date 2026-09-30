#Requires -Modules Pester
<#
    The release tools in tools/: which PE files of a published folder this repository built, signing only
    those, the checks of signatures and tags, and the steps of the release, the pre-flight and the sandbox.

    Nothing is signed and no certificate store is read: Get-AuthenticodeSignature, Set-AuthenticodeSignature,
    Get-PfxCertificate and signtool are mocked, and the files are PE headers made up under TestDrive.

    Run:  Invoke-Pester -Path .\tests\Release.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:Tools = Join-Path $script:RepoRoot 'tools'
    # Stand-ins where the Security module is missing (pwsh on Linux), so the commands can be mocked.
    foreach ($name in @('Get-AuthenticodeSignature', 'Set-AuthenticodeSignature', 'Get-PfxCertificate')) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            Set-Item -Path "function:global:$name" -Value { param($LiteralPath, $FilePath, $Certificate, [Parameter(ValueFromRemainingArguments)]$Rest) }
        }
    }
    Import-Module (Join-Path $script:Tools 'Release.psm1') -Force

    $global:ReleaseTestMicrosoft = 'CN=.NET, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    $global:ReleaseTestMicrosoftCA = 'CN=Microsoft Code Signing PCA 2024, O=Microsoft Corporation, C=US'
    $global:ReleaseTestOurs = 'CN=Engramic Ltd, O=Engramic Ltd, C=GB'
    $global:ReleaseTestOursCA = 'CN=Microsoft ID Verified CS EOC CA 01, O=Microsoft Corporation, C=US'
    $global:ReleaseTestOurThumbprint = 'AA11BB22CC33DD44EE55FF6677889900AABBCCDD'

    function global:New-TestPEFile {
        # The smallest file with a PE header: "MZ", the offset of the header at 0x3C, and "PE" and two zeros there.
        param([string]$Path)
        $bytes = New-Object byte[] 512
        $bytes[0] = 0x4D
        $bytes[1] = 0x5A
        $bytes[0x3C] = 0x80
        $bytes[0x80] = 0x50
        $bytes[0x81] = 0x45
        [IO.File]::WriteAllBytes($Path, $bytes)
    }

    function global:New-TestPayload {
        # A published folder in miniature: the launcher and two assemblies of ours, which baseline.deps.json
        # names as projects, a package assembly, three runtime files and a file of data.
        param([string]$Path)
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        foreach ($file in @('baseline.exe', 'baseline.dll', 'Engramic.Baseline.Model.dll', 'System.CommandLine.dll', 'coreclr.dll', 'createdump.exe', 'hostfxr.dll')) {
            New-TestPEFile -Path (Join-Path $Path $file)
        }
        Set-Content -LiteralPath (Join-Path $Path 'baseline.runtimeconfig.json') -Value '{}' -Encoding ASCII
        $target = '.NETCoreApp,Version=v10.0/win-x64'
        $deps = [ordered]@{
            runtimeTarget = [ordered]@{ name = $target; signature = '' }
            targets       = [ordered]@{
                $target = [ordered]@{
                    'baseline/1.0.0-alpha.0'                                   = [ordered]@{ runtime = [ordered]@{ 'baseline.dll' = @{} } }
                    'runtimepack.Microsoft.NETCore.App.Runtime.win-x64/10.0.12' = [ordered]@{
                        runtime = [ordered]@{ 'System.Runtime.dll' = @{} }
                        native  = [ordered]@{ 'coreclr.dll' = @{}; 'createdump.exe' = @{}; 'hostfxr.dll' = @{} }
                    }
                    'System.CommandLine/2.0.12'                                = [ordered]@{ runtime = [ordered]@{ 'lib/net8.0/System.CommandLine.dll' = @{} } }
                    'Engramic.Baseline.Model/1.0.0-alpha.0'                    = [ordered]@{ runtime = [ordered]@{ 'Engramic.Baseline.Model.dll' = @{} } }
                }
            }
            libraries     = [ordered]@{
                'baseline/1.0.0-alpha.0'                                   = @{ type = 'project' }
                'runtimepack.Microsoft.NETCore.App.Runtime.win-x64/10.0.12' = @{ type = 'runtimepack' }
                'System.CommandLine/2.0.12'                                = @{ type = 'package' }
                'Engramic.Baseline.Model/1.0.0-alpha.0'                    = @{ type = 'project' }
            }
        }
        $deps | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Path 'baseline.deps.json') -Encoding ASCII
        return $Path
    }

    function global:New-TestSignature {
        # What the mocked Get-AuthenticodeSignature returns: the properties the release tools read.
        param([string]$Status = 'Valid', [string]$Subject = '', [string]$Issuer = '', [string]$Thumbprint = '', [switch]$NoTimestamp, [string]$Type = 'Authenticode')
        $signer = $null
        if ($Subject) { $signer = [pscustomobject]@{ Subject = $Subject; Issuer = $Issuer; Thumbprint = $Thumbprint } }
        $stamper = $null
        if ($Subject -and -not $NoTimestamp) { $stamper = [pscustomobject]@{ Subject = 'CN=Test Time-Stamp Service' } }
        [pscustomobject]@{
            Status                 = $Status
            StatusMessage          = "status $Status"
            SignatureType          = $Type
            SignerCertificate      = $signer
            TimeStamperCertificate = $stamper
        }
    }
    function global:New-TestOurSignature { param([switch]$NoTimestamp, [string]$Status = 'Valid') New-TestSignature -Status $Status -Subject $global:ReleaseTestOurs -Issuer $global:ReleaseTestOursCA -Thumbprint $global:ReleaseTestOurThumbprint -NoTimestamp:$NoTimestamp }
    function global:New-TestMicrosoftSignature { New-TestSignature -Subject $global:ReleaseTestMicrosoft -Issuer $global:ReleaseTestMicrosoftCA -Thumbprint '1234567890ABCDEF1234567890ABCDEF12345678' }

    # The signature of each file by its name, as the mocked Get-AuthenticodeSignature reports it. No entry is NotSigned.
    $global:ReleaseTestSignatures = @{}
    function global:Get-TestSignature {
        param([string]$Path)
        $name = Split-Path -Leaf $Path
        if ($global:ReleaseTestSignatures.ContainsKey($name)) { return $global:ReleaseTestSignatures[$name] }
        return (New-TestSignature -Status 'NotSigned' -Type 'None')
    }
    function global:Set-TestReleaseSigned {
        # Ours signed by us, the runtime and the package by Microsoft: a build as a release leaves it.
        $global:ReleaseTestSignatures = @{}
        foreach ($name in @('baseline.exe', 'baseline.dll', 'Engramic.Baseline.Model.dll')) { $global:ReleaseTestSignatures[$name] = New-TestOurSignature }
        foreach ($name in @('System.CommandLine.dll', 'coreclr.dll', 'createdump.exe', 'hostfxr.dll')) { $global:ReleaseTestSignatures[$name] = New-TestMicrosoftSignature }
    }
    function global:Set-TestReleaseUnsigned {
        # As dotnet publish leaves it: nothing of ours signed, everything else Microsoft's.
        Set-TestReleaseSigned
        foreach ($name in @('baseline.exe', 'baseline.dll', 'Engramic.Baseline.Model.dll')) { $global:ReleaseTestSignatures.Remove($name) }
    }
}

AfterAll {
    Remove-Module Release -ErrorAction SilentlyContinue
}

Describe 'Release module: which PE files this repository built' {
    It 'names the launcher and the assemblies of its own projects, from the publish''s .deps.json, and nothing of the runtime or packages' {
        $payload = New-TestPayload -Path (Join-Path $TestDrive 'own')
        $own = @(Get-ReleaseOwnFile -Path $payload | ForEach-Object { Split-Path -Leaf $_ } | Sort-Object)
        $own | Should -Be @('baseline.dll', 'baseline.exe', 'Engramic.Baseline.Model.dll')
    }

    It 'finds every PE file, whatever its extension, and nothing else' {
        $payload = New-TestPayload -Path (Join-Path $TestDrive 'pe')
        New-TestPEFile -Path (Join-Path $payload 'addon.node')
        [IO.File]::WriteAllBytes((Join-Path $payload 'notes.txt'), [byte[]](0x4D, 0x5A, 0x20, 0x20))
        $found = @(Get-ReleasePEFile -Path $payload | ForEach-Object { $_.Name } | Sort-Object)
        $found | Should -Contain 'addon.node' -Because 'a PE file with another extension is still code'
        $found | Should -Not -Contain 'notes.txt' -Because '"MZ" alone does not make a PE file'
        $found | Should -Not -Contain 'baseline.deps.json'
        $found.Count | Should -Be 8
    }

    It 'refuses a folder without a .deps.json, so nothing is signed or judged on a guess' {
        $folder = Join-Path $TestDrive 'no-manifest'
        New-Item -ItemType Directory -Path $folder | Out-Null
        New-TestPEFile -Path (Join-Path $folder 'baseline.exe')
        { Get-ReleaseOwnFile -Path $folder } | Should -Throw '*no .deps.json*'
    }

    It 'refuses a manifest that names a file which is not there, or one outside the folder' {
        $payload = New-TestPayload -Path (Join-Path $TestDrive 'missing')
        Remove-Item -LiteralPath (Join-Path $payload 'Engramic.Baseline.Model.dll')
        { Get-ReleaseOwnFile -Path $payload } | Should -Throw '*Engramic.Baseline.Model.dll*not in*'

        $escape = New-TestPayload -Path (Join-Path $TestDrive 'escape\payload')
        New-TestPEFile -Path (Join-Path $TestDrive 'escape\outside.dll')
        $manifest = Join-Path $escape 'baseline.deps.json'
        (Get-Content -LiteralPath $manifest -Raw).Replace('"baseline.dll"', '"../outside.dll"') | Set-Content -LiteralPath $manifest -Encoding ASCII
        { Get-ReleaseOwnFile -Path $escape } | Should -Throw '*outside*'
    }

    It 'reads an attribute of a certificate subject, and a quoted value cannot pose as another' {
        Get-ReleaseNamePart -Name $global:ReleaseTestMicrosoft -Attribute 'O' | Should -Be 'Microsoft Corporation'
        Get-ReleaseNamePart -Name $global:ReleaseTestMicrosoft -Attribute 'CN' | Should -Be '.NET'
        Get-ReleaseNamePart -Name 'CN="Evil, O=Microsoft Corporation", O=Evil Ltd' -Attribute 'O' | Should -Be 'Evil Ltd'
        Get-ReleaseNamePart -Name 'CN=Test, OU=Unit' -Attribute 'O' | Should -Be ''
    }

    It 'reads the version of baseline.exe from Directory.Build.props, prefix and suffix' {
        $props = Join-Path $TestDrive 'Directory.Build.props'
        Set-Content -LiteralPath $props -Value '<Project><PropertyGroup><VersionPrefix>1.0.0</VersionPrefix><VersionSuffix>alpha.0</VersionSuffix></PropertyGroup></Project>'
        Get-ReleaseDotNetVersion -Path $props | Should -Be '1.0.0-alpha.0'
        Set-Content -LiteralPath $props -Value '<Project><PropertyGroup><VersionPrefix>1.2.3</VersionPrefix></PropertyGroup></Project>'
        Get-ReleaseDotNetVersion -Path $props | Should -Be '1.2.3'
        Set-Content -LiteralPath $props -Value '<Project><PropertyGroup><VersionPrefix>1.2.3</VersionPrefix><VersionSuffix></VersionSuffix></PropertyGroup></Project>'
        Get-ReleaseDotNetVersion -Path $props | Should -Be '1.2.3'
    }

    It 'refuses a version written twice, under a condition, or not as plain numbers and a label' {
        $props = Join-Path $TestDrive 'Directory.Build.props'
        Set-Content -LiteralPath $props -Value '<Project><PropertyGroup><VersionPrefix>1.0.0</VersionPrefix><VersionPrefix>2.0.0</VersionPrefix></PropertyGroup></Project>'
        { Get-ReleaseDotNetVersion -Path $props } | Should -Throw '*VersionPrefix exactly once*'
        Set-Content -LiteralPath $props -Value '<Project><PropertyGroup Condition="''$(CI)'' == ''true''"><VersionPrefix>1.0.0</VersionPrefix></PropertyGroup></Project>'
        { Get-ReleaseDotNetVersion -Path $props } | Should -Throw '*under a condition*'
        Set-Content -LiteralPath $props -Value '<Project><PropertyGroup><VersionPrefix>1.0.0</VersionPrefix><VersionSuffix Condition="true">beta</VersionSuffix></PropertyGroup></Project>'
        { Get-ReleaseDotNetVersion -Path $props } | Should -Throw '*under a condition*'
        Set-Content -LiteralPath $props -Value '<Project><PropertyGroup><VersionPrefix>$(Major).0.0</VersionPrefix></PropertyGroup></Project>'
        { Get-ReleaseDotNetVersion -Path $props } | Should -Throw '*not three numbers*'
        Set-Content -LiteralPath $props -Value '<Project><PropertyGroup><VersionPrefix>1.0.0</VersionPrefix><VersionSuffix>alpha 0</VersionSuffix></PropertyGroup></Project>'
        { Get-ReleaseDotNetVersion -Path $props } | Should -Throw '*not a prerelease label*'
    }
}

Describe 'Test-ReleaseSignatures.ps1: every PE file signed and timestamped, ours or Microsoft''s' {
    BeforeAll {
        $script:Check = Join-Path $script:Tools 'Test-ReleaseSignatures.ps1'
        Mock -ModuleName Release Get-AuthenticodeSignature { Get-TestSignature -Path ([string]@($LiteralPath)[0]) }
    }

    BeforeEach {
        $script:Payload = New-TestPayload -Path (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))
        Set-TestReleaseSigned
    }

    It 'passes when ours carry our signature and every other PE file Microsoft''s, all valid and timestamped' {
        $rows = @(& $script:Check -Path $script:Payload -Publisher 'Engramic Ltd' -PassThru 6>$null)
        $rows.Count | Should -Be 7
        @($rows | Where-Object { $_.Owner -eq 'ours' }).Count | Should -Be 3
        @($rows | Where-Object { $_.Problems.Count }).Count | Should -Be 0
    }

    It 'reports every problem, file by file, and then fails' {
        $global:ReleaseTestSignatures.Remove('baseline.dll')
        $global:ReleaseTestSignatures['Engramic.Baseline.Model.dll'] = New-TestSignature -Subject 'CN=Someone, O=Someone Else' -Issuer 'CN=Some CA, O=Some CA' -Thumbprint '11'
        $global:ReleaseTestSignatures['baseline.exe'] = New-TestOurSignature -NoTimestamp
        $global:ReleaseTestSignatures.Remove('System.CommandLine.dll')
        $global:ReleaseTestSignatures['coreclr.dll'] = New-TestOurSignature
        $global:ReleaseTestSignatures['createdump.exe'] = New-TestSignature -Status 'HashMismatch' -Subject $global:ReleaseTestMicrosoft -Issuer $global:ReleaseTestMicrosoftCA -Thumbprint '12'
        $global:ReleaseTestSignatures['hostfxr.dll'] = New-TestSignature -Subject $global:ReleaseTestMicrosoft -Issuer $global:ReleaseTestMicrosoftCA -Thumbprint '12' -Type 'Catalog'
        $problems = @{}
        { & $script:Check -Path $script:Payload -Publisher 'Engramic Ltd' -PassThru 6>$null | ForEach-Object { $problems[$_.File] = ($_.Problems -join ' | ') } } |
            Should -Throw '*7 of 7 PE file(s)*'
        $problems['baseline.dll'] | Should -Be 'not signed'
        $problems['Engramic.Baseline.Model.dll'] | Should -Match 'signed by CN=Someone, O=Someone Else, not Engramic Ltd'
        $problems['baseline.exe'] | Should -Match 'not timestamped'
        $problems['System.CommandLine.dll'] | Should -Match 'PublishReadyToRunExclude' -Because 'an unsigned package assembly is most likely one ReadyToRun rewrote'
        $problems['coreclr.dll'] | Should -Match 'signed by us .* this repository did not build it'
        $problems['createdump.exe'] | Should -Match 'changed since it was signed'
        $problems['hostfxr.dll'] | Should -Match 'catalog'
    }

    It 'accepts an untrusted chain on our files only when told to, and never on Microsoft''s' {
        foreach ($name in @('baseline.exe', 'baseline.dll', 'Engramic.Baseline.Model.dll')) { $global:ReleaseTestSignatures[$name] = New-TestOurSignature -Status 'UnknownError' }
        { & $script:Check -Path $script:Payload -Publisher 'Engramic Ltd' 6>$null } | Should -Throw
        { & $script:Check -Path $script:Payload -Publisher 'Engramic Ltd' -AllowUntrustedChain 6>$null 3>$null } | Should -Not -Throw
        $global:ReleaseTestSignatures['coreclr.dll'] = New-TestSignature -Status 'NotTrusted' -Subject $global:ReleaseTestMicrosoft -Issuer $global:ReleaseTestMicrosoftCA -Thumbprint '12'
        { & $script:Check -Path $script:Payload -Publisher 'Engramic Ltd' -AllowUntrustedChain 6>$null 3>$null } | Should -Throw
    }

    It 'takes our certificate by thumbprint, written in any case or with spaces' {
        $spaced = ($global:ReleaseTestOurThumbprint.ToLowerInvariant() -split '(.{8})' | Where-Object { $_ }) -join ' '
        { & $script:Check -Path $script:Payload -Thumbprint $spaced 6>$null } | Should -Not -Throw
        { & $script:Check -Path $script:Payload -Thumbprint 'FFFF' 6>$null } | Should -Throw
    }

    It 'wants none of ours signed before a release, and every other PE file already Microsoft''s' {
        Set-TestReleaseUnsigned
        { & $script:Check -Path $script:Payload -Unsigned 6>$null } | Should -Not -Throw
        $global:ReleaseTestSignatures['baseline.dll'] = New-TestOurSignature
        { & $script:Check -Path $script:Payload -Unsigned 6>$null } | Should -Throw
        Set-TestReleaseUnsigned
        $global:ReleaseTestSignatures.Remove('System.CommandLine.dll')
        { & $script:Check -Path $script:Payload -Unsigned 6>$null } | Should -Throw
    }

    It 'fails a folder that is not a published one' {
        $empty = Join-Path $TestDrive 'empty'
        New-Item -ItemType Directory -Path $empty | Out-Null
        { & $script:Check -Path $empty -Unsigned 6>$null } | Should -Throw
        { & $script:Check -Path (Join-Path $TestDrive 'nowhere') -Unsigned 6>$null } | Should -Throw '*no folder*'
    }
}

Describe 'Sign-Release.ps1 with .exe and .dll: only what this repository built' {
    BeforeAll {
        $script:Sign = Join-Path $script:Tools 'Sign-Release.ps1'
        Mock -ModuleName Release Get-AuthenticodeSignature { Get-TestSignature -Path ([string]@($LiteralPath)[0]) }
        $script:Kit = Join-Path $TestDrive 'kit'
        New-Item -ItemType Directory -Path $script:Kit -Force | Out-Null
        $script:SignTool = Join-Path $script:Kit 'signtool.exe'
        $script:Dlib = Join-Path $script:Kit 'Azure.CodeSigning.Dlib.dll'
        $script:Metadata = Join-Path $script:Kit 'metadata.json'
        Set-Content -LiteralPath $script:SignTool -Value 'stand-in'
        Set-Content -LiteralPath $script:Dlib -Value 'stand-in'
        Set-Content -LiteralPath $script:Metadata -Value '{ "AccessToken": "stand-in", "ExcludeCredentials": [ "ManagedIdentityCredential" ] }'
        $script:Azure = @{ AzureMetadata = $script:Metadata; SignToolPath = $script:SignTool; DlibPath = $script:Dlib; TimestampUrl = 'http://timestamp.example.test'; IncludeExtensions = @('.exe', '.dll') }
    }

    BeforeEach {
        $script:Payload = New-TestPayload -Path (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))
        Set-TestReleaseUnsigned
        $global:ReleaseTestSignToolCalls = New-Object System.Collections.ArrayList
        $azure = $script:Azure
    }

    It 'signs with signtool, SHA256 and timestamped, each file of ours and no other' {
        Mock Invoke-ReleaseSignTool {
            [void]$global:ReleaseTestSignToolCalls.Add(@($ArgumentList))
            $global:ReleaseTestSignatures[(Split-Path -Leaf $ArgumentList[-1])] = New-TestOurSignature
            [pscustomobject]@{ ExitCode = 0; Output = @('Successfully signed') }
        }
        & $script:Sign -Path $script:Payload @azure 6>$null
        $signed = @($global:ReleaseTestSignToolCalls | ForEach-Object { Split-Path -Leaf $_[-1] } | Sort-Object)
        $signed | Should -Be @('baseline.dll', 'baseline.exe', 'Engramic.Baseline.Model.dll')
        foreach ($call in $global:ReleaseTestSignToolCalls) {
            ($call[0..11] -join ' ') | Should -Be "sign /v /fd SHA256 /tr http://timestamp.example.test /td SHA256 /dlib $($script:Dlib) /dmdf $($script:Metadata)"
        }
    }

    It 'refuses to sign a PE file that already carries a signature, even one the manifest calls ours' {
        $global:ReleaseTestSignatures['baseline.dll'] = New-TestMicrosoftSignature
        Mock Invoke-ReleaseSignTool { [void]$global:ReleaseTestSignToolCalls.Add(@($ArgumentList)); [pscustomobject]@{ ExitCode = 0; Output = @() } }
        { & $script:Sign -Path $script:Payload @azure 6>$null } | Should -Throw '*baseline.dll*already carries a signature*'
        $global:ReleaseTestSignToolCalls.Count | Should -Be 0 -Because 'nothing is signed once one file would be signed over'
    }

    It 'fails when a PE signature has no timestamp' {
        Mock Invoke-ReleaseSignTool {
            $global:ReleaseTestSignatures[(Split-Path -Leaf $ArgumentList[-1])] = New-TestOurSignature -NoTimestamp
            [pscustomobject]@{ ExitCode = 0; Output = @() }
        }
        { & $script:Sign -Path $script:Payload @azure 6>$null 3>$null } | Should -Throw '*3 PE file(s) have no timestamp*'
    }

    It 'fails, saying what signtool said, when signtool fails' {
        Mock Invoke-ReleaseSignTool { [pscustomobject]@{ ExitCode = 1; Output = @('SignTool Error: 403 Forbidden') } }
        { & $script:Sign -Path $script:Payload @azure 6>$null 3>$null } | Should -Throw '*signtool exit 1*403 Forbidden*'
    }

    It 'refuses a folder without a .deps.json' {
        Remove-Item -LiteralPath (Join-Path $script:Payload 'baseline.deps.json')
        Mock Invoke-ReleaseSignTool { [pscustomobject]@{ ExitCode = 0; Output = @() } }
        { & $script:Sign -Path $script:Payload @azure 6>$null } | Should -Throw '*no .deps.json*'
        Should -Invoke Invoke-ReleaseSignTool -Times 0 -Exactly
    }

    It 'signs the PE files of ours with a certificate from a .pfx, through Set-AuthenticodeSignature' {
        $pfx = Join-Path $script:Kit 'test.pfx'
        Set-Content -LiteralPath $pfx -Value 'stand-in'
        Mock Get-PfxCertificate { [pscustomobject]@{ HasPrivateKey = $true; Subject = $global:ReleaseTestOurs; Issuer = $global:ReleaseTestOursCA; NotAfter = (Get-Date).AddDays(3); Thumbprint = $global:ReleaseTestOurThumbprint } }
        Mock Set-AuthenticodeSignature {
            $global:ReleaseTestSignatures[(Split-Path -Leaf ([string]@($LiteralPath)[0]))] = New-TestOurSignature
            [pscustomobject]@{ Status = 'Valid' }
        } -RemoveParameterType 'Certificate'
        & $script:Sign -Path $script:Payload -PfxPath $pfx -IncludeExtensions '.exe', '.dll' -TimestampUrl 'http://timestamp.example.test' 6>$null
        Should -Invoke Set-AuthenticodeSignature -Times 3 -Exactly
        Should -Invoke Set-AuthenticodeSignature -Times 0 -Exactly -ParameterFilter { @('coreclr.dll', 'createdump.exe', 'hostfxr.dll', 'System.CommandLine.dll') -contains (Split-Path -Leaf ([string]@($LiteralPath)[0])) }
        Should -Invoke Set-AuthenticodeSignature -Times 3 -Exactly -ParameterFilter { $TimestampServer -eq 'http://timestamp.example.test' -and $HashAlgorithm -eq 'SHA256' }
    }

    It 'still signs only the PowerShell when not asked for .exe and .dll' {
        Set-Content -LiteralPath (Join-Path $script:Payload 'Invoke-Thing.ps1') -Value "'hello'"
        $pfx = Join-Path $script:Kit 'test.pfx'
        Set-Content -LiteralPath $pfx -Value 'stand-in'
        Mock Get-PfxCertificate { [pscustomobject]@{ HasPrivateKey = $true; Subject = $global:ReleaseTestOurs; Issuer = $global:ReleaseTestOursCA; NotAfter = (Get-Date).AddDays(3); Thumbprint = $global:ReleaseTestOurThumbprint } }
        Mock Set-AuthenticodeSignature {
            $global:ReleaseTestSignatures[(Split-Path -Leaf ([string]@($LiteralPath)[0]))] = New-TestOurSignature
            [pscustomobject]@{ Status = 'Valid' }
        } -RemoveParameterType 'Certificate'
        & $script:Sign -Path $script:Payload -PfxPath $pfx -TimestampUrl 'http://timestamp.example.test' 6>$null
        Should -Invoke Set-AuthenticodeSignature -Times 1 -Exactly
        Should -Invoke Set-AuthenticodeSignature -Times 1 -Exactly -ParameterFilter { (Split-Path -Leaf ([string]@($LiteralPath)[0])) -eq 'Invoke-Thing.ps1' }
    }

    It '-VerifyOnly fails a PE signature without a timestamp, which a script''s only warns about' {
        Set-TestReleaseSigned
        { & $script:Sign -Path $script:Payload -VerifyOnly -IncludeExtensions '.exe', '.dll' 6>$null } | Should -Not -Throw
        $global:ReleaseTestSignatures['baseline.dll'] = New-TestOurSignature -NoTimestamp
        { & $script:Sign -Path $script:Payload -VerifyOnly -IncludeExtensions '.exe', '.dll' 6>$null 3>$null } | Should -Throw '*without a timestamp*'
    }
}

Describe 'Test-ReleaseTag.ps1: a tag is v and the version it releases' {
    BeforeAll {
        $script:TagCheck = Join-Path $script:Tools 'Test-ReleaseTag.ps1'
        function global:New-TestRepository {
            param([string]$Path, [string]$ModuleVersion = '0.3.2', [string]$Props)
            New-Item -ItemType Directory -Path (Join-Path $Path 'src\CEAudit') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $Path 'src\CEAudit\CEAudit.psd1') -Value "@{ ModuleVersion = '$ModuleVersion' }"
            if ($Props) { Set-Content -LiteralPath (Join-Path $Path 'Directory.Build.props') -Value $Props }
            return $Path
        }
        $script:WithDotNet = '<Project><PropertyGroup><VersionPrefix>1.0.0</VersionPrefix><VersionSuffix>alpha.0</VersionSuffix></PropertyGroup></Project>'
    }

    It 'passes a tag for the module as it always has, with or without the .NET solution' {
        $bare = New-TestRepository -Path (Join-Path $TestDrive 'bare')
        & $script:TagCheck -Tag 'v0.3.2' -Root $bare 6>$null | Should -Be 'module'
        { & $script:TagCheck -Tag 'v0.3.3' -Root $bare 6>$null } | Should -Throw "*module's 0.3.2*"
        $both = New-TestRepository -Path (Join-Path $TestDrive 'both') -Props $script:WithDotNet
        & $script:TagCheck -Tag 'v0.3.2' -Root $both 6>$null | Should -Be 'module'
    }

    It 'passes a tag for baseline.exe only with the prefix and the suffix, exactly' {
        $repo = New-TestRepository -Path (Join-Path $TestDrive 'dotnet') -Props $script:WithDotNet
        & $script:TagCheck -Tag 'v1.0.0-alpha.0' -Root $repo 6>$null | Should -Be 'baseline.exe'
        { & $script:TagCheck -Tag 'v1.0.0' -Root $repo 6>$null } | Should -Throw "*baseline.exe's 1.0.0-alpha.0*"
        { & $script:TagCheck -Tag 'v1.0.0-ALPHA.0' -Root $repo 6>$null } | Should -Throw
        { & $script:TagCheck -Tag '1.0.0-alpha.0' -Root $repo 6>$null } | Should -Throw
    }

    It 'fails a tag for baseline.exe when Directory.Build.props writes the version in a way it cannot trust, and never one for the module' {
        $repo = New-TestRepository -Path (Join-Path $TestDrive 'twice') -Props '<Project><PropertyGroup><VersionPrefix>1.0.0</VersionPrefix></PropertyGroup><PropertyGroup><VersionPrefix>1.0.1</VersionPrefix></PropertyGroup></Project>'
        { & $script:TagCheck -Tag 'v1.0.0' -Root $repo 6>$null } | Should -Throw '*cannot be read*exactly once*'
        & $script:TagCheck -Tag 'v0.3.2' -Root $repo 6>$null | Should -Be 'module'
    }

    It 'is what the release workflow runs on every v* tag, for this repository''s own props' {
        $workflow = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github\workflows\release.yml') -Raw
        $workflow | Should -Match ([regex]::Escape('run: ./tools/Test-ReleaseTag.ps1 -Tag $env:GITHUB_REF_NAME'))
        $version = Get-ReleaseDotNetVersion -Path (Join-Path $script:RepoRoot 'Directory.Build.props')
        & $script:TagCheck -Tag "v$version" 6>$null | Should -Be 'baseline.exe'
    }
}

Describe 'New-SignedRelease.ps1 -DotNet' {
    It 'checks the unsigned build, signs only .exe and .dll, and checks every PE file before packing' {
        $text = Get-Content -LiteralPath (Join-Path $script:Tools 'New-SignedRelease.ps1') -Raw
        $start = $text.IndexOf('if ($DotNet) {')
        $start | Should -BeGreaterThan 0
        $block = $text.Substring($start)
        $order = @(
            "--locked-mode",
            "Test-ReleaseSignatures.ps1') -Path `$payload -Unsigned",
            "IncludeExtensions = @('.exe', '.dll')",
            "Sign-Release.ps1') @signArgs",
            "Test-ReleaseSignatures.ps1') @checkArgs",
            "--version",
            'Compress-Archive')
        $at = -1
        foreach ($step in $order) {
            $next = $block.IndexOf($step, [Math]::Max($at, 0))
            $next | Should -BeGreaterThan $at -Because "'$step' comes next in the .NET release"
            $at = $next
        }
        $block.IndexOf('return') | Should -BeLessThan $block.IndexOf('Build-IntunePackage.ps1') -Because 'the PowerShell release is untouched by -DotNet'
    }
}

Describe 'Invoke-PreFlight.ps1' {
    It 'runs the .NET steps exactly as the .NET workflow does, and hygiene and actionlint' {
        $preflight = Get-Content -LiteralPath (Join-Path $script:Tools 'Invoke-PreFlight.ps1') -Raw
        $workflow = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github\workflows\dotnet.yml') -Raw
        $pairs = @(
            @{ Workflow = 'dotnet restore Baseline.slnx --locked-mode'; PreFlight = "@('restore', 'Baseline.slnx', '--locked-mode')" }
            @{ Workflow = 'dotnet build Baseline.slnx --configuration Release --no-restore -warnaserror'; PreFlight = "@('build', 'Baseline.slnx', '--configuration', 'Release', '--no-restore', '-warnaserror')" }
            @{ Workflow = 'dotnet test --solution Baseline.slnx --configuration Release --no-build'; PreFlight = "@('test', '--solution', 'Baseline.slnx', '--configuration', 'Release', '--no-build')" }
        )
        foreach ($pair in $pairs) {
            $workflow | Should -Match ([regex]::Escape($pair.Workflow)) -Because 'the pre-flight copies this step of dotnet.yml; change both together'
            $preflight | Should -Match ([regex]::Escape($pair.PreFlight))
        }
        $preflight | Should -Match ([regex]::Escape("tools\hygiene\Test-Hygiene.ps1"))
        $preflight | Should -Match 'Get-Command actionlint'
    }
}

Describe 'The sign-test sandbox' {
    It 'signs baseline.exe, checks every PE file and runs the slice from the signed build' {
        $sandbox = Get-Content -LiteralPath (Join-Path $script:Tools 'sandbox\Invoke-SandboxSignTest.ps1') -Raw
        $sandbox | Should -Match ([regex]::Escape("& `$checkScript -Path `$payload -Unsigned"))
        $sandbox | Should -Match ([regex]::Escape("-IncludeExtensions '.exe', '.dll'"))
        $sandbox | Should -Match ([regex]::Escape("& `$checkScript -Path `$payload -Thumbprint `$cert.Thumbprint -AllowUntrustedChain -PassThru"))
        $sandbox | Should -Match ([regex]::Escape("@('audit', '--id', 'SU-01')"))
        $sandbox | Should -Match ([regex]::Escape("@('--version')"))
    }
}
