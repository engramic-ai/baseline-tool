#Requires -Version 5.1
<#
.SYNOPSIS
    Runs inside Windows Sandbox: proves tools\Sign-Release.ps1, the -RequireSignature gate, and the
    signing of baseline.exe with the check that every PE file is signed and timestamped.
.DESCRIPTION
    A self-signed certificate is useless for a real release, but it exercises every step of the
    pipeline, so the only thing left to change when a real certificate arrives is which credential
    is passed in. The certificate is created here and dies with the sandbox; it is trusted only
    inside this throwaway machine.

    Checks, in order:
      1. Sign-Release refuses a self-signed certificate unless told it is a test.
      2. -RequireSignature refuses to pack an unsigned payload.
      3. Signing then packing succeeds, and every shipped .ps1/.psm1/.psd1 verifies as Valid.
      4. Signatures are timestamped, so they outlive the certificate.
      5. The separately-uploaded Intune scripts are signed too.
      6. Data files are left alone.

    Then baseline.exe, the .NET port, with the SDK that global.json names (installed here by
    dotnet-install.ps1, which must carry Microsoft's valid signature):
      7. It is published self-contained.
      8. Before signing, none of our PE files is signed and every other one carries Microsoft's
         signature, and the every-PE check (tools\Test-ReleaseSignatures.ps1) fails, naming each of ours.
      9. Sign-Release signs only the .exe and .dll files this repository built, and every runtime and
         package file stays byte for byte as it was. It refuses to sign over Microsoft's signature, even
         on a file that a manifest calls ours.
     10. Every PE file then carries a timestamped signature, ours or Microsoft's, and a byte changed in
         a signed file is caught.
     11. The signed baseline.exe runs: --version, audit --id SU-01, and the status.json it writes.
     12. When the host holds a build signed by tools\New-SignedRelease.ps1 -DotNet
         (build\release-dotnet), the same check and the same run on that build as it was signed there.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or -not (Test-Path 'C:\baseline-tool\tools\Sign-Release.ps1')) {
    throw 'This creates and trusts a certificate. It only runs inside a Windows Sandbox started by tools\sandbox\New-SandboxRun.ps1 -Environment sign-test.'
}
$results = if ($env:SANDBOX_RESULTS) { $env:SANDBOX_RESULTS } else { Join-Path 'C:\results' (Get-Date -Format 'yyyyMMdd-HHmmss') }
New-Item -ItemType Directory -Path $results -Force | Out-Null

$checks = New-Object System.Collections.ArrayList
function Add-Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    [void]$checks.Add([pscustomobject]@{ Check = $Name; Ok = $Ok; Detail = $Detail })
    Write-Host ("  [{0}] {1}{2}" -f $(if ($Ok) { '+' } else { '-' }), $Name, $(if ($Detail) { " - $Detail" })) -ForegroundColor $(if ($Ok) { 'Green' } else { 'Red' })
}

$work = 'C:\work\baseline-tool'
New-Item -ItemType Directory -Path $work -Force | Out-Null
# artifacts holds the host's .NET build output, which the sandbox builds again for itself.
& robocopy.exe 'C:\baseline-tool' $work /E /NFL /NDL /NJH /NJS /XD .git output build artifacts .playwright-mcp | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed with exit code $LASTEXITCODE" }
Set-Location $work

Write-Host '==> Creating a throwaway code-signing certificate' -ForegroundColor Cyan
$cert = New-SelfSignedCertificate -Type CodeSigningCert `
    -Subject 'CN=Engramic Baseline TEST - self-signed, do not publish' `
    -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddDays(30)
# The certificate is deliberately NOT installed as a trusted root. Doing so needs a consent dialog
# no automated run can answer, and trusting it would test Windows rather than this pipeline. What
# matters here is that every shipped file ends up carrying our signature and a timestamp.
Write-Host "    thumbprint $($cert.Thumbprint)"

Write-Host '==> 1. a self-signed certificate is refused unless declared a test' -ForegroundColor Cyan
New-Item -ItemType Directory -Path 'C:\work\probe' -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $work 'app\Invoke-CEAudit.ps1') -Destination 'C:\work\probe' -Force
$refused = $false
try { & (Join-Path $work 'tools\Sign-Release.ps1') -Path 'C:\work\probe' -Thumbprint $cert.Thumbprint -ErrorAction Stop }
catch { $refused = ($_.Exception.Message -match 'self-signed') }
Add-Check 'Sign-Release refuses a self-signed certificate by default' $refused

Write-Host '==> 2. -RequireSignature refuses to pack an unsigned payload' -ForegroundColor Cyan
$blocked = $false
try { & (Join-Path $work 'intune\Build-IntunePackage.ps1') -OutputPath 'C:\work\build-unsigned' -RequireSignature -ErrorAction Stop | Out-Null }
catch { $blocked = ($_.Exception.Message -match 'not validly signed|NotSigned') }
Add-Check '-RequireSignature blocks an unsigned package' $blocked

Write-Host '==> 3. sign, then pack' -ForegroundColor Cyan
$out = 'C:\work\build-signed'
& (Join-Path $work 'intune\Build-IntunePackage.ps1') -OutputPath $out -DownloadTool `
    -SignThumbprint $cert.Thumbprint -AllowSelfSigned -RequireSignature | Out-Host
$intunewin = @(Get-ChildItem -LiteralPath $out -Filter '*.intunewin' -ErrorAction SilentlyContinue)
Add-Check 'package produced from signed files' ($intunewin.Count -eq 1) ($intunewin.Name -join ',')

Write-Host '==> 4. every shipped script verifies, and is timestamped' -ForegroundColor Cyan
$payload = Join-Path $out 'payload'
$shipped = @(Get-ChildItem -LiteralPath $payload -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1' })
$sigs = @($shipped | ForEach-Object { Get-AuthenticodeSignature -LiteralPath $_.FullName })
$signedByUs = @($sigs | Where-Object { $_.SignerCertificate.Thumbprint -eq $cert.Thumbprint }).Count
$stamped = @($sigs | Where-Object { $_.TimeStamperCertificate }).Count
$notSigned = @($sigs | Where-Object { $_.Status -eq 'NotSigned' }).Count
Add-Check 'every shipped PowerShell file carries our signature' ($signedByUs -eq $shipped.Count) "$signedByUs of $($shipped.Count)"
Add-Check 'none left unsigned' ($notSigned -eq 0) "$notSigned unsigned"
Add-Check 'all signatures are timestamped' ($stamped -eq $shipped.Count) "$stamped of $($shipped.Count)"

Write-Host '==> 5. the separately-uploaded Intune scripts are signed' -ForegroundColor Cyan
$uploadScripts = @(Get-ChildItem -LiteralPath (Join-Path $out 'upload') -Filter '*.ps1')
$uploadSigned = @($uploadScripts | ForEach-Object { Get-AuthenticodeSignature -LiteralPath $_.FullName } | Where-Object { $_.SignerCertificate.Thumbprint -eq $cert.Thumbprint }).Count
Add-Check 'uploaded Intune scripts are signed' ($uploadSigned -eq $uploadScripts.Count) "$uploadSigned of $($uploadScripts.Count)"

Write-Host '==> 6. data files are left alone' -ForegroundColor Cyan
$json = @(Get-ChildItem -LiteralPath (Join-Path $payload 'config') -Filter '*.json' -ErrorAction SilentlyContinue)
$touched = @($json | Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match 'SIG # Begin signature block' }).Count
Add-Check 'config JSON is not signed' ($touched -eq 0) "$($json.Count) file(s) checked"

# --- baseline.exe --------------------------------------------------------------------------------
function Invoke-Captured {
    # Runs a program in this console and returns its exit code and output. A line on stderr must not
    # stop the script, as it would under 'Stop' in Windows PowerShell 5.1.
    param([string]$FilePath, [string[]]$ArgumentList)
    $ErrorActionPreference = 'Continue'
    $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" })
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output -join "`r`n") }
}

function Test-SignedSlice {
    # Runs the slice from a signed build: --version must print the version in Directory.Build.props,
    # audit --id SU-01 must run, and its status.json must carry SU-01 and a byte order mark.
    param([string]$Folder, [string]$Label, [string]$ExpectedVersion)
    $exe = Join-Path $Folder 'baseline.exe'
    $version = Invoke-Captured -FilePath $exe -ArgumentList @('--version')
    Add-Check "$Label --version prints $ExpectedVersion" ($version.ExitCode -eq 0 -and $version.Output.Trim() -eq $ExpectedVersion) "$($version.Output.Trim()) (exit $($version.ExitCode))"
    $audit = Invoke-Captured -FilePath $exe -ArgumentList @('audit', '--id', 'SU-01')
    $audit.Output | Out-Host
    Add-Check "$Label audit --id SU-01 runs" ($audit.ExitCode -eq 0 -and $audit.Output -match 'SU-01') "exit $($audit.ExitCode)"
    # Through a file handle, so the bytes arrive exactly as written.
    $statusFile = Join-Path $results ("status-{0}.json" -f ($Label -replace '[^A-Za-z0-9]+', '-').Trim('-'))
    $run = Start-Process -FilePath $exe -ArgumentList @('audit', '--id', 'SU-01', '--json', 'status') -RedirectStandardOutput $statusFile -NoNewWindow -Wait -PassThru
    $bytes = [IO.File]::ReadAllBytes($statusFile)
    $bom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $su01 = $null
    $toolVersion = ''
    if ($bom) {
        $status = [Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3) | ConvertFrom-Json
        if ($status.PSObject.Properties['toolVersion']) { $toolVersion = [string]$status.toolVersion }
        if ($status.PSObject.Properties['checks'] -and $status.checks.PSObject.Properties['SU-01']) { $su01 = $status.checks.'SU-01' }
    }
    Add-Check "$Label writes status.json with SU-01" ($run.ExitCode -eq 0 -and $bom -and $null -ne $su01 -and $toolVersion -eq $ExpectedVersion) $(if ($su01) { "SU-01 $($su01.status), toolVersion $toolVersion" } else { "exit $($run.ExitCode), byte order mark $bom" })
}

Import-Module (Join-Path $work 'tools\Release.psm1') -Force
$checkScript = Join-Path $work 'tools\Test-ReleaseSignatures.ps1'
$signScript = Join-Path $work 'tools\Sign-Release.ps1'
$expectedVersion = Get-ReleaseDotNetVersion -Path (Join-Path $work 'Directory.Build.props')
$sdkVersion = [string](Get-Content -LiteralPath (Join-Path $work 'global.json') -Raw | ConvertFrom-Json).sdk.version

Write-Host "==> 7. publish baseline.exe self-contained, with SDK $sdkVersion" -ForegroundColor Cyan
$dotnetRoot = 'C:\work\dotnet'
$dotnet = Join-Path $dotnetRoot 'dotnet.exe'
$payload = 'C:\work\dotnet-payload'
$published = $false
$publishDetail = ''
try {
    $installer = 'C:\work\dotnet-install.ps1'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri 'https://dot.net/v1/dotnet-install.ps1' -OutFile $installer -UseBasicParsing
    $installerSignature = Get-AuthenticodeSignature -LiteralPath $installer
    $installerSigner = if ($installerSignature.SignerCertificate) { [string]$installerSignature.SignerCertificate.Subject } else { '' }
    if ($installerSignature.Status -ne 'Valid' -or $installerSigner -notmatch '(^|, )O=Microsoft Corporation(,|$)') {
        throw "dotnet-install.ps1 is not validly signed by Microsoft ($($installerSignature.Status), $installerSigner), so it was not run."
    }
    & $installer -Version $sdkVersion -InstallDir $dotnetRoot -Architecture x64 -NoPath | Out-Host
    $env:DOTNET_ROOT = $dotnetRoot
    $env:PATH = "$dotnetRoot;$env:PATH"
    $env:DOTNET_NOLOGO = 'true'
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = 'true'
    $env:NUGET_XMLDOC_MODE = 'skip'
    $cli = Join-Path $work 'src\Engramic.Baseline.Cli\Engramic.Baseline.Cli.csproj'
    # Restoring the command line restores what it references too; publishing then adds the runtime
    # without restoring again, as CI does.
    $restore = Invoke-Captured -FilePath $dotnet -ArgumentList @('restore', $cli, '--locked-mode')
    $restore.Output | Out-Host
    if ($restore.ExitCode -ne 0) { throw "the locked restore failed with exit code $($restore.ExitCode)" }
    $publish = Invoke-Captured -FilePath $dotnet -ArgumentList @('publish', $cli, '--configuration', 'Release', '--runtime', 'win-x64', '--no-restore', '--output', $payload)
    $publish.Output | Out-Host
    if ($publish.ExitCode -ne 0) { throw "dotnet publish failed with exit code $($publish.ExitCode)" }
    $published = (Test-Path -LiteralPath (Join-Path $payload 'baseline.exe')) -and (Test-Path -LiteralPath (Join-Path $payload 'coreclr.dll'))
    $publishDetail = "SDK $sdkVersion, $(@(Get-ChildItem -LiteralPath $payload -File).Count) file(s)"
}
catch { $publishDetail = $_.Exception.Message }
Add-Check 'baseline.exe published self-contained' $published $publishDetail

if ($published) {
    $own = @(Get-ReleaseOwnFile -Path $payload)
    $ownNames = @($own | ForEach-Object { $_.Substring($payload.Length + 1) })
    $before = @{}
    foreach ($file in @(Get-ReleasePEFile -Path $payload)) { $before[$file.FullName] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }

    Write-Host '==> 8. before signing' -ForegroundColor Cyan
    $unsignedOk = $false
    $unsignedDetail = ''
    try { & $checkScript -Path $payload -Unsigned; $unsignedOk = $true; $unsignedDetail = "$($own.Count) of ours, $($before.Count - $own.Count) Microsoft's" }
    catch { $unsignedDetail = $_.Exception.Message }
    Add-Check 'before signing, nothing of ours is signed and every other PE file is Microsoft''s' $unsignedOk $unsignedDetail
    $named = New-Object System.Collections.ArrayList
    $refusedUnsigned = $false
    try {
        & $checkScript -Path $payload -Thumbprint $cert.Thumbprint -AllowUntrustedChain -PassThru |
            ForEach-Object { if ($_.Problems.Count) { [void]$named.Add([string]$_.File) } }
    }
    catch { $refusedUnsigned = $true }
    $allNamed = ($named.Count -eq $ownNames.Count) -and -not @($ownNames | Where-Object { $named -notcontains $_ }).Count
    Add-Check 'the every-PE check fails the unsigned build and names each file of ours' ($refusedUnsigned -and $allNamed) ($named -join ', ')

    Write-Host '==> 9. sign what this repository built, and nothing else' -ForegroundColor Cyan
    $signedOk = $true
    try { & $signScript -Path $payload -Thumbprint $cert.Thumbprint -AllowSelfSigned -IncludeExtensions '.exe', '.dll' | Out-Host }
    catch { $signedOk = $false; Write-Host "    $($_.Exception.Message)" -ForegroundColor Red }
    $changed = @($before.Keys | Where-Object { (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash -ne $before[$_] })
    $ownSet = @{}
    foreach ($o in $own) { $ownSet[$o] = $true }
    $changedOurs = @($changed | Where-Object { $ownSet.ContainsKey($_) })
    $changedOthers = @($changed | Where-Object { -not $ownSet.ContainsKey($_) })
    Add-Check 'Sign-Release signed each .exe and .dll this repository built' ($signedOk -and $changedOurs.Count -eq $own.Count) "$($changedOurs.Count) of $($own.Count): $($ownNames -join ', ')"
    Add-Check 'every runtime and package file is byte for byte as published' ($changedOthers.Count -eq 0) $(if ($changedOthers.Count) { "changed: $(($changedOthers | Select-Object -First 5) -join ', ')" } else { "$($before.Count - $own.Count) file(s) untouched" })

    # A manifest that calls a copy of Microsoft's coreclr.dll a project of ours: the signature it
    # already carries must stop Sign-Release, whatever the manifest says.
    $probe = 'C:\work\resign-probe'
    New-Item -ItemType Directory -Path $probe -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $payload 'coreclr.dll') -Destination (Join-Path $probe 'probe.dll') -Force
    $target = '.NETCoreApp,Version=v10.0/win-x64'
    [ordered]@{
        runtimeTarget = [ordered]@{ name = $target }
        targets       = [ordered]@{ $target = [ordered]@{ 'probe/1.0.0' = [ordered]@{ runtime = [ordered]@{ 'probe.dll' = [ordered]@{} } } } }
        libraries     = [ordered]@{ 'probe/1.0.0' = [ordered]@{ type = 'project' } }
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $probe 'probe.deps.json') -Encoding ASCII
    $probeHash = (Get-FileHash -LiteralPath (Join-Path $probe 'probe.dll') -Algorithm SHA256).Hash
    $refusedResign = $false
    try { & $signScript -Path $probe -Thumbprint $cert.Thumbprint -AllowSelfSigned -IncludeExtensions '.dll' | Out-Null }
    catch { $refusedResign = ($_.Exception.Message -match 'already carries a signature') }
    $probeKept = ((Get-FileHash -LiteralPath (Join-Path $probe 'probe.dll') -Algorithm SHA256).Hash -eq $probeHash)
    Add-Check 'Sign-Release refuses to sign over Microsoft''s signature, whatever a manifest says' ($refusedResign -and $probeKept)

    Write-Host '==> 10. every PE file signed and timestamped, and a changed byte caught' -ForegroundColor Cyan
    $everyOk = $false
    $everyDetail = ''
    try {
        $rows = @(& $checkScript -Path $payload -Thumbprint $cert.Thumbprint -AllowUntrustedChain -PassThru)
        $everyOk = $true
        $everyDetail = "$(@($rows | Where-Object { $_.Owner -eq 'ours' }).Count) of ours by the test certificate, $(@($rows | Where-Object { $_.Owner -ne 'ours' }).Count) by Microsoft"
    }
    catch { $everyDetail = $_.Exception.Message }
    Add-Check 'every PE file carries a timestamped signature, ours or Microsoft''s' $everyOk $everyDetail
    $tampered = 'C:\work\dotnet-tampered'
    & robocopy.exe $payload $tampered /E /NFL /NDL /NJH /NJS | Out-Null
    $victim = Join-Path $tampered 'Engramic.Baseline.Model.dll'
    $bytes = [IO.File]::ReadAllBytes($victim)
    $at = [int]($bytes.Length / 3)
    $bytes[$at] = $bytes[$at] -bxor 0xFF
    [IO.File]::WriteAllBytes($victim, $bytes)
    $tamperRows = New-Object System.Collections.ArrayList
    try { & $checkScript -Path $tampered -Thumbprint $cert.Thumbprint -AllowUntrustedChain -PassThru | ForEach-Object { [void]$tamperRows.Add($_) } }
    catch { Write-Host "    $($_.Exception.Message)" }
    $caught = @($tamperRows | Where-Object { $_.File -eq 'Engramic.Baseline.Model.dll' -and ($_.Problems -join ' ') -match 'changed since it was signed' }).Count -eq 1
    Add-Check 'a byte changed in a signed file is caught' $caught 'Engramic.Baseline.Model.dll'

    Write-Host '==> 11. the signed baseline.exe runs the slice' -ForegroundColor Cyan
    Test-SignedSlice -Folder $payload -Label 'the signed baseline.exe' -ExpectedVersion $expectedVersion
}

# A build signed on the host by tools\New-SignedRelease.ps1 -DotNet, as it was signed there.
Write-Host '==> 12. a build signed on the host' -ForegroundColor Cyan
$hostBuild = 'C:\baseline-tool\build\release-dotnet'
$hostBuildNote = 'none: run tools\New-SignedRelease.ps1 -DotNet on the host to include one'
if (Test-Path -LiteralPath (Join-Path $hostBuild 'release.json')) {
    $info = Get-Content -LiteralPath (Join-Path $hostBuild 'release.json') -Raw | ConvertFrom-Json
    $hostCopy = 'C:\work\host-signed'
    & robocopy.exe (Join-Path $hostBuild ([string]$info.payload)) $hostCopy /E /NFL /NDL /NJH /NJS | Out-Null
    $hostBuildNote = "$($info.version) from commit $($info.commit), published by $($info.publisher)$(if ($info.untrustedChain) { ', on an untrusted chain (a test profile)' })"
    $hostArgs = @{ Path = $hostCopy; Publisher = [string]$info.publisher }
    if ($info.untrustedChain) { $hostArgs['AllowUntrustedChain'] = $true }
    $hostOk = $false
    $hostDetail = ''
    try { $hostRows = @(& $checkScript @hostArgs -PassThru); $hostOk = $true; $hostDetail = "$($hostRows.Count) PE file(s)" }
    catch { $hostDetail = $_.Exception.Message }
    Add-Check 'the build signed on the host: every PE file signed and timestamped, ours or Microsoft''s' $hostOk $hostDetail
    Test-SignedSlice -Folder $hostCopy -Label 'the host-signed baseline.exe' -ExpectedVersion ([string]$info.version)
}
else { Write-Host "    $hostBuildNote" -ForegroundColor Yellow }

$fail = @($checks | Where-Object { -not $_.Ok }).Count
$lines = @("# Signing pipeline test $(Split-Path -Leaf $results)", '',
    "Verdict: **$(if ($fail) { 'FAILED' } else { 'PASSED' })**", '',
    "Certificate: self-signed, `CN=Engramic Baseline TEST`, created in and destroyed with the sandbox.", '',
    "Build signed on the host: $hostBuildNote.", '',
    '| Check | Result | Detail |', '|---|---|---|')
foreach ($c in $checks) { $lines += "| $($c.Check) | $(if ($c.Ok) { 'pass' } else { '**fail**' }) | $($c.Detail) |" }
$lines += @('', 'A self-signed certificate proves the mechanism, not the trust. Only a certificate from Azure Artifact Signing or a public CA produces a release anyone should install.')
Set-Content -LiteralPath (Join-Path $results 'sign-test.md') -Value ($lines -join "`r`n") -Encoding UTF8
if ($intunewin.Count) { Copy-Item -LiteralPath $intunewin[0].FullName -Destination $results -Force }

Write-Host ''
$checks | Format-Table -AutoSize | Out-String | Write-Host
Write-Host "Signing pipeline: $(if ($fail) { "FAILED ($fail check(s))" } else { 'PASSED' })" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
Write-Host "Results on the host under build\sandbox\results\sign-test\$(Split-Path -Leaf $results). Close this window to destroy the sandbox." -ForegroundColor Cyan
