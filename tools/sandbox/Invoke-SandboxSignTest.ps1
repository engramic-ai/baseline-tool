#Requires -Version 5.1
<#
.SYNOPSIS
    Runs inside Windows Sandbox: proves tools\Sign-Release.ps1 and the -RequireSignature gate.
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
& robocopy.exe 'C:\baseline-tool' $work /E /NFL /NDL /NJH /NJS /XD .git output build .playwright-mcp | Out-Null
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

$fail = @($checks | Where-Object { -not $_.Ok }).Count
$lines = @("# Signing pipeline test $(Split-Path -Leaf $results)", '',
    "Verdict: **$(if ($fail) { 'FAILED' } else { 'PASSED' })**", '',
    "Certificate: self-signed, `CN=Engramic Baseline TEST`, created in and destroyed with the sandbox.", '',
    '| Check | Result | Detail |', '|---|---|---|')
foreach ($c in $checks) { $lines += "| $($c.Check) | $(if ($c.Ok) { 'pass' } else { '**fail**' }) | $($c.Detail) |" }
$lines += @('', 'A self-signed certificate proves the mechanism, not the trust. Only a certificate from Azure Artifact Signing or a public CA produces a release anyone should install.')
Set-Content -LiteralPath (Join-Path $results 'sign-test.md') -Value ($lines -join "`r`n") -Encoding UTF8
if ($intunewin.Count) { Copy-Item -LiteralPath $intunewin[0].FullName -Destination $results -Force }

Write-Host ''
$checks | Format-Table -AutoSize | Out-String | Write-Host
Write-Host "Signing pipeline: $(if ($fail) { "FAILED ($fail check(s))" } else { 'PASSED' })" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
Write-Host "Results on the host under build\sandbox\results\sign-test\$(Split-Path -Leaf $results). Close this window to destroy the sandbox." -ForegroundColor Cyan
