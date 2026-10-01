#Requires -Version 5.1
<#
.SYNOPSIS
    On a machine that is there to be changed, such as a CI runner: installs Engramic Baseline and proves the
    status.json contract end to end, as SYSTEM.

.DESCRIPTION
    The Contracts job in .github\workflows\dotnet.yml runs this. Each step prints PASS or FAIL; the script exits 1
    if any fails.

      1. baseline.exe scheduled-audit, run as SYSTEM before anything is installed, refuses the missing data folder
         and creates nothing: SecureStore checks the folder, it never makes one.
      2. intune\Install-CEChecker.ps1 installs, and the data folder it makes is born locked (owned by
         Administrators, a protected access list of SYSTEM and Administrators only) and sealed (DataRootSealed).
      3. With the seal taken away, scheduled-audit as SYSTEM refuses the folder and writes nothing; the seal is
         put back.
      4. scheduled-audit as SYSTEM writes status.json: UTF-8 with a byte order mark, every key as the golden file
         status-su01-pass.json spells and orders it, written by this baseline.exe as SYSTEM, owned by
         Administrators, trusted by the Intune scripts' own check, and no temporary file left.
      5. Three more runs replace it atomically: each time a new file takes the name (its file ID changes), and a
         reader polling the file throughout only ever sees the old file or the new one, whole, never a part of
         one and never no file.
      6. The unchanged discovery and detection scripts read it, in 64-bit and 32-bit Windows PowerShell 5.1, as
         SYSTEM and as this elevated administrator (tools\contracts\Invoke-IntuneReaders.ps1).
      7. The installed module writes status.json for SU-01 into the same data folder as SYSTEM
         (tools\contracts\Write-ModuleStatus.ps1), and the scripts read that too, the same ways.
      8. What they reported for the two files is the same, account by account, apart from what the ledger,
         tests\parity\divergences.json, ignores: the tool version (tools\contracts\Compare-IntuneReaders.ps1).
      9. With Users given write access to the data folder, scheduled-audit as SYSTEM refuses it and leaves
         status.json alone; the access is taken away again.
     10. With a junction in the data folder's place, leading to an empty folder only SYSTEM and Administrators can
         change, scheduled-audit as SYSTEM sees the junction itself, through the handle it opens, refuses it and
         writes nothing where it leads; the data folder is put back.

    Runs as SYSTEM go through tools\ci\Invoke-AsSystem.ps1, a temporary scheduled task, from -WorkPath, which is
    made so that only SYSTEM and Administrators can change it. Every file the steps make is kept there: both
    status.json files, what the scripts reported, the comparisons and the output of every run.

    It installs the tool machine-wide and replaces status.json in its data folder, so it refuses to run where
    the tool is already installed or its data folder exists, unless given -Force. It leaves the tool installed.

.PARAMETER BaselineExe
    The published, self-contained baseline.exe to test, in a folder only administrators can change.

.PARAMETER WorkPath
    A folder for the runs as SYSTEM and everything the steps keep. It must not exist yet.

.PARAMETER TimeoutMinutes
    How long each run may take. Default: 10.

.PARAMETER Force
    Run even where Engramic Baseline is installed or its data folder exists.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\contracts\Test-StatusContract.ps1 -BaselineExe 'C:\Program Files\EngramicBaselineCI\baseline.exe' -WorkPath C:\contracts
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BaselineExe,
    [Parameter(Mandatory = $true)][string]$WorkPath,
    [ValidateRange(1, 60)][int]$TimeoutMinutes = 10,
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell on a machine that is there to be changed, such as a CI runner.'
}

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$system32 = [Environment]::GetFolderPath('System')
$ps64 = Join-Path $system32 'WindowsPowerShell\v1.0\powershell.exe'
$dataRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EngramicBaseline'
$statusPath = Join-Path $dataRoot 'status.json'
$installKey = 'HKLM:\SOFTWARE\EngramicBaseline'
$sealKey = 'HKLM:\SOFTWARE\EngramicBaseline.DataRoot'
$invokeAsSystem = Join-Path $repo 'tools\ci\Invoke-AsSystem.ps1'
$readers = Join-Path $repo 'tools\contracts\Invoke-IntuneReaders.ps1'
$golden = Join-Path $repo 'tests\Engramic.Baseline.Contracts.Tests\Golden\status-su01-pass.json'
$timeoutSeconds = $TimeoutMinutes * 60
$steps = New-Object System.Collections.ArrayList

if (-not $Force -and ((Test-Path -LiteralPath $installKey) -or (Test-Path -LiteralPath $dataRoot))) {
    throw "Engramic Baseline is installed here or $dataRoot exists. This installs the tool and replaces its status.json, so run it only on a machine that is there to be changed, such as a CI runner, or pass -Force."
}
if (Test-Path -LiteralPath $WorkPath) { throw "$WorkPath exists already; give a folder that does not exist yet." }
if (-not (Test-Path -LiteralPath $BaselineExe -PathType Leaf)) { throw "baseline.exe was not found at $BaselineExe." }
# TEMPORARY, for spike 2 of the .NET port, reverted before review: the SHA-256 of every file CI published, for
# tools/spikes/Measure-RuntimeSpike.ps1 -Phase Determinism -ReferenceManifest to compare a rebuild of the same commit.
if ($env:GITHUB_ACTIONS -eq 'true') {
    $spikeRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $BaselineExe)).ProviderPath.TrimEnd('\')
    Write-Host "SPIKE2-ROOT $spikeRoot"
    foreach ($spikeFile in @(Get-ChildItem -LiteralPath $spikeRoot -Recurse -File -Force | Sort-Object FullName)) {
        Write-Host ('SPIKE2-SHA256 {0}  {1}' -f (Get-FileHash -LiteralPath $spikeFile.FullName -Algorithm SHA256).Hash, $spikeFile.FullName.Substring($spikeRoot.Length + 1))
    }
}
$BaselineExe = (Resolve-Path -LiteralPath $BaselineExe).ProviderPath
$security = New-Object Security.AccessControl.DirectorySecurity
$security.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
if ($PSVersionTable.PSVersion.Major -ge 6) { [void][IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($WorkPath), $security) }
else { [void][IO.Directory]::CreateDirectory($WorkPath, $security) }
$systemWork = Join-Path $WorkPath 'system'
$log = Join-Path $WorkPath 'runs.log'

function Add-Step {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    [void]$steps.Add([pscustomobject]@{ Step = $Name; Result = $(if ($Ok) { 'PASS' } else { 'FAIL' }); Detail = $Detail })
    Write-Host ('  [{0}] {1}{2}' -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $(if ($Detail) { ": $Detail" } else { '' }))
}

function Invoke-System {
    <# Runs a program as SYSTEM (tools\ci\Invoke-AsSystem.ps1) and keeps what it printed in runs.log. #>
    param([string]$FilePath, [string[]]$ArgumentList, [scriptblock]$WhileRunning)
    $run = & $invokeAsSystem -FilePath $FilePath -ArgumentList $ArgumentList -WorkPath $systemWork -TimeoutSeconds $timeoutSeconds -WhileRunning $WhileRunning
    $text = @("== as SYSTEM: $FilePath $($ArgumentList -join ' ')", "exit $($run.ExitCode)$(if ($run.TimedOut) { ' (timed out)' })") + @($run.Output) + @($run.Errors | ForEach-Object { "error: $_" }) + ''
    [IO.File]::AppendAllText($log, ($text -join "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    return $run
}

function Invoke-ScheduledAudit {
    <# baseline.exe scheduled-audit as SYSTEM. #>
    param([scriptblock]$WhileRunning)
    return Invoke-System -FilePath $BaselineExe -ArgumentList @('scheduled-audit') -WhileRunning $WhileRunning
}

function Invoke-SystemScript {
    <# A script in Windows PowerShell 5.1 as SYSTEM. #>
    param([string]$Script, [string[]]$ArgumentList)
    return Invoke-System -FilePath $ps64 -ArgumentList (@('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Script) + $ArgumentList)
}

function Get-FileId {
    <# The NTFS file ID of a file: a different ID under the same name means another file took the name. #>
    param([string]$Path)
    $text = & (Join-Path $system32 'fsutil.exe') file queryfileid $Path
    if ($LASTEXITCODE -ne 0) { throw "fsutil could not read the file ID of $Path ($LASTEXITCODE): $text" }
    return [regex]::Match([string]($text -join ' '), '0x[0-9a-fA-F]+').Value
}

function Get-Hash {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Bytes)) }
    finally { $sha.Dispose() }
}

function Get-KeyShape {
    <#
        Every object's keys in a JSON document, in order and exactly as written, by the object's path: the shape the
        contract fixes, whatever the values. PowerShell keeps a property's name as the file spells it.
    #>
    param($Value, [string]$Path, [System.Collections.Specialized.OrderedDictionary]$Into)
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $Into[$Path] = (@($Value.PSObject.Properties | ForEach-Object { $_.Name }) -join ', ')
        foreach ($property in $Value.PSObject.Properties) { Get-KeyShape -Value $property.Value -Path "$Path.$($property.Name)" -Into $Into }
    }
    elseif ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $i = 0
        foreach ($item in $Value) { Get-KeyShape -Value $item -Path "$Path[$i]" -Into $Into; $i++ }
    }
}

function Get-StatusFileProblem {
    <# Why the bytes are not status.json as the contract says: a byte order mark, then strict UTF-8, then the golden file's keys. #>
    param([byte[]]$Bytes)
    if (-not (Test-ByteOrderMark -Bytes $Bytes)) { return 'it does not start with the UTF-8 byte order mark' }
    $text = $null
    try { $text = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($Bytes, 3, $Bytes.Length - 3) }
    catch { return "it is not valid UTF-8: $($_.Exception.Message)" }
    $document = $null
    try { $document = $text | ConvertFrom-Json } catch { return "it is not JSON: $($_.Exception.Message)" }
    $goldenBytes = [IO.File]::ReadAllBytes($golden)
    $goldenDocument = [Text.Encoding]::UTF8.GetString($goldenBytes, 3, $goldenBytes.Length - 3) | ConvertFrom-Json
    $expected = New-Object System.Collections.Specialized.OrderedDictionary
    $actual = New-Object System.Collections.Specialized.OrderedDictionary
    Get-KeyShape -Value $goldenDocument -Path 'status' -Into $expected
    Get-KeyShape -Value $document -Path 'status' -Into $actual
    foreach ($path in $expected.Keys) {
        if (-not $actual.Contains($path)) { return "it has no $path" }
        if (-not [string]::Equals($expected[$path], $actual[$path], [StringComparison]::Ordinal)) { return "the keys of $path are '$($actual[$path])', not '$($expected[$path])'" }
    }
    foreach ($path in $actual.Keys) { if (-not $expected.Contains($path)) { return "it has $path, which the golden file does not" } }
    return ''
}

function Get-TemporaryFile {
    <# Files a write left behind in the data folder: status.json.<id>.tmp. #>
    return , @(Get-ChildItem -LiteralPath $dataRoot -Force -Filter 'status.json.*' | Where-Object { $_.Name -ne 'status.json' } | ForEach-Object { $_.Name })
}

function Test-ByteOrderMark {
    param([byte[]]$Bytes)
    return $Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF
}

function Get-DataFolderLock {
    <# '' when the data folder is born locked as the installer makes it, or what is not. #>
    $item = Get-Item -LiteralPath $dataRoot -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return 'it is a link' }
    $acl = Get-Acl -LiteralPath $dataRoot
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne 'S-1-5-32-544') { return "it is owned by $owner, not Administrators" }
    if (-not $acl.AreAccessRulesProtected) { return 'its access list inherits from ProgramData' }
    $entries = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
            '{0} {1} {2} {3}' -f $_.IdentityReference.Value, $_.AccessControlType, $_.FileSystemRights, $_.InheritanceFlags
        } | Sort-Object)
    $expected = @('S-1-5-18 Allow FullControl ContainerInherit, ObjectInherit', 'S-1-5-32-544 Allow FullControl ContainerInherit, ObjectInherit')
    if (($entries -join '; ') -ne ($expected -join '; ')) { return "its access list is $($entries -join '; ')" }
    return ''
}

function Move-Folder {
    <# Renames a folder, trying again for a few seconds while another process, such as a scanner, has a file in it open. #>
    param([string]$From, [string]$To)
    for ($attempt = 1; ; $attempt++) {
        try { [IO.Directory]::Move($From, $To); return }
        catch {
            if ($attempt -ge 10) { throw }
            Start-Sleep -Milliseconds (200 * $attempt)
        }
    }
}

function Test-Refused {
    <# A scheduled-audit run as SYSTEM that must refuse: exit 1, SecureStore's reason, and status.json as it was. #>
    param([string]$Name, [string]$Reason)
    $before = if (Test-Path -LiteralPath $statusPath) { Get-Hash ([IO.File]::ReadAllBytes($statusPath)) } else { 'none' }
    $run = Invoke-ScheduledAudit
    $after = if (Test-Path -LiteralPath $statusPath) { Get-Hash ([IO.File]::ReadAllBytes($statusPath)) } else { 'none' }
    $said = (@($run.Errors) -join ' ')
    Add-Step $Name ($run.ExitCode -eq 1 -and $said.Contains($Reason) -and $before -eq $after) "exit $($run.ExitCode): $said"
}

Write-Host ''
Write-Host "status.json contract on $([Environment]::MachineName) with $BaselineExe" -ForegroundColor Cyan
$version = [string](& $BaselineExe --version)
Write-Host "  baseline.exe $version; working in $WorkPath"
$savedSeal = $null
$sealTaken = $false
$usersGranted = $false
$aside = "$dataRoot.contract-aside"
$movedAside = $false
$junctionMade = $false
$icacls = Join-Path $system32 'icacls.exe'
try {
    # 1. Nothing installed: SecureStore refuses the missing folder, and scheduled-audit creates nothing.
    if (-not (Test-Path -LiteralPath $dataRoot)) {
        Test-Refused -Name '1. scheduled-audit as SYSTEM refuses a data folder that does not exist' -Reason 'does not exist'
        Add-Step '1. ...and creates no data folder' (-not (Test-Path -LiteralPath $dataRoot))
    }
    else { Add-Step '1. scheduled-audit refuses a missing data folder (not run: the folder exists and -Force was given)' $true }

    # 2. Install as Intune's Win32 app would, without the module's own scheduled task, which would write
    # status.json at times of its own.
    $install = Start-Process -FilePath $ps64 -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $repo 'intune\Install-CEChecker.ps1')`"", '-NoScheduledTask', '-NoUserProbeTask', '-NoShortcut') -Wait -PassThru -WindowStyle Hidden
    Add-Step '2. Install-CEChecker.ps1 installs' ($install.ExitCode -eq 0) "exit $($install.ExitCode)"
    if ($install.ExitCode -ne 0) { throw 'The install failed; see the install log in the data folder.' }
    $lock = Get-DataFolderLock
    Add-Step '2. The data folder is born locked: owned by Administrators, only SYSTEM and Administrators in a protected access list' (-not $lock) $lock
    $seal = Get-ItemProperty -LiteralPath $sealKey -ErrorAction SilentlyContinue
    $savedSeal = if ($seal -and $seal.PSObject.Properties['DataRootSealed']) { [string]$seal.DataRootSealed } else { '' }
    Add-Step '2. The data folder is sealed (DataRootSealed)' ([bool]$savedSeal) $savedSeal

    # 3. The seal is what says the install made the folder locked: without it, the folder is refused.
    Remove-ItemProperty -LiteralPath $sealKey -Name 'DataRootSealed'
    $sealTaken = $true
    Test-Refused -Name '3. scheduled-audit as SYSTEM refuses the data folder without its seal, and writes nothing' -Reason 'DataRootSealed marker is missing'
    New-ItemProperty -LiteralPath $sealKey -Name 'DataRootSealed' -Value $savedSeal -PropertyType String -Force | Out-Null
    $sealTaken = $false

    # 4. The first status.json.
    $run = Invoke-ScheduledAudit
    Add-Step '4. scheduled-audit as SYSTEM writes status.json' ($run.ExitCode -eq 0 -and (@($run.Output) -contains "Status: $statusPath")) "exit $($run.ExitCode): $(@($run.Output) -join ' / ') $(@($run.Errors) -join ' ')"
    if ($run.ExitCode -ne 0) { throw 'scheduled-audit did not write status.json.' }
    $bytes = [IO.File]::ReadAllBytes($statusPath)
    [IO.File]::WriteAllBytes((Join-Path $WorkPath 'status-baseline.json'), $bytes)
    $problem = Get-StatusFileProblem -Bytes $bytes
    Add-Step '4. It is UTF-8 with a byte order mark, with every key as the golden file spells and orders it' (-not $problem) $problem
    $status = [Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3) | ConvertFrom-Json
    $checks = @($status.checks.PSObject.Properties | ForEach-Object { $_.Name })
    $su01 = if ($status.checks.PSObject.Properties['SU-01']) { $status.checks.'SU-01'.status } else { 'missing' }
    Add-Step '4. This baseline.exe wrote it, as SYSTEM, for SU-01' ($status.toolVersion -eq $version -and $status.runAs -eq 'NT AUTHORITY\SYSTEM' -and $status.elevated -eq $true -and ($checks -join ',') -eq 'SU-01') "toolVersion $($status.toolVersion), runAs $($status.runAs), checks $($checks -join ', '), SU-01 $su01"
    $owner = (Get-Acl -LiteralPath $statusPath).GetOwner([Security.Principal.SecurityIdentifier]).Value
    Add-Step '4. It is owned by Administrators' ($owner -eq 'S-1-5-32-544') $owner
    # The discovery script's own check of the data folder, status.json and last-error.json. Dot-sourcing it only
    # defines its functions; Intune runs it without strict mode.
    $discover = Join-Path $repo 'intune\Discover-CECompliance.ps1'
    $untrusted = & { Set-StrictMode -Off; . $discover; Get-CEStatusTrustProblem -DataRoot $dataRoot }
    Add-Step '4. The Intune scripts trust it' (-not $untrusted) $untrusted
    $left = Get-TemporaryFile
    Add-Step '4. No temporary file is left' ($left.Count -eq 0) ($left -join ', ')
    if (-not (Test-ByteOrderMark -Bytes $bytes) -or $problem) { throw 'status.json is not what the contract says; the steps after this compare it.' }

    # 5. Atomic replacement, watched by a reader.
    $reads = @{ Whole = 0; Busy = 0; Missing = 0; Other = 0; Failures = (New-Object System.Collections.ArrayList) }
    $seen = @{}
    $poll = {
        $stream = $null
        try {
            $stream = New-Object System.IO.FileStream($statusPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
            $buffer = New-Object System.IO.MemoryStream
            $stream.CopyTo($buffer)
            $stream.Dispose()
            $stream = $null
            $hash = Get-Hash $buffer.ToArray()
            if (-not $seen.ContainsKey($hash)) { $seen[$hash] = $buffer.ToArray() }
            $reads.Whole++
        }
        catch [System.IO.FileNotFoundException] { $reads.Missing++ }
        catch [System.IO.IOException] { $reads.Busy++ }
        catch [System.UnauthorizedAccessException] { $reads.Busy++ }
        catch { $reads.Other++; [void]$reads.Failures.Add($_.Exception.Message) }
        finally { if ($stream) { $stream.Dispose() } }
        # An uneven pace, so the reader cannot fall into step with the write's retries.
        Start-Sleep -Milliseconds (Get-Random -Minimum 5 -Maximum 40)
    }
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $old = [IO.File]::ReadAllBytes($statusPath)
        $oldId = Get-FileId -Path $statusPath
        $seen.Clear()
        $run = Invoke-ScheduledAudit -WhileRunning $poll
        $new = [IO.File]::ReadAllBytes($statusPath)
        $newId = Get-FileId -Path $statusPath
        $allowed = @((Get-Hash $old), (Get-Hash $new))
        $odd = @($seen.Keys | Where-Object { $allowed -notcontains $_ })
        foreach ($hash in $odd) { [IO.File]::WriteAllBytes((Join-Path $WorkPath "partial-read-$attempt-$($hash.Replace('-', '').Substring(0, 12)).json"), $seen[$hash]) }
        $problem = Get-StatusFileProblem -Bytes $new
        $left = Get-TemporaryFile
        $ok = $run.ExitCode -eq 0 -and $newId -ne $oldId -and $odd.Count -eq 0 -and -not $problem -and $left.Count -eq 0
        Add-Step "5. Replacement $attempt is atomic: a new file takes the name, and every read is the old file or the new one, whole" $ok "exit $($run.ExitCode), file ID $oldId to $newId, $($odd.Count) other contents seen $problem"
    }
    $readTotal = $reads.Whole + $reads.Busy + $reads.Missing + $reads.Other
    Add-Step '5. The name was never missing while a reader watched' ($reads.Missing -eq 0 -and $reads.Other -eq 0 -and $reads.Whole -gt 0) "$readTotal reads: $($reads.Whole) whole, $($reads.Busy) found the file busy, $($reads.Missing) found no file, $($reads.Other) failed otherwise $($reads.Failures -join ' ')"
    $bytes = [IO.File]::ReadAllBytes($statusPath)
    [IO.File]::WriteAllBytes((Join-Path $WorkPath 'status-baseline.json'), $bytes)

    # 6. The Intune scripts on baseline.exe's status.json, as SYSTEM and as this administrator.
    $run = Invoke-SystemScript -Script $readers -ArgumentList @('-MachineDataFolder', '-WorkPath', $WorkPath, '-ResultPath', (Join-Path $WorkPath 'readers-baseline-system.json'))
    Add-Step '6. The Intune scripts read baseline.exe''s status.json as SYSTEM, in both hosts' ($run.ExitCode -eq 0) "exit $($run.ExitCode) $(@($run.Errors) -join ' ')"
    $null = & $readers -MachineDataFolder -WorkPath $WorkPath -ResultPath (Join-Path $WorkPath 'readers-baseline-admin.json')
    Add-Step '6. ...and as an elevated administrator' $true

    # 7. The module's status.json for the same check, in the same folder, as SYSTEM.
    $run = Invoke-SystemScript -Script (Join-Path $repo 'tools\contracts\Write-ModuleStatus.ps1') -ArgumentList @('-Id', 'SU-01', '-ModulePath', (Join-Path ([string](Get-ItemProperty -LiteralPath $installKey).InstallPath) 'src\CEAudit\CEAudit.psd1'))
    $moduleBytes = [IO.File]::ReadAllBytes($statusPath)
    [IO.File]::WriteAllBytes((Join-Path $WorkPath 'status-module.json'), $moduleBytes)
    $moduleStatus = [Text.Encoding]::UTF8.GetString($moduleBytes, 3, $moduleBytes.Length - 3) | ConvertFrom-Json
    # The module's own version, so the file compared below is the module's and not baseline.exe's left in place.
    $written = $run.ExitCode -eq 0 -and (Test-ByteOrderMark -Bytes $moduleBytes) -and $moduleStatus.toolVersion -ne $version -and $moduleStatus.runAs -eq 'NT AUTHORITY\SYSTEM'
    Add-Step '7. The installed module writes status.json for SU-01 as SYSTEM, UTF-8 with a byte order mark' $written "exit $($run.ExitCode), toolVersion $($moduleStatus.toolVersion): $(@($run.Output) -join ' / ') $(@($run.Errors) -join ' ')"
    if (-not $written) { throw 'The module did not write status.json, so there is nothing to compare.' }
    $run = Invoke-SystemScript -Script $readers -ArgumentList @('-MachineDataFolder', '-WorkPath', $WorkPath, '-ResultPath', (Join-Path $WorkPath 'readers-module-system.json'))
    Add-Step '7. The Intune scripts read the module''s status.json as SYSTEM, in both hosts' ($run.ExitCode -eq 0) "exit $($run.ExitCode) $(@($run.Errors) -join ' ')"
    $null = & $readers -MachineDataFolder -WorkPath $WorkPath -ResultPath (Join-Path $WorkPath 'readers-module-admin.json')
    Add-Step '7. ...and as an elevated administrator' $true

    # 8. The same output from both files, apart from the ledger's version entries.
    foreach ($account in 'system', 'admin') {
        & $ps64 -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $repo 'tools\contracts\Compare-IntuneReaders.ps1') -ModuleResultPath (Join-Path $WorkPath "readers-module-$account.json") -BaselineResultPath (Join-Path $WorkPath "readers-baseline-$account.json") -ResultPath (Join-Path $WorkPath "compare-$account.json")
        $name = if ($account -eq 'system') { 'SYSTEM' } else { 'an elevated administrator' }
        Add-Step "8. Read as $name, both scripts in both hosts report the same for both files, apart from the tool version" ($LASTEXITCODE -eq 0) "compare-$account.json"
    }

    # 9. A data folder a standard user could change is refused, and status.json is left as it is.
    & $icacls $dataRoot /grant '*S-1-5-32-545:(W)' /Q | Out-Null
    $usersGranted = $LASTEXITCODE -eq 0
    Test-Refused -Name '9. scheduled-audit as SYSTEM refuses a data folder Users can write to, and leaves status.json alone' -Reason 'can be changed by S-1-5-32-545'
    & $icacls $dataRoot /remove:g '*S-1-5-32-545' /Q | Out-Null
    $usersGranted = $false
    $lock = Get-DataFolderLock
    Add-Step '9. The data folder is locked again afterwards' (-not $lock) $lock

    # 10. A junction in the data folder's place is opened as itself and refused, even where it leads to a folder
    # only SYSTEM and Administrators can change: nothing is written there.
    $kept = Get-Hash ([IO.File]::ReadAllBytes($statusPath))
    $decoy = Join-Path $WorkPath 'decoy'
    New-Item -ItemType Directory -Path $decoy | Out-Null
    Move-Folder -From $dataRoot -To $aside
    $movedAside = $true
    New-Item -ItemType Junction -Path $dataRoot -Target $decoy | Out-Null
    $junctionMade = $true
    Test-Refused -Name '10. scheduled-audit as SYSTEM refuses a junction in the data folder''s place' -Reason 'junction, symbolic link or other reparse point'
    $written = @(Get-ChildItem -LiteralPath $decoy -Force | ForEach-Object { $_.Name })
    Add-Step '10. ...and writes nothing where the junction leads' ($written.Count -eq 0) ($written -join ', ')
    [IO.Directory]::Delete($dataRoot, $false)
    $junctionMade = $false
    Move-Folder -From $aside -To $dataRoot
    $movedAside = $false
    $lock = Get-DataFolderLock
    $back = (Test-Path -LiteralPath $statusPath) -and (Get-Hash ([IO.File]::ReadAllBytes($statusPath))) -eq $kept
    Add-Step '10. The data folder is back as it was' (-not $lock -and $back) $lock
}
catch {
    Add-Step 'Unexpected error' $false $_.Exception.Message
}
finally {
    # Whatever failed, put the data folder back as the install left it.
    if ($junctionMade) { [IO.Directory]::Delete($dataRoot, $false) }
    if ($movedAside) { Move-Folder -From $aside -To $dataRoot }
    if ($usersGranted) { & $icacls $dataRoot /remove:g '*S-1-5-32-545' /Q | Out-Null }
    if ($sealTaken -and $savedSeal) { New-ItemProperty -LiteralPath $sealKey -Name 'DataRootSealed' -Value $savedSeal -PropertyType String -Force | Out-Null }
}

$failed = @($steps | Where-Object { $_.Result -eq 'FAIL' })
Write-Host ''
if ($failed.Count) {
    Write-Host "status.json contract: FAILED ($($failed.Count) step(s)). Everything the steps kept is in $WorkPath." -ForegroundColor Red
    exit 1
}
Write-Host "status.json contract: PASSED ($($steps.Count) steps)." -ForegroundColor Green
exit 0
