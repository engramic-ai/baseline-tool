#Requires -Version 5.1
<#
.SYNOPSIS
    Spike 2 of the .NET port, measured: one runtime folder for three executables, the size of the published
    folder, start-up with and without ReadyToRun, and whether the ReadyToRun publish is reproducible byte for byte.

.DESCRIPTION
    A measurement, not part of the product: nothing here ships, the solution does not build it and CI does not run
    it. It produces the numbers in docs/DOTNET.md ("Spike 2"), so that anyone can run it again on another machine
    or a later SDK.

    It builds only from clones of a commit (-Commit, by default this checkout's HEAD), never from this working tree,
    and it changes nothing outside its work folder (-WorkPath, by default a new folder with a random name under
    %TEMP%). Each clone is checked out as a Windows runner checks out (core.autocrlf true) and given the public
    repository as its origin, as CI's checkout is. The Cleanup phase deletes the work folder by its exact path,
    and only a folder this script made (it holds the marker file .baseline-runtime-spike).

    The phases, which run in this order and can each be run on its own against the same -WorkPath:

      Clone         A clone of the commit at <work>\a\repo.
      Publish       baseline.exe published from that clone as tools\New-SignedRelease.ps1 -DotNet publishes it:
                    the locked restore of Baseline.slnx, then dotnet publish self-contained for win-x64 with
                    --no-restore. Once as the project says (ReadyToRun) to <work>\pub\r2r, once with
                    PublishReadyToRun=false to <work>\pub\il.
      Size          Each folder's file count and size, the zip Compress-Archive makes of it (as the release does),
                    and the files this repository built (tools\Release.psm1), each marked ReadyToRun or IL only.
      Startup       baseline.exe --version and baseline.exe audit --id SU-01 --shipped-config from each folder,
                    as this account. First runs: each from a fresh copy of the folder (-FirstRuns copies). Warm
                    runs: one discarded, then -Runs measured, the two builds and two commands interleaved so that
                    drift on the machine falls on all of them alike. Wall-clock time of each process from start to
                    exit, and its CPU time (which Windows counts in ticks of about 15.6 ms).
      SharedFolder  Stand-ins for the desktop app (WPF, net10.0-windows) and a Windows service
                    (Microsoft.Extensions.Hosting.WindowsServices), generated under <work>\standins, referencing the
                    clone's libraries and published as baseline.exe is (self-contained, ReadyToRun, package
                    assemblies left out of ReadyToRun so they keep their signatures). Each is published alone,
                    then all three into one folder, CLI first. Reported: every file two apps publish with different
                    content and whose copy the shared folder kept; for each app, the files its .deps.json names
                    that the shared folder holds with other content than its own publish; each app's
                    .runtimeconfig.json and .deps.json; a host trace (COREHOST_TRACE) of each app started from the
                    shared folder; tools\Test-ReleaseSignatures.ps1 -Unsigned on the shared folder; the sizes.
      Determinism   Two clean publishes of the ReadyToRun build, each from a fresh clone at a different path
                    (<work>\det-<label>\1\repo and <work>\det-<label>\second-clone-at-another-path\2\repo), every
                    file compared by SHA-256. For a file that differs: the byte ranges that differ, the debug
                    directory (CodeView path and GUID, PDB checksum), the MVID (in PowerShell 7) and whether the
                    file holds its build path. -Mode Local publishes as a release does on a workstation today;
                    -Mode CI as CI does (CI=true, which sets ContinuousIntegrationBuild in Directory.Build.props).
                    -Property adds MSBuild properties to the restore and publish of both, to try a fix.
                    -FreshPackages gives the second build a NuGet package folder of its own, and -LfCheckout
                    checks the second clone out as Linux or WSL would.
                    -ReferenceManifest compares the first build with a list of hashes made elsewhere, such as by
                    CI, in the format this phase writes: "<SHA-256>  <relative path>" per line.
      Report        The results of the phases run so far, as Markdown tables.
      Cleanup       Deletes the work folder.

    -Phase All runs every phase, Determinism once in each mode, then Cleanup unless -Keep.

    Everything is measured on the machine it runs on, which should be otherwise quiet. On a shared machine run one
    phase at a time, never two builds or timings at once: Publish, Startup, SharedFolder and Determinism build or
    time. Every process starts hidden. Builds use two MSBuild nodes and no build servers. Results, logs and host
    traces are written under <work>\results and <work>\logs.

    It needs the SDK that global.json names on PATH as dotnet, git, and the network to restore packages
    (Microsoft.Extensions.Hosting.WindowsServices, for the service stand-in, at the version of the runtime the
    SDK publishes). Run it in PowerShell 7 to read MVIDs; Windows PowerShell 5.1 does the rest.

.PARAMETER Phase
    The phase to run. Default: All.

.PARAMETER WorkPath
    The work folder. Required for any phase but All and Clone, which make a new one when it is not given.

.PARAMETER Commit
    The commit to build. Default: HEAD of the repository this script is in.

.PARAMETER Repository
    The repository to clone from: a path or URL git accepts. Default: the repository this script is in.

.PARAMETER Runs
    Measured warm runs of each build and command, after one discarded. Default: 10.

.PARAMETER FirstRuns
    First runs of each build and command, each from a fresh copy of the published folder, made two seconds
    before it runs. The builds take turns to go first. Default: 4.

.PARAMETER Mode
    Determinism: Local (as a workstation publishes) or CI (CI=true). Default: CI.

.PARAMETER Property
    Determinism: extra MSBuild properties, as Name=Value, for the restore and publish of both builds.

.PARAMETER ReferenceManifest
    Determinism: a list of hashes to compare the first build with.

.PARAMETER FreshPackages
    Determinism: the second build restores into a new, empty NuGet package folder (NUGET_PACKAGES, under the work
    folder), as another machine would, and restores the command line's project alone, so that only its packages
    are fetched.

.PARAMETER LfCheckout
    Determinism: the second clone is checked out with LF line endings wherever .gitattributes leaves them to git
    (core.autocrlf false, core.eol lf), as a Linux or WSL checkout is.

.PARAMETER Keep
    With -Phase All: keep the work folder.

.EXAMPLE
    pwsh -NoProfile -File tools\spikes\Measure-RuntimeSpike.ps1 -Keep

.EXAMPLE
    # One phase at a time, against one work folder.
    $work = Join-Path $env:TEMP 'baseline-spike2'
    foreach ($phase in 'Clone', 'Publish', 'Size', 'Startup', 'SharedFolder') {
        pwsh -NoProfile -File tools\spikes\Measure-RuntimeSpike.ps1 -Phase $phase -WorkPath $work
    }
    pwsh -NoProfile -File tools\spikes\Measure-RuntimeSpike.ps1 -Phase Determinism -Mode Local -WorkPath $work
    pwsh -NoProfile -File tools\spikes\Measure-RuntimeSpike.ps1 -Phase Determinism -Mode CI -WorkPath $work
    pwsh -NoProfile -File tools\spikes\Measure-RuntimeSpike.ps1 -Phase Report -WorkPath $work
    pwsh -NoProfile -File tools\spikes\Measure-RuntimeSpike.ps1 -Phase Cleanup -WorkPath $work
#>
[CmdletBinding()]
param(
    [ValidateSet('All', 'Clone', 'Publish', 'Size', 'Startup', 'SharedFolder', 'Determinism', 'Report', 'Cleanup')]
    [string]$Phase = 'All',
    [string]$WorkPath,
    [string]$Commit,
    [string]$Repository,
    [ValidateRange(1, 100)][int]$Runs = 10,
    [ValidateRange(0, 10)][int]$FirstRuns = 4,
    [ValidateSet('Local', 'CI')][string]$Mode = 'CI',
    [string[]]$Property = @(),
    [string]$ReferenceManifest,
    [switch]$FreshPackages,
    [switch]$LfCheckout,
    [switch]$Keep
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path (Join-Path $PSScriptRoot '..') '..')).ProviderPath
$script:PublicOrigin = 'https://github.com/engramic-ai/baseline-tool'
$script:MarkerName = '.baseline-runtime-spike'
$script:CliProject = 'src\Engramic.Baseline.Cli\Engramic.Baseline.Cli.csproj'
Import-Module (Join-Path (Join-Path $script:RepoRoot 'tools') 'Release.psm1')

# The two builds of baseline.exe the size and start-up phases compare.
$script:Variants = @(
    [pscustomobject]@{ Name = 'r2r'; Label = 'ReadyToRun (as released)'; Arguments = @() },
    [pscustomobject]@{ Name = 'il'; Label = 'Without ReadyToRun'; Arguments = @('-p:PublishReadyToRun=false') }
)
$script:Commands = @(
    [pscustomobject]@{ Name = 'version'; Label = 'baseline.exe --version'; Arguments = @('--version') },
    [pscustomobject]@{ Name = 'audit'; Label = 'baseline.exe audit --id SU-01 --shipped-config'; Arguments = @('audit', '--id', 'SU-01', '--shipped-config') }
)

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;

public static class RuntimeSpikeBytes
{
    // Element 0: how many bytes differ (a difference in length counts in full); element 1: how many runs of
    // differing bytes there are, runs closer than 16 bytes merged; then up to maxRuns pairs of offset and length.
    public static long[] Diff(byte[] a, byte[] b, int maxRuns)
    {
        long count = 0;
        List<long> runs = new List<long>();
        int common = Math.Min(a.Length, b.Length);
        long start = -1, last = -1;
        for (int i = 0; i < common; i++)
        {
            if (a[i] == b[i]) { continue; }
            count++;
            if (start >= 0 && i - last <= 16) { last = i; continue; }
            if (start >= 0) { runs.Add(start); runs.Add(last - start + 1); }
            start = i;
            last = i;
        }
        if (start >= 0) { runs.Add(start); runs.Add(last - start + 1); }
        if (a.Length != b.Length)
        {
            count += Math.Abs(a.Length - b.Length);
            runs.Add(common);
            runs.Add(Math.Abs(a.Length - b.Length));
        }
        List<long> result = new List<long>();
        result.Add(count);
        result.Add(runs.Count / 2);
        for (int i = 0; i < Math.Min(runs.Count, maxRuns * 2); i++) { result.Add(runs[i]); }
        return result.ToArray();
    }

    // Where needle first occurs in haystack, or -1; and how many times it occurs.
    public static long[] Find(byte[] haystack, byte[] needle)
    {
        long first = -1, count = 0;
        if (needle.Length == 0) { return new long[] { -1, 0 }; }
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            int j = 0;
            while (j < needle.Length && haystack[i + j] == needle[j]) { j++; }
            if (j == needle.Length)
            {
                if (first < 0) { first = i; }
                count++;
                i += needle.Length - 1;
            }
        }
        return new long[] { first, count };
    }
}
'@

# --- Helpers ---------------------------------------------------------------------------------------------------

function Write-SpikeStep {
    param([string]$Text)
    Write-Host ''
    Write-Host "== $Text" -ForegroundColor Cyan
}

function ConvertTo-SpikeArgument {
    <# One argument quoted for a Windows command line, as CommandLineToArgvW reads it back. #>
    param([string]$Value)
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-SpikeProcess {
    <#
    .SYNOPSIS
        Runs a program hidden, with its output captured, and returns the exit code, the output, the wall-clock
        time from start to exit and the CPU time it used. Throws on a non-zero exit unless -AllowFailure.
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [string]$WorkingDirectory,
        [hashtable]$Environment = @{},
        [string[]]$RemoveName = @(),
        [string[]]$RemovePrefix = @(),
        [string]$LogPath,
        [switch]$AllowFailure
    )
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $FilePath
    $info.Arguments = (@($ArgumentList | ForEach-Object { ConvertTo-SpikeArgument $_ }) -join ' ')
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    if ($WorkingDirectory) { $info.WorkingDirectory = $WorkingDirectory }
    foreach ($name in @($info.EnvironmentVariables.Keys)) {
        $drop = $RemoveName -contains $name
        foreach ($prefix in $RemovePrefix) {
            if ($name.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { $drop = $true }
        }
        if ($drop) { $info.EnvironmentVariables.Remove($name) }
    }
    foreach ($key in $Environment.Keys) { $info.EnvironmentVariables[$key] = [string]$Environment[$key] }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    $watch = New-Object System.Diagnostics.Stopwatch
    $watch.Start()
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $watch.Stop()
    $result = [pscustomobject]@{
        ExitCode = $process.ExitCode
        Output   = $stdout.Result
        Errors   = $stderr.Result
        WallMs   = [Math]::Round($watch.Elapsed.TotalMilliseconds, 1)
        CpuMs    = [Math]::Round($process.TotalProcessorTime.TotalMilliseconds, 1)
    }
    $process.Dispose()
    if ($LogPath) {
        $text = @("> $FilePath $($info.Arguments)", "  (exit $($result.ExitCode), $($result.WallMs) ms)", $result.Output, $result.Errors, '')
        Add-Content -LiteralPath $LogPath -Value $text -Encoding UTF8
    }
    if (-not $AllowFailure -and $result.ExitCode -ne 0) {
        $tail = @(($result.Output + "`n" + $result.Errors) -split "`r?`n" | Where-Object { $_ } | Select-Object -Last 25) -join "`n"
        throw "$(Split-Path -Leaf $FilePath) $($info.Arguments) exited with $($result.ExitCode).`n$tail"
    }
    $result
}

function Get-SpikeTool {
    param([string]$Name)
    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) { throw "$Name is not on PATH." }
    $command.Source
}

function Invoke-SpikeGit {
    <# git, with no GIT_ variable of this process (such as GIT_DIR) steering it away from the folder it is given. #>
    param([string[]]$ArgumentList)
    Invoke-SpikeProcess -FilePath (Get-SpikeTool 'git') -ArgumentList $ArgumentList -RemovePrefix @('GIT_') -LogPath (Join-Path $script:Logs 'git.log')
}

function Invoke-SpikeDotNet {
    <#
    .SYNOPSIS
        dotnet, as CI runs it (no logo, no telemetry, no XML docs from packages), on two MSBuild nodes with no build
        servers left behind. Local: no CI variable reaches it. CI: CI=true. GIT_ variables never reach it, since
        source link reads the repository the project is in.
    #>
    param([string[]]$ArgumentList, [string]$Name, [switch]$CI, [string]$WorkingDirectory, [hashtable]$Environment = @{})
    $variables = @{ DOTNET_NOLOGO = 'true'; DOTNET_CLI_TELEMETRY_OPTOUT = 'true'; NUGET_XMLDOC_MODE = 'skip' }
    foreach ($key in $Environment.Keys) { $variables[$key] = $Environment[$key] }
    if ($CI) { $variables['CI'] = 'true' }
    $arguments = @($ArgumentList) + @('-m:2', '--disable-build-servers')
    $log = Join-Path $script:Logs "$Name.log"
    Write-Host ("  dotnet {0}" -f ($ArgumentList -join ' '))
    $run = @{
        FilePath     = (Get-SpikeTool 'dotnet')
        ArgumentList = $arguments
        Environment  = $variables
        RemoveName   = @('CI', 'TF_BUILD', 'ContinuousIntegrationBuild', 'NUGET_PACKAGES')
        RemovePrefix = @('GIT_', 'GITHUB_')
        LogPath      = $log
    }
    if ($WorkingDirectory) { $run['WorkingDirectory'] = $WorkingDirectory }
    $result = Invoke-SpikeProcess @run
    Write-Host ("    {0:N1} s" -f ($result.WallMs / 1000))
    $result
}

function Save-SpikeResult {
    param([string]$Name, $Value)
    $path = Join-Path $script:Results "$Name.json"
    Set-Content -LiteralPath $path -Value (ConvertTo-Json -InputObject $Value -Depth 12) -Encoding UTF8
}

function Read-SpikeResult {
    param([string]$Name)
    $path = Join-Path $script:Results "$Name.json"
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Get-SpikeJsonValue {
    <# A property of an object ConvertFrom-Json made, or $null (strict mode throws on a missing one). #>
    param($InputObject, [string]$Name)
    if ($null -eq $InputObject) { return $null }
    $member = $InputObject.PSObject.Properties[$Name]
    if ($member) { return $member.Value }
    return $null
}

function Get-SpikeStatistic {
    param([double[]]$Values)
    $sorted = @($Values | Sort-Object)
    $n = $sorted.Count
    if (-not $n) { return $null }
    $middle = [int][Math]::Floor($n / 2)
    $median = $sorted[$middle]
    if ($n % 2 -eq 0) { $median = ($sorted[$middle - 1] + $sorted[$middle]) / 2 }
    [pscustomobject]@{
        Count  = $n
        Median = [Math]::Round($median, 1)
        Min    = [Math]::Round($sorted[0], 1)
        Max    = [Math]::Round($sorted[$n - 1], 1)
        P25    = [Math]::Round($sorted[[int][Math]::Floor(($n - 1) * 0.25)], 1)
        P75    = [Math]::Round($sorted[[int][Math]::Ceiling(($n - 1) * 0.75)], 1)
    }
}

function Get-SpikeHashes {
    <# Every file under a folder: its path relative to the folder, its size and SHA-256, sorted by path. #>
    param([string]$Path)
    $root = (Resolve-Path -LiteralPath $Path).ProviderPath.TrimEnd('\')
    $rows = foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force)) {
        [pscustomobject]@{
            Path   = $file.FullName.Substring($root.Length + 1)
            Length = $file.Length
            Hash   = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        }
    }
    , @($rows | Sort-Object Path)
}

function Get-SpikePeInfo {
    <#
    .SYNOPSIS
        What the PE headers of a file say: its timestamp and checksum, whether it is ReadyToRun (a managed native
        header with the RTR signature), its debug directory (CodeView GUID, age and PDB path; PDB checksum), and, in
        PowerShell 7, its MVID. $null for a file that is not a PE image.
    #>
    param([string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or [BitConverter]::ToUInt16($bytes, 0) -ne 0x5A4D) { return $null }
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($pe -lt 0 -or $pe -gt $bytes.Length - 24 -or [BitConverter]::ToUInt32($bytes, $pe) -ne 0x4550) { return $null }
    $coff = $pe + 4
    $sectionCount = [BitConverter]::ToUInt16($bytes, $coff + 2)
    $optional = $coff + 20
    $optionalSize = [BitConverter]::ToUInt16($bytes, $coff + 16)
    $is64 = [BitConverter]::ToUInt16($bytes, $optional) -eq 0x20B
    $directories = $optional + $(if ($is64) { 112 } else { 96 })
    $sectionTable = $optional + $optionalSize
    $sections = for ($i = 0; $i -lt $sectionCount; $i++) {
        $s = $sectionTable + 40 * $i
        [pscustomobject]@{
            VirtualAddress = [BitConverter]::ToUInt32($bytes, $s + 12)
            VirtualSize    = [BitConverter]::ToUInt32($bytes, $s + 8)
            RawSize        = [BitConverter]::ToUInt32($bytes, $s + 16)
            RawPointer     = [BitConverter]::ToUInt32($bytes, $s + 20)
        }
    }
    $toOffset = {
        param([uint32]$Rva)
        foreach ($section in @($sections)) {
            $span = [Math]::Max($section.VirtualSize, $section.RawSize)
            if ($Rva -ge $section.VirtualAddress -and $Rva -lt $section.VirtualAddress + $span) {
                return [long]($Rva - $section.VirtualAddress + $section.RawPointer)
            }
        }
        return [long]-1
    }

    $readyToRun = $false
    $clrRva = [BitConverter]::ToUInt32($bytes, $directories + 14 * 8)
    if ($clrRva) {
        $clr = & $toOffset $clrRva
        if ($clr -ge 0) {
            $nativeHeaderRva = [BitConverter]::ToUInt32($bytes, [int]$clr + 64)
            if ($nativeHeaderRva) {
                $nativeHeader = & $toOffset $nativeHeaderRva
                $readyToRun = ($nativeHeader -ge 0 -and [BitConverter]::ToUInt32($bytes, [int]$nativeHeader) -eq 0x00525452)
            }
        }
    }

    $debug = @()
    $debugRva = [BitConverter]::ToUInt32($bytes, $directories + 6 * 8)
    $debugSize = [BitConverter]::ToUInt32($bytes, $directories + 6 * 8 + 4)
    if ($debugRva) {
        $start = & $toOffset $debugRva
        for ($i = 0; $start -ge 0 -and $i -lt [Math]::Floor($debugSize / 28); $i++) {
            $entry = [int]$start + 28 * $i
            $type = [BitConverter]::ToUInt32($bytes, $entry + 12)
            $size = [BitConverter]::ToUInt32($bytes, $entry + 16)
            $data = [BitConverter]::ToUInt32($bytes, $entry + 24)
            $detail = ''
            if ($type -eq 2 -and $size -ge 24 -and [BitConverter]::ToUInt32($bytes, [int]$data) -eq 0x53445352) {
                $guid = New-Object Guid (, [byte[]]$bytes[([int]$data + 4)..([int]$data + 19)])
                $age = [BitConverter]::ToUInt32($bytes, [int]$data + 20)
                $pdbPath = [Text.Encoding]::UTF8.GetString($bytes, [int]$data + 24, [int]$size - 25)
                $detail = "CodeView $guid age $age $pdbPath"
            }
            elseif ($type -eq 19 -and $size -gt 0) {
                $text = [Text.Encoding]::ASCII.GetString($bytes, [int]$data, [int]$size)
                $algorithm = $text.Split([char]0)[0]
                $sum = [BitConverter]::ToString($bytes, [int]$data + $algorithm.Length + 1, [int]$size - $algorithm.Length - 1).Replace('-', '')
                $detail = "PdbChecksum $algorithm $sum"
            }
            elseif ($type -eq 16) { $detail = 'Reproducible' }
            elseif ($type -eq 17) { $detail = "EmbeddedPortablePdb $size bytes" }
            else { $detail = "Type $type, $size bytes" }
            $debug += [pscustomobject]@{ Type = $type; Offset = $data; Size = $size; Detail = $detail }
        }
    }

    $mvid = $null
    try {
        $stream = [IO.File]::OpenRead($Path)
        try {
            $reader = New-Object System.Reflection.PortableExecutable.PEReader($stream)
            if ($reader.HasMetadata) {
                $metadata = [System.Reflection.Metadata.PEReaderExtensions]::GetMetadataReader($reader)
                $mvid = $metadata.GetGuid($metadata.GetModuleDefinition().Mvid).ToString()
            }
            $reader.Dispose()
        }
        finally { $stream.Dispose() }
    }
    catch { $mvid = '(not read: System.Reflection.Metadata is not loaded in this PowerShell)' }

    [pscustomobject]@{
        TimeDateStamp = ('0x{0:X8}' -f [BitConverter]::ToUInt32($bytes, $coff + 4))
        CheckSum      = ('0x{0:X8}' -f [BitConverter]::ToUInt32($bytes, $optional + 64))
        Managed       = [bool]$clrRva
        ReadyToRun    = $readyToRun
        Debug         = @($debug)
        Mvid          = $mvid
    }
}

function Find-SpikeText {
    <# Where a file holds a piece of text, in UTF-8 or UTF-16, in its own case, lower or upper: the count and a sample. #>
    param([byte[]]$Bytes, [string]$Text)
    $hits = 0
    $sample = $null
    foreach ($variant in @($Text, $Text.ToLowerInvariant(), $Text.ToUpperInvariant() | Select-Object -Unique)) {
        foreach ($encoding in @([Text.Encoding]::UTF8, [Text.Encoding]::Unicode)) {
            $found = [RuntimeSpikeBytes]::Find($Bytes, $encoding.GetBytes($variant))
            if ($found[1] -gt 0) {
                $hits += $found[1]
                if (-not $sample) {
                    $from = [Math]::Max(0, $found[0] - 60)
                    $to = [Math]::Min($Bytes.Length, $found[0] + 140)
                    $chars = foreach ($b in $Bytes[[int]$from..([int]$to - 1)]) { if ($b -ge 32 -and $b -lt 127) { [char]$b } elseif ($b -ne 0) { '.' } }
                    $sample = (-join $chars)
                }
            }
        }
    }
    [pscustomobject]@{ Count = $hits; Sample = $sample }
}

function Measure-SpikeFolder {
    <# A published folder's file count and size, the PDBs in it, and the PE files this repository built. #>
    param([string]$Path)
    $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Force)
    $ours = @(Get-ReleaseOwnFile -Path $Path | ForEach-Object {
            $item = Get-Item -LiteralPath $_
            $info = Get-SpikePeInfo -Path $item.FullName
            [pscustomobject]@{
                Name       = $item.Name
                Bytes      = $item.Length
                ReadyToRun = ($null -ne $info -and $info.ReadyToRun)
            }
        })
    $pdbs = @($files | Where-Object { $_.Extension -eq '.pdb' })
    [pscustomobject]@{
        Files     = $files.Count
        Bytes     = [long]($files | Measure-Object -Property Length -Sum).Sum
        PdbFiles  = $pdbs.Count
        PdbBytes  = [long]($pdbs | Measure-Object -Property Length -Sum).Sum
        Ours      = @($ours | Sort-Object Name)
        OursBytes = [long]($ours | Measure-Object -Property Bytes -Sum).Sum
    }
}

function New-SpikeClone {
    <#
    .SYNOPSIS
        A clone of the commit at Destination, checked out as a Windows runner checks out (or, with -Lf, as Linux
        does), with CI's origin.
    #>
    param([string]$Destination, [switch]$Lf)
    $source = Get-SpikeSource
    if (Test-Path -LiteralPath $Destination) { throw "$Destination already exists." }
    New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null
    $endings = @('--config', 'core.autocrlf=true')
    if ($Lf) { $endings = @('--config', 'core.autocrlf=false', '--config', 'core.eol=lf') }
    Invoke-SpikeGit (@('clone', '--quiet', '--shared', '--no-checkout') + $endings + @($source.Repository, $Destination)) | Out-Null
    Invoke-SpikeGit @('-C', $Destination, 'checkout', '--quiet', '--detach', $source.Commit) | Out-Null
    Invoke-SpikeGit @('-C', $Destination, 'remote', 'set-url', 'origin', $script:PublicOrigin) | Out-Null
}

function Get-SpikeSource {
    <# The commit and repository to build, the SDK and this machine, worked out once and kept in the results. #>
    $saved = Read-SpikeResult 'source'
    if ($null -ne $saved) { return $saved }

    # Read with this process's own git variables, which may point at a worktree's git folder.
    $git = Get-SpikeTool 'git'
    $sha = $Commit
    if (-not $sha) { $sha = 'HEAD' }
    $sha = (Invoke-SpikeProcess -FilePath $git -ArgumentList @('-C', $script:RepoRoot, 'rev-parse', "$sha^{commit}")).Output.Trim()
    $from = $Repository
    if (-not $from) {
        $from = (Invoke-SpikeProcess -FilePath $git -ArgumentList @('-C', $script:RepoRoot, 'rev-parse', '--path-format=absolute', '--git-common-dir')).Output.Trim()
    }

    $sdk = [string](Get-Content -LiteralPath (Join-Path $script:RepoRoot 'global.json') -Raw | ConvertFrom-Json).sdk.version
    $actual = (Invoke-SpikeProcess -FilePath (Get-SpikeTool 'dotnet') -ArgumentList @('--version') -Environment @{ DOTNET_NOLOGO = 'true'; DOTNET_CLI_TELEMETRY_OPTOUT = 'true' }).Output.Trim()
    if ($actual -ne $sdk) { throw "dotnet --version is '$actual', but global.json names $sdk." }

    $current = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $cpu = [string][Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0', 'ProcessorNameString', '')
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $power = 'unknown'
    try {
        $battery = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop)
        if (-not $battery.Count) { $power = 'mains (no battery)' }
        elseif ($battery[0].BatteryStatus -eq 2) { $power = 'mains' }
        else { $power = 'battery' }
    }
    catch { $power = 'unknown' }
    $defender = 'unknown'
    try { $defender = [string](Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled } catch { $defender = 'unknown' }

    $source = [pscustomobject]@{
        Commit            = $sha
        Repository        = $from
        Sdk               = $actual
        Windows           = ('{0} build {1}.{2}' -f (Get-SpikeJsonValue $current 'DisplayVersion'), $current.CurrentBuildNumber, (Get-SpikeJsonValue $current 'UBR'))
        Processor         = $cpu.Trim()
        LogicalProcessors = [Environment]::ProcessorCount
        Power             = $power
        DefenderRealTime  = $defender
        Elevated          = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        PowerShell        = $PSVersionTable.PSVersion.ToString()
        Started           = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    }
    Save-SpikeResult 'source' $source
    $source
}

# --- Phases ----------------------------------------------------------------------------------------------------

function Invoke-ClonePhase {
    Write-SpikeStep 'Clone'
    $source = Get-SpikeSource
    Write-Host ("  {0} from {1}" -f $source.Commit, $source.Repository)
    New-SpikeClone -Destination (Join-Path $WorkPath 'a\repo')
}

function Invoke-PublishPhase {
    Write-SpikeStep 'Publish baseline.exe as the release does, with and without ReadyToRun'
    $repo = Join-Path $WorkPath 'a\repo'
    if (-not (Test-Path -LiteralPath $repo)) { throw 'Run the Clone phase first.' }
    $times = @{}
    $restore = Invoke-SpikeDotNet -Name 'publish-restore' -ArgumentList @('restore', (Join-Path $repo 'Baseline.slnx'), '--locked-mode')
    $times['restore'] = $restore.WallMs
    foreach ($variant in $script:Variants) {
        $output = Join-Path $script:Published $variant.Name
        $arguments = @('publish', (Join-Path $repo $script:CliProject), '--configuration', 'Release', '--runtime', 'win-x64', '--no-restore', '--output', $output) + $variant.Arguments
        $times[$variant.Name] = (Invoke-SpikeDotNet -Name "publish-$($variant.Name)" -ArgumentList $arguments).WallMs
    }
    Save-SpikeResult 'publish' ([pscustomobject]$times)
}

function Invoke-SizePhase {
    Write-SpikeStep 'Size'
    $rows = foreach ($variant in $script:Variants) {
        $folder = Join-Path $script:Published $variant.Name
        if (-not (Test-Path -LiteralPath $folder)) { throw 'Run the Publish phase first.' }
        $zip = Join-Path $WorkPath "zip\$($variant.Name).zip"
        New-Item -ItemType Directory -Path (Split-Path -Parent $zip) -Force | Out-Null
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        Compress-Archive -Path (Join-Path $folder '*') -DestinationPath $zip
        $measure = Measure-SpikeFolder -Path $folder
        $row = [pscustomobject]@{
            Variant   = $variant.Name
            Label     = $variant.Label
            Files     = $measure.Files
            Bytes     = $measure.Bytes
            ZipBytes  = (Get-Item -LiteralPath $zip).Length
            PdbFiles  = $measure.PdbFiles
            PdbBytes  = $measure.PdbBytes
            OursBytes = $measure.OursBytes
            Ours      = $measure.Ours
        }
        Write-Host ("  {0,-26} {1,4} files {2,8:N1} MB, zip {3,6:N1} MB, ours {4,5:N2} MB" -f $variant.Label, $row.Files, ($row.Bytes / 1MB), ($row.ZipBytes / 1MB), ($row.OursBytes / 1MB))
        $row
    }
    Save-SpikeResult 'size' @($rows)
}

function Invoke-StartupPhase {
    Write-SpikeStep "Start-up: $FirstRuns first run(s) from fresh copies, then 1 discarded and $Runs measured warm runs"
    $version = Get-ReleaseDotNetVersion -Path (Join-Path $WorkPath 'a\repo\Directory.Build.props')
    $samples = New-Object System.Collections.ArrayList
    # Nothing in this process's environment may change how the runtime starts.
    $clean = @{ RemovePrefix = @('DOTNET_', 'COMPlus_', 'COREHOST_'); AllowFailure = $true }

    $check = {
        param($Variant, $Command, $Result)
        if ($Result.ExitCode -ne 0) { throw "$($Command.Label) from the $($Variant.Name) build exited with $($Result.ExitCode): $($Result.Errors)" }
        if ($Command.Name -eq 'version' -and $Result.Output.Trim() -ne $version) { throw "--version printed '$($Result.Output.Trim())', not '$version'." }
    }

    for ($copy = 1; $copy -le $FirstRuns; $copy++) {
        # Each build goes first in every other round, so that neither gains from the order.
        $order = @($script:Variants)
        if ($copy % 2 -eq 0) { [array]::Reverse($order) }
        foreach ($variant in $order) {
            foreach ($command in $script:Commands) {
                $fresh = Join-Path $WorkPath ("fresh\{0}-{1}-{2}" -f $variant.Name, $command.Name, $copy)
                New-Item -ItemType Directory -Path (Split-Path -Parent $fresh) -Force | Out-Null
                Copy-Item -LiteralPath (Join-Path $script:Published $variant.Name) -Destination $fresh -Recurse
                # As after an install: the files have been written a while, and the antivirus has seen them close.
                Start-Sleep -Seconds 2
                $result = Invoke-SpikeProcess -FilePath (Join-Path $fresh 'baseline.exe') -ArgumentList $command.Arguments -WorkingDirectory $fresh @clean
                & $check $variant $command $result
                [void]$samples.Add([pscustomobject]@{ Variant = $variant.Name; Command = $command.Name; Kind = 'first'; Run = $copy; WallMs = $result.WallMs; CpuMs = $result.CpuMs })
                Remove-Item -LiteralPath $fresh -Recurse -Force
            }
        }
    }

    for ($run = 0; $run -le $Runs; $run++) {
        foreach ($variant in $script:Variants) {
            $folder = Join-Path $script:Published $variant.Name
            foreach ($command in $script:Commands) {
                $result = Invoke-SpikeProcess -FilePath (Join-Path $folder 'baseline.exe') -ArgumentList $command.Arguments -WorkingDirectory $folder @clean
                & $check $variant $command $result
                $kind = 'warm'
                if ($run -eq 0) { $kind = 'discarded' }
                [void]$samples.Add([pscustomobject]@{ Variant = $variant.Name; Command = $command.Name; Kind = $kind; Run = $run; WallMs = $result.WallMs; CpuMs = $result.CpuMs })
            }
        }
    }

    $summary = foreach ($variant in $script:Variants) {
        foreach ($command in $script:Commands) {
            $mine = @($samples | Where-Object { $_.Variant -eq $variant.Name -and $_.Command -eq $command.Name })
            $first = @($mine | Where-Object { $_.Kind -eq 'first' })
            $warm = @($mine | Where-Object { $_.Kind -eq 'warm' })
            $row = [pscustomobject]@{
                Variant   = $variant.Name
                Label     = $variant.Label
                Command   = $command.Label
                First     = $(if ($first.Count) { Get-SpikeStatistic @($first | ForEach-Object { $_.WallMs }) } else { $null })
                FirstCpu  = $(if ($first.Count) { Get-SpikeStatistic @($first | ForEach-Object { $_.CpuMs }) } else { $null })
                Warm      = Get-SpikeStatistic @($warm | ForEach-Object { $_.WallMs })
                WarmCpu   = Get-SpikeStatistic @($warm | ForEach-Object { $_.CpuMs })
                Discarded = @($mine | Where-Object { $_.Kind -eq 'discarded' } | ForEach-Object { $_.WallMs })
            }
            Write-Host ("  {0,-26} {1,-48} warm median {2,6:N1} ms ({3:N1}-{4:N1}), CPU {5,6:N1} ms" -f $row.Label, $row.Command, $row.Warm.Median, $row.Warm.Min, $row.Warm.Max, $row.WarmCpu.Median)
            $row
        }
    }
    Save-SpikeResult 'startup' ([pscustomobject]@{ Runs = $Runs; FirstRuns = $FirstRuns; Summary = @($summary); Samples = @($samples) })
}

function New-SpikeStandIns {
    <# The desktop and service stand-ins, under <work>\standins, kept apart from any build file above them. #>
    param([string]$Repo, [string]$Version, [string]$RuntimeVersion)
    $root = Join-Path $WorkPath 'standins'
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    # MSBuild and NuGet stop at the first of these they find, so nothing above the work folder applies.
    foreach ($name in 'Directory.Build.props', 'Directory.Build.targets', 'Directory.Packages.props') {
        Set-Content -LiteralPath (Join-Path $root $name) -Value '<Project />' -Encoding ASCII
    }
    Copy-Item -LiteralPath (Join-Path $Repo 'NuGet.config') -Destination (Join-Path $root 'NuGet.config')

    $project = @'
<Project Sdk="Microsoft.NET.Sdk">
  <!-- A stand-in for spike 2 of the .NET port, published as baseline.exe is. Not part of the product. -->
  <PropertyGroup>
    <OutputType>__OUTPUTTYPE__</OutputType>
    <TargetFramework>net10.0-windows</TargetFramework>
    <AssemblyName>__NAME__</AssemblyName>
    <RootNamespace>StandIn</RootNamespace>
    <Version>__VERSION__</Version>
    <Nullable>enable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <Deterministic>true</Deterministic>
    <RuntimeIdentifiers>win-x64</RuntimeIdentifiers>
    <SelfContained Condition="'$(RuntimeIdentifier)' != ''">true</SelfContained>
    <PublishReadyToRun>true</PublishReadyToRun>
    <PublishTrimmed>false</PublishTrimmed>
    <PublishSingleFile>false</PublishSingleFile>
    <StartupHookSupport>false</StartupHookSupport>
    <SatelliteResourceLanguages>en</SatelliteResourceLanguages>
    <PublishDocumentationFile>false</PublishDocumentationFile>
    <PublishReferencesDocumentationFiles>false</PublishReferencesDocumentationFiles>
    __EXTRA__
  </PropertyGroup>
  <ItemGroup>
    __PACKAGES__
    <ProjectReference Include="__REPO__\src\Engramic.Baseline.Controls\Engramic.Baseline.Controls.csproj" />
    <ProjectReference Include="__REPO__\src\Engramic.Baseline.Windows\Engramic.Baseline.Windows.csproj" />
  </ItemGroup>
  <!--
    As in baseline.exe: a package's assembly keeps its publisher's signature, so it stays out of ReadyToRun. The
    libraries this repository builds, referenced through another project, carry a package id too, so they are
    told apart by name. (The runtime pack's assemblies are ReadyToRun already, so excluding them changes nothing.)
  -->
  <Target Name="StandInKeepPackageSignatures" BeforeTargets="_PrepareForReadyToRunCompilation">
    <ItemGroup>
      <PublishReadyToRunExclude Include="@(ResolvedFileToPublish->'%(Filename)%(Extension)')"
                                Condition="'%(ResolvedFileToPublish.NuGetPackageId)' != '' and !$([System.String]::Copy('%(ResolvedFileToPublish.NuGetPackageId)').StartsWith('Engramic.Baseline.')) and '%(ResolvedFileToPublish.Extension)' == '.dll'" />
    </ItemGroup>
  </Target>
</Project>
'@

    $shared = @'
using System;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace StandIn;

internal static class Report
{
    public static string Version()
    {
        return typeof(Report).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "?";
    }

    // Calls into the libraries baseline.exe uses, then lists every assembly loaded and where from.
    public static void Libraries()
    {
        var catalog = Engramic.Baseline.Controls.BuiltInChecks.CreateCatalog();
        Console.WriteLine("Checks in the catalog: " + catalog.Checks.Count);
        var build = new Engramic.Baseline.Windows.WindowsRegistry().GetValue(
            Engramic.Baseline.Platform.RegistryHive.LocalMachine, Engramic.Baseline.Platform.RegistryView.Registry64,
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber");
        Console.WriteLine("Windows build: " + build?.Text);
        Console.WriteLine("Runtime: " + RuntimeInformation.FrameworkDescription + " in " + RuntimeEnvironment.GetRuntimeDirectory());
        Console.WriteLine("App folder: " + AppContext.BaseDirectory);
        foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies().OrderBy(a => a.GetName().Name, StringComparer.Ordinal))
        {
            Console.WriteLine("Loaded: " + assembly.GetName().Name + " " + assembly.GetName().Version + " " + assembly.Location);
        }
    }
}
'@

    $desktop = @'
using System;
using System.IO;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace StandIn;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--version")
        {
            Console.WriteLine(Report.Version());
            return 0;
        }

        // WPF's managed and native parts without showing a window: lay out some text and render it to a PNG.
        var text = new TextBlock { Text = "Baseline" };
        text.Measure(new System.Windows.Size(200, 50));
        text.Arrange(new System.Windows.Rect(0, 0, 200, 50));
        var bitmap = new RenderTargetBitmap(200, 50, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(text);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var png = new MemoryStream();
        encoder.Save(png);
        Console.WriteLine("Rendered a PNG of " + png.Length + " bytes");
        Report.Libraries();
        return png.Length > 0 ? 0 : 1;
    }
}
'@

    $service = @'
using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace StandIn;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--version")
        {
            Console.WriteLine(Report.Version());
            return 0;
        }

        // The host a Windows service runs in, started and stopped as a console app (it is not installed).
        var builder = Host.CreateApplicationBuilder(Array.Empty<string>());
        builder.Services.AddWindowsService(options => options.ServiceName = "BaselineServiceStandIn");
        builder.Services.AddHostedService<Worker>();
        using var host = builder.Build();
        await host.StartAsync();
        await Task.Delay(300);
        await host.StopAsync();

        // What a service uses that the desktop runtime pack also carries, read only.
        Console.WriteLine("Services: " + System.ServiceProcess.ServiceController.GetServices().Length);
        Console.WriteLine("Application log exists: " + System.Diagnostics.EventLog.Exists("Application"));
        Report.Libraries();
        return 0;
    }
}

internal sealed class Worker : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Console.WriteLine("Worker ran");
        return Task.CompletedTask;
    }
}
'@

    $apps = @(
        [pscustomobject]@{ Name = 'BaselineDesktop'; Folder = 'desktop'; OutputType = 'WinExe'; Extra = '<UseWPF>true</UseWPF>'; Packages = ''; Source = $desktop },
        [pscustomobject]@{
            Name = 'BaselineService'; Folder = 'service'; OutputType = 'Exe'; Extra = ''; Source = $service
            Packages = "<PackageReference Include=`"Microsoft.Extensions.Hosting.WindowsServices`" Version=`"$RuntimeVersion`" />"
        }
    )
    foreach ($app in $apps) {
        $folder = Join-Path $root $app.Folder
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $text = $project.Replace('__OUTPUTTYPE__', $app.OutputType).Replace('__NAME__', $app.Name).Replace('__VERSION__', $Version)
        $text = $text.Replace('__EXTRA__', $app.Extra).Replace('__PACKAGES__', $app.Packages).Replace('__REPO__', $Repo)
        Set-Content -LiteralPath (Join-Path $folder "$($app.Name).csproj") -Value $text -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $folder 'Program.cs') -Value $app.Source -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $folder 'Report.cs') -Value $shared -Encoding ASCII
        $app | Add-Member -NotePropertyName Project -NotePropertyValue (Join-Path $folder "$($app.Name).csproj")
    }
    , $apps
}

function Get-SpikeDepsAsset {
    <#
    .SYNOPSIS
        Every file an app's .deps.json names, as the host looks for it in a published app's folder (by its file
        name, and a resource assembly under its culture's folder), with the library that brings it and its kind.
    #>
    param([string]$DepsPath)
    $deps = Get-Content -LiteralPath $DepsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $targetName = [string](Get-SpikeJsonValue (Get-SpikeJsonValue $deps 'runtimeTarget') 'name')
    $target = Get-SpikeJsonValue (Get-SpikeJsonValue $deps 'targets') $targetName
    $libraries = Get-SpikeJsonValue $deps 'libraries'
    $rows = foreach ($library in @($target.PSObject.Properties)) {
        $kind = [string](Get-SpikeJsonValue (Get-SpikeJsonValue $libraries $library.Name) 'type')
        foreach ($group in 'runtime', 'native', 'resources') {
            $assets = Get-SpikeJsonValue $library.Value $group
            if ($null -eq $assets) { continue }
            foreach ($asset in @($assets.PSObject.Properties)) {
                $file = Split-Path -Leaf $asset.Name.Replace('/', '\')
                $locale = [string](Get-SpikeJsonValue $asset.Value 'locale')
                if ($group -eq 'resources' -and $locale) { $file = Join-Path $locale $file }
                [pscustomobject]@{
                    Path            = $file
                    Library         = $library.Name
                    Kind            = $kind
                    AssemblyVersion = [string](Get-SpikeJsonValue $asset.Value 'assemblyVersion')
                    FileVersion     = [string](Get-SpikeJsonValue $asset.Value 'fileVersion')
                }
            }
        }
    }
    , @($rows)
}

function Read-SpikeHostTrace {
    <# The lines of a host trace that say which host, runtime, .deps.json and .runtimeconfig.json an app used. #>
    param([string]$Path, [string]$Folder)
    if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{ Lines = @('(no trace written)'); TrustedCount = 0; TrustedElsewhere = @() } }
    $lines = @(Get-Content -LiteralPath $Path -Encoding UTF8)
    $wanted = @($lines | Where-Object {
            $_ -match 'Invoked apphost|hostfxr|hostpolicy|\.deps\.json|\.runtimeconfig\.json|self-contained|coreclr\.dll|Executing as|mode:'
        } | Select-Object -First 30)
    $tpaLine = @($lines | Where-Object { $_ -match 'TRUSTED_PLATFORM_ASSEMBLIES' } | Select-Object -First 1)
    $tpa = @()
    if ($tpaLine.Count) {
        $value = $tpaLine[0].Substring($tpaLine[0].IndexOf('=') + 1).Trim()
        $tpa = @($value.Split(';') | Where-Object { $_ })
    }
    $prefix = $Folder.TrimEnd('\') + '\'
    [pscustomobject]@{
        Lines            = $wanted
        TrustedCount     = $tpa.Count
        TrustedElsewhere = @($tpa | Where-Object { -not $_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })
    }
}

function Invoke-SharedFolderPhase {
    Write-SpikeStep 'One runtime folder for three executables'
    $repo = Join-Path $WorkPath 'a\repo'
    $cliAlone = Join-Path $script:Published 'r2r'
    if (-not (Test-Path -LiteralPath $cliAlone)) { throw 'Run the Clone and Publish phases first.' }
    $version = Get-ReleaseDotNetVersion -Path (Join-Path $repo 'Directory.Build.props')
    $runtimeConfig = Get-Content -LiteralPath (Join-Path $cliAlone 'baseline.runtimeconfig.json') -Raw | ConvertFrom-Json
    $runtimeVersion = [string]@($runtimeConfig.runtimeOptions.includedFrameworks)[0].version
    Write-Host "  Runtime $runtimeVersion; the service stand-in takes Microsoft.Extensions.Hosting.WindowsServices $runtimeVersion"

    # A fresh start: dotnet publish copies a file only when it is newer than the one already there.
    foreach ($folder in (Join-Path $WorkPath 'standins'), (Join-Path $script:Published 'desktop'), (Join-Path $script:Published 'service'), (Join-Path $script:Published 'shared')) {
        if (Test-Path -LiteralPath $folder) { Remove-Item -LiteralPath $folder -Recurse -Force }
    }
    $standIns = New-SpikeStandIns -Repo $repo -Version $version -RuntimeVersion $runtimeVersion
    $apps = @([pscustomobject]@{ Name = 'baseline'; Folder = 'cli'; Project = (Join-Path $repo $script:CliProject) }) + @($standIns)
    $shared = Join-Path $script:Published 'shared'
    foreach ($app in @($standIns)) {
        Invoke-SpikeDotNet -Name "standin-restore-$($app.Folder)" -ArgumentList @('restore', $app.Project) | Out-Null
        $alone = Join-Path $script:Published $app.Folder
        Invoke-SpikeDotNet -Name "standin-publish-$($app.Folder)" -ArgumentList @('publish', $app.Project, '--configuration', 'Release', '--runtime', 'win-x64', '--no-restore', '--output', $alone) | Out-Null
    }
    # One folder, in the order an installer's build might publish them: the CLI, then the app, then the service.
    foreach ($app in $apps) {
        Invoke-SpikeDotNet -Name "shared-publish-$($app.Folder)" -ArgumentList @('publish', $app.Project, '--configuration', 'Release', '--runtime', 'win-x64', '--no-restore', '--output', $shared) | Out-Null
    }

    # Every file two apps publish, by content; and whose copy the shared folder kept.
    $alone = @{}
    foreach ($app in $apps) {
        $folder = $cliAlone
        if ($app.Folder -ne 'cli') { $folder = Join-Path $script:Published $app.Folder }
        $app | Add-Member -NotePropertyName Alone -NotePropertyValue $folder -Force
        $alone[$app.Name] = @{}
        $hashes = Get-SpikeHashes -Path $folder
        foreach ($row in $hashes) { $alone[$app.Name][$row.Path] = $row }
    }
    $sharedHashes = @{}
    $hashes = Get-SpikeHashes -Path $shared
    foreach ($row in $hashes) { $sharedHashes[$row.Path] = $row }
    $paths = @($apps | ForEach-Object { $alone[$_.Name].Keys } | Sort-Object -Unique)
    $collisions = foreach ($path in $paths) {
        $owners = @($apps | Where-Object { $alone[$_.Name].ContainsKey($path) })
        if ($owners.Count -lt 2) { continue }
        $distinct = @($owners | ForEach-Object { $alone[$_.Name][$path].Hash } | Sort-Object -Unique)
        if ($distinct.Count -lt 2) { continue }
        $kept = @($owners | Where-Object { $sharedHashes.ContainsKey($path) -and $alone[$_.Name][$path].Hash -eq $sharedHashes[$path].Hash } | ForEach-Object { $_.Name })
        $info = @($owners | ForEach-Object {
                $file = Join-Path $_.Alone $path
                $fileVersion = (Get-Item -LiteralPath $file).VersionInfo.FileVersion
                $pe = Get-SpikePeInfo -Path $file
                '{0}: {1:N0} bytes, file version {2}, {3}' -f $_.Name, $alone[$_.Name][$path].Length, $fileVersion, $(if ($null -eq $pe) { 'not PE' } elseif ($pe.ReadyToRun) { 'ReadyToRun' } elseif ($pe.Managed) { 'IL only' } else { 'native' })
            })
        [pscustomobject]@{ Path = $path; Apps = @($owners | ForEach-Object { $_.Name }); Kept = $kept; Copies = $info }
    }
    $sameShared = @(foreach ($path in $paths) {
            if (@($apps | Where-Object { $alone[$_.Name].ContainsKey($path) }).Count -ge 2) { $path }
        })

    # For each app: the files its .deps.json names that the shared folder holds with content other than its own.
    $perApp = foreach ($app in $apps) {
        $assets = Get-SpikeDepsAsset -DepsPath (Join-Path $app.Alone "$($app.Name).deps.json")
        $changed = @($assets | Where-Object {
                $sharedHashes.ContainsKey($_.Path) -and $alone[$app.Name].ContainsKey($_.Path) -and $sharedHashes[$_.Path].Hash -ne $alone[$app.Name][$_.Path].Hash
            } | ForEach-Object { '{0} ({1} {2}, its deps.json: assembly {3}, file {4})' -f $_.Path, $_.Kind, $_.Library, $_.AssemblyVersion, $_.FileVersion })
        $runtimeConfigText = Get-Content -LiteralPath (Join-Path $app.Alone "$($app.Name).runtimeconfig.json") -Raw
        $config = $runtimeConfigText | ConvertFrom-Json
        $kinds = @($assets | Group-Object Kind | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name })
        [pscustomobject]@{
            App              = $app.Name
            Assets           = $assets.Count
            AssetKinds       = ($kinds -join ', ')
            DifferentInShare = $changed
            Frameworks       = @(@($config.runtimeOptions.includedFrameworks) | ForEach-Object { '{0} {1}' -f $_.name, $_.version })
            RuntimeConfig    = $runtimeConfigText
        }
    }

    # Each app started from the shared folder, with a host trace.
    $runs = @(
        @{ App = 'baseline'; Arguments = @('--version') },
        @{ App = 'baseline'; Arguments = @('audit', '--id', 'SU-01', '--shipped-config') },
        @{ App = 'BaselineDesktop'; Arguments = @('--version') },
        @{ App = 'BaselineDesktop'; Arguments = @('--selftest') },
        @{ App = 'BaselineService'; Arguments = @('--version') },
        @{ App = 'BaselineService'; Arguments = @('--run') }
    )
    $started = foreach ($run in $runs) {
        $name = '{0}-{1}' -f $run.App, ($run.Arguments[0].TrimStart('-'))
        $trace = Join-Path $script:Results "trace-$name.txt"
        if (Test-Path -LiteralPath $trace) { Remove-Item -LiteralPath $trace -Force }
        $result = Invoke-SpikeProcess -FilePath (Join-Path $shared "$($run.App).exe") -ArgumentList $run.Arguments -WorkingDirectory $shared -AllowFailure `
            -RemovePrefix @('DOTNET_', 'COMPlus_', 'COREHOST_') -Environment @{ COREHOST_TRACE = '1'; COREHOST_TRACEFILE = $trace; COREHOST_TRACE_VERBOSITY = '4' }
        $hostTrace = Read-SpikeHostTrace -Path $trace -Folder $shared
        $loaded = @($result.Output -split "`r?`n" | Where-Object { $_ -like 'Loaded: *' })
        $loadedElsewhere = @($loaded | Where-Object { $_ -notlike "*$shared\*" })
        Write-Host ("  {0,-16} {1,-38} exit {2}, {3} assemblies trusted, {4} outside the folder; {5} loaded, {6} from elsewhere" -f $run.App, ($run.Arguments -join ' '), $result.ExitCode, $hostTrace.TrustedCount, $hostTrace.TrustedElsewhere.Count, $loaded.Count, $loadedElsewhere.Count)
        [pscustomobject]@{
            App              = $run.App
            Arguments        = ($run.Arguments -join ' ')
            ExitCode         = $result.ExitCode
            WallMs           = $result.WallMs
            Output           = @($result.Output -split "`r?`n" | Where-Object { $_ -and $_ -notlike 'Loaded: *' } | Select-Object -First 12)
            Errors           = $result.Errors
            Loaded           = $loaded.Count
            LoadedElsewhere  = $loadedElsewhere
            TrustedCount     = $hostTrace.TrustedCount
            TrustedElsewhere = $hostTrace.TrustedElsewhere
            Trace            = $hostTrace.Lines
        }
    }

    # The check a release runs before signing (tools\Test-ReleaseSignatures.ps1 -Unsigned), on the shared folder.
    $rows = @(Get-ReleaseSignatureReport -Path $shared -Unsigned)
    $problems = @($rows | Where-Object { @($_.Problems).Count } | ForEach-Object { '{0} ({1}): {2}' -f (Split-Path -Leaf $_.File), $_.Owner, (@($_.Problems) -join '; ') })
    $signature = [pscustomobject]@{
        Passed    = ($problems.Count -eq 0)
        Ours      = @($rows | Where-Object { $_.Owner -eq 'ours' } | ForEach-Object { Split-Path -Leaf $_.File } | Sort-Object)
        Microsoft = @($rows | Where-Object { $_.Owner -ne 'ours' }).Count
        Problems  = $problems
    }
    Write-Host ("  Test-ReleaseSignatures -Unsigned on the shared folder: {0}" -f $(if ($signature.Passed) { "passed, $($signature.Ours.Count) of ours, $($signature.Microsoft) Microsoft's" } else { 'FAILED: ' + ($signature.Problems -join '; ') }))

    $sizes = foreach ($app in $apps) {
        $measure = Measure-SpikeFolder -Path $app.Alone
        [pscustomobject]@{ Folder = "$($app.Name) alone"; Files = $measure.Files; Bytes = $measure.Bytes }
    }
    $sharedMeasure = Measure-SpikeFolder -Path $shared
    $sizes = @($sizes) + @([pscustomobject]@{ Folder = 'shared'; Files = $sharedMeasure.Files; Bytes = $sharedMeasure.Bytes })
    foreach ($row in $sizes) { Write-Host ("  {0,-22} {1,5} files {2,8:N1} MB" -f $row.Folder, $row.Files, ($row.Bytes / 1MB)) }
    Write-Host ("  {0} file(s) published by two or more apps, {1} of them with different content" -f $sameShared.Count, @($collisions).Count)
    foreach ($c in @($collisions)) { Write-Host ("    {0}: kept {1}" -f $c.Path, ($c.Kept -join ', ')) }

    Save-SpikeResult 'shared' ([pscustomobject]@{
            RuntimeVersion = $runtimeVersion
            PublishedByTwo = $sameShared.Count
            Collisions     = @($collisions)
            PerApp         = @($perApp)
            Started        = @($started)
            Signature      = $signature
            Sizes          = @($sizes)
        })
}

function Compare-SpikeFile {
    <# Why two copies of one published file differ. #>
    param([string]$Left, [string]$Right, [string[]]$Tokens)
    $a = [IO.File]::ReadAllBytes($Left)
    $b = [IO.File]::ReadAllBytes($Right)
    $diff = [RuntimeSpikeBytes]::Diff($a, $b, 8)
    $ranges = for ($i = 2; $i + 1 -lt $diff.Count; $i += 2) { '0x{0:X}+{1}' -f $diff[$i], $diff[$i + 1] }
    $peLeft = Get-SpikePeInfo -Path $Left
    $peRight = Get-SpikePeInfo -Path $Right
    $paths = foreach ($token in $Tokens) {
        $inLeft = Find-SpikeText -Bytes $a -Text $token
        if ($inLeft.Count) { "holds its build path $($inLeft.Count) time(s), such as: $($inLeft.Sample)" }
    }
    $text = $null
    if ($null -eq $peLeft -and [IO.Path]::GetExtension($Left) -in '.json', '.txt', '.xml') {
        $l = @(Get-Content -LiteralPath $Left)
        $r = @(Get-Content -LiteralPath $Right)
        for ($i = 0; $i -lt [Math]::Max($l.Count, $r.Count); $i++) {
            $x = $null; $y = $null
            if ($i -lt $l.Count) { $x = $l[$i] }
            if ($i -lt $r.Count) { $y = $r[$i] }
            if ($x -ne $y) { $text = "first differing line $($i + 1): '$x' / '$y'"; break }
        }
    }
    [pscustomobject]@{
        Sizes        = '{0:N0} / {1:N0} bytes' -f $a.Length, $b.Length
        BytesDiffer  = $diff[0]
        Runs         = $diff[1]
        FirstRuns    = @($ranges)
        Left         = $peLeft
        Right        = $peRight
        MvidSame     = $(if ($null -ne $peLeft -and $null -ne $peRight) { $peLeft.Mvid -eq $peRight.Mvid } else { $null })
        EmbeddedPath = @($paths)
        Text         = $text
    }
}

function Invoke-DeterminismPhase {
    param([string]$BuildMode)
    $label = $BuildMode.ToLowerInvariant()
    if ($Property.Count) {
        $sha = [Security.Cryptography.SHA256]::Create()
        $label += '-' + [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($Property -join ';')))).Replace('-', '').Substring(0, 6).ToLowerInvariant()
        $sha.Dispose()
    }
    if ($FreshPackages) { $label += '-packages' }
    if ($LfCheckout) { $label += '-lf' }
    Write-SpikeStep "Determinism ($BuildMode$(if ($Property.Count) { ', ' + ($Property -join ' ') })$(if ($FreshPackages) { ', the second with its own package folder' })$(if ($LfCheckout) { ', the second checked out with LF' })): two clean ReadyToRun publishes from two paths"
    $base = Join-Path $WorkPath "det-$label"
    if (Test-Path -LiteralPath $base) { throw "$base exists already: this experiment has run. Clean it up or use another -WorkPath." }
    $builds = @(
        [pscustomobject]@{ Repo = (Join-Path $base '1\repo'); Output = (Join-Path $base 'out1') },
        [pscustomobject]@{ Repo = (Join-Path $base 'second-clone-at-another-path\2\repo'); Output = (Join-Path $base 'out2') }
    )
    $extra = @($Property | ForEach-Object { "-p:$_" })
    $i = 0
    foreach ($build in $builds) {
        $i++
        New-SpikeClone -Destination $build.Repo -Lf:($LfCheckout -and $i -eq 2)
        $ci = $BuildMode -eq 'CI'
        $restore = Join-Path $build.Repo 'Baseline.slnx'
        $packages = @{}
        if ($FreshPackages -and $i -eq 2) {
            $packages['NUGET_PACKAGES'] = Join-Path $base 'packages'
            $restore = Join-Path $build.Repo $script:CliProject
        }
        Invoke-SpikeDotNet -CI:$ci -Environment $packages -Name "det-$label-$i-restore" -ArgumentList (@('restore', $restore, '--locked-mode') + $extra) | Out-Null
        Invoke-SpikeDotNet -CI:$ci -Environment $packages -Name "det-$label-$i-publish" -ArgumentList (@('publish', (Join-Path $build.Repo $script:CliProject), '--configuration', 'Release', '--runtime', 'win-x64', '--no-restore', '--output', $build.Output) + $extra) | Out-Null
        $hashes = Get-SpikeHashes -Path $build.Output
        Set-Content -LiteralPath (Join-Path $script:Results "det-$label-$i.sha256") -Value @($hashes | ForEach-Object { '{0}  {1}' -f $_.Hash, $_.Path }) -Encoding ASCII
        $build | Add-Member -NotePropertyName Hashes -NotePropertyValue $hashes
    }

    $left = @{}
    foreach ($row in $builds[0].Hashes) { $left[$row.Path] = $row }
    $right = @{}
    foreach ($row in $builds[1].Hashes) { $right[$row.Path] = $row }
    $onlyOne = @(@($left.Keys | Where-Object { -not $right.ContainsKey($_) }) + @($right.Keys | Where-Object { -not $left.ContainsKey($_) }))
    $different = @($left.Keys | Where-Object { $right.ContainsKey($_) -and $left[$_].Hash -ne $right[$_].Hash } | Sort-Object)
    # Each build's path, as the files would hold it: the clone's folder.
    $tokens = @((Split-Path -Leaf $base), (Split-Path -Leaf (Split-Path -Parent (Split-Path -Parent $builds[1].Repo))))
    $diagnosis = foreach ($path in $different) {
        $why = Compare-SpikeFile -Left (Join-Path $builds[0].Output $path) -Right (Join-Path $builds[1].Output $path) -Tokens $tokens
        [pscustomobject]@{ Path = $path; Why = $why }
    }
    $reference = $null
    if ($ReferenceManifest) {
        $theirs = @{}
        foreach ($line in @(Get-Content -LiteralPath $ReferenceManifest)) {
            if ($line -match '^([0-9A-Fa-f]{64})\s+\*?(.+)$') { $theirs[$Matches[2].Trim().Replace('/', '\')] = $Matches[1].ToUpperInvariant() }
        }
        $reference = [pscustomobject]@{
            Manifest  = $ReferenceManifest
            Files     = $theirs.Count
            Different = @($left.Keys | Where-Object { $theirs.ContainsKey($_) -and $theirs[$_] -ne $left[$_].Hash } | Sort-Object)
            OnlyHere  = @($left.Keys | Where-Object { -not $theirs.ContainsKey($_) } | Sort-Object)
            OnlyThere = @($theirs.Keys | Where-Object { -not $left.ContainsKey($_) } | Sort-Object)
        }
    }

    Write-Host ("  {0} files; {1} identical, {2} differ, {3} in one build only" -f $left.Count, ($left.Count - $different.Count - @($left.Keys | Where-Object { -not $right.ContainsKey($_) }).Count), $different.Count, $onlyOne.Count)
    foreach ($d in @($diagnosis)) {
        Write-Host ("    {0}: {1} byte(s) in {2} run(s); MVID same: {3}; {4}" -f $d.Path, $d.Why.BytesDiffer, $d.Why.Runs, $d.Why.MvidSame, (@($d.Why.EmbeddedPath) -join ' ') )
    }
    Save-SpikeResult "det-$label" ([pscustomobject]@{
            Mode      = $BuildMode
            Property  = @($Property)
            Packages  = [bool]$FreshPackages
            Lf        = [bool]$LfCheckout
            Label     = $label
            Files     = $left.Count
            Different = @($different)
            OnlyOne   = @($onlyOne)
            Diagnosis = @($diagnosis)
            Reference = $reference
        })
}

function Invoke-ReportPhase {
    Write-SpikeStep 'Report'
    $mb = { param($Bytes) '{0:N1}' -f ($Bytes / 1MB) }
    $source = Read-SpikeResult 'source'
    if ($null -ne $source) {
        Write-Output ("Commit {0}; SDK {1}; Windows {2}; {3}, {4} logical processors; power: {5}; Defender real-time: {6}; elevated: {7}; PowerShell {8}" -f `
                $source.Commit, $source.Sdk, $source.Windows, $source.Processor, $source.LogicalProcessors, $source.Power, $source.DefenderRealTime, $source.Elevated, $source.PowerShell)
        Write-Output ''
    }
    $size = Read-SpikeResult 'size'
    if ($null -ne $size) {
        Write-Output '| baseline.exe, self-contained win-x64 | Files | Folder (MB) | Zip (MB) | Ours (MB) | PDBs (MB) |'
        Write-Output '|---|---:|---:|---:|---:|---:|'
        foreach ($row in @($size)) {
            Write-Output ('| {0} | {1} | {2} | {3} | {4} | {5} |' -f $row.Label, $row.Files, (& $mb $row.Bytes), (& $mb $row.ZipBytes), (& $mb $row.OursBytes), (& $mb $row.PdbBytes))
        }
        Write-Output ''
        Write-Output '| File of ours | ReadyToRun (KB) | IL only (KB) |'
        Write-Output '|---|---:|---:|'
        $r2r = @(@($size) | Where-Object { $_.Variant -eq 'r2r' })[0]
        $il = @(@($size) | Where-Object { $_.Variant -eq 'il' })[0]
        foreach ($file in @($r2r.Ours)) {
            $other = @(@($il.Ours) | Where-Object { $_.Name -eq $file.Name })
            $ilBytes = $(if ($other.Count) { '{0:N0}' -f ($other[0].Bytes / 1KB) } else { '-' })
            Write-Output ('| {0}{1} | {2:N0} | {3} |' -f $file.Name, $(if ($file.ReadyToRun) { '' } else { ' (not ReadyToRun)' }), ($file.Bytes / 1KB), $ilBytes)
        }
        Write-Output ''
    }
    $startup = Read-SpikeResult 'startup'
    if ($null -ne $startup) {
        Write-Output ("Wall-clock ms from process start to exit; first run: median of {0}, each from a fresh copy of the folder; warm: median of {1} after 1 discarded, with the range and the interquartile range." -f $startup.FirstRuns, $startup.Runs)
        Write-Output ''
        Write-Output '| Build | Command | First run | Warm median | Warm range | Warm IQR | Warm CPU ms |'
        Write-Output '|---|---|---:|---:|---:|---:|---:|'
        foreach ($row in @($startup.Summary)) {
            $first = '-'
            if ($null -ne $row.First) { $first = '{0:N0} ({1:N0}-{2:N0})' -f $row.First.Median, $row.First.Min, $row.First.Max }
            Write-Output ('| {0} | `{1}` | {2} | {3:N0} | {4:N0}-{5:N0} | {6:N0}-{7:N0} | {8:N0} |' -f $row.Label, $row.Command, $first, $row.Warm.Median, $row.Warm.Min, $row.Warm.Max, $row.Warm.P25, $row.Warm.P75, $row.WarmCpu.Median)
        }
        Write-Output ''
    }
    $shared = Read-SpikeResult 'shared'
    if ($null -ne $shared) {
        Write-Output '| Folder | Files | MB |'
        Write-Output '|---|---:|---:|'
        foreach ($row in @($shared.Sizes)) { Write-Output ('| {0} | {1} | {2} |' -f $row.Folder, $row.Files, (& $mb $row.Bytes)) }
        Write-Output ''
        Write-Output ("Files published by two or more apps: {0}; with different content: {1}" -f $shared.PublishedByTwo, @($shared.Collisions).Count)
        foreach ($c in @($shared.Collisions)) { Write-Output ("- {0}: kept {1}. {2}" -f $c.Path, (@($c.Kept) -join ', '), (@($c.Copies) -join '; ')) }
        foreach ($app in @($shared.PerApp)) {
            Write-Output ("- {0}: {1} assets ({2}); frameworks {3}; named in its deps.json but different in the shared folder: {4}" -f $app.App, $app.Assets, $app.AssetKinds, (@($app.Frameworks) -join ', '), $(if (@($app.DifferentInShare).Count) { @($app.DifferentInShare) -join '; ' } else { 'none' }))
        }
        foreach ($run in @($shared.Started)) {
            Write-Output ("- {0} {1}: exit {2}; {3} trusted assemblies, {4} outside the folder; {5} loaded, {6} from elsewhere" -f $run.App, $run.Arguments, $run.ExitCode, $run.TrustedCount, @($run.TrustedElsewhere).Count, $run.Loaded, @($run.LoadedElsewhere).Count)
        }
        Write-Output ("- Test-ReleaseSignatures.ps1 -Unsigned on the shared folder: {0}" -f $(if ($shared.Signature.Passed) { "passed: ours are $(@($shared.Signature.Ours) -join ', '); $($shared.Signature.Microsoft) are Microsoft's" } else { 'failed: ' + (@($shared.Signature.Problems) -join '; ') }))
        Write-Output ''
    }
    foreach ($file in @(Get-ChildItem -LiteralPath $script:Results -Filter 'det-*.json' -File | Sort-Object Name)) {
        $det = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $fresh = ''
        if ([bool](Get-SpikeJsonValue $det 'Packages')) { $fresh += ', the second build with its own package folder' }
        if ([bool](Get-SpikeJsonValue $det 'Lf')) { $fresh += ', the second checked out with LF line endings' }
        Write-Output ("Determinism, {0}{1}{2}: {3} files, {4} differ, {5} in one build only" -f $det.Mode, $(if (@($det.Property).Count) { ' with ' + (@($det.Property) -join ' ') } else { '' }), $fresh, $det.Files, @($det.Different).Count, @($det.OnlyOne).Count)
        foreach ($d in @($det.Diagnosis)) {
            $debugLeft = @(@(Get-SpikeJsonValue $d.Why.Left 'Debug') | Where-Object { $null -ne $_ } | ForEach-Object { $_.Detail })
            Write-Output ("- {0}: {1}, {2} byte(s) differ in {3} run(s) ({4}); MVID same: {5}; {6} {7} debug: {8}" -f $d.Path, $d.Why.Sizes, $d.Why.BytesDiffer, $d.Why.Runs, (@($d.Why.FirstRuns) -join ' '), $d.Why.MvidSame, (@($d.Why.EmbeddedPath) -join ' '), $d.Why.Text, ($debugLeft -join ' | '))
        }
        if ($null -ne $det.Reference) {
            Write-Output ("- Against {0}: {1} differ, {2} only here, {3} only there" -f $det.Reference.Manifest, @($det.Reference.Different).Count, @($det.Reference.OnlyHere).Count, @($det.Reference.OnlyThere).Count)
        }
        Write-Output ''
    }
}

function Invoke-CleanupPhase {
    Write-SpikeStep "Cleanup: $WorkPath"
    if (-not (Test-Path -LiteralPath (Join-Path $WorkPath $script:MarkerName))) { throw "$WorkPath was not made by this script, so it is left alone." }
    Remove-Item -LiteralPath $WorkPath -Recurse -Force
}

# --- Main ------------------------------------------------------------------------------------------------------

if (-not $WorkPath) {
    if ($Phase -notin 'All', 'Clone') { throw "Give -WorkPath: the folder the earlier phases used." }
    $WorkPath = Join-Path ([IO.Path]::GetTempPath()) ('baseline-spike2-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
}
$WorkPath = [IO.Path]::GetFullPath($WorkPath)
if (-not (Test-Path -LiteralPath $WorkPath)) {
    if ($Phase -notin 'All', 'Clone') { throw "$WorkPath does not exist: run the Clone phase first." }
    New-Item -ItemType Directory -Path $WorkPath | Out-Null
    Set-Content -LiteralPath (Join-Path $WorkPath $script:MarkerName) -Value 'Made by tools\spikes\Measure-RuntimeSpike.ps1, which deletes it.' -Encoding ASCII
}
elseif (-not (Test-Path -LiteralPath (Join-Path $WorkPath $script:MarkerName))) {
    throw "$WorkPath exists and was not made by this script. Give a new folder."
}
$script:Results = Join-Path $WorkPath 'results'
$script:Logs = Join-Path $WorkPath 'logs'
$script:Published = Join-Path $WorkPath 'pub'
foreach ($folder in $script:Results, $script:Logs, $script:Published) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
Write-Host "Work folder: $WorkPath"

switch ($Phase) {
    'Clone' { Invoke-ClonePhase }
    'Publish' { Invoke-PublishPhase }
    'Size' { Invoke-SizePhase }
    'Startup' { Invoke-StartupPhase }
    'SharedFolder' { Invoke-SharedFolderPhase }
    'Determinism' { Invoke-DeterminismPhase -BuildMode $Mode }
    'Report' { Invoke-ReportPhase }
    'Cleanup' { Invoke-CleanupPhase }
    'All' {
        Invoke-ClonePhase
        Invoke-PublishPhase
        Invoke-SizePhase
        Invoke-StartupPhase
        Invoke-SharedFolderPhase
        Invoke-DeterminismPhase -BuildMode 'Local'
        Invoke-DeterminismPhase -BuildMode 'CI'
        Invoke-ReportPhase
        if (-not $Keep) { Invoke-CleanupPhase }
    }
}
