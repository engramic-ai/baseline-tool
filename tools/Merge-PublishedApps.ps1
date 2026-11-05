#Requires -Version 5.1
<#
.SYNOPSIS
    Merges apps published self-contained, each to its own folder, into one runtime folder, and fails on any file
    two of them publish with different content.
.DESCRIPTION
    The release ships baseline.exe, the desktop app and the agent's service from one runtime folder, signed once
    (docs\DOTNET.md, spike 2). Publishing all of them into one folder is not safe: dotnet publish copies a file only
    when it is newer than the one there, so which copy of a file two apps publish differently is kept depends on
    timestamps. Here each app is published alone first, and this script merges the folders:

    - A file only one app publishes is copied as it is.
    - A file several apps publish with the same content (SHA-256) is copied once.
    - A file several apps publish with different content stops the merge, which then writes nothing, with two
      exceptions: WindowsBase.dll and System.Diagnostics.EventLog.dll at the top of the folder. For those the copy
      of the app that uses the Windows desktop runtime (its runtimeconfig.json names Microsoft.WindowsDesktop.App)
      is kept, as spike 2 found every app runs with it.

    Every source must be a published app: a folder with one <app>.deps.json and its <app>.runtimeconfig.json at the
    top. A source with a link (a symbolic link or junction) anywhere in it is refused, and so is a destination that
    already holds anything. After copying, every file in the destination is hashed again and compared with the copy
    chosen.
.PARAMETER Source
    The folders the apps were published to, each on its own.
.PARAMETER Destination
    The runtime folder to make. It must not exist, or be empty.
.PARAMETER PassThru
    Return one row for each file: its path, the apps that publish it, which app's copy was kept, and why.
.EXAMPLE
    .\tools\Merge-PublishedApps.ps1 -Source .\build\publish\baseline, .\build\publish\desktop -Destination .\build\runtime
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Source,
    [Parameter(Mandatory)][string]$Destination,
    [switch]$PassThru
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# The two files the desktop runtime pack and another publish differently, where the desktop pack's copy is kept.
$desktopWins = @('WindowsBase.dll', 'System.Diagnostics.EventLog.dll')

function Get-PublishedApp {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "There is no folder at $Path." }
    $root = (Resolve-Path -LiteralPath $Path).ProviderPath.TrimEnd('\', '/')
    $deps = @(Get-ChildItem -LiteralPath $root -Filter '*.deps.json' -File -Force)
    if ($deps.Count -ne 1) { throw "$root is not one published app: it has $($deps.Count) .deps.json files at the top, not one." }
    $name = $deps[0].Name.Substring(0, $deps[0].Name.Length - '.deps.json'.Length)
    $configPath = Join-Path $root "$name.runtimeconfig.json"
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "$root has $name.deps.json but no $name.runtimeconfig.json." }
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $frameworks = @()
    $options = $config.PSObject.Properties['runtimeOptions']
    if ($options) {
        foreach ($key in 'includedFrameworks', 'frameworks', 'framework') {
            $entry = $options.Value.PSObject.Properties[$key]
            if ($entry) { $frameworks += @($entry.Value | ForEach-Object { [string]$_.name }) }
        }
    }
    $links = @(Get-ChildItem -LiteralPath $root -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
    if ($links.Count) { throw "$root holds a link, which a runtime folder must not: $($links[0].FullName)" }
    $files = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force)) {
        $relative = $file.FullName.Substring($root.Length + 1)
        $files[$relative] = [pscustomobject]@{ Path = $file.FullName; Hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
    }
    [pscustomobject]@{
        Name    = $name
        Root    = $root
        Desktop = ($frameworks -contains 'Microsoft.WindowsDesktop.App')
        Files   = $files
    }
}

$apps = @($Source | ForEach-Object { Get-PublishedApp -Path $_ })
$names = @($apps | ForEach-Object { $_.Name })
if (@($names | Sort-Object -Unique).Count -ne $names.Count) { throw "Two sources publish the same app: $($names -join ', ')." }
if (@($apps | Where-Object Desktop).Count -gt 1) {
    throw "More than one source uses the Windows desktop runtime ($(@($apps | Where-Object Desktop | ForEach-Object Name) -join ', ')), so whose copy of $($desktopWins -join ' and ') to keep is not clear."
}

if (Test-Path -LiteralPath $Destination) {
    if (-not (Test-Path -LiteralPath $Destination -PathType Container)) { throw "$Destination exists and is not a folder." }
    if (@(Get-ChildItem -LiteralPath $Destination -Force).Count) { throw "$Destination is not empty: the merge only makes a new runtime folder." }
}

# Decide every file before copying any, so a conflict leaves the destination as it was.
$paths = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($app in $apps) { foreach ($key in $app.Files.Keys) { [void]$paths.Add($key) } }
$plan = New-Object System.Collections.ArrayList
$conflicts = New-Object System.Collections.ArrayList
foreach ($path in $paths) {
    $owners = @($apps | Where-Object { $_.Files.ContainsKey($path) })
    $hashes = @($owners | ForEach-Object { $_.Files[$path].Hash } | Sort-Object -Unique)
    $kept = $owners[0]
    $why = if ($owners.Count -eq 1) { 'one app' } else { 'same content' }
    if ($hashes.Count -gt 1) {
        $desktop = @($owners | Where-Object Desktop)
        if ($desktopWins -contains $path -and $desktop.Count -eq 1) {
            $kept = $desktop[0]
            $why = 'the desktop runtime''s copy'
        }
        else {
            [void]$conflicts.Add(('{0}: {1}' -f $path, (@($owners | ForEach-Object { '{0} {1}' -f $_.Name, $_.Files[$path].Hash.Substring(0, 12) }) -join ', ')))
            continue
        }
    }
    [void]$plan.Add([pscustomobject]@{
            Path = $path
            Apps = @($owners | ForEach-Object { $_.Name })
            Kept = $kept.Name
            Why  = $why
            From = $kept.Files[$path].Path
            Hash = $kept.Files[$path].Hash
        })
}
if ($conflicts.Count) {
    throw ("{0} file(s) are published with different content by more than one app, so the apps cannot share one folder:`n  {1}" -f $conflicts.Count, ($conflicts -join "`n  "))
}

if (-not (Test-Path -LiteralPath $Destination)) { New-Item -ItemType Directory -Path $Destination | Out-Null }
$target = (Resolve-Path -LiteralPath $Destination).ProviderPath.TrimEnd('\', '/')
foreach ($row in $plan) {
    $to = Join-Path $target $row.Path
    $folder = Split-Path -Parent $to
    if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    Copy-Item -LiteralPath $row.From -Destination $to
}

# Check what was written: exactly the files planned, each with the content chosen.
$written = @(Get-ChildItem -LiteralPath $target -Recurse -File -Force)
if ($written.Count -ne $plan.Count) { throw "The runtime folder holds $($written.Count) files, not the $($plan.Count) planned." }
foreach ($row in $plan) {
    $hash = (Get-FileHash -LiteralPath (Join-Path $target $row.Path) -Algorithm SHA256).Hash
    if ($hash -ne $row.Hash) { throw "$($row.Path) in the runtime folder is not the copy chosen from $($row.Kept)." }
}

$shared = @($plan | Where-Object { $_.Apps.Count -gt 1 }).Count
$desktopKept = @($plan | Where-Object { $_.Why -eq 'the desktop runtime''s copy' } | ForEach-Object Path)
Write-Host ("Merged {0} app(s) into {1}: {2} file(s), {3} published by more than one app." -f $apps.Count, $target, $plan.Count, $shared)
if ($desktopKept.Count) { Write-Host ("Kept the desktop runtime's copy of {0}." -f ($desktopKept -join ' and ')) }
if ($PassThru) { $plan | Select-Object Path, Apps, Kept, Why }
