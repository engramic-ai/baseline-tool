#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the tracked files for text that must not reach this public repository.
.DESCRIPTION
    The Hygiene job in .github/workflows/dotnet.yml runs this on every push and pull request. It fails when:
      - a tracked text file holds a non-ASCII byte, unless public-allowlist.txt lists the file with a reason;
      - a URL in src/, tests/, tools/ or docs/ names a host that is not on the allowlist;
      - any tracked file names an engramic-ai/ repository or an engramic.ai name that is not on the allowlist;
      - an advanced .ps1 script reads $PSScriptRoot or $PSCommandPath in a parameter's default, which Windows
        PowerShell 5.1 leaves empty when the script is run with -File, as Intune and the SYSTEM runs do.
    The allowlist, public-allowlist.txt beside this script, explains why it lists allowed names rather
    than private ones. The file list comes from git, so run it in a clone that git can read.
.PARAMETER Root
    The repository to check. Defaults to the one this script is in.
.EXAMPLE
    pwsh -NoProfile -File tools/hygiene/Test-Hygiene.ps1
#>
[CmdletBinding()]
param(
    [string]$Root
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 leaves $PSScriptRoot empty in parameter defaults, so the default is set here.
if (-not $Root) { $Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }

function Read-CEHygieneAllowlist {
    <# The sections of public-allowlist.txt: [hosts], [engramic] and [non-ascii] (path to reason). #>
    param([string]$Path)
    $list = @{ hosts = @(); engramic = @(); 'non-ascii' = @{} }
    $section = ''
    foreach ($raw in [IO.File]::ReadAllLines($Path)) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith('#', [StringComparison]::Ordinal)) { continue }
        if ($line -match '^\[([a-z-]+)\]$') {
            $section = $Matches[1]
            if (-not $list.ContainsKey($section)) { throw "public-allowlist.txt: unknown section [$section]" }
            continue
        }
        switch ($section) {
            'non-ascii' {
                $split = $line.IndexOf([char]';')
                if ($split -lt 1 -or -not $line.Substring($split + 1).Trim()) { throw "public-allowlist.txt: '$line' needs a path, a semicolon and the reason" }
                $list['non-ascii'][$line.Substring(0, $split).Trim()] = $line.Substring($split + 1).Trim()
            }
            '' { throw "public-allowlist.txt: '$line' comes before any section" }
            default { $list[$section] += $line.ToLowerInvariant() }
        }
    }
    return $list
}

function Get-CEHygieneTrackedFile {
    <# Every tracked file, with whether git sees its content as text. #>
    param([string]$Repository)
    $listed = & git -C $Repository -c core.quotepath=off ls-files --eol -z
    if ($LASTEXITCODE -ne 0) { throw "git could not list the files in $Repository" }
    foreach ($entry in (($listed -join "`n") -split "`0")) {
        $tab = $entry.IndexOf([char]9)
        if ($tab -lt 0) { continue }
        # "i/<eol>" describes the index copy; git marks content it takes for binary as i/-text.
        [pscustomobject]@{
            Path   = $entry.Substring($tab + 1)
            IsText = -not $entry.StartsWith('i/-text', [StringComparison]::Ordinal)
        }
    }
}

function Test-CEHygieneHostAllowed {
    param([string]$HostName, [string[]]$Allowed)
    foreach ($entry in $Allowed) {
        if ($entry.StartsWith('.', [StringComparison]::Ordinal)) {
            if ($HostName -eq $entry.Substring(1) -or $HostName.EndsWith($entry, [StringComparison]::Ordinal)) { return $true }
        }
        elseif ($HostName -eq $entry) { return $true }
    }
    return $false
}

$allowlist = Read-CEHygieneAllowlist -Path (Join-Path $PSScriptRoot 'public-allowlist.txt')
$files = @(Get-CEHygieneTrackedFile -Repository $Root | Where-Object { $_.IsText })
if ($files.Count -lt 50) { throw "Only $($files.Count) tracked text files found in $Root; is it a clone git can read?" }

# A URL's authority: stops at the path, query, fragment, quotes, brackets of prose and markup, and
# separators. Characters no host can hold ($ { } [ ] % *) stay in, so a placeholder such as
# scheme://$name is recognised as one and skipped rather than read as a host.
$urlPattern = [regex]'(?i)\b[a-z][a-z0-9+.-]*://([^\s/?#"''`<>()\\,;|]+)'
$hostPattern = [regex]'^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'
$repositoryPattern = [regex]'(?i)\bengramic-ai/([a-z0-9._-]+)'
$domainPattern = [regex]'(?i)(?<![a-z0-9.-])([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*engramic\.ai(?![a-z0-9-])'
$hostFolders = @('src/', 'tests/', 'tools/', 'docs/')
$nonAsciiPattern = [regex]'[^\x00-\x7F]'

$problems = New-Object System.Collections.ArrayList
$nonAsciiSeen = @{}
foreach ($file in $files) {
    $full = Join-Path $Root $file.Path
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
    # Decoding keeps a byte order mark (U+FEFF) and turns bytes that are not UTF-8 into U+FFFD,
    # so any non-ASCII byte in the file shows up as a non-ASCII character here.
    $text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($full))

    $nonAscii = $nonAsciiPattern.Match($text)
    if ($nonAscii.Success) {
        if ($allowlist['non-ascii'].ContainsKey($file.Path)) { $nonAsciiSeen[$file.Path] = $true }
        else {
            $line = $text.Substring(0, $nonAscii.Index).Split("`n").Count
            [void]$problems.Add(('{0}({1}): non-ASCII character U+{2:X4}; sources are ASCII only' -f $file.Path, $line, [int][char]$nonAscii.Value))
        }
    }

    $inHostFolder = @($hostFolders | Where-Object { $file.Path.StartsWith($_, [StringComparison]::Ordinal) }).Count -gt 0
    if ($inHostFolder) {
        foreach ($match in $urlPattern.Matches($text)) {
            $authority = $match.Groups[1].Value
            $at = $authority.LastIndexOf([char]'@')
            if ($at -ge 0) { $authority = $authority.Substring($at + 1) }
            $name = ($authority -replace ':\d*$', '').TrimEnd('.').ToLowerInvariant()
            if (-not $hostPattern.IsMatch($name)) { continue }
            if (-not (Test-CEHygieneHostAllowed -HostName $name -Allowed $allowlist['hosts'])) {
                [void]$problems.Add("$($file.Path): URL host '$name' is not on the public allowlist")
            }
        }
    }

    foreach ($match in $repositoryPattern.Matches($text)) {
        $repository = ($match.Groups[1].Value.TrimEnd('.') -replace '\.git$', '').ToLowerInvariant()
        if ($allowlist['engramic'] -notcontains "engramic-ai/$repository") {
            [void]$problems.Add("$($file.Path): 'engramic-ai/$repository' is not on the public allowlist")
        }
    }
    if ($file.Path.EndsWith('.ps1', [StringComparison]::OrdinalIgnoreCase)) {
        $tokens = $null
        $parseErrors = $null
        $paramBlock = [System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$tokens, [ref]$parseErrors).ParamBlock
        if ($paramBlock) {
            $attributes = @($paramBlock.Attributes) + @($paramBlock.Parameters | ForEach-Object { $_.Attributes })
            $advanced = @($attributes | Where-Object { $_ -is [System.Management.Automation.Language.AttributeAst] -and $_.TypeName.Name -in 'CmdletBinding', 'Parameter' }).Count -gt 0
            foreach ($parameter in $paramBlock.Parameters) {
                if ($advanced -and $parameter.DefaultValue -and $parameter.DefaultValue.Extent.Text -match '\$(PSScriptRoot|PSCommandPath)\b') {
                    [void]$problems.Add(('{0}({1}): the default of ${2} reads the script''s own path, which Windows PowerShell 5.1 leaves empty in an advanced script run with -File; set it in the body' -f $file.Path, $parameter.Extent.StartLineNumber, $parameter.Name.VariablePath.UserPath))
                }
            }
        }
    }

    foreach ($match in $domainPattern.Matches($text)) {
        $name = $match.Value.ToLowerInvariant()
        if ($allowlist['engramic'] -notcontains $name) {
            [void]$problems.Add("$($file.Path): '$name' is not on the public allowlist")
        }
    }
}

foreach ($path in $allowlist['non-ascii'].Keys) {
    if (-not $nonAsciiSeen.ContainsKey($path)) {
        [void]$problems.Add("public-allowlist.txt: $path no longer holds non-ASCII bytes; take it off the [non-ascii] list")
    }
}

Write-Host "Checked $($files.Count) tracked text files."
if ($problems.Count) {
    $problems | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" }
    Write-Host "$($problems.Count) problem(s). Names and hosts are allowed in tools/hygiene/public-allowlist.txt."
    exit 1
}
Write-Host 'No non-ASCII text, every URL host and engramic-ai name is on the public allowlist, and no advanced script''s parameter default reads its own path.'
