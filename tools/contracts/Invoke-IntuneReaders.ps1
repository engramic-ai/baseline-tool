#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the unchanged Intune discovery and detection scripts on a status.json in 64-bit and 32-bit Windows
    PowerShell 5.1, and returns what each of them reported, as data.

.DESCRIPTION
    Intune runs intune\Discover-CECompliance.ps1 (custom compliance) and intune\Detect-CECompliance.ps1
    (Remediations) as SYSTEM in Windows PowerShell 5.1, 64-bit or 32-bit, and both read
    %ProgramData%\EngramicBaseline\status.json. This runs each script file as it is, in a new hidden
    powershell.exe for each host (System32's for 64-bit, SysWOW64's for 32-bit), all at once, and returns one
    result for each script and host:

      Script, Bitness      which script, and which host it was run in
      HostPath             the powershell.exe that ran it
      Is64BitProcess       what the host said it was, so a 32-bit run is known to be one
      PSVersion            the host's version, 5.1.x
      Context              who it ran as: SYSTEM, elevated administrator or standard user (the scripts check
                           who can change the data folder only when elevated or SYSTEM)
      DataFolder           the data folder the script read
      ExitCode             the script's exit code
      Output, Errors       what it wrote to its output and error streams, a line each
      Values               the discovery script's JSON as names and values, or the detection script's line split
                           into its parts (LastRunError, State, AutoFail, Attention, Review, AgeHours, CEPlus,
                           Version, Failing); null when the output is not in that form
      TaskStartRequested   whether the script tried to start the scheduled audit

    -StatusPath copies the file, byte for byte, into a data folder of this script's own
    (<work>\ProgramData\EngramicBaseline) and starts each host with ProgramData set to <work>\ProgramData, which
    is where both scripts look for the data folder. Elevated or as SYSTEM, the scripts refuse a data folder or
    status.json that anyone but SYSTEM and Administrators can change, so the folders are then made as the
    installer makes the data folder, owned by Administrators with only SYSTEM and Administrators allowed to
    change them, and the file is born the same way. The work folder is deleted afterwards.

    -MachineDataFolder leaves ProgramData alone, so the scripts read this device's own data folder, as they do
    under Intune.

    The discovery script starts the scheduled audit when status.json is a day old, missing or unreadable, and a
    stale or damaged test file must never start a real audit on this device. So each host first replaces
    Get-ScheduledTask and Start-ScheduledTask, in its own session only, with stand-ins that record the attempt
    (TaskStartRequested) and fail as they do where the task is missing, which the script already allows for.
    Nothing else about the scripts changes: each runs from its file, with no profile and without strict mode, as
    Intune runs it. Only the progress display is turned off, so it does not fill the error stream.

.PARAMETER StatusPath
    The status.json to read.

.PARAMETER MachineDataFolder
    Read %ProgramData%\EngramicBaseline instead, as Intune does.

.PARAMETER Script
    The scripts to run: Discover, Detect, or both (the default).

.PARAMETER Bitness
    The hosts to run them in: 64-bit, 32-bit, or both (the default).

.PARAMETER WorkPath
    Where to make the work folder, which is deleted afterwards. Default: the temp folder.

.PARAMETER ResultPath
    Also write the results to this file as JSON, UTF-8 with a byte order mark.

.PARAMETER TimeoutSeconds
    How long each host may run. Default: 120.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\contracts\Invoke-IntuneReaders.ps1 -StatusPath .\status.json

.EXAMPLE
    .\tools\contracts\Invoke-IntuneReaders.ps1 -MachineDataFolder -ResultPath .\readers.json
#>
[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'File')][string]$StatusPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Machine')][switch]$MachineDataFolder,
    [ValidateSet('Discover', 'Detect')][string[]]$Script = @('Discover', 'Detect'),
    [ValidateSet('64-bit', '32-bit')][string[]]$Bitness = @('64-bit', '32-bit'),
    [string]$WorkPath,
    [string]$ResultPath,
    [ValidateRange(10, 3600)][int]$TimeoutSeconds = 120
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scriptFiles = @{
    Discover = Join-Path $repo 'intune\Discover-CECompliance.ps1'
    Detect   = Join-Path $repo 'intune\Detect-CECompliance.ps1'
}

function Test-Elevated {
    <# Whether this process is elevated or SYSTEM: then the scripts check who can change the data folder. #>
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-HostPath {
    <# Windows PowerShell 5.1 of the given bitness, by its full path. #>
    param([string]$Of)
    $windows = [Environment]::GetFolderPath('Windows')
    if (-not [Environment]::Is64BitOperatingSystem) {
        if ($Of -eq '64-bit') { throw 'This is 32-bit Windows, which has no 64-bit Windows PowerShell.' }
        return Join-Path $windows 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    if ($Of -eq '32-bit') { return Join-Path $windows 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe' }
    # A 32-bit process is shown SysWOW64 as System32; Sysnative is the real System32.
    $folder = if ([Environment]::Is64BitProcess) { 'System32' } else { 'Sysnative' }
    return Join-Path $windows "$folder\WindowsPowerShell\v1.0\powershell.exe"
}

function New-DataFolder {
    <#
        A folder for the scripts to read. Elevated, it is made owned by Administrators with only SYSTEM and
        Administrators allowed to change it, in the call that creates it, as the installer makes the data folder;
        otherwise it is a plain folder, since the scripts check who can change it only when elevated.
    #>
    param([string]$Path, [bool]$Locked)
    if (-not $Locked) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        return
    }
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    if ($PSVersionTable.PSVersion.Major -ge 6) { [void][IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path), $security) }
    else { [void][IO.Directory]::CreateDirectory($Path, $security) }
}

function New-DataFile {
    <# A new file with these bytes: born owned by Administrators and changeable only by SYSTEM and Administrators when elevated. #>
    param([string]$Path, [byte[]]$Bytes, [bool]$Locked)
    if (-not $Locked) {
        [IO.File]::WriteAllBytes($Path, $Bytes)
        return
    }
    $security = New-Object Security.AccessControl.FileSecurity
    $security.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    $stream = if ($PSVersionTable.PSVersion.Major -ge 6) {
        [IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($Path), [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $security)
    }
    else { [IO.File]::Create($Path, 4096, [IO.FileOptions]::None, $security) }
    try { $stream.Write($Bytes, 0, $Bytes.Length) }
    finally { $stream.Dispose() }
}

function Remove-WorkFolder {
    <#
        Deletes the work folder and everything in it, removing a link as a link and never following one:
        Remove-Item -Recurse follows junctions in Windows PowerShell 5.1. Best effort; a folder left in the temp
        folder does no harm.
    #>
    param([string]$Path)
    try {
        $attributes = [IO.File]::GetAttributes($Path)
        if ($attributes -band [IO.FileAttributes]::ReparsePoint) {
            if ($attributes -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete($Path, $false) } else { [IO.File]::Delete($Path) }
            return
        }
        if ($attributes -band [IO.FileAttributes]::Directory) {
            foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force)) { Remove-WorkFolder -Path $child.FullName }
            [IO.Directory]::Delete($Path, $false)
        }
        else { [IO.File]::Delete($Path) }
    }
    catch { Write-Verbose "Could not delete $Path : $($_.Exception.Message)" }
}

function ConvertTo-Literal {
    <# A PowerShell single-quoted string literal. #>
    param([string]$Text)
    return "'" + $Text.Replace("'", "''") + "'"
}

function Get-HostCommand {
    <#
        What each host runs: stand-ins for the two scheduled-task commands the discovery script may call, then the
        script itself by its path, with its output, errors and exit code written to $ResultFile as JSON.
    #>
    param([string]$ScriptFile, [string]$ResultFile)
    return @"
`$ProgressPreference = 'SilentlyContinue'
`$ceReaderRun = [ordered]@{ Is64BitProcess = [Environment]::Is64BitProcess; PSVersion = `$PSVersionTable.PSVersion.ToString(); Context = ''; DataFolder = (Join-Path `$env:ProgramData 'EngramicBaseline'); ExitCode = 0; Output = @(); Errors = @(); TaskStartRequested = `$false }
`$ceIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
`$ceReaderRun.Context = if (`$ceIdentity.User.Value -eq 'S-1-5-18') { 'SYSTEM' } elseif ((New-Object Security.Principal.WindowsPrincipal(`$ceIdentity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'elevated administrator' } else { 'standard user' }
function Get-ScheduledTask { [CmdletBinding()] param([string]`$TaskPath, [string]`$TaskName) `$ceReaderRun.TaskStartRequested = `$true; throw 'The contract tests never start a scheduled task.' }
function Start-ScheduledTask { [CmdletBinding()] param([Parameter(ValueFromPipeline = `$true)]`$InputObject, [string]`$TaskPath, [string]`$TaskName) `$ceReaderRun.TaskStartRequested = `$true; throw 'The contract tests never start a scheduled task.' }
`$global:LASTEXITCODE = 0
try {
    `$ceItems = @(& $(ConvertTo-Literal $ScriptFile) 2>&1)
    `$ceReaderRun.ExitCode = [int]`$LASTEXITCODE
}
catch {
    `$ceItems = @(`$_)
    `$ceReaderRun.ExitCode = 1
}
foreach (`$ceItem in `$ceItems) {
    if (`$ceItem -is [System.Management.Automation.ErrorRecord]) { `$ceReaderRun.Errors += [string]`$ceItem }
    else { `$ceReaderRun.Output += [string]`$ceItem }
}
[IO.File]::WriteAllText($(ConvertTo-Literal $ResultFile), (ConvertTo-Json -InputObject `$ceReaderRun -Depth 3 -Compress), (New-Object System.Text.UTF8Encoding(`$true)))
exit 0
"@
}

function Start-Host {
    <# Starts one hidden host running one script. ProgramData is moved for it when -StatusPath is used. #>
    param([string]$Name, [string]$Of, [string]$ProgramData, [string]$Folder)
    $exe = Get-HostPath -Of $Of
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "$Of Windows PowerShell was not found at $exe." }
    $resultFile = Join-Path $Folder ('{0}-{1}.json' -f $Name, $Of)
    $command = Get-HostCommand -ScriptFile $scriptFiles[$Name] -ResultFile $resultFile
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $exe
    $start.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    # Windows PowerShell finds its own modules; a PSModulePath inherited from PowerShell 7 would point it at 7's.
    [void]$start.EnvironmentVariables.Remove('PSModulePath')
    if ($ProgramData) { $start.EnvironmentVariables['ProgramData'] = $ProgramData }
    $process = [System.Diagnostics.Process]::Start($start)
    return [pscustomobject]@{
        Script     = $Name
        Bitness    = $Of
        HostPath   = $exe
        ResultFile = $resultFile
        Process    = $process
        Output     = $process.StandardOutput.ReadToEndAsync()
        Errors     = $process.StandardError.ReadToEndAsync()
    }
}

function ConvertFrom-DiscoveryOutput {
    <# The discovery script's one line of JSON as names and values, in its order, or $null. #>
    param([string[]]$Lines)
    if (@($Lines).Count -ne 1) { return $null }
    $parsed = $null
    try { $parsed = $Lines[0] | ConvertFrom-Json } catch { return $null }
    if ($parsed -isnot [System.Management.Automation.PSCustomObject]) { return $null }
    $values = [ordered]@{}
    foreach ($property in $parsed.PSObject.Properties) { $values[$property.Name] = $property.Value }
    return $values
}

function ConvertFrom-DetectionOutput {
    <#
        The detection script's line, "<state> | autofail=<n> attention=<n> review=<n> | age=<n>h | <CE+ test cases>
        | v<version> | <failing>" after an optional "LAST_RUN_ERROR | ", split into its parts, or $null for any
        other line (UNTRUSTED, NO_DATA).
    #>
    param([string[]]$Lines)
    if (@($Lines).Count -ne 1) { return $null }
    $pattern = '^(?<lastRunError>LAST_RUN_ERROR \| )?(?<state>[A-Z-]+) \| autofail=(?<autoFail>-?\d+) attention=(?<attention>-?\d+) review=(?<review>-?\d+) \| age=(?<age>-?\d+)h \| (?<cePlus>.*?) \| v(?<version>.*?) \| (?<failing>.*)$'
    $match = [regex]::Match($Lines[0], $pattern)
    if (-not $match.Success) { return $null }
    return [ordered]@{
        LastRunError = $match.Groups['lastRunError'].Success
        State        = $match.Groups['state'].Value
        AutoFail     = $match.Groups['autoFail'].Value
        Attention    = $match.Groups['attention'].Value
        Review       = $match.Groups['review'].Value
        AgeHours     = $match.Groups['age'].Value
        CEPlus       = $match.Groups['cePlus'].Value
        Version      = $match.Groups['version'].Value
        Failing      = $match.Groups['failing'].Value
    }
}

function Receive-Host {
    <# Waits for a host, then reads what its script reported. #>
    param($Run, [datetime]$Deadline)
    $left = [int][math]::Max(0, ($Deadline - [datetime]::UtcNow).TotalMilliseconds)
    if (-not $Run.Process.WaitForExit($left)) {
        try { $Run.Process.Kill() } catch { $null = $_ }
        throw "$($Run.Script) in $($Run.Bitness) Windows PowerShell did not finish within $TimeoutSeconds seconds."
    }
    $Run.Process.WaitForExit()
    if (-not (Test-Path -LiteralPath $Run.ResultFile -PathType Leaf)) {
        throw "$($Run.Script) in $($Run.Bitness) Windows PowerShell ended ($($Run.Process.ExitCode)) without a result: $($Run.Errors.Result) $($Run.Output.Result)"
    }
    $reported = [IO.File]::ReadAllText($Run.ResultFile) | ConvertFrom-Json
    $lines = @($reported.Output | ForEach-Object { [string]$_ })
    $values = if ($Run.Script -eq 'Discover') { ConvertFrom-DiscoveryOutput -Lines $lines } else { ConvertFrom-DetectionOutput -Lines $lines }
    return [pscustomobject][ordered]@{
        Script             = $Run.Script
        Bitness            = $Run.Bitness
        HostPath           = $Run.HostPath
        Is64BitProcess     = [bool]$reported.Is64BitProcess
        PSVersion          = [string]$reported.PSVersion
        Context            = [string]$reported.Context
        DataFolder         = [string]$reported.DataFolder
        ExitCode           = [int]$reported.ExitCode
        Output             = $lines
        Errors             = @($reported.Errors | ForEach-Object { [string]$_ })
        Values             = $values
        TaskStartRequested = [bool]$reported.TaskStartRequested
    }
}

foreach ($name in $Script) {
    if (-not (Test-Path -LiteralPath $scriptFiles[$name] -PathType Leaf)) { throw "The Intune script was not found at $($scriptFiles[$name])." }
}
if (-not $WorkPath) { $WorkPath = [IO.Path]::GetTempPath() }
$locked = Test-Elevated
$work = Join-Path $WorkPath ('intune-readers-' + [guid]::NewGuid().ToString('n'))
New-DataFolder -Path $work -Locked $locked
try {
    $programData = $null
    if (-not $MachineDataFolder) {
        $bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $StatusPath).ProviderPath)
        $programData = Join-Path $work 'ProgramData'
        New-DataFolder -Path $programData -Locked $locked
        $dataFolder = Join-Path $programData 'EngramicBaseline'
        New-DataFolder -Path $dataFolder -Locked $locked
        New-DataFile -Path (Join-Path $dataFolder 'status.json') -Bytes $bytes -Locked $locked
    }
    $runs = New-Object System.Collections.ArrayList
    try {
        foreach ($name in $Script) {
            foreach ($of in $Bitness) { [void]$runs.Add((Start-Host -Name $name -Of $of -ProgramData $programData -Folder $work)) }
        }
        $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
        $results = @(foreach ($run in $runs) { Receive-Host -Run $run -Deadline $deadline })
    }
    finally {
        foreach ($run in $runs) {
            if (-not $run.Process.HasExited) { try { $run.Process.Kill() } catch { $null = $_ } }
            $run.Process.Dispose()
        }
    }
}
finally {
    Remove-WorkFolder -Path $work
}

if ($ResultPath) {
    [IO.File]::WriteAllText($ResultPath, (ConvertTo-Json -InputObject $results -Depth 5), (New-Object System.Text.UTF8Encoding($true)))
}
return $results
