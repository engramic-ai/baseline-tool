#Requires -Version 5.1
<#
.SYNOPSIS
    Runs a program as SYSTEM through a temporary scheduled task, and returns its exit code and output.

.DESCRIPTION
    For CI runners and other machines that are there to be changed. baseline.exe scheduled-audit runs only as
    SYSTEM, and Intune runs its scripts as SYSTEM, so the Contracts and Parity jobs need SYSTEM. As
    intune\Test-IntuneDeployment.ps1 does, this registers a one-off task for S-1-5-18 that runs the program,
    waits for it, and unregisters the task.

    The task runs a wrapper script from -WorkPath, and the program's output and exit code come back through
    files there. -WorkPath must be a folder that only SYSTEM and Administrators can change: it is made so, owned
    by Administrators in the call that creates it, if it does not exist, and refused if it exists and anyone
    else can change it. So nothing another account could change is run as SYSTEM or read back.

    The wait ends after -TimeoutSeconds: the task is stopped, the result says it timed out, and Task Scheduler
    ends the run itself a minute later in any case. While it waits, -WhileRunning is called over and over, for
    work that must happen during the run, and it sets its own pace; without it the wait checks every quarter
    second.

    It needs an elevated administrator, and it registers a scheduled task: run it only where that is meant.

.PARAMETER FilePath
    The program to run, by its full path.

.PARAMETER ArgumentList
    Its arguments, one each; PowerShell quotes them for the program.

.PARAMETER WorkPath
    The folder for the wrapper and its output files, which only SYSTEM and Administrators may change.

.PARAMETER TimeoutSeconds
    How long to wait. Default: 600.

.PARAMETER WhileRunning
    Called over and over while the program runs.

.OUTPUTS
    ExitCode, Output (lines), Errors (lines) and TimedOut.

.EXAMPLE
    $run = .\tools\ci\Invoke-AsSystem.ps1 -FilePath 'C:\Program Files\EngramicBaselineCI\baseline.exe' -ArgumentList 'scheduled-audit' -WorkPath C:\ci-system
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [string[]]$ArgumentList = @(),
    [Parameter(Mandatory = $true)][string]$WorkPath,
    [ValidateRange(10, 7200)][int]$TimeoutSeconds = 600,
    [scriptblock]$WhileRunning
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this as an elevated administrator: registering a task that runs as SYSTEM needs one.'
}
if (-not [IO.Path]::IsPathRooted($FilePath)) { throw "Give the program by its full path, not $FilePath." }

function Get-WorkFolderProblem {
    <# Why SYSTEM must not use this folder, or '' when only SYSTEM, Administrators and TrustedInstaller can change it and it is not a link. #>
    param([string]$Path)
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    # Rights that let someone change, delete or re-permission it, including GENERIC_WRITE and GENERIC_ALL.
    $writeRights = 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288 -bor 0x40000000 -bor 0x10000000
    if ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) { return "$Path is a link" }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($trusted -notcontains $owner) { return "$Path is owned by $owner" }
    foreach ($rule in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        $sid = "$($rule.IdentityReference)"
        if ("$($rule.AccessControlType)" -ne 'Allow' -or $trusted -contains $sid -or $sid -eq 'S-1-3-0') { continue }
        $rights = [long]0
        try { $rights = [long]$rule.FileSystemRights } catch { $rights = [long]::MaxValue }
        if ($rights -band $writeRights) { return "$Path can be changed by $sid" }
    }
    return ''
}

function ConvertTo-Literal {
    <# A PowerShell single-quoted string literal. #>
    param([string]$Text)
    return "'" + $Text.Replace("'", "''") + "'"
}

if (-not (Test-Path -LiteralPath $WorkPath)) {
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    if ($PSVersionTable.PSVersion.Major -ge 6) { [void][IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($WorkPath), $security) }
    else { [void][IO.Directory]::CreateDirectory($WorkPath, $security) }
}
$problem = Get-WorkFolderProblem -Path $WorkPath
if ($problem) { throw "$problem, so it is not used for a run as SYSTEM. Give a folder only SYSTEM and Administrators can change." }

$id = [guid]::NewGuid().ToString('n')
$wrapper = Join-Path $WorkPath "$id.ps1"
$outFile = Join-Path $WorkPath "$id.out"
$errFile = Join-Path $WorkPath "$id.err"
$codeFile = Join-Path $WorkPath "$id.code"
$arguments = '@(' + (($ArgumentList | ForEach-Object { ConvertTo-Literal $_ }) -join ', ') + ')'
# The wrapper records output and errors line by line, then the exit code, last and by a rename, so the code
# file appearing means the run is over and everything else is written.
$wrapperText = @"
`$ErrorActionPreference = 'Continue'
`$ProgressPreference = 'SilentlyContinue'
`$out = New-Object System.Collections.ArrayList
`$err = New-Object System.Collections.ArrayList
`$code = 255
try {
    `$ceArguments = $arguments
    `$global:LASTEXITCODE = 0
    & $(ConvertTo-Literal $FilePath) @ceArguments 2>&1 | ForEach-Object {
        if (`$_ -is [System.Management.Automation.ErrorRecord]) { [void]`$err.Add([string]`$_) } else { [void]`$out.Add([string]`$_) }
    }
    `$code = `$LASTEXITCODE
}
catch { [void]`$err.Add(`$_.Exception.Message) }
`$utf8 = New-Object System.Text.UTF8Encoding(`$false)
[IO.File]::WriteAllLines($(ConvertTo-Literal $outFile), [string[]]`$out.ToArray(), `$utf8)
[IO.File]::WriteAllLines($(ConvertTo-Literal $errFile), [string[]]`$err.ToArray(), `$utf8)
[IO.File]::WriteAllText($(ConvertTo-Literal "$codeFile.tmp"), [string]`$code)
[IO.File]::Move($(ConvertTo-Literal "$codeFile.tmp"), $(ConvertTo-Literal $codeFile))
"@
# With a byte order mark, so Windows PowerShell 5.1 reads any path in it beyond ASCII as written.
[IO.File]::WriteAllText($wrapper, $wrapperText, (New-Object System.Text.UTF8Encoding($true)))

$taskName = "EngramicBaselineCI-$id"
$shell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
$action = New-ScheduledTaskAction -Execute $shell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$wrapper`""
$system = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds ($TimeoutSeconds + 60))
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $system -Settings $settings -Force | Out-Null
$timedOut = $false
$ended = ''
try {
    Start-ScheduledTask -TaskName $taskName
    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
    $nextLook = [datetime]::UtcNow.AddSeconds(5)
    while (-not (Test-Path -LiteralPath $codeFile)) {
        if ([datetime]::UtcNow -gt $deadline) {
            $timedOut = $true
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            break
        }
        # A task that is no longer running but left no exit code failed to start the wrapper, or it died:
        # say so now rather than at the time limit.
        if ([datetime]::UtcNow -gt $nextLook) {
            $nextLook = [datetime]::UtcNow.AddSeconds(5)
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task -and "$($task.State)" -eq 'Ready') {
                Start-Sleep -Milliseconds 500
                if (-not (Test-Path -LiteralPath $codeFile)) {
                    $ended = 'The task ended with result 0x{0:X8} before its wrapper wrote an exit code.' -f [long](Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
                    break
                }
            }
        }
        if ($WhileRunning) { & $WhileRunning } else { Start-Sleep -Milliseconds 250 }
    }
    $read = {
        param([string]$Path)
        if (Test-Path -LiteralPath $Path) { return @([IO.File]::ReadAllLines($Path)) }
        return @()
    }
    $finished = -not $timedOut -and -not $ended
    [pscustomobject][ordered]@{
        ExitCode = if ($finished) { [int]([IO.File]::ReadAllText($codeFile).Trim()) } else { -1 }
        Output   = @(& $read $outFile)
        Errors   = if ($timedOut) { @("Timed out after $TimeoutSeconds seconds running $FilePath as SYSTEM.") } elseif ($ended) { @($ended) } else { @(& $read $errFile) }
        TimedOut = $timedOut
    }
}
finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $wrapper, $outFile, $errFile, $codeFile, "$codeFile.tmp" -Force -ErrorAction SilentlyContinue
}
