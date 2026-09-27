#Requires -Version 5.1
<#
    CEAudit module loader.

    Load order matters:
      1. Private helpers (finding model, registry helpers, device context)
      2. Check registry + all check definitions (Checks\*.ps1)
      3. Remediation library (Remediations\*.ps1)
      4. Reporting and changeset generation

    Import-Module ... -ArgumentList <data folder>, <pack folders> moves the data
    folder (default %ProgramData%\EngramicBaseline) and adds pack folders. Tests
    and the scheduled audit's -DataRoot use this. Unlike the CE_CHECKER_DATA and
    CE_CHECKER_PACKS environment variables it can't be inherited from a user's
    session, so it still works when the audit is elevated (see Get-CEEnvironmentHook).
#>
param(
    [string]$DataRootOverride,
    [string[]]$PackPathOverride
)

Set-StrictMode -Version 2.0

$script:ModuleRoot = $PSScriptRoot
$script:RepoRoot   = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:CEChecks        = New-Object System.Collections.ArrayList
$script:CERemediations  = @{}
$script:CEDeviceContext = $null
$script:CEConfig        = $null
$script:CEVirtualisationCache = $null
$script:CEAIToolCache   = $null
$script:CECurrentPack   = $null
$script:CEPacks         = @()
$script:CEPackConfigPaths = New-Object System.Collections.ArrayList
$script:CEDataRootOverride = $DataRootOverride
$script:CEPackPathOverride = @($PackPathOverride | Where-Object { $_ })
$script:CEIgnoredEnvHooks = @{}

$loadOrder = @('Private', 'Checks', 'Remediations', 'Public')
foreach ($folder in $loadOrder) {
    $path = Join-Path $PSScriptRoot $folder
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem -Path $path -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
        . $_.FullName
    }
}

# Feature packs (see Private\09-Packs.ps1). Loaded here, at module scope, so that
# functions a pack defines stay available to its checks. Variable names are
# prefixed so a pack script can't overwrite them by accident.
$script:CECoreFunctionNames = @(Get-ChildItem -Path function: | Where-Object { $_.ScriptBlock.File -and $_.ScriptBlock.File.StartsWith($PSScriptRoot) } | ForEach-Object { $_.Name })
$script:CEPacks = Get-CEPackCandidate
foreach ($__cePack in @($script:CEPacks | Where-Object { $_.Status -eq 'Ready' })) {
    $__ceSnapshot = $null
    try {
        $__ceSnapshot = Start-CEPackLoad -Pack $__cePack
        foreach ($__ceFile in $__cePack.Files) { . $__ceFile }
        Complete-CEPackLoad -Pack $__cePack -Snapshot $__ceSnapshot
    }
    catch {
        if ($__ceSnapshot) { Undo-CEPackLoad -Pack $__cePack -Snapshot $__ceSnapshot -Reason $_.Exception.Message }
        else { $__cePack.Status = 'Skipped'; $__cePack.Reason = "Failed to load: $($_.Exception.Message)"; $script:CECurrentPack = $null }
    }
}
Remove-Variable -Name __cePack, __ceSnapshot, __ceFile -ErrorAction SilentlyContinue

Export-ModuleMember -Function @(
    'Invoke-CEAuditCore',
    'Get-CECheck',
    'Get-CECategory',
    'Get-CEPack',
    'Get-CEDeviceContext',
    'Get-CEConfig',
    'New-CEChangeset',
    'Export-CEReport',
    'Invoke-CERemediation',
    'Get-CERemediation',
    'Restore-CEUndoLog',
    'Test-CEIsAdmin',
    'Invoke-CEChangeset',
    'Get-CEUndoLogs',
    'Get-CESummary',
    'Get-CEStatusCheckMap',
    'Get-CEFrameworkRollup',
    'Get-CEAiPosture',
    'Get-CEStatusStyle',
    'Get-CESeverityStyle',
    'Get-CEBucketStyle',
    'ConvertTo-CEStatus',
    'Write-CEStatus',
    'Write-CEEventLog',
    'Get-CEDataRoot',
    'Get-CEToolVersion',
    'Test-CEComplianceRules'
)
