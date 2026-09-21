@{
    RootModule        = 'CEAudit.psm1'
    ModuleVersion     = '0.2.0'
    GUID              = '5d1f6f0e-1c3b-4b7e-9a51-3f7a2c1e8b44'
    Author            = 'Engramic'
    CompanyName       = 'Engramic'
    Copyright         = '(c) 2026 Engramic Ltd'
    Description       = 'Engramic Baseline. Audits a Windows 11 device against Cyber Essentials v3.3 (Danzell) / Cyber Essentials Plus test cases and NCSC device guidance, and produces a reviewable changeset of remediations.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-CEAuditCore', 'Get-CECheck', 'Get-CECategory', 'Get-CEPack', 'Get-CEDeviceContext', 'Get-CEConfig',
        'New-CEChangeset', 'Export-CEReport', 'Invoke-CERemediation', 'Get-CERemediation',
        'Restore-CEUndoLog', 'Test-CEIsAdmin', 'Invoke-CEChangeset', 'Get-CEUndoLogs', 'Get-CESummary',
        'Get-CEStatusCheckMap', 'Get-CEFrameworkRollup', 'Get-CEAiPosture',
        'ConvertTo-CEStatus', 'Write-CEStatus', 'Write-CEEventLog', 'Get-CEDataRoot', 'Get-CEToolVersion', 'Test-CEComplianceRules'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('CyberEssentials', 'NCSC', 'Compliance', 'Security', 'Windows')
            ProjectUri = 'https://github.com/engramic-ai/baseline-tool'
            LicenseUri = 'https://github.com/engramic-ai/baseline-tool/blob/main/LICENSE'
        }
    }
}
