# ---------------------------------------------------------------------------
# Device context: edition, build, join state, management, who is logged on.
# Checks use this to decide applicability and to warn when a setting is
# likely to be overwritten by Group Policy or Intune.
# ---------------------------------------------------------------------------

function Get-CEDsregStatus {
    [CmdletBinding()]
    param()
    $result = @{}
    try {
        $native = Invoke-CENative -FilePath 'dsregcmd.exe' -ArgumentList @('/status')
        foreach ($line in $native.Output) {
            if ($line -match '^\s*([A-Za-z0-9]+)\s*:\s*(.+?)\s*$') {
                if (-not $result.ContainsKey($Matches[1])) { $result[$Matches[1]] = $Matches[2] }
            }
        }
    }
    catch {
        Write-Verbose "dsregcmd unavailable: $_"
    }
    return $result
}

function Test-CEMdmEnrolled {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try {
        $keys = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction Stop
        foreach ($k in $keys) {
            $provider = Get-CERegistryValue -Path $k.PSPath -Name 'ProviderID'
            if ($provider -eq 'MS DM Server') { return $true }
        }
    }
    catch {
        Write-Verbose "Unable to read MDM enrolments: $_"
    }
    return $false
}

function Get-CEConsoleUser {
    [CmdletBinding()]
    param()
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        return [string]$cs.UserName
    }
    catch {
        return ''
    }
}

function Get-CEConsoleUserSid {
    param([string]$ConsoleUser)
    if (-not $ConsoleUser) { return $null }
    try {
        return (New-Object Security.Principal.NTAccount($ConsoleUser)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        # Entra ID accounts don't always translate; fall back to the owner of explorer.exe.
        try {
            $explorer = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | Select-Object -First 1
            if ($explorer) { return (Invoke-CimMethod -InputObject $explorer -MethodName GetOwnerSid -ErrorAction Stop).Sid }
        }
        catch {
            Write-Verbose "Could not resolve SID for $ConsoleUser"
        }
    }
    return $null
}

function Get-CEDeviceContext {
    [CmdletBinding()]
    param([switch]$Force)

    if ($script:CEDeviceContext -and -not $Force) { return $script:CEDeviceContext }

    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build   = [int](Get-CERegistryValue -Path $cv -Name 'CurrentBuildNumber' -Default 0)
    $ubr     = [int](Get-CERegistryValue -Path $cv -Name 'UBR' -Default 0)
    $display = [string](Get-CERegistryValue -Path $cv -Name 'DisplayVersion' -Default '')
    $edition = [string](Get-CERegistryValue -Path $cv -Name 'EditionID' -Default '')
    $product = [string](Get-CERegistryValue -Path $cv -Name 'ProductName' -Default '')

    # ProductName still says "Windows 10" on Windows 11; build number is authoritative.
    # Windows Server shares build numbers with client releases (Server 2025 and
    # Windows 11 24H2 are both 26100), so check the installation type first.
    $installType = [string](Get-CERegistryValue -Path $cv -Name 'InstallationType' -Default 'Client')
    $osFamily = if ($installType -match 'Server') { 'Windows Server' }
                elseif ($build -ge 22000) { 'Windows 11' }
                elseif ($build -ge 10240) { 'Windows 10' }
                else { 'Unknown' }

    $domainJoined = $false
    $computerName = $env:COMPUTERNAME
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $domainJoined = [bool]$cs.PartOfDomain
    }
    catch {
        Write-Verbose "Win32_ComputerSystem unavailable: $_"
    }

    $dsreg = Get-CEDsregStatus
    $entraJoined = ($dsreg['AzureAdJoined'] -eq 'YES')
    $helloProvisioned = ($dsreg['NgcSet'] -eq 'YES')

    $identity = $null
    $isSystem = $false
    if (Test-CEIsWindows) {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent()
        $identity = $current.Name
        $isSystem = [bool]$current.IsSystem
    }

    $isAdmin = Test-CEIsAdmin
    $consoleUser = Get-CEConsoleUser

    $editionClass = if ($osFamily -eq 'Windows Server') { 'Server' } else { switch -Regex ($edition) {
        '^Enterprise|^Education|^IoTEnterprise' { 'Enterprise'; break }
        '^Professional|^ProfessionalWorkstation|^ProfessionalEducation' { 'Pro'; break }
        '^Core' { 'Home'; break }
        default { 'Unknown' }
    } }

    $ctx = [pscustomobject]@{
        ComputerName      = $computerName
        OSFamily          = $osFamily
        InstallationType  = $installType
        ProductName       = $product
        EditionID         = $edition
        EditionClass      = $editionClass
        DisplayVersion    = $display
        Build             = $build
        UBR               = $ubr
        FullBuild         = "$build.$ubr"
        DomainJoined      = $domainJoined
        EntraJoined       = $entraJoined
        MdmEnrolled       = (Test-CEMdmEnrolled)
        HelloProvisioned  = $helloProvisioned
        RunningAs         = $identity
        ConsoleUser       = $consoleUser
        IsElevated        = ($isAdmin -or $isSystem)
        IsSystem          = $isSystem
        ConsoleUserSid    = $(if ($isSystem) { Get-CEConsoleUserSid $consoleUser } else { $null })
        PSVersion         = $PSVersionTable.PSVersion.ToString()
        AuditTime         = (Get-Date)
        Hardware          = (Get-CEHardwareInventory -IsElevated ($isAdmin -or $isSystem))
    }
    $managed = ($ctx.DomainJoined -or $ctx.EntraJoined -or $ctx.MdmEnrolled)
    $ctx | Add-Member -NotePropertyName 'CentrallyManaged' -NotePropertyValue $managed

    $script:CEDeviceContext = $ctx
    return $ctx
}
