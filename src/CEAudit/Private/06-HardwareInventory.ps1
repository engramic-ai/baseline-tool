# ---------------------------------------------------------------------------
# Hardware and firmware inventory: model, serial, BIOS/UEFI, TPM, CPU, disks.
# Collected once with the device context and shown in reports and status.json.
# Every read is best effort; what could not be read is listed in Errors.
# ---------------------------------------------------------------------------

function Get-CEObjectValue {
    <# Reads a property that may not exist (strict mode throws on a missing property). #>
    param($InputObject, [Parameter(Mandatory)][string]$Name, $Default = $null)
    if ($null -eq $InputObject) { return $Default }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $prop -or $null -eq $prop.Value) { return $Default }
    return $prop.Value
}

function ConvertTo-CEVersionPart {
    <# '7.63.3353.0' -> 7,63,3353,0. Returns an empty array for anything that is not dotted numbers. #>
    param([AllowNull()][AllowEmptyString()][string]$Version)
    if (-not $Version -or $Version.Trim() -notmatch '^\d+(\.\d+)*$') { return ,@() }
    return ,@($Version.Trim().Split('.') | ForEach-Object { [long]$_ })
}

function Compare-CEVersionPrefix {
    <# Compares a version with a bound on the bound's own length, so '4.33.4' equals the bound '4.33'. #>
    param([long[]]$Parts, [string]$Bound)
    # No @() around these calls: the function already returns an array (,@()), and @() would nest it.
    $b = ConvertTo-CEVersionPart $Bound
    for ($i = 0; $i -lt $b.Count; $i++) {
        $x = if ($i -lt $Parts.Count) { $Parts[$i] } else { 0 }
        if ($x -lt $b[$i]) { return -1 }
        if ($x -gt $b[$i]) { return 1 }
    }
    return 0
}

function Test-CEVersionInRange {
    <# True when Version is between From and To inclusive, compared on the bounds' precision. #>
    param([AllowNull()][AllowEmptyString()][string]$Version, [Parameter(Mandatory)][string]$From, [Parameter(Mandatory)][string]$To)
    $v = ConvertTo-CEVersionPart $Version
    if ($v.Count -eq 0 -or (ConvertTo-CEVersionPart $From).Count -eq 0 -or (ConvertTo-CEVersionPart $To).Count -eq 0) { return $false }
    return ((Compare-CEVersionPrefix $v $From) -ge 0 -and (Compare-CEVersionPrefix $v $To) -le 0)
}

function ConvertTo-CEDateString {
    <# CIM dates arrive as DateTime, or as DMTF strings (20230115000000.000000+000) from some providers. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd') }
    if ([string]$Value -match '^(\d{4})(\d{2})(\d{2})') { return "$($Matches[1])-$($Matches[2])-$($Matches[3])" }
    return $null
}

function Get-CEHardwareInventory {
    [CmdletBinding()]
    param([bool]$IsElevated = $true)

    $errors = New-Object System.Collections.ArrayList
    $cim = {
        param([string]$Class, [string]$Namespace = 'root/cimv2')
        try { return @(Get-CimInstance -Namespace $Namespace -ClassName $Class -ErrorAction Stop) }
        catch {
            [void]$errors.Add("${Class}: $($_.Exception.Message)")
            return ,@()
        }
    }
    $text = { param($obj, $name) ([string](Get-CEObjectValue $obj $name '')).Trim() }

    $cs = @(& $cim 'Win32_ComputerSystem') | Select-Object -First 1
    $bios = @(& $cim 'Win32_BIOS') | Select-Object -First 1
    $board = @(& $cim 'Win32_BaseBoard') | Select-Object -First 1

    $manufacturer = & $text $cs 'Manufacturer'
    $model = & $text $cs 'Model'
    $isVm = ("$manufacturer $model" -match 'Virtual Machine|VMware|VirtualBox|KVM|QEMU|Xen|Parallels|Google Compute Engine|Amazon EC2|OpenStack')

    $peType = Get-CERegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'PEFirmwareType'
    $fwType = switch ("$peType") {
        '2' { 'UEFI' }
        '1' { 'Legacy BIOS' }
        default { if ($env:firmware_type) { [string]$env:firmware_type } else { 'Unknown' } }
    }

    $tpm = [pscustomobject]@{ Readable = $false; Present = $null; Manufacturer = ''; FirmwareVersion = ''; SpecVersion = '' }
    if ($IsElevated) {
        $before = $errors.Count
        $t = @(& $cim 'Win32_Tpm' 'root/cimv2/Security/MicrosoftTpm') | Select-Object -First 1
        if ($errors.Count -eq $before) {
            $tpm.Readable = $true
            $tpm.Present = ($null -ne $t)
            if ($t) {
                $maker = & $text $t 'ManufacturerIdTxt'
                $id = Get-CEObjectValue $t 'ManufacturerId'
                if (-not $maker -and $null -ne $id) {
                    # ManufacturerId is the TCG vendor id as big-endian ASCII, e.g. 0x49465800 = 'IFX'.
                    try {
                        $bytes = [BitConverter]::GetBytes([uint32]$id)
                        [array]::Reverse($bytes)
                        $maker = [Text.Encoding]::ASCII.GetString($bytes).Trim([char]0, ' ')
                    }
                    catch { $maker = '' }
                }
                $tpm.Manufacturer = $maker
                $tpm.FirmwareVersion = & $text $t 'ManufacturerVersion'
                $tpm.SpecVersion = ((& $text $t 'SpecVersion') -split ',')[0].Trim()
            }
        }
    }

    $microcode = ''
    $rev = Get-CERegistryValue -Path 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -Name 'Update Revision'
    # REG_BINARY comes back through the pipeline as separate numbers, so rebuild the byte array.
    # Newer systems store 4 bytes (the revision); older Intel systems store 8 with it in the upper half.
    try {
        $revBytes = [byte[]]@($rev | Where-Object { $null -ne $_ })
        if ($revBytes.Length -ge 8) { $microcode = '0x{0:X}' -f [BitConverter]::ToUInt32($revBytes, 4) }
        elseif ($revBytes.Length -eq 4) { $microcode = '0x{0:X}' -f [BitConverter]::ToUInt32($revBytes, 0) }
    }
    catch { $microcode = '' }

    $cpus = @(& $cim 'Win32_Processor' | ForEach-Object {
        [pscustomobject]@{
            Name              = & $text $_ 'Name'
            Manufacturer      = & $text $_ 'Manufacturer'
            Cores             = Get-CEObjectValue $_ 'NumberOfCores'
            LogicalProcessors = Get-CEObjectValue $_ 'NumberOfLogicalProcessors'
            MicrocodeRevision = $microcode
        }
    } | Where-Object { $_.Name })

    $disks = @(& $cim 'Win32_DiskDrive' | ForEach-Object {
        $size = Get-CEObjectValue $_ 'Size'
        [pscustomobject]@{
            Model            = & $text $_ 'Model'
            FirmwareRevision = & $text $_ 'FirmwareRevision'
            InterfaceType    = & $text $_ 'InterfaceType'
            SizeGB           = $(if ($null -ne $size) { [math]::Round([double]$size / 1GB) } else { $null })
            SerialNumber     = & $text $_ 'SerialNumber'
        }
    } | Where-Object { $_.Model })

    return [pscustomobject]@{
        Manufacturer     = $manufacturer
        Model            = $model
        SystemSku        = & $text $cs 'SystemSKUNumber'
        SerialNumber     = & $text $bios 'SerialNumber'
        Baseboard        = ("$(& $text $board 'Manufacturer') $(& $text $board 'Product')").Trim()
        BaseboardProduct = & $text $board 'Product'
        IsVirtualMachine = $isVm
        Firmware         = [pscustomobject]@{
            Vendor      = & $text $bios 'Manufacturer'
            Version     = & $text $bios 'SMBIOSBIOSVersion'
            ReleaseDate = ConvertTo-CEDateString (Get-CEObjectValue $bios 'ReleaseDate')
            Type        = $fwType
        }
        Tpm              = $tpm
        Cpu              = $cpus
        Disks            = $disks
        Errors           = @($errors)
    }
}
