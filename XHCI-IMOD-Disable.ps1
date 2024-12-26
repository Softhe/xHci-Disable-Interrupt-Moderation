<# Created by Softhe... bla bla HOW TO USE ect
#>

# Start as administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

$ToolsKX = "$(Split-Path -Path $PSScriptRoot -Parent)C:\_\Programs\_exe\KX.exe"
$LocalKX = "$PSScriptRoot\KX.exe"

function KX-Exists {
    $ToolsKXExists = Test-Path -Path $ToolsKX -PathType Leaf
    $LocalKXExists = Test-Path -Path $LocalKX -PathType Leaf
    return @{LocalKXExists = $LocalKXExists; ToolsKXExists = $ToolsKXExists}
}

function Download-KX {
    $KXExists = KX-Exists
    if ($KXExists.ToolsKXExists -or $KXExists.LocalKXExists) {
        return
    }
    $downloadUrl = "https://github.com/Softhe/xHci-Disable-Interrupt-Moderation/raw/refs/heads/main/KX.exe"
    Write-Host "KX Utility not found, started downloading - $downloadUrl"
    [Environment]::NewLine
    Invoke-WebRequest -URI $downloadUrl -OutFile $LocalKX -UseBasicParsing
}

function Get-KX {
    $KXExists = KX-Exists
    if ($KXExists.ToolsKXExists) { return $ToolsKX } else { return $LocalKX }
}

function Check-For-Tool-Viability {
    $Value = & "$(Get-KX)" /RdMem32 "0x0"
    if ($Value -match 'Kernel Driver can not be loaded') {
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\CI\Config\" -Name VulnerableDriverBlocklistEnable -PropertyType Dword -Value 0 -Force | Out-Null
        [Environment]::NewLine
        Write-Host "Kernel Driver can not be loaded. A certificate was explicitly revoked by its issuer."
        Write-Host "In some cases, you might need to disable Microsoft Vulnerable Driver Blocklist for the tool to work."
        Write-Host "It will be done automatically, but it can also be done through the UI, in the Core Isolation section. If doesnt work immediatelly, it may require a restart."
        Write-Host "If you are getting this message, means you need to do this, otherwise you cannot run any type of tool that does this kind of change, therefore doing this would not be possible, if you undo this change, the next reboot, it would stop working again. Enable or Disable at your own risk."
        [Environment]::NewLine
        cmd /c pause
        exit 0
    }
}

function Get-Config {
    $configFilePath = Join-Path -Path $PSScriptRoot -ChildPath "usb_controller_config.txt"
    if (Test-Path -Path $configFilePath) {
        return Get-Content -Path $configFilePath | Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*$' }
    } else {
        return $null
    }
}

function Get-All-USB-Controllers {
    [PsObject[]]$USBControllers= @()

    $allUSBControllers = Get-CimInstance -ClassName Win32_USBController | Select-Object -Property Name, DeviceID
    foreach ($usbController in $allUSBControllers) {
        $allocatedResource = Get-CimInstance -ClassName Win32_PNPAllocatedResource | Where-Object { $_.Dependent.DeviceID -like "*$($usbController.DeviceID)*" } | Select @{N="StartingAddress";E={$_.Antecedent.StartingAddress}}
        $deviceMemory = Get-CimInstance -ClassName Win32_DeviceMemoryAddress | Where-Object { $_.StartingAddress -eq "$($allocatedResource.StartingAddress)" }

        $deviceProperties = Get-PnpDeviceProperty -InstanceId $usbController.DeviceID
        $locationInfo = $deviceProperties | Where KeyName -eq 'DEVPKEY_Device_LocationInfo' | Select -ExpandProperty Data
        $PDOName = $deviceProperties | Where KeyName -eq 'DEVPKEY_Device_PDOName' | Select -ExpandProperty Data

        $moreControllerData = Get-CimInstance -ClassName Win32_PnPEntity | Where-Object { $_.DeviceID -eq "$($usbController.DeviceID)" } | Select-Object Service
        $Type = Get-Type-From-Service -value $moreControllerData.Service

        if ([string]::IsNullOrWhiteSpace($deviceMemory.Name)) {
            continue
        }

        $USBControllers += [PsObject]@{
            Name = $usbController.Name
            DeviceId = $usbController.DeviceID
            MemoryRange = $deviceMemory.Name
            LocationInfo = $locationInfo
            PDOName = $PDOName
            Type = $Type
        }
    }
    return $USBControllers
}

function Get-Type-From-Service {
    param ([string] $value)
    if ($value -ieq 'USBXHCI') {
        return 'XHCI'
    }
    if ($value -ieq 'USBEHCI') {
        return 'EHCI'
    }
    return 'Unknown'
}

function Convert-Decimal-To-Hex {
    param ([int64] $value)
    if ([string]::IsNullOrWhiteSpace($value)) { $value = "0" }
    return '0x' + [System.Convert]::ToString($value, 16).ToUpper()
}

function Convert-Hex-To-Decimal {
    param ([string] $value)
    if ([string]::IsNullOrWhiteSpace($value)) { $value = "0x0" }
    return [convert]::ToInt64($value, 16)
}

function Convert-Hex-To-Binary {
    param ([string] $value)
    $ConvertedValue = [Convert]::ToString($value, 2)
    return $ConvertedValue.PadLeft(32, '0')
}

function Convert-Binary-To-Hex {
    param ([string] $value)
    $convertedValue = [Convert]::ToInt64($value, 2)
    return Convert-Decimal-To-Hex -value $convertedValue
}

function Get-Hex-Value-From-Tool-Result {
    param ([string] $value)
    return $value.Split(" ")[19].Trim()
}

function Get-R32-Hex-From-Address {
    param ([string] $address)
    $Value = & "$(Get-KX)" /RdMem32 $address
    while ([string]::IsNullOrWhiteSpace($Value)) { Start-Sleep -Seconds 1 }
    return Get-Hex-Value-From-Tool-Result -value $Value
}

function Get-Left-Side-From-MemoryRange {
    param ([string] $memoryRange)
    return $memoryRange.Split("-")[0]
}

function Get-BitRange-From-Binary {
    param ([string] $binaryValue, [int] $from, [int] $to)
    $backwardsFrom = $to
    $backwardsTo = $from
    return $binaryValue.SubString($binaryValue.Length - $backwardsFrom, $backwardsFrom - $backwardsTo)
}

function Find-First-Interrupter-Data {
    param ([string] $memoryRange)
    $LeftSideMemoryRange = Get-Left-Side-From-MemoryRange -memoryRange $memoryRange
    $CapabilityBaseAddressInDecimal = Convert-Hex-To-Decimal -value $LeftSideMemoryRange
    $RuntimeRegisterSpaceOffsetInDecimal = Convert-Hex-To-Decimal -value "0x18"
    $SumCapabilityPlusRuntime = Convert-Decimal-To-Hex -value ($CapabilityBaseAddressInDecimal + $RuntimeRegisterSpaceOffsetInDecimal)
    $Value = Get-R32-Hex-From-Address -address $SumCapabilityPlusRuntime
    $ValueInDecimal = Convert-Hex-To-Decimal -value $Value
    $TwentyFourInDecimal = Convert-Hex-To-Decimal -value "0x24"
    $Interrupter0PreAddressInDecimal = $CapabilityBaseAddressInDecimal + $ValueInDecimal + $TwentyFourInDecimal

    $FourInDecimal = Convert-Hex-To-Decimal -value "0x4"
    $HCSPARAMS1InHex = Convert-Decimal-To-Hex -value ($CapabilityBaseAddressInDecimal + $FourInDecimal)

    return @{ Interrupter0PreAddressInDecimal = $Interrupter0PreAddressInDecimal; HCSPARAMS1 = $HCSPARAMS1InHex }
}

function Build-Interrupt-Threshold-Control-Data {
    param ([string] $memoryRange)
    $LeftSideMemoryRange = Get-Left-Side-From-MemoryRange -memoryRange $memoryRange
    $LeftSideMemoryRangeInDecimal = Convert-Hex-To-Decimal -value $LeftSideMemoryRange
    $TwentyInDecimal = Convert-Hex-To-Decimal -value "0x20"
    $MemoryBase = Convert-Decimal-To-Hex -value ($LeftSideMemoryRangeInDecimal + $TwentyInDecimal)
    $MemoryBaseValue = Get-R32-Hex-From-Address -address $MemoryBase
    $ValueInBinary = Convert-Hex-To-Binary -value $MemoryBaseValue
    $ReplaceValue = '00000000'
    $BackwardsFrom = 16
    $BackwardsTo = 23
    $ValueInBinaryLeftSide = $ValueInBinary.Substring(0, $ValueInBinary.Length - $BackwardsTo)
    $ValueInBinaryRightSide = $ValueInBinary.Substring($ValueInBinary.Length - $BackwardsTo + $ReplaceValue.Length, ($ValueInBinary.Length - 1) - $BackwardsFrom)
    $ValueAddress = Convert-Binary-To-Hex -value ($ValueInBinaryLeftSide + $ReplaceValue + $ValueInBinaryRightSide)
    return [PsObject]@{ValueAddress = $ValueAddress; InterruptAddress = $MemoryBase}
}

function Find-Interrupters-Amount {
    param ([string] $hcsParams1)
    $Value = Get-R32-Hex-From-Address -address $hcsParams1
    $ValueInBinary = Convert-Hex-To-Binary -value $Value
    $MaxIntrsInBinary = Get-BitRange-From-Binary -binaryValue $ValueInBinary -from 8 -to 18
    $InterruptersAmount = Convert-Hex-To-Decimal -value (Convert-Binary-To-Hex -value $MaxIntrsInBinary)
    return $InterruptersAmount
}

function Disable-IMOD {
    param ([string] $address, [string] $value)
    $ValueData = "0x00000000"
    if (![string]::IsNullOrWhiteSpace($value)) { $ValueData = $value }
    $Value = & "$(Get-KX)" /WrMem32 $address $ValueData
    while ([string]::IsNullOrWhiteSpace($Value)) { Start-Sleep -Seconds 1 }
    return $Value
}

function Get-All-Interrupters {
    param ([int64] $preAddressInDecimal, [int32] $interruptersAmount)
    [PsObject[]]$Data = @()
    if ($interruptersAmount -lt 1 -or $interruptersAmount -gt 1024) {
        Write-Host "Device interrupters amount is different than specified MIN (1) and MAX (1024) - FOUND $interruptersAmount - No address from this device will be IMOD disabled"
        return $Data
    }
    for ($i=0; $i -lt $interruptersAmount; $i++) {
        $AddressInDecimal = $preAddressInDecimal + (32 * $i)
        $InterrupterAddress = Convert-Decimal-To-Hex -value $AddressInDecimal
        $Address = Get-R32-Hex-From-Address -address $InterrupterAddress
        $Data += [PsObject]@{ValueAddress = $Address; InterrupterAddress = $InterrupterAddress; Interrupter = $i}
    }
    return $Data
}

function Execute-IMOD-Process {
    Write-Host "Started disabling Interrupt Moderation (XHCI) or Interrupt Threshold Control (EHCI) in USB controllers"
    [Environment]::NewLine

    # Get all USB controllers
    $USBControllers = Get-All-USB-Controllers

    if ($USBControllers.Length -eq 0) {
        Write-Host "Script didn't find any valid USB controllers to disable. Please check your system."
        return $false
    } else {
        Write-Host "Available USB Controllers:"
        $USBControllers | ForEach-Object { Write-Host "$($_.Name) - Type: $($_.Type) - Device ID: $($_.DeviceId)" }
        Write-Host ""
    }

    # Check for configuration file
    $configuredDeviceIds = Get-Config
    $controllerSelection = $null

    if ($configuredDeviceIds) {
        Write-Host "Using configuration file for controller selection."
        $controllerSelection = $configuredDeviceIds -join ','
        return $true  # Return true if config file is used
    } else {
        Write-Host "No configuration file found. Falling back to user selection."
        $controllerSelection = Read-Host "Enter the Device IDs of the USB controllers you want to disable Interrupt Moderation for (separate by commas), or press Enter to disable all"
        return $false  # False if manual selection is used
    }

    # If user selects specific controllers or from config
    if (![string]::IsNullOrWhiteSpace($controllerSelection)) {
        # Split the input into an array
        $selectedDeviceIds = $controllerSelection.Split(',') | ForEach-Object { $_.Trim() }

        # Validate the selected Device IDs
        $validSelections = @()
        $invalidSelections = @()

        foreach ($deviceId in $selectedDeviceIds) {
            $matchingControllers = $USBControllers | Where-Object { $_.DeviceId -eq $deviceId }

            if ($matchingControllers.Count -gt 0) {
                $validSelections += $matchingControllers
            } else {
                $invalidSelections += $deviceId
            }
        }

        # Show validation results
        if ($invalidSelections.Count -gt 0) {
            Write-Host "Invalid Device IDs: $($invalidSelections -join ', ')"
            Write-Host "Please check the device IDs and try again."
            return
        }

        # If no valid selection, exit
        if ($validSelections.Count -eq 0) {
            Write-Host "No valid controllers selected. Exiting..."
            return
        }

        # Use valid selections for further processing
        $USBControllers = $validSelections
    }

    # Process the selected controllers (or all if none selected)
    foreach ($item in $USBControllers) {
        $InterruptersAmount = 'None'

        if ($item.Type -eq 'XHCI') {
            Write-Host "Processing XHCI controller: $($item.Name) - Device ID: $($item.DeviceId)"

            # Fetch the interrupter data and disable IMOD
            $FirstInterrupterData = Find-First-Interrupter-Data -memoryRange $item.MemoryRange
            $InterruptersAmount = Find-Interrupters-Amount -hcsParams1 $FirstInterrupterData.HCSPARAMS1
            $AllInterrupters = Get-All-Interrupters -preAddressInDecimal $FirstInterrupterData.Interrupter0PreAddressInDecimal -interruptersAmount $InterruptersAmount

            foreach ($interrupterItem in $AllInterrupters) {
                $DisableResult = Disable-IMOD -address $interrupterItem.InterrupterAddress
                Write-Host "Disabled IMOD - Interrupter $($interrupterItem.Interrupter) - Interrupter Address: $($interrupterItem.InterrupterAddress) - Value Address: $($interrupterItem.ValueAddress) - Result: $DisableResult"
            }
        }

        if ($item.Type -eq 'EHCI') {
            Write-Host "Processing EHCI controller: $($item.Name) - Device ID: $($item.DeviceId)"
            # For EHCI, build interrupt threshold control data
            $InterruptData = Build-Interrupt-Threshold-Control-Data -memoryRange $item.MemoryRange
            $DisableResult = Disable-IMOD -address $InterruptData.InterruptAddress -value $InterruptData.ValueAddress
            Write-Host "Disabled Interrupt Threshold Control - Interrupt Address: $($InterruptData.InterruptAddress) - Value Address: $($InterruptData.ValueAddress) - Result: $DisableResult"
        }

        Write-Host "Device: $($item.Name)"
        Write-Host "Device ID: $($item.DeviceId)"
        Write-Host "Location Info: $($item.LocationInfo)"
        Write-Host "PDO Name: $($item.PDOName)"
        Write-Host "Device Type: $($item.Type)"
        Write-Host "Memory Range: $($item.MemoryRange)"
        Write-Host "Interrupters Count: $InterruptersAmount"
        [Environment]::NewLine
        Write-Host "------------------------------------------------------------------"
        [Environment]::NewLine
    }
}

# --------------------------------------------------------------------------------------------

Download-KX

Check-For-Tool-Viability

$configUsed = Execute-IMOD-Process

if ($configUsed) {
    Write-Host "Configuration file was used."
    Write-Host "Waiting for 1 second..."
    [System.Threading.Thread]::Sleep(3000)  # Wait for 1000 milliseconds (1 second) before exiting
    Write-Host "Exiting now."
} else {
    Write-Host "Manual selection was used."
    cmd /c pause  # Pause only if manual selection was used
}