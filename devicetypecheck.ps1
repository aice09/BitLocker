unction Get-DeviceType {
    $systemInfo = Get-WmiObject Win32_ComputerSystem

    $manufacturer = $systemInfo.Manufacturer
    $model = $systemInfo.Model
    $isLaptop = $systemInfo.Laptop

    if ($isLaptop -eq $true) {
        return "Laptop"
    }

    if ($manufacturer -eq "Microsoft Corporation" -and $model -eq "Virtual Machine") {
        return "Virtual Machine"
    }

    $systemType = (Get-WmiObject -Class Win32_ComputerSystem).SystemType

    if ($systemType -like "*Server*") {
        return "Server"
    }

    return "Desktop"
}

# Example usage
$deviceType = Get-DeviceType
Write-Host "The identified device type is: $deviceType"