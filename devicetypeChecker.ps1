# Get device type
$deviceType = Get-WmiObject Win32_ComputerSystem | Select-Object Name, Model
$isLaptop = $deviceType.Name -like "Laptop" -or $deviceType.Model -like "Laptop"

# Check if device type is laptop
if (!$isLaptop) {
    Write-Host "BitLocker is only supported on laptops. Device type detected: $deviceType.Name - $deviceType.Model"
    #exit
}