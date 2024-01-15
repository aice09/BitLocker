# Function to determine if the device is a laptop
function IsLaptop {
    $batteryStatus = Get-WmiObject -Class Win32_Battery
    return $batteryStatus -ne $null
}

# Function to determine if the device is a desktop
function IsDesktop {
    $batteryStatus = Get-WmiObject -Class Win32_Battery
    return $batteryStatus -eq $null
}

# Function to determine if the device is a virtual machine
function IsVirtualMachine {
    $hypervisors = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty HypervisorVirtualSystemIdentifier
    return $hypervisors -ne $null
}

# Function to determine if the device is a server
function IsServer {
    $os = Get-WmiObject -Class Win32_OperatingSystem
    return $os.ProductType -eq 2 -or $os.ProductType -eq 3
}

# Determine the type of device
if (IsLaptop) {
    Write-Host "Device type: Laptop"
}
elseif (IsDesktop) {
    Write-Host "Device type: Desktop"
}
elseif (IsVirtualMachine) {
    Write-Host "Device type: Virtual Machine"
}
elseif (IsServer) {
    Write-Host "Device type: Server"
}
else {
    Write-Host "Unable to determine the device type"
}
