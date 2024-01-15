# Function to determine if the device is a laptop
function IsLaptop {
    try {
        $batteryStatus = Get-WmiObject -Class Win32_Battery -ErrorAction Stop
        return $batteryStatus -ne $null
    }
    catch {
        return $false
    }
}

# Function to determine if the device is a desktop
function IsDesktop {
    try {
        $batteryStatus = Get-WmiObject -Class Win32_Battery -ErrorAction Stop
        return $batteryStatus -eq $null
    }
    catch {
        return $false
    }
}

# Function to determine if the device is a virtual machine
function IsVirtualMachine {
    try {
        $hypervisors = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop | Select-Object -ExpandProperty HypervisorVirtualSystemIdentifier
        return $hypervisors -ne $null
    }
    catch {
        return $false
    }
}

# Function to determine if the device is a server
function IsServer {
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        return $os.ProductType -eq 2 -or $os.ProductType -eq 3
    }
    catch {
        return $false
    }
}

# Determine the type of device
try {
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
}
catch {
    Write-Host "An error occurred: $_"
}
