# Check if the system is running in UEFI or Legacy (BIOS) mode and if Secure Boot is enabled

# Get the system information
$systemInfo = Get-WmiObject -Class Win32_ComputerSystem
$firmware = Get-WmiObject -Class Win32_BIOS

# Check the value of the SystemType property
if ($systemInfo.SystemType -eq "x64-based PC") {
    Write-Host "Firmware: UEFI"
} else {
    Write-Host "Firmware: Legacy (BIOS)"
}

# Check if Secure Boot is enabled
if ($firmware.SecureBoot -eq $true) {
    Write-Host "Secure Boot: Enabled"
} else {
    Write-Host "Secure Boot: Disabled"
}
