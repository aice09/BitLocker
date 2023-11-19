# Check if the system is running in UEFI or Legacy (BIOS) mode

# Get the system information
$systemInfo = Get-WmiObject -Class Win32_ComputerSystem

# Check the value of the SystemType property
if ($systemInfo.SystemType -eq "x64-based PC") {
    Write-Host "UEFI"
} else {
    Write-Host "Legacy (BIOS)"
}
