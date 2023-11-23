# Get basic computer information
$computerInfo = Get-ComputerInfo

# Get operating system information
$osInfo = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture, InstallDate

# Get processor information
$processorInfo = Get-CimInstance Win32_Processor | Select-Object Name, MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors

# Get memory (RAM) information
$memoryInfo = Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity, Speed

# Get disk drive information
$diskInfo = Get-CimInstance Win32_DiskDrive | Select-Object DeviceID, Model, Size

# Get network adapter information
$networkInfo = Get-CimInstance Win32_NetworkAdapter | Select-Object Name, AdapterType, Speed

# Display information using Write-Host
Write-Host "----- Computer Information -----"
Write-Host "Computer Name: $($env:COMPUTERNAME)"
Write-Host "----- Operating System Information -----"
Write-Host "Caption: $($osInfo.Caption)"
Write-Host "Version: $($osInfo.Version)"
Write-Host "Architecture: $($osInfo.OSArchitecture)"
Write-Host "Install Date: $($osInfo.InstallDate)"
Write-Host "----- Processor Information -----"
Write-Host "Processor Name: $($processorInfo.Name)"
Write-Host "Max Clock Speed: $($processorInfo.MaxClockSpeed) MHz"
Write-Host "Number of Cores: $($processorInfo.NumberOfCores)"
Write-Host "Number of Logical Processors: $($processorInfo.NumberOfLogicalProcessors)"
Write-Host "----- Memory Information -----"
Write-Host "Total Memory Capacity: $($memoryInfo.Capacity) bytes"
Write-Host "Memory Speed: $($memoryInfo.Speed) MHz"
Write-Host "----- Disk Drive Information -----"
Write-Host "Device ID: $($diskInfo.DeviceID)"
Write-Host "Model: $($diskInfo.Model)"
Write-Host "Size: $($diskInfo.Size) bytes"
Write-Host "----- Network Adapter Information -----"
Write-Host "Adapter Name: $($networkInfo.Name)"
Write-Host "Adapter Type: $($networkInfo.AdapterType)"
Write-Host "Speed: $($networkInfo.Speed) bps"
