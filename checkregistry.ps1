$registryPath = "HKLM:\SOFTWARE\WOW6432Node\Tanium\Tanium Client\Sensor Data\Tags"
$registryName = "Prod-LT-Encrypt"
$registryValue = "Added: $(Get-Date -Format 'M/d/yyyy h:mm:ss tt')"

# Check if the registry path exists, and create it if necessary
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force
}

# Set the registry value
Set-ItemProperty -Path $registryPath -Name $registryName -Value $registryValue

Write-Host "Registry entry added successfully."
