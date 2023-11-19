# Define the log file path
<# $logFilePath = "C:\BitLockerInstallation_Log.txt"

# Create or append to the log file
$null > $logFilePath

# Function to write log messages
function Write-Log {
    param(
        [string]$message
    )
    $timestamp = Get-Date -Format 'M/d/yyyy h:mm:ss tt'
    $logMessage = "$timestamp - $message"
    $logMessage | Out-File -Append -FilePath $logFilePath
} #>


# Check if BitLocker is enabled
$bitlockerStatus = Get-BitLockerVolume -MountPoint "C:" | Select-Object -ExpandProperty VolumeStatus

if ($bitlockerStatus -eq 'FullyEncrypted') {
    # If BitLocker Protection Status is Turned On, Check Volume if Fully Encrypted
    $encryptionStatus = Get-BitLockerVolume -MountPoint "C:" | Select-Object -ExpandProperty EncryptionPercent

    if ($encryptionStatus -eq 100) {
        # If Volume is Fully Encrypted, send message that device is fully encrypted by BitLocker
        Write-Host "Device is fully encrypted by BitLocker."
    }
    else {
        # If Volume is Decrypted, ask to turn on encryption
        $userInput = Read-Host "BitLocker protection is on, but volume is not fully encrypted. Do you want to turn on encryption? (yes/no)"
        
        if ($userInput -eq 'yes') {
            # Turn on encryption
            Enable-BitLocker -MountPoint "C:" -RecoveryPasswordProtector -UsedSpaceOnly
            Write-Host "Device drive C is now encrypted."
        }
        else {
            # End the task
            Write-Host "Task ended. Device is not fully encrypted."
            exit
        }
    }
}
else {
    # Check the Requirements

    # Check TPM if enabled
    $tpm = Get-WmiObject -Namespace "Root\Microsoft\Windows\DeviceGuard" -Class Win32_DeviceGuard

    # Check if TPM is available
    if ($tpm) {
        # Check if Device Guard is present and enabled
        if ($tpm.SecurityServicesConfigured -and $tpm.SecurityServicesRunning) {
            Write-Host "TPM is enabled on this system."
            # You can add additional actions or information specific to when TPM is enabled
        }
        else {
            Write-Host "TPM is present but not enabled on this system."
            # You can add additional actions or information specific to when TPM is not enabled
        }

        # Check TPM version
        $tpmVersion = $tpm.SpecVersion
        if ($tpmVersion) {
            Write-Host "TPM version: $tpmVersion"
        }
        else {
            Write-Host "TPM version information not available."
        }
    }
    else {
        Write-Host "TPM is not available on this system."
    }


    # Check if the system is running in UEFI or Legacy (BIOS) mode
    $systemInfo = Get-WmiObject -Class Win32_ComputerSystem

    # Check the value of the SystemType property
    if ($systemInfo.SystemType -eq "x64-based PC") {
        Write-Host "UEFI"
    }
    else {
        Write-Host "Legacy (BIOS)"
    }


    # Check if Secure Boot is enabled
    $firmware = Get-WmiObject -Class Win32_BIOS
    if ($firmware.SecureBoot -eq $true) {
        Write-Host "Secure Boot: Enabled"
    }
    else {
        Write-Host "Secure Boot: Disabled"
    }

    # Check storage capacity or if have 350MB free space
    $storageCapacity = (Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }).FreeSpace

    if ($storageCapacity -ge 350MB) {
        Write-Host "Storage capacity has more than 350MB space available: $($storageCapacity / 1GB) GB"
    }
    else {
        Write-Host "Storage capacity does not have 350MB space available: $($storageCapacity / 1MB) MB"
    }



    # Check Windows version
    $osInfo = Get-CimInstance Win32_OperatingSystem

    # Display detected OS version and architecture
    Write-Host "Detected OS Version: $($osInfo.Caption)"
    Write-Host "Detected OS Architecture: $($osInfo.OSArchitecture)"

    # Check if OS is Windows 10 or Windows 11
    if ($osInfo.Version -like '10*' -or $osInfo.Version -like '11*') {
        Write-Host "Windows 10 or Windows 11 detected."

        # Check Windows edition
        $version = $osInfo.Caption

        # Display detected version for debugging
        Write-Host "Detected Version: $($version)"

        # Check if the edition is Pro, Enterprise, Education, or Ultimate
        if ($version -match 'Microsoft Windows 7 Ultimate|Microsoft Windows 7 Enterprise|Microsoft Windows 8 Pro|Microsoft Windows 8 Enterprise|Microsoft Windows 8.1 Pro|Microsoft Windows 8.1 Enterprise|Microsoft Windows 10 Pro|Microsoft Windows 10 Enterprise|Microsoft Windows 10 Education|Microsoft Windows 11 Pro|Microsoft Windows 11 Enterprise|Microsoft Windows 11 Education') {
            # Perform actions for compatible OS and edition
            Write-Host "Compatible OS and edition detected: $($osInfo.Caption)"
            # Add your specific actions here
        }
        else {
            # Inform that the edition is not compatible
            Write-Host "Not compatible edition: $($osInfo.Caption)"
        }
    }
    else {
        Write-Host "Not compatible edition."
    }

    # Check Tanium if installed
    $TaniumClientPath = "C:\Program Files\Tanium\TaniumClient\TaniumClient.exe"

    if (Test-Path $TaniumClientPath -PathType Leaf) {
        Write-Host "Tanium is installed."

    
    }
    else {
        Write-Host "Tanium is not installed."
    }



    # Check the status of each requirement if all passed
    foreach ($requirement in $requirements.GetEnumerator()) {
        Write-Host "$($requirement.Key): $($requirement.Value)"
    }
 
    # Check if any requirement has failed
    if ($requirements.ContainsValue($false)) {
        # Write the following status
        TPM: Enabled - PASS/FAIL
        TPM Version: Version - PASS/FAIL
        Firmware Type: UEFI or Legacy - PASS/FAIL
        Secure Boot: Enabled/Disabled - PASS/FAIL
        Storage Capacity: >350MB space available or not - PASS/FAIL
        OS Version: OS version - PASS/FAIL
    }
    else {
        # Write the following status
        TPM: Enabled - PASS/FAIL
        TPM Version: Version - PASS/FAIL
        Firmware Type: UEFI or Legacy - PASS/FAIL
        Secure Boot: Enabled/Disabled - PASS/FAIL
        Storage Capacity: >350MB space available or not - PASS/FAIL
        OS Version: OS version - PASS/FAIL

        Write-Host "All requirements passed. Proceed with the next steps."


        # Check registry if Prod-LT-Encrypt is already added
        $registryPath = "HKLM:\SOFTWARE\WOW6432Node\Tanium\Tanium Client\Sensor Data\Tags"
        $registryName = "Prod-LT-Encrypt"

        if (Test-Path -Path $registryPath) {
            $existingValue = Get-ItemProperty -Path $registryPath -Name $registryName -ErrorAction SilentlyContinue

            if ($null -eq $existingValue) {
                # Check if Prod-LT-Encrypt not yet available, install it to the registry
                Set-ItemProperty -Path $registryPath -Name $registryName -Value "Added: $(Get-Date -Format 'M/d/yyyy h:mm:ss tt')"
            }
            else {
                # Check if Prod-LT-Encrypt already installed, delete that and reinstall
                Remove-ItemProperty -Path $registryPath -Name $registryName
                Set-ItemProperty -Path $registryPath -Name $registryName -Value "Added: $(Get-Date -Format 'M/d/yyyy h:mm:ss tt')"
            }
        }
        else {
            Write-Host "Registry path $registryPath does not exist."
        }
    }
}