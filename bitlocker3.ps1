# Set the log file path
$logFilePath = "C:\BitLockerStatus.log"

# Function to log messages to the file
function Log-Message {
    param(
        [string]$message
    )
    
    Add-content -Path $logFilePath -Value "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $message"
}

# Check if the script is running as administrator
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator

if (-not $currentUser.IsInRole($adminRole)) {
    Write-Host "Please run this script as an administrator. Exiting."
    exit
}

# Check if BitLocker is enabled
Log-Message "Installing BitLocker"
Log-Message "Starting-BitLocker Verification"
Log-Message "Checking drive C"
$bitlockerStatus = Get-BitLockerVolume -MountPoint "C:" | Select-Object -ExpandProperty VolumeStatus

if ($bitlockerStatus -eq "FullyEncrypted" -or $bitlockerStatus -eq "EncryptionInProgress") {
    # Check if BitLocker is enabled on any volume
    $bitLockerInfo = Get-BitLockerVolume

   if ($bitLockerInfo) {
       foreach ($volume in $bitLockerInfo) {
            $volumeStatus = $volume.ProtectionStatus

           # Check if the volume is fully encrypted and protected
           if ($volumeStatus -eq 'On' -and $volume.VolumeStatus -eq 'FullyEncrypted') {
               Write-Host "Device is fully encrypted by BitLocker."
               Log-Message "BitLocker Status: Fully Encrypted"
       
           }
           else {
               # If Volume is Decrypted, ask to turn on encryption
               $userInput = Read-Host "BitLocker protection is on, but volume is not fully encrypted. Do you want to turn on encryption? (yes/no)"
               
               if ($userInput -eq 'yes') {
                   Enable-BitLocker -MountPoint "C:" -RecoveryPasswordProtector -UsedSpaceOnly
                   Write-Host "Device drive C is now encrypted."
                   Log-Message "Agreed to enable disk encryption."
                   Log-Message "BitLocker Status: Encryption Started"
               }
               else {
                   Write-Host "Task ended. Device is not fully encrypted."
                   Log-Message "Disagree to enable disk encryption"
                   Log-Message "BitLocker Status: Encryption Not Started"
                   exit
               }
           }
       }
   }
}
else {
    # Check the Requirements
    Log-Message "BitLocker Status: Encryption Decyrpted and volume protection turned off."
    Log-Message "Starting gathering information"
    Log-Message "Gathering TPM Info"
    $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    
    # Check if TPM is available
    if ($tpm) {
        Log-Message "TPM Manufacturer ID: $($tpm.ManufacturerID)"
        Log-Message "TPM Manufacturer Version: $($tpm.ManufacturerVersion)"
        Log-Message "TPM Version: $($tpm.ManufacturerVersion)"
        Log-Message "TPM Status: $($tpm.IsEnabled)"

        # Check if Device Guard is present and enabled
        if ($tpm.IsEnabled) {
            Log-Message "TPM is enabled on this system."

            # Check TPM version
            Log-Message "Gathering TPM Version"
            $tpmVersion = $tpm.ManufacturerVersion
            if ($tpm.ManufacturerVersion -ge 1.2) {
                Log-Message "TPM version is 1.2 or higher"
                Log-Message "TPM version: $tpmVersion"
            }
            else {
                Log-Message "TPM version is less than 1.2. Consider upgrading TPM version."
            }
        }
        else {
            Log-Message "TPM is present but not enabled on this system. Consider turning on TPM"
        }        
    }
    else {
        Log-Message "TPM is not available on this system."
    }

    # Check system mode (UEFI or Legacy)
    Log-Message "Gathering System/BIOS Mode"
    $systemInfo = Get-WmiObject -Class Win32_ComputerSystem

    # Check the value of the SystemType property
    if ($systemInfo.SystemType -eq "x64-based PC") {
        Log-Message "BIOS Mode: UEFI"
    }
    else {
        Log-Message "BIOS Mode: Legacy"
    }

    # Check if Secure Boot is enabled
    Log-Message "Gathering Secure Boot State"
    $SecureBoot=Confirm-SecureBootUEFI
    if ($SecureBoot) {
        Log-Message "Secure Boot: Enabled"
    }
    else {
        Log-Message "Secure Boot: Disabled"
    }
    
    # Check storage capacity
    Log-Message "Gathering storage capacity"
    $storageCapacity = (Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }).FreeSpace
    if ($storageCapacity -ge 350MB) {
        Log-Message  "Storage capacity has more than 350MB space available: $($storageCapacity / 1GB) GB"
    }
    else {
        Log-Message  "Storage capacity does not have 350MB space available: $($storageCapacity / 1MB) MB"
    }

    # Check Windows version
    Log-Message "Gathering OS Version"
    $osInfo = Get-CimInstance Win32_OperatingSystem
    Log-Message "Detected OS Version: $($osInfo.Caption)"
    Log-Message "Detected OS Architecture: $($osInfo.OSArchitecture)"

    # Check if OS compatability"
    Log-Message "Checking if OS BitLocker Compatability"
    if ($osInfo.Version -like '7*' -or $osInfo.Version -like '8*' -or $osInfo.Version -like '8.1*' -or $osInfo.Version -like '10*' -or $osInfo.Version -like '11*') {
        $version = $osInfo.Caption

        # Check if the edition is compatible
        if ($version -match 'Microsoft Windows (7|8|8.1|10|11) (Pro|Enterprise|Education|Ultimate)') {
            Log-Message "Compatible OS and edition detected: $($osInfo.Caption)"
        }
        else {
            Log-Message "Not compatible edition: $($osInfo.Caption)"
        }
    }
    else {
        Log-Message "Not compatible edition."
    }

    # Check if Tanium is installed
    Log-Message "Gathering Tanium information"
    $TaniumClientPath = "C:\Program Files (x86)\Tanium\Tanium Client\TaniumClient.exe"
    if (Test-Path $TaniumClientPath -PathType Leaf) {
        Log-Message "Tanium is installed."
    }
    else {
        Log-Message "Tanium is not installed."
    }

    # Check the status of each requirement
    Log-Message "Creating requirement summary"
    $requirements = @{
        "TPM"              = $tpm.IsEnabled;
        "TPM Version"      = $tpm.ManufacturerVersion -ge 1.2;
        "Firmware Type"    = $systemInfo.SystemType -eq 'x64-based PC';
        "Secure Boot"      = $SecureBoot;
        "Storage Capacity" = $storageCapacity -ge 350MB;
        "OS Version"       = $version -match 'Microsoft Windows (7|8|8.1|10|11) (Pro|Enterprise|Education|Ultimate)';
        "Tanium"           = $TaniumClientPath
    }

    # Display requirement status
    Write-Host "BitLocker Requirements Status:"
    Log-Message "BitLocker Requirements Status:"
    foreach ($requirement in $requirements.GetEnumerator()) {
        if ($requirement.Value) {
            Write-Host "$($requirement.Key): PASS"
            Log-Message "$($requirement.Key): PASS"
        } else {
            Write-Host "$($requirement.Key): FAIL"
            Log-Message "$($requirement.Key): FAIL"
        }
    }
    

    # Check if all requirements passed
    if ($requirements.ContainsValue($false)) {
        Write-Host "Requirements Status: Some requirements failed"
        Log-Message "Requirements Status: Some requirements failed"
    }
    else {
        Write-Host "All requirements passed. Proceed with the next steps."
        Log-Message "Requirements Check: All requirements passed. Proceed with the next steps."

        # Check registry for Prod-LT-Encrypt        
        Write-Host "Checking registry"
        Log-Message "Checking registry"

        $registryPath = "HKLM:\SOFTWARE\WOW6432Node\Tanium\Tanium Client\Sensor Data\Tags"
        $registryName = "Prod-LT-Encrypt"

        if (Test-Path -Path $registryPath) {     
            Write-Host "Registry path $registryPath exist."
            Log-Message "Registry path $registryPath exist."
            $existingValue = Get-ItemProperty -Path $registryPath -Name $registryName -ErrorAction SilentlyContinue

            if ($null -eq $existingValue) {
                Set-ItemProperty -Path $registryPath -Name $registryName -Value "Added: $(Get-Date -Format 'M/d/yyyy h:mm:ss tt')"
                Write-Host "Registry Update: Added registry value!"
                Log-Message "Registry Update: Added registry value"                
            }
            else {
                Remove-ItemProperty -Path $registryPath -Name $registryName
                Set-ItemProperty -Path $registryPath -Name $registryName -Value "Added: $(Get-Date -Format 'M/d/yyyy h:mm:ss tt')"
                Write-Host "Registry Update: Updated registry value!"
                Log-Message "Registry Update: Updated registry value"
            }
        }
        else {
            Write-Host "Registry path $registryPath does not exist."
            Log-Message "Registry path $registryPath does not exist."
        }
    }
}

Log-Message "Fin de la acción/End of the action"
