# Check if the script is running as administrator
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator

if (-not $currentUser.IsInRole($adminRole)) {
    Write-Host "Please run this script as an administrator. Exiting."
    exit
}

# Check if BitLocker is enabled
$bitlockerStatus = Get-BitLockerVolume -MountPoint "C:" | Select-Object -ExpandProperty VolumeStatus

if ($bitlockerStatus -eq 'FullyEncrypted') {
    # Check if BitLocker Protection Status is Turned On, and Volume is Fully Encrypted
    $encryptionStatus = Get-BitLockerVolume -MountPoint "C:" | Select-Object -ExpandProperty EncryptionPercent

    if ($encryptionStatus -eq 100) {
        Write-Host "Device is fully encrypted by BitLocker."
    }
    else {
        # If Volume is Decrypted, ask to turn on encryption
        $userInput = Read-Host "BitLocker protection is on, but volume is not fully encrypted. Do you want to turn on encryption? (yes/no)"
        
        if ($userInput -eq 'yes') {
            Enable-BitLocker -MountPoint "C:" -RecoveryPasswordProtector -UsedSpaceOnly
            Write-Host "Device drive C is now encrypted."
        }
        else {
            Write-Host "Task ended. Device is not fully encrypted."
            exit
        }
    }
}
else {
    # Check the Requirements
    $tpm = Get-WmiObject -Namespace "Root\Microsoft\Windows\DeviceGuard" -Class Win32_DeviceGuard

    # Check if TPM is available
    if ($tpm) {
        # Check if Device Guard is present and enabled
        if ($tpm.SecurityServicesConfigured -and $tpm.SecurityServicesRunning) {
            Write-Host "TPM is enabled on this system."
        }
        else {
            Write-Host "TPM is present but not enabled on this system."
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

    # Check system mode (UEFI or Legacy)
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

    # Check storage capacity
    $storageCapacity = (Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }).FreeSpace
    if ($storageCapacity -ge 350MB) {
        Write-Host "Storage capacity has more than 350MB space available: $($storageCapacity / 1GB) GB"
    }
    else {
        Write-Host "Storage capacity does not have 350MB space available: $($storageCapacity / 1MB) MB"
    }

    # Check Windows version
    $osInfo = Get-CimInstance Win32_OperatingSystem
    Write-Host "Detected OS Version: $($osInfo.Caption)"
    Write-Host "Detected OS Architecture: $($osInfo.OSArchitecture)"

    # Check if OS is Windows 10 or Windows 11
    if ($osInfo.Version -like '10*' -or $osInfo.Version -like '11*') {
        Write-Host "Windows 10 or Windows 11 detected."
        $version = $osInfo.Caption

        # Check if the edition is compatible
        if ($version -match 'Microsoft Windows (7|8|8.1|10|11) (Pro|Enterprise|Education|Ultimate)') {
            Write-Host "Compatible OS and edition detected: $($osInfo.Caption)"
        }
        else {
            Write-Host "Not compatible edition: $($osInfo.Caption)"
        }
    }
    else {
        Write-Host "Not compatible edition."
    }

    # Check if Tanium is installed
    $TaniumClientPath = "C:\Program Files\Tanium\TaniumClient\TaniumClient.exe"
    if (Test-Path $TaniumClientPath -PathType Leaf) {
        Write-Host "Tanium is installed."    
    }
    else {
        Write-Host "Tanium is not installed."
    }

    # Check the status of each requirement
    $requirements = @{
        "TPM"              = $null -ne $tpm;
        "TPM Version"      = $null -ne $tpmVersion;
        "Firmware Type"    = $systemInfo.SystemType -eq 'x64-based PC';
        "Secure Boot"      = $firmware.SecureBoot;
        "Storage Capacity" = $storageCapacity -ge 350MB;
        "OS Version"       = $version -match 'Microsoft Windows (7|8|8.1|10|11) (Pro|Enterprise|Education|Ultimate)';
    }

    # Display requirement status
    foreach ($requirement in $requirements.GetEnumerator()) {
        if ($requirement.Value) {
            Write-Host "$($requirement.Key): PASS"
        } else {
            Write-Host "$($requirement.Key): FAIL"
        }
    }
    

    # Check if all requirements passed
    if ($requirements.ContainsValue($false)) {
        Write-Host "Some requirements failed. Task ended."
    }
    else {
        Write-Host "All requirements passed. Proceed with the next steps."

        # Check registry for Prod-LT-Encrypt
        $registryPath = "HKLM:\SOFTWARE\WOW6432Node\Tanium\Tanium Client\Sensor Data\Tags"
        $registryName = "Prod-LT-Encrypt"

        if (Test-Path -Path $registryPath) {
            $existingValue = Get-ItemProperty -Path $registryPath -Name $registryName -ErrorAction SilentlyContinue

            if ($null -eq $existingValue) {
                Set-ItemProperty -Path $registryPath -Name $registryName -Value "Added: $(Get-Date -Format 'M/d/yyyy h:mm:ss tt')"
            }
            else {
                Remove-ItemProperty -Path $registryPath -Name $registryName
                Set-ItemProperty -Path $registryPath -Name $registryName -Value "Added: $(Get-Date -Format 'M/d/yyyy h:mm:ss tt')"
            }
        }
        else {
            Write-Host "Registry path $registryPath does not exist."
        }
    }
}
