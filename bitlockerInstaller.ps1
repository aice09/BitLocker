# Purpose of this script : This script will verify all BitLocker requirements before adding registry file, and if the script check that the devices already encrypted using Used Space Only Encryption it will decrypt the device and ask the user to reboot.
# Author: Carl Angelo Nievarez - A70458
# Created Date: 20/November/2023
# Modified Date: 25/January/2024
# Tested Devices: Dell 7440, 7430, 7420, 7410 / Lenovo T490
# Tested OS Platform : Windows 11.XX, 10.XX
# Usage : 
#   1. Download this script to local machine in /tmp area and run the script using below method
#   2. Run the script ./bitlockerInstaller.ps1
#   3. Then wait once you get the summary verify and some requirement status fail check the device and fix it then run the script again
#   4. Optional, copy the even log in the C:\BitLockerStatus.log for your reference to Service Now ticket

# Check if the script is running as administrator
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator

if (-not $currentUser.IsInRole($adminRole)) {
    Write-Host "Please run this script as an administrator. Exiting."
    exit
}

# Set the log file path
$logFilePath = "C:\BitLockerStatus.log"

# Function to log messages to the file
function Log-Message {
    param(
        [string]$message
    )
    
    Add-content -Path $logFilePath -Value "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $message"
}

function Test-RegistryValue {
    param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name
    )

    process {
        $key = Get-Item -LiteralPath $Path
        return $key.GetValue($Name, $null) -ne $null
    }
}



# Get device info
$driveLetter = "C"
$computerName = [System.Environment]::MachineName
$osInfo = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture, InstallDate, ProductType, Manufacturer
$systemInfo = Get-WmiObject Win32_ComputerSystem | Select-Object PCSystemType, Manufacturer, Model
$processorInfo = Get-CimInstance Win32_Processor | Select-Object Name, MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors
$batteryStatus = Get-WmiObject -Class Win32_Battery -ErrorAction SilentlyContinue

# Get Device requirement status
$tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
$systemInfo = Get-WmiObject -Class Win32_ComputerSystem
$SecureBoot = Confirm-SecureBootUEFI
$storageCapacity = (Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }).FreeSpace
$TaniumClientPath = "C:\Program Files (x86)\Tanium\Tanium Client\TaniumClient.exe"
$version = $osInfo.Caption
# Registry information
$registryPath = "HKLM:\SOFTWARE\WOW6432Node\Tanium\Tanium Client\Sensor Data\Tags"
$registryName = "Prod-LT-Encrypt"
# Service Now knowledgebase
$servicenowkb = "https://microchip.service-now.com/sp?sys_kb_id=a009f638978e795456adf8e3a253af15&id=kb_article_view&sysparm_rank=3&sysparm_tsqueryId=792f547f47ae39d44ebca8b5536d430b"

#Adding device information for log purpose
Write-Host "----- Initiating Script -----"
Log-Message "----- Initiating Script -----"
Log-Message "----- Computer Information -----"
Log-Message "Computer Name: $computerName"
Log-Message "System Type: $($systemInfo.PCSystemType)"
Log-Message "Manufacturer: $($systemInfo.Manufacturer)"
Log-Message "Model: $($systemInfo.Model)"
Log-Message "Battery Status: $batteryStatus"
Log-Message "----- Operating System Information -----"
Log-Message "Product Type: $($osInfo.ProductType)"
Log-Message "Caption: $($osInfo.Caption)"
Log-Message "Version: $($osInfo.Version)"
Log-Message "Architecture: $($osInfo.OSArchitecture)"
Log-Message "Install Date: $($osInfo.InstallDate)"
Log-Message "----- Processor Information -----"
Log-Message "Processor Name: $($processorInfo.Name)"
Log-Message "Max Clock Speed: $($processorInfo.MaxClockSpeed) MHz"
Log-Message "Number of Cores: $($processorInfo.NumberOfCores)"
Log-Message "Number of Logical Processors: $($processorInfo.NumberOfLogicalProcessors)"
Log-Message "----- System Verification -----"
Write-Host "----- System Verification -----"
if ($batteryStatus -and $systemInfo.PCSystemType -eq 2) {
    Log-Message "Device Type: Laptop"
    Log-Message "BitLocker installation is allowed."
    Write-Host "Device Type: Laptop"
    Write-Host "BitLocker installation is allowed."

    Log-Message "----- Drive Verification -----"
    Write-Host "----- Drive Verification -----"
    $bitlockerStatus = Get-BitLockerVolume -MountPoint $driveLetter | Select-Object -ExpandProperty VolumeStatus
    $bitlockerProtectionStatus = Get-BitLockerVolume -MountPoint $driveLetter | Select-Object -ExpandProperty ProtectionStatus
        
    Log-Message "Drive C Volume Status: $bitlockerStatus"
    Log-Message "Drive C Protection Status: $bitlockerProtectionStatus"
    if ($bitlockerStatus -eq "FullyEncrypted" -and $bitlockerProtectionStatus -eq "On") {
        Write-Host "BitLocker is fully encrypted and protection is on."
        Log-Message "BitLocker is fully encrypted and protection is on."
    }
    elseif ($bitlockerStatus -eq "FullyEncrypted" -and $bitlockerProtectionStatus -eq "Off") {
        Write-Host "----- Decryption -----"
        Log-Message "----- Decryption -----"
        Log-Message "BitLocker is fully encrypted, but protection is turned off."
        $userInput = Read-Host "BitLocker is fully encrypted, but protection is turned off. Do you want to decrypt the drive? (yes/no)"

        if ($userInput -eq 'yes') {
            Disable-BitLocker -MountPoint "C:"
            Write-Host "Decrypting drive C. Please wait..."

            $pollingInterval = 10
            $totalSteps = 100
            $progress = 100

            for ($step = $totalSteps; $step -ge 1; $step--) {
                Start-Sleep -Seconds $pollingInterval

                $encryptionStatus = Get-BitLockerVolume -MountPoint "C:" | Select-Object -ExpandProperty EncryptionPercentage

                $progress = $totalSteps - $encryptionStatus
                Write-Progress -Activity "Decrypting Drive C" -Status "Progress: $progress%" -PercentComplete $progress

                if ($progress -eq 100) {
                    Write-Host "Decryption process completed."
                    Log-Message "Decryption process completed."
                    break
                }

                if ($host.UI.RawUI.KeyAvailable -and ($host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp").VirtualKeyCode -eq 27)) {
                    Write-Host "Decryption process canceled by the user."
                    Log-Message "Decryption process canceled by the user."
                    break
                }
            }

            if ($progress -eq 100) {
                Remove-ItemProperty -Path $registryPath -Name $registryName
                Log-Message "Registry key '$registryName' removed successfully."                
                Write-Host "Rebooting the system..."
                Log-Message "Rebooting the system..."
                Restart-Computer -Force
            }

                
            Log-Message "Drive C decryption completed."
        }
        else {
            Write-Host "Task ended. Device is not fully encrypted."
            Log-Message "Task ended. Device is not fully encrypted."
            exit
        }
    }
    else {
        Write-Host "BitLocker is not fully encrypted or protection is off."
        Log-Message "BitLocker is not fully encrypted or protection is off"
            

        Write-Host "----- Checking requirements -----"
        Log-Message "----- Checking requirements -----"

        if ($tpm) {
            if ($tpm.SecurityServicesConfigured -and $tpm.SecurityServicesRunning) {
                Log-Message "TPM is enabled on this system."
            }
            else {
                Log-Message "TPM is present but not enabled on this system."
            }
        
            $tpmVersion = $tpm.SpecVersion
            if ($tpmVersion) {
                Log-Message "TPM version: $tpmVersion"
            }
            else {
                Log-Message "TPM version information not available."
            }
        }
        else {
            Log-Message "TPM is not available on this system."
        }

        if ($systemInfo.SystemType -eq "x64-based PC") {
            Log-Message "System Info: UEFI"
        }
        else {
            Log-Message "System Info: Legacy (BIOS)"
        }

        if ($SecureBoot) {
            Log-Message "Secure Boot: Enabled"
        }
        else {
            Log-Message "Secure Boot: Disabled"
        }

        $storageCapacity = (Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }).FreeSpace
        if ($storageCapacity -ge 350MB) {
            Log-Message "Storage capacity has more than 350MB space available: $($storageCapacity / 1GB) GB"
        }
        else {
            Log-Message "Storage capacity does not have 350MB space available: $($storageCapacity / 1MB) MB"
        }

        if ($osInfo.Version -like '7*' -or $osInfo.Version -like '8*' -or $osInfo.Version -like '8.1*' -or $osInfo.Version -like '10*' -or $osInfo.Version -like '11*') {
            $version = $osInfo.Caption

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

        $TaniumClientPath = "C:\Program Files (x86)\Tanium\Tanium Client\TaniumClient.exe"
        if (Test-Path $TaniumClientPath -PathType Leaf) {
            Log-Message "Tanium is installed."
        }
        else {
            Log-Message "Tanium is not installed."
        }


        $requirements = @{
            "- TPM"              = $tpm.IsEnabled;
            "- TPM Version"      = $tpm.ManufacturerVersion -ge 1.2;
            "- Firmware Type"    = $systemInfo.SystemType -eq 'x64-based PC';
            "- Secure Boot"      = $SecureBoot;
            "- Storage Capacity" = $storageCapacity -ge 350MB;
            "- OS Version"       = $version -match 'Microsoft Windows (7|8|8.1|10|11) (Pro|Enterprise|Education|Ultimate)';
            "- Tanium"           = $TaniumClientPath
        }

        Write-Host "BitLocker Requirements Status:"
        Log-Message "BitLocker Requirements Status:"
        foreach ($requirement in $requirements.GetEnumerator()) {
            if ($requirement.Value) {
                Write-Host "$($requirement.Key): PASS"
                Log-Message "$($requirement.Key): PASS"
            }
            else {
                Write-Host "$($requirement.Key): FAIL"
                Log-Message "$($requirement.Key): FAIL"
            }
        }

        if ($requirements.ContainsValue($false)) {
            Write-Host "Requirements Status: Some requirements failed"
            Log-Message "Requirements Status: Some requirements failed"
        }
        else {
            Write-Host "Requirements Status passed"
            Log-Message "Requirements Status passed"
            Write-Host "----- Installation -----"
            Log-Message "----- Installation -----"

                
            if (Test-RegistryValue -Path $registryPath -Name $registryName) {
                Write-Host "Registry value $registryName exists in $registryPath."
                Log-Message "Registry value $registryName exists in $registryPath."
                Write-Host "Reinstalling registry file"                
                Log-Message "Removing existing registry file"
                Remove-ItemProperty -Path $registryPath -Name $registryName
                Write-Host "Adding new registry file"
                Log-Message "Adding new registry file"
                Write-Host "Note: After some time (~5 to 30 minutes), you will receive a prompt from Tanium indicating the user is required to set a unique password used to access the disk."
                Write-Host "Visit the user knowledge base: $servicenowkb"
                Set-ItemProperty -Path $registryPath -Name $registryName -Value "Added: $(Get-Date -Format 'M/d/yyyy h:mm:ss tt')"
            }
            else {
                Write-Host "Registry value $registryName does not exist in $registryPath."
                Log-Message "Registry value $registryName does not exist in $registryPath."
                Write-Host "Adding new registry file"                               
                Log-Message "Adding new registry file"
                Write-Host "Note: After some time (~5 to 30 minutes), you will receive a prompt from Tanium indicating the user is required to set a unique password used to access the disk."
                Write-Host "Visit the user knowledge base: $servicenowkb"
                Set-ItemProperty -Path $registryPath -Name $registryName -Value "Added: $(Get-Date -Format 'M/d/yyyy h:mm:ss tt')"
            }
        }
    }
}
 
elseif (-not $batteryStatus -and $systemInfo.PCSystemType -eq 1 -and $osInfo.ProductType -eq 1) {
    Log-Message "Device Type: Desktop"
    Log-Message "BitLocker installation is not allowed on this device."
    Write-Host "Device Type: Desktop"
    Write-Host "BitLocker installation is not allowed on this device."
}
 
elseif ($osInfo.ProductType -eq 3 -and ($systemInfo.PCSystemType -eq 4 -or $systemInfo.PCSystemType -eq 5 -or $systemInfo.PCSystemType -eq 7)) {
    Log-Message "Device Type: Server"
    Log-Message "BitLocker installation is not allowed on this device."
    Write-Host "Device Type: Server"
    Write-Host "BitLocker installation is not allowed on this device."
}

elseif ($systemInfo.Model -like '*Virtual*' -or $systemInfo.Model -like '*VMware*') {
    Log-Message "Device Type: Virtual Machine"
    Log-Message "BitLocker installation is not allowed on this device."
    Write-Host "Device Type: Virtual Machine"
    Write-Host "BitLocker installation is not allowed on this device."
}
else {
    Log-Message "Device Type: Unknown"
    Log-Message "BitLocker installation is not allowed on this device."
    Write-Host "Device Type: Unknown"
    Write-Host "BitLocker installation is not allowed on this device."
}
Write-Host "----- End of Script -----"
Log-Message "----- End of Script -----"
