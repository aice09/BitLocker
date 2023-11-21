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

# Get BitLocker status for the specified volume
$bitlockerStatus = Get-BitLockerVolume -MountPoint "C:" | Select-Object -ExpandProperty VolumeStatus
$bitlockerProtectionStatus = Get-BitLockerVolume -MountPoint "C:" | Select-Object -ExpandProperty ProtectionStatus
# Get Device requirement status
$tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
$systemInfo = Get-WmiObject -Class Win32_ComputerSystem
$SecureBoot=Confirm-SecureBootUEFI
$storageCapacity = (Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }).FreeSpace
$TaniumClientPath = "C:\Program Files (x86)\Tanium\Tanium Client\TaniumClient.exe"
$osInfo = Get-CimInstance Win32_OperatingSystem
$version = $osInfo.Caption
# Registry information
$registryPath = "HKLM:\SOFTWARE\WOW6432Node\Tanium\Tanium Client\Sensor Data\Tags"
$registryName = "Prod-LT-Encrypt"

# Check if the volume is fully encrypted or BitLocker protection is on
if ($bitlockerStatus -eq "FullyEncrypted" -and $bitlockerProtectionStatus -eq "On") {
    # Your code here for the condition when BitLocker is fully encrypted or protection is on
    Write-Host "BitLocker is fully encrypted and protection is on."
    Log-Message "BitLocker is fully encrypted and protection is on."
} elseif ($bitlockerStatus -eq "FullyEncrypted" -and $bitlockerProtectionStatus -eq "Off") {
    Write-Host "BitLocker is Used Space Only Encrypted"
    $userInput = Read-Host "BitLocker protection is on, but volume is using UsedSpaceOnly. Do you want to decrypt the drive? (yes/no)"

    if ($userInput -eq 'yes') {
        Disable-BitLocker -MountPoint "C:" -RebootCount 1
        Write-Host "Device drive C is now decrypted. Please reboot your system and run this script again after your reboot."
        Log-Message "Device drive C is now decrypted. Please reboot your system and run this script again after your reboot."
    } else {
        Write-Host "Task ended. Device is not fully encrypted."
        Log-Message "Task ended. Device is not fully encrypted."
        exit
    }
}else {
    # Your code here for the condition when BitLocker is not fully encrypted or protection is off
    Write-Host "BitLocker is not fully encrypted or protection is off."
    Log-Message "BitLocker is not fully encrypted or protection is off"
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
        Write-Host "Requirements Status passed"
        Log-Message "Requirements Status passed"

        
        if (Test-RegistryValue -Path $registryPath -Name $registryName) {
            # The registry value exists
            Write-Host "Registry value $registryName exists in $registryPath."
            Log-Message "Registry value $registryName exists in $registryPath."
            Remove-ItemProperty -Path $registryPath -Name $registryName
            Set-ItemProperty -Path $registryPath -Name $registryName -Value "Added: $(Get-Date -Format 'M/d/yyyy h:mm:ss tt')"
        } else {
            # The registry value does not exist
            Write-Host "Registry value $registryName does not exist in $registryPath."
            Log-Message "Registry value $registryName does not exist in $registryPath."
            Set-ItemProperty -Path $registryPath -Name $registryName -Value "Added: $(Get-Date -Format 'M/d/yyyy h:mm:ss tt')"
        }
    }
}