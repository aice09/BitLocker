# Set the log file path
$logFilePath = "C:\BitLockerStatus.log"

# Function to log messages to the file
function Log-Message {
    param(
        [string]$message
    )
    
    Add-Content -Path $logFilePath -Value "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $message"
}

Log-Message "----- Initiating Script -----"
# Disable BitLocker on the C: drive
Disable-BitLocker -MountPoint "C:"

Write-Host "Decrypting drive C. Please wait..."
Log-Message "Decrypting drive C."

# Set the polling interval in seconds
$pollingInterval = 10
$totalSteps = 100
$progress = 100  # Initialize progress to 100

# Start a loop to simulate the decryption progress
for ($step = $totalSteps; $step -ge 1; $step++) {
    # Simulate the decryption process
    Start-Sleep -Seconds $pollingInterval

    # Check the percentage of encryption on the C: drive
    $encryptionStatus = Get-BitLockerVolume -MountPoint "C:" | Select-Object -ExpandProperty EncryptionPercentage

    # Update the progress bar
    $progress = $totalSteps-$encryptionStatus
    Write-Progress -Activity "Decrypting Drive C" -Status "Progress: $progress%" -PercentComplete $progress

    # Check if decryption is complete
    if ($progress -eq 100) {
        Write-Host "Decryption process completed."
        Log-Message "Decryption process completed."
        break
    }

    # Break the loop if the user cancels the operation
    if ($host.UI.RawUI.KeyAvailable -and ($host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp").VirtualKeyCode -eq 27)) {
        Write-Host "Decryption process canceled by the user."
        Log-Message "Decryption process canceled by the user."
        break
    }
}

# Check if the encryption percentage is 100% and prompt for reboot
if ($progress -eq 100) {
    $rebootInput = Read-Host "Decryption process is complete. Do you want to reboot your system now? (yes/no)"
    if ($rebootInput -eq 'yes') {
        Write-Host "Rebooting the system..."
        Log-Message "Rebooting the system."
        Restart-Computer -Force
    } else {
        Write-Host "Please reboot your system manually after running this script again."
    }
}

# Log the script completion
Log-Message "----- Script execution completed. -----"