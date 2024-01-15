function Get-TraceRoute {
    param (
        [string]$IpAddress
    )

    $traceRoute = Invoke-Expression -Command "tracert $IpAddress"
    return $traceRoute
}

function Log-Change {
    param (
        [string]$ChangeType,
        [string]$MainIP,
        [string]$BackupIP,
        [string]$TraceRoute,
        [string]$LogFilePath
    )

    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $ChangeType - Main IP: $MainIP, Backup IP: $BackupIP`r`n$TraceRoute`r`n"
    Add-Content -Path $LogFilePath -Value $logEntry
}

function Check-IPChange {
    param (
        [string]$PreviousMainIP,
        [string]$BackupIP,
        [string]$LogFilePath
    )

    $currentTraceRoute = Get-TraceRoute -IpAddress "8.8.4.4"  # Use a reliable external IP for trace route

    # Extract the last hop (which is assumed to be the ISP)
    $currentMainIP = ($currentTraceRoute | Select-Object -Last 1).Address

    if ($currentMainIP -ne $PreviousMainIP) {
        # Check if the change is from Main IP to Backup IP
        if ($currentMainIP -eq $BackupIP) {
            Write-Host "Main IP has changed to Backup IP."
            Log-Change -ChangeType "Switched to Backup IP" -MainIP $BackupIP -BackupIP $currentMainIP -TraceRoute $currentTraceRoute -LogFilePath $LogFilePath
        }
        else {
            Write-Host "Main IP has changed to $currentMainIP."
            Log-Change -ChangeType "Main IP Change" -MainIP $currentMainIP -BackupIP $BackupIP -TraceRoute $currentTraceRoute -LogFilePath $LogFilePath
        }

        return $currentMainIP
    }
    else {
        Write-Host "Main IP has not changed."
        return $PreviousMainIP
    }
}

$backupIP = "10.22.2.2"  # Replace with the backup IP
$mainIP = "10.161.10.5"   # Replace with the main IP
$previousMainIP = $null
$logFilePath = "E:\Scripts\ChangeLog.txt"  # Replace with the desired log file path

while ($true) {
    $previousMainIP = Check-IPChange -PreviousMainIP $previousMainIP -BackupIP $backupIP -LogFilePath $logFilePath
    Start-Sleep -Seconds 60  # Check every 60 seconds (adjust as needed)
}
