Function Detect-Laptop {
    Param([string]$computer = "localhost")

    $isLaptop = $false

    if (Get-WmiObject -Class win32_systemenclosure -ComputerName $computer | Where-Object { $_.chassistypes -eq 9 -or $_.chassistypes -eq 10 -or $_.chassistypes -eq 14 }) {
        $isLaptop = $true
    }

    if (Get-WmiObject -Class win32_battery -ComputerName $computer) {
        $isLaptop = $true
    }

    $isLaptop
}

if (Detect-Laptop) {
    Write-Output "It's a laptop."
}
else {
    Write-Output "It's not a laptop."
}

Get-CimInstance -ClassName Win32_ComputerSystem
