#---------------------- USER SIDE ----------------------

# SHORT URL: http://tinyurl.com/lumynsps

# Download the Script
# Invoke-WebRequest https://github.com/martoon123/Lumyns/raw/main/Lumyns.ps1 -OutFile Lumyns.ps1

# Allow Running Scripts
# [NEWER]: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Disable Running Scripts
# [NEWER]: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Restricted

#---------------------- CODE SIDE ----------------------
# Colors
# Title = Magenta
# Menu = Yellow
# Input = Green
# Seperators = DarkGray
# EndOfProcess = Cyan

# Exit Program
function ExitProgram {
    Write-Host "Disabled running scripts for your protection!" -ForegroundColor Red
    Set-ExecutionPolicy Restricted #OLDER
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Restricted #NEWER
    Write-Host "Thank you, see you soon!" -ForegroundColor Cyan     
    Exit
}

# General Section
function InstallPackages {
    $doORnot = "";

    Write-Host "Create Lumyns Administrator account with generated password?" -ForegroundColor Red 
    $doORnot = $(Write-Host "Press any key to continue or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    if($doORnot -eq "") {
        $RandomString = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object {[char]$_})
        Write-Output "Generated Password: $RandomString (Make sure to save, modify, or use LAPS!)"
        net user /add Lumyns $RandomString
        net localgroup administrators Lumyns /add
    }

    Write-Host "Set Country/Region, Time Zone, Languages, Display Language to Hebrew and Israel?" -ForegroundColor Red 
    $doORnot = $(Write-Host "Press any key to continue or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    if($doORnot -eq "") {
        Write-Host "Set Country/Region to Hebrew (Israel)" -ForegroundColor Red
        Set-WinSystemLocale he-IL

        Write-Host "Set Time Zone to Israel" -ForegroundColor Red
        Set-TimeZone -Id "Israel Standard Time"
            
        Write-Host "Set Languages Hebrew and English (Default)" -ForegroundColor Red
        Set-WinUserLanguageList en-US,he-IL -Force

        Write-Host "Set Display Language" -ForegroundColor Red
        Set-WinUILanguageOverride -Language en-US
    }

    Write-Host "Download and Update Microsoft Store Library?" -ForegroundColor Red 
    $doORnot = $(Write-Host "Press any key to continue or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    if($doORnot -eq "") {
        Write-Host "Download and update Microsoft Store Library" -ForegroundColor Red
        start ms-windows-store://downloadsandupdates
        $(Write-Host "Press any key to continue..." -ForegroundColor Green -NoNewLine; Read-Host)

        Write-Host "Make sure that the winget link is: https://cdn.winget.microsoft.com/cache" -ForegroundColor Red
        winget source list
    }

    Write-Host "Install device updating software?" -ForegroundColor Red 
    $doORnot = $(Write-Host "Enter your device Type (Lenovo, Dell) or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    switch($doORnot) { 
        "Lenovo" {
            winget install "Lenovo Vantage" --source=msstore --accept-package-agreements --accept-source-agreements
        }
        "Dell" {
            winget install -e --id Dell.CommandUpdate
        }
    }

    Write-Host "Install packages? (Chrome, Notepad++, 7zip)" -ForegroundColor Red 
    $doORnot = $(Write-Host "Press any key to continue or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    if($doORnot -eq "") {
        Write-Host "Installing all packages..." -ForegroundColor Red
        winget install Google.Chrome --source winget --silent
        winget install Notepad++.Notepad++ --source winget --silent
        winget install 7zip.7zip --source winget --silent
    }

    Write-Host "Install Microsoft Office?" -ForegroundColor Red 
    $doORnot = $(Write-Host "Press any key to continue or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    if($doORnot -eq "") { 
        Write-Host "Installing Microsoft Office (Outlook, Word, Excel, PowerPoint, Teams, To Do, Teams)" -ForegroundColor Red
        winget install --id Microsoft.Office --accept-source-agreements
    }

    $(Write-Host "The process is completed, press enter to continue!" -ForegroundColor Cyan -NoNewLine; Read-Host)
}

#Section for Printing System Details
function SystemDetails {
   systeminfo > Systeminfo.txt
    #List of Installed Softwares
    wmic /output:InstalledSoftwareList.txt product get name,version
    #List of Installed Printers
    wmic /output:Printers.txt printer list brief
    #List of connected IP Addresses
    echo "------------------------------- Connected IP Addresses -------------------------------" > IPConfig.txt
    ipconfig /all | findstr /r /c:"IPv4" >> IPConfig.txt
    echo "------------------------------- Connection Profile -------------------------------" >> IPConfig.txt
    Get-NetConnectionProfile >> IPConfig.txt
    #Print IPConfig Command
    echo "------------------------------- ipconfig /all -------------------------------" >> IPConfig.txt
    ipconfig /all >> IPConfig.txt
    $(Write-Host "The process is completed, press enter to continue!" -ForegroundColor Cyan -NoNewLine; Read-Host)
}

#Section for Diagnosing OS configurations and Cleanups
function DiagnoseOperationSystem {
    $doORnot = "";
    Write-Host "Reset Network Adapters configurations?" -ForegroundColor Red 
    $doORnot = $(Write-Host "Press any key to continue or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    if($doORnot -eq "") {
        netsh winsock reset
        netsh int ip reset
        netsh interface ipv4 show neighbors #Show ARP List
        netsh interface ipv4 delete neighbors #Clear ARP List - Ideal for servers
        ipconfig /release
        ipconfig /renew
        ipconfig /flushdns
        ipconfig /registerdns
    }

    Write-Host "Deep Disk Clean Up? (Serious)!" -ForegroundColor Red 
    $doORnot = $(Write-Host "Press any key to continue or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    if($doORnot -eq "") {
        cleanmgr /sageset:1 #Choose what to remove on Disk Cleanup
        $(Write-Host "Press any key to continue..." -ForegroundColor Green -NoNewLine; Read-Host)
        cleanmgr /sagerun:1 #Force Disk Cleanup
        $(Write-Host "Press any key to continue..." -ForegroundColor Green -NoNewLine; Read-Host)
    }

    Write-Host "Manually remove windows updates files from C:\Windows folder? (On your own responsibility!)" -ForegroundColor Red 
    $doORnot = $(Write-Host "Press any key to continue or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    if($doORnot -eq "") {
        Write-Host "Stopping Windows Update Process." -ForegroundColor Red
        net stop wuauserv
        Write-Host "Cleaning Windows Update Folder" -ForegroundColor Red
        Remove-Item -LiteralPath "C:\Windows\SoftwareDistribution\Download" -Force -Recurse
        Write-Host "Starting Windows Update Process." -ForegroundColor Red
        net start wuauserv
    }
     
    Write-Host "Clean Temp folders? both C:\Windows\Temp and %USERPROFILE%\AppData\Local\Temp (On your own responsibility!)" -ForegroundColor Red 
    $doORnot = $(Write-Host "Press any key to continue or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    if($doORnot -eq "") {
        Write-Host "Cleaning Windows Temp Folder" -ForegroundColor Red
        Remove-Item -LiteralPath "C:\Windows\Temp" -Force -Recurse
        Write-Host "Cleaning User Profile Temp Folder" -ForegroundColor Red
        Remove-Item -LiteralPath "%USERPROFILE%\AppData\Local\Temp" -Force -Recurse
    }

    Write-Host "Reset Microsoft Store? (Solves tons of issues!)" -ForegroundColor Red 
    $doORnot = $(Write-Host "Press any key to continue or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    if($doORnot -eq "") {
        wsreset.exe
    }

    Write-Host "Update Microsoft Store Library?" -ForegroundColor Red 
    $doORnot = $(Write-Host "Press any key to continue or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    if($doORnot -eq "") {
        Write-Host "Download and update Microsoft Store Library" -ForegroundColor Red
        start ms-windows-store://downloadsandupdates
        Write-Host "Make sure that the winget link is: https://cdn.winget.microsoft.com/cache" -ForegroundColor Red
        winget source list
        $(Write-Host "Press any key to continue..." -ForegroundColor Green -NoNewLine; Read-Host)
    }
    
    echo Y | winget upgrade
    Write-Host "Upgrade all the applications using winget?" -ForegroundColor Red 
    $doORnot = $(Write-Host "Press any key to continue or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    if($doORnot -eq "") {
        echo Y | winget upgrade --all
        echo Y | winget upgrade
        $(Write-Host "Press any key to continue..." -ForegroundColor Green -NoNewLine; Read-Host)
    }

    Write-Host "Detecting Windows Updates." -ForegroundColor Red
    wuauclt /detectnow

    $(Write-Host "The process is completed, press enter to continue!" -ForegroundColor Cyan -NoNewLine; Read-Host)
}

#Section for Diagnosing and Repairing OS Image
function DiagnoseOperationSystemImage {
	# https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/repair-a-windows-image?view=windows-11
    Write-Host "Repair Windows 10 Using CMD [with SFC Command]" -ForegroundColor Red
    sfc /scannow 
    Write-Host "Check if there are corruptions or not." -ForegroundColor Red
    DISM /Online /Cleanup-Image /CheckHealth
    Write-Host "Scan the corruptions of Windows images." -ForegroundColor Red
    DISM /Online /Cleanup-Image /ScanHealth
    Write-Host "Fix Windows image corruptions." -ForegroundColor Red
    DISM /Online /Cleanup-Image /RestoreHealth
    $(Write-Host "The process is completed, press enter to continue!" -ForegroundColor Cyan -NoNewLine; Read-Host)
	
	Write-Host "Run check disk and fix? This might happen on the next restart." -ForegroundColor Red 
    $doORnot = $(Write-Host "Press any key to continue or 'x' to skip... Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)
    if($doORnot -eq "") {
		echo Y | chkdsk /f
	}
}

function Test-NetworkPing {
    param (
        [string]$TargetIP = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | 
                             Select-Object -ExpandProperty IPv4DefaultGateway | Select-Object -First 1).NextHop,
        [int]$MaxPacketSize = 65500,  # Maximum allowed packet size for ICMP
        [int]$PingCount = 5           # Number of ping attempts
    )

    # Define log file path in the same location as the script
    $LogFile = "$PSScriptRoot\network_ping_log.txt"

    $LogMessages = @()

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $TestMessage = "$Timestamp - Testing connection to: $TargetIP"
    Write-Host $TestMessage -ForegroundColor Magenta
    $LogMessages += $TestMessage

    $PingResult = Test-Connection -ComputerName $TargetIP -Count $PingCount -BufferSize $MaxPacketSize -ErrorAction SilentlyContinue
        
    if ($PingResult) {
        $ReceivedPackets = ($PingResult | Where-Object { $_.ResponseTime -ne $null }).Count
        $LostPackets = $PingCount - $ReceivedPackets
        $AvgLatency = ($PingResult | Measure-Object -Property ResponseTime -Average).Average

        # Conditional formatting for Packet Loss output
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        if ($LostPackets -gt 0) {
            $PacketMessage = "$Timestamp - Packet Loss: 		❌ $LostPackets out of $PingCount"
            Write-Host $PacketMessage -ForegroundColor Red
        } else {
            $PacketMessage = "$Timestamp - Packet Loss: 		✅ $LostPackets out of $PingCount"
            Write-Host $PacketMessage -ForegroundColor Green
        }
        $LogMessages += $PacketMessage

        # Conditional formatting for Latency output
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        if ($AvgLatency -le 1) {
            $LatencyMessage = "$Timestamp - Average Latency:		✅  $AvgLatency ms (Excellent)"
            Write-Host $LatencyMessage -ForegroundColor Green
        } elseif ($AvgLatency -gt 1 -and $AvgLatency -le 5) {
            $LatencyMessage = "$Timestamp - Average Latency:		⚠️ $AvgLatency ms (Acceptable)"
            Write-Host $LatencyMessage -ForegroundColor Cyan
        } elseif ($AvgLatency -gt 5 -and $AvgLatency -le 20) {
            $LatencyMessage = "$Timestamp - Average Latency:		📉 ️ $AvgLatency ms (Poor)"
            Write-Host $LatencyMessage -ForegroundColor Yellow
        } else {
            $LatencyMessage = "$Timestamp - Average Latency:		❌  $AvgLatency ms (Critical)"
            Write-Host $LatencyMessage -ForegroundColor Red
        }
        $LogMessages += $LatencyMessage
    } else {
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $FailMessage = "$Timestamp - ❌ Failed to ping $TargetIP"
        Write-Host $FailMessage -ForegroundColor Red
        $LogMessages += $FailMessage
    }

    # Save all messages to the log file
    $LogMessages | Out-File -Append -FilePath $LogFile
}

function Test-SystemUsage {
    # Define log file path in the same location as the script
    $LogFile = "$PSScriptRoot\system_usage_log.txt"
    $LogMessages = @()

    # Get timestamp
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	
	# Print Testing System Usage Message
    Write-Host "$Timestamp - Testing System Usage" -ForegroundColor Magenta
    
	# === Memory Usage ===
    $Memory = Get-CimInstance Win32_OperatingSystem
    $TotalMemory = $Memory.TotalVisibleMemorySize
    $FreeMemory = $Memory.FreePhysicalMemory
	$UsedMemoryPercentage = [int]((($TotalMemory - $FreeMemory) / $TotalMemory) * 100)
	
    if ($UsedMemoryPercentage -gt 75) {
        $MemoryMessage = "$Timestamp - Memory Usage: 		❌ $UsedMemoryPercentage% (Above 75%)"
        Write-Host $MemoryMessage -ForegroundColor Red
    } else {
        $MemoryMessage = "$Timestamp - Memory Usage: 		✅ $UsedMemoryPercentage% (Below 75%)"
        Write-Host $MemoryMessage -ForegroundColor Green
    }
    $LogMessages += $MemoryMessage

    # === CPU Usage ===
    $CPUUsage = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
    $CPUUsage = [math]::Round($CPUUsage)

    if ($CPUUsage -gt 75) {
        $CpuMessage = "$Timestamp - CPU Usage: 		❌ $CPUUsage% (Above 75%)"
        Write-Host $CpuMessage -ForegroundColor Red
    } else {
        $CpuMessage = "$Timestamp - CPU Usage: 		✅ $CPUUsage% (Below 75%)"
        Write-Host $CpuMessage -ForegroundColor Green
    }
    $LogMessages += $CpuMessage

    # Top CPU-consuming processes
    $TotalProcessorTime = (Get-Process | Measure-Object -Property CPU -Sum).Sum
    $TopProcesses = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
    $ProcessLine = ($TopProcesses | ForEach-Object { 
        $ProcessUsage = [math]::Round(($_.CPU / $TotalProcessorTime) * $CPUUsage, 2)
        "$($_.ProcessName): $ProcessUsage%"
    }) -join " | "
    $ProcessMessage = "$Timestamp - CPU Processes: 		$ProcessLine"
    Write-Host $ProcessMessage
    $LogMessages += $ProcessMessage

    # Save all messages to the log file
    $LogMessages | Out-File -Append -FilePath $LogFile
}

#Section for Log Performance
function LogPerformance {
    # Inputted IP
    $UserIP = $(Write-Host "Enter the Server IP Address: " -ForegroundColor Green -NoNewLine; Read-Host)

    while ($true) {
        Test-NetworkPing    # Test default gateway
        Test-NetworkPing -TargetIP $UserIP
        Test-SystemUsage
        Write-Host ""
        #Start-Sleep -Seconds 1  # Adjust interval as needed
    }
}

# Menu and Loop
function DisplayMenu {
    while($true) {
        Clear-Host
        Write-Host "PLEASE RUN THE TOOL AS ADMINISTRATOR!" -ForegroundColor Red
        Write-Host ""
        Write-Host "PowerShell Tool [Version: 19.05.2025] ©LiadSmart" -ForegroundColor Magenta
        $pwd = Get-Location
        Write-Host "Working Location: " $pwd -ForegroundColor DarkGray
        Write-Host "----------------------------------" -ForegroundColor DarkGray
        systeminfo | findstr /B /C:"Host Name" /B /C:"Domain" /B /C:"OS Version" /B /C:"System Manufacturer" /B /C:"System Model"
        
        $OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
        if ($OSVersion -match "Windows 10|Windows 11") {
            Write-Host "OS Name:                   ✅ $OSVersion" -ForegroundColor Green
        } else {
            Write-Host "OS Name:                   ❌ $OSVersion" -ForegroundColor Red
        }

        $SystemLocale = (Get-WinSystemLocale).Name
        if ($SystemLocale -eq "he-IL") {
            Write-Host "System Locale (Unicode):   ✅ $SystemLocale" -ForegroundColor Green
        } else {
            Write-Host "System Locale (Unicode):   ❌$SystemLocale - Change to Hebrew (Israel)" -ForegroundColor Red
        }

        # Time Zone (UTC+02:00) Jerusalem
        $TimeZone = Get-TimeZone
        if ($TimeZone.Id -eq "Israel Standard Time") {
            Write-Host "Time Zone:                 ✅ $($TimeZone)" -ForegroundColor Green
        } else {
            Write-Host "Time Zone:                 ❌ $($TimeZone) Change to (UTC+02:00) Jerusalem" -ForegroundColor Red
        }

        # System Type 64x or 32x
        $SystemType = (Get-CimInstance Win32_ComputerSystem).SystemType
        if ($SystemType -eq "x64-based PC") {
            Write-Host "System Type:               ✅ $SystemType" -ForegroundColor Green
        } else {
            Write-Host "System Type:               ❌ $SystemType" -ForegroundColor Red
        }

        # Total Memory
        $TotalMemory = [int]((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
        if ($TotalMemory -lt 8000) {
            Write-Host "Total Physical Memory:     ❌ $TotalMemory MB (Critical Memory)" -ForegroundColor Red
        } elseif ($TotalMemory -lt 12000) {
            Write-Host "Total Physical Memory:     ⚠️ $TotalMemory MB (Bad Memory)" -ForegroundColor Orange
        } elseif ($TotalMemory -lt 16000) {
            Write-Host "Total Physical Memory:     ! $TotalMemory MB (Moderate Memory)" -ForegroundColor Yellow
        } elseif ($TotalMemory -lt 32000) {
            Write-Host "Total Physical Memory:     ✅ $TotalMemory MB (Good Memory)" -ForegroundColor Green
        } else {
            Write-Host "Total Physical Memory:     ✅ $TotalMemory MB (Very Good Memory)" -ForegroundColor Green
        }

		# Memory Usage
        $Memory = Get-CimInstance Win32_OperatingSystem
        $TotalMemory = $Memory.TotalVisibleMemorySize
        $FreeMemory = $Memory.FreePhysicalMemory
        $UsedMemoryPercentage = [int]((($TotalMemory - $FreeMemory) / $TotalMemory) * 100)
        if ($UsedMemoryPercentage -gt 75) {
            Write-Host "Memory Usage:              ❌ $UsedMemoryPercentage% (Above 75%)" -ForegroundColor Red
        } else {
            Write-Host "Memory Usage:              ✅ $UsedMemoryPercentage% (Below 75%)" -ForegroundColor Green
        }

		# CPU Usage
        $CPU = Get-CimInstance Win32_Processor
        $CPUUsage = [math]::Round($CPU.LoadPercentage)
        if ($CPUUsage -gt 75) {
            Write-Host "CPU Usage:                 ❌ $CPUUsage% (Above 75%)" -ForegroundColor Red
        } else {
            Write-Host "CPU Usage:                 ✅ $CPUUsage% (Below 75%)" -ForegroundColor Green
        }

        Write-Host "----------------------------------" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "General Menu" -ForegroundColor Magenta
        Write-Host "[1] New Installation - General Configuration and Application Installed" -ForegroundColor Yellow  
        Write-Host "[2] System Details - Installed Apps, Printers, Network Adapters, etc..." -ForegroundColor Yellow
        Write-Host "[3] Diagnose Operation System (Network Adapters, Microsoft Store, Disk Cleanup, Windows Updates, etc...)" -ForegroundColor Yellow
        Write-Host "[4] Diagnose Operation System Image Files" -ForegroundColor Yellow
        Write-Host "[5] Log Performance" -ForegroundColor Yellow
        Write-Host "[0] Exit" -ForegroundColor Yellow
        Write-Host ""

        # Prompt for a string input
        $menu = $(Write-Host "Enter your choice: " -ForegroundColor Green -NoNewLine; Read-Host)

        Write-Host ""
        Write-Host ">>>>>>>>>> Output <<<<<<<<<" -ForegroundColor Magenta
        Write-Host "----------------------------------" -ForegroundColor DarkGray
        switch($menu) { 
            0 { ExitProgram } 
            1 { InstallPackages }
            2 { SystemDetails }
            3 { DiagnoseOperationSystem }
            4 { DiagnoseOperationSystemImage }
            5 { LogPerformance }
            #default { "You entered nothing." } 
        }
    }
}

DisplayMenu