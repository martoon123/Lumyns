#---------------------- USER SIDE ----------------------

# SHORT URL: http://tinyurl.com/lumynsps

# Allow Running Scripts
# [OLDER]: Set-ExecutionPolicy RemoteSigned
# [NEWER]: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Download the Script
# Invoke-WebRequest https://github.com/martoon123/Lumyns/raw/main/Lumyns.ps1 -OutFile Lumyns.ps1

# Disable Running Scripts
# [OLDER]: Set-ExecutionPolicy Restricted
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
        winget install --id Microsoft.Office
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
        netsh interface ipv4 delete neighbors #Clear ARP List
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
		chkdsk /f
	}
}

#Nervio General Section
function NervioAll {
    Write-Host "Set Country/Region to Hebrew (Israel)" -ForegroundColor Red
    Set-WinSystemLocale he-IL

    Write-Host "Set Time Zone to Israel" -ForegroundColor Red
    Set-TimeZone -Id "Israel Standard Time"
            
    Write-Host "Set Languages Hebrew and English (Default)" -ForegroundColor Red
    Set-WinUserLanguageList en-US,he-IL -Force

    Write-Host "Set Display Language" -ForegroundColor Red
    Set-WinUILanguageOverride -Language en-US

    Write-Host "Download and update Microsoft Store Library" -ForegroundColor Red
    start ms-windows-store://downloadsandupdates
    $(Write-Host "Press any key to continue..." -ForegroundColor Green -NoNewLine; Read-Host)

    Write-Host "Make sure that the winget link is: https://cdn.winget.microsoft.com/cache" -ForegroundColor Red
    winget source list
    $(Write-Host "Press any key to continue..." -ForegroundColor Green -NoNewLine; Read-Host)

    Write-Host "Installing all packages..." -ForegroundColor Red
    winget install Microsoft.PowerShell --source winget --silent
    winget install Microsoft.WindowsTerminal --source winget --silent
    winget install --id=RustDesk.RustDesk --exact --source winget --silent
    winget install Microsoft.PowerToys --source winget --silent
    winget install Notepad++.Notepad++ --source winget --silent
    winget install 7zip.7zip --source winget --silent
    winget install ShareX.ShareX --source winget --silent
    winget install Microsoft.Teams --source winget --silent
    $(Write-Host "The process is completed, press enter to continue!" -ForegroundColor Cyan -NoNewLine; Read-Host)
}

#Nervio NAS Section
function NervioNas {
    Write-Host "Installing all packages..." -ForegroundColor Red
    winget install Microsoft.VCRedist.2015+.x64	--source winget --silent
    winget install Microsoft.VCRedist.2015+.x86	--source winget --silent
    wsl --install
    winget install MongoDB.DatabaseTools	--source winget --silent
    winget install MongoDB.Shell	--source winget --silent
    winget install MongoDB.Compass.Full	--source winget --silent
    winget install Docker.DockerDesktop	--source winget --silent
    $(Write-Host "The process is completed, press enter to continue!" -ForegroundColor Cyan -NoNewLine; Read-Host)    
}

# Menu and Loop
function DisplayMenu {
    while($true) {
        Clear-Host
        Write-Host "Please run the tool as Administrator!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Lumyns - IT PowerShell Tool [Version: 25.04.2024]" -ForegroundColor Magenta
        $pwd = Get-Location
        Write-Host "Working Location: " $pwd -ForegroundColor DarkGray
        Write-Host "----------------------------------" -ForegroundColor DarkGray
        systeminfo | findstr /B /C:"Host Name" /B /C:"Domain" /B /C:"OS Name" /B /C:"OS Version" /B /C:"System Manufacturer" /B /C:"System Model" /B /C:"System Type" /B /C:"Total Physical Memory" /B /C:"System Locale" /B /C:"Input Locale" /B /C:"Time Zone"
        Write-Host "----------------------------------" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "General Menu" -ForegroundColor Magenta
        Write-Host "[1] New Installation - General Configuration and Application Installed" -ForegroundColor Yellow  
        Write-Host "[2] System Details - Installed Apps, Printers, Network Adapters, etc..." -ForegroundColor Yellow
        Write-Host "[3] Diagnose Operation System (Network Adapters, Microsoft Store, Disk Cleanup, Windows Updates, etc...)" -ForegroundColor Yellow
        Write-Host "[4] Diagnose Operation System Image Files" -ForegroundColor Yellow
        Write-Host "[0] Exit" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Nervio Menu" -ForegroundColor Magenta
        Write-Host "----------------------------------" -ForegroundColor DarkGray
        Write-Host "[nerv-all] Configuration for general workstation." -ForegroundColor Yellow
        Write-Host "[nerv-nas] Configuration for NAS workstation." -ForegroundColor Yellow
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
            "nerv-all" { NervioAll }
            "nerv-nas" { NervioNas }
            #default { "You entered nothing." } 
        }
    }
}

DisplayMenu