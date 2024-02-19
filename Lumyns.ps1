#---------------------- USER SIDE ----------------------
#Allow Running Scripts
#Set-ExecutionPolicy RemoteSigned

#Download the Script
#Invoke-WebRequest https://github.com/martoon123/Lumyns/raw/main/Lumyns%20-%20PowerShell%20Tool.ps1 -OutFile Lumyns.ps1

#Disable Running Scripts
#Set-ExecutionPolicy Restricted



#---------------------- CODE SIDE ----------------------
#Colors
#Title = Magenta
#Menu = Yellow
#Input = Green
#Seperators = DarkGray
#EndOfProcess = Cyan

Write-Host "Please run the tool as Administrator!" -ForegroundColor Red

while($true) {
    Write-Host ""
    Write-Host "Lumyns - IT PowerShell Tool" -ForegroundColor Magenta
    $pwd = Get-Location
    Write-Host "Working Location: " $pwd -ForegroundColor DarkGray
    Write-Host "----------------------------------" -ForegroundColor DarkGray
    systeminfo | findstr /B /C:"Host Name" /B /C:"Domain" /B /C:"OS Name" /B /C:"OS Version" /B /C:"System Manufacturer" /B /C:"System Model" /B /C:"System Type" /B /C:"Total Physical Memory" /B /C:"System Locale" /B /C:"Input Locale" /B /C:"Time Zone"
    Write-Host "----------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "General Menu" -ForegroundColor Magenta
    Write-Host "[1] New Installation - General Configuration and Application Installed" -ForegroundColor Yellow  
    Write-Host "[2] System Details - Installed Apps, Printers, Network Adapaters, etc..." -ForegroundColor Yellow
    Write-Host "[3] Windows Update - Cleanup/Fix/Update." -ForegroundColor Yellow
    Write-Host "[4] Windows Operation System - Repair/Cleanup/Check." -ForegroundColor Yellow
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
        0 { 
            Write-Host "Thank you, see you soon!"
            Exit
        } 
        1 { 
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
            winget install 9WZDNCRD29V9 --source msstore --silent #Install Office 365 (Office) throught Microsoft Store
            winget install Google.Chrome --source winget --silent
            winget install Notepad++.Notepad++ --source winget --silent
            winget install 7zip.7zip --source winget --silent
            Write-Host "The process is completed!" -ForegroundColor Cyan
        } 
        {($_ -eq "2")} {          
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
            Write-Host "The process is completed!" -ForegroundColor Cyan
        }
        3 {
            Write-Host "Stop Windows Update Process" -ForegroundColor Red
            net stop wuauserv
            Write-Host "Clean Windows Update Folder" -ForegroundColor Red
            #rmdir /s "C:\Windows\SoftwareDistribution\Download"
            Remove-Item -LiteralPath "C:\Windows\SoftwareDistribution\Download" -Force -Recurse
            Write-Host "Windows Update Cleanup" -ForegroundColor Red
            cleanmgr /sageset:1 #Choose what to remove on Disk Cleanup
            $(Write-Host "Press any key to continue..." -ForegroundColor Green -NoNewLine; Read-Host)
            #Read-Host -Prompt "Press any key to continue" -ForegroundColor Green | Out-Null
            cleanmgr /sagerun:1 #Force Disk Cleanup
            $(Write-Host "Press any key to continue..." -ForegroundColor Green -NoNewLine; Read-Host)
            Write-Host "Start Windows Update Process" -ForegroundColor Red
            net start wuauserv
            Write-Host "Timeout is for 60 seconds" -ForegroundColor Red
            Timeout /T 60
            Write-Host "Windows Update - Detect Updates Now" -ForegroundColor Red
            wuauclt /detectnow
            Write-Host "The process is completed!" -ForegroundColor Cyan
        }
        4 {
            Write-Host "Repair Windows 10 Using CMD [with SFC Command]" -ForegroundColor Red
            sfc /scannow 
            Write-Host "Check if there are corruptions or not." -ForegroundColor Red
            DISM /Online /Cleanup-Image /CheckHealth
            Write-Host "Scan the corruptions of Windows images." -ForegroundColor Red
            DISM /Online /Cleanup-Image /ScanHealth
            Write-Host "Fix Windows image corruptions." -ForegroundColor Red
            DISM /Online /Cleanup-Image /RestoreHealth /Source:repairSource\install.wim
            Write-Host "The process is completed!" -ForegroundColor Cyan
        }
        "nerv-all" {
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
            Write-Host "The process is completed!" -ForegroundColor Cyan
        }
        "nerv-nas" {
            Write-Host "Installing all packages..." -ForegroundColor Red
            winget install Microsoft.VCRedist.2015+.x64	--source winget --silent
            winget install Microsoft.VCRedist.2015+.x86	--source winget --silent
            wsl --install
            winget install MongoDB.DatabaseTools	--source winget --silent
            winget install MongoDB.Shell	--source winget --silent
            winget install MongoDB.Compass.Full	--source winget --silent
            winget install Docker.DockerDesktop	--source winget --silent
            Write-Host "The process is completed!" -ForegroundColor Cyan
        }
        default { 
            "You entered nothing." 
        } 
    }
    # {($_ -eq "0") -or ($_ -eq "yes")} { "You entered Yes." } 
}