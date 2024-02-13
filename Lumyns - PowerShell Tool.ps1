#---------------------- USER SIDE ----------------------
#Allow Running Scripts
#Set-ExecutionPolicy RemoteSigned

#Disable Running Scripts
#Set-ExecutionPolicy Restricted

#Download the Script
#Invoke-WebRequest https://github.com/martoon123/Lumyns/raw/main/Lumyns%20-%20PowerShell%20Tool.ps1 -OutFile Lumyns.ps1



#---------------------- CODE SIDE ----------------------
#Colors
#Title = Magenta
#Menu = Yellow
#Input = Green
#Seperators = DarkGray
#EndOfProcess = Cyan

$hostname = hostname

while($true) {
    Write-Host ""
    Write-Host "Lumyns - IT PowerShell Tool" -ForegroundColor Magenta
    Write-Host "----------------------------------" -ForegroundColor DarkGray
    systeminfo | findstr /B /C:"Host Name" /B /C:"Domain" /B /C:"OS Name" /B /C:"OS Version" /B /C:"System Manufacturer" /B /C:"System Model" /B /C:"System Type" /B /C:"Total Physical Memory" /B /C:"System Locale" /B /C:"Input Locale" /B /C:"Time Zone"
    Write-Host "----------------------------------" -ForegroundColor DarkGray
    $pwd = Get-Location
    Write-Host "Working Location: " $pwd
    Write-Host "----------------------------------" -ForegroundColor DarkGray
    Write-Host "Menu" -ForegroundColor Magenta
    Write-Host "1. System Details - Installed Apps, Printers, Network Adapaters, etc..." -ForegroundColor Yellow
    Write-Host "2. Windows Update - Cleanup/Fix/Update." -ForegroundColor Yellow
    Write-Host "3. Windows Operation System - Repair/Cleanup/Check." -ForegroundColor Yellow
    Write-Host "0. Exit" -ForegroundColor Yellow
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
        {($_ -eq "1")} {          
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
        2 {
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
        3 {
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
        default { 
            "You entered nothing." 
        } 
    }
    # {($_ -eq "0") -or ($_ -eq "yes")} { "You entered Yes." } 
}