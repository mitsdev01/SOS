############################################################################################################
#                                          Office 365 Installation                                         #
#                                                                                                          #
############################################################################################################
#
$LogFile = "C:\temp\M365-Installation.log"
function Write-Delayed {
    param(
        [string]$Text, 
        [switch]$NewLine = $true,
        [System.ConsoleColor]$Color = [System.ConsoleColor]::White
    )
    $currentColor = [Console]::ForegroundColor
    [Console]::ForegroundColor = $Color
    foreach ($Char in $Text.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 25
    }
    if ($NewLine) {
        [Console]::WriteLine()
    }
    [Console]::ForegroundColor = $currentColor
}

function Write-Log {
    param ([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date) - $Message"
}


# Install Office 365
$O365 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                             HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Microsoft 365 Apps for enterprise - en-us*" }

if ($O365) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    [Console]::Write("Existing Microsoft Office installation found.")
    [Console]::ResetColor()
    [Console]::WriteLine()   
} else {
    $OfficePath = "c:\temp\OfficeSetup.exe"
    if (-not (Test-Path $OfficePath)) {
        $OfficeURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeSetup.exe"
        Write-Delayed "Downloading Microsoft Office 365..." -NewLine:$false
        Invoke-WebRequest -OutFile $OfficePath -Uri $OfficeURL -UseBasicParsing
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $OfficePath).Length
    $ExpectedSize = 7733536 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        Write-Delayed "Installing Microsoft Office 365..." -NewLine:$false
            taskkill /f /im OfficeClickToRun.exe *> $null
            taskkill /f /im OfficeC2RClient.exe *> $null
            Start-Sleep -Seconds 10
            Start-Process -FilePath $OfficePath -Wait
            Start-Sleep -Seconds 15
        if (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "Microsoft 365 Apps for enterprise - en-us"}) {
            Write-Log "Office 365 Installation Completed Successfully."
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            [Console]::Write(" done.")
            [Console]::ResetColor()
            [Console]::WriteLine()  
            Start-Sleep -Seconds 10
            taskkill /f /im OfficeClickToRun.exe *> $null
            taskkill /f /im OfficeC2RClient.exe *> $null
            Remove-Item -Path $OfficePath -force -ErrorAction SilentlyContinue
            } else {
            Write-Log "Office 365 installation failed."
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            [Console]::Write("`nMicrosoft Office 365 installation failed.")
            [Console]::ResetColor()
            [Console]::WriteLine()  
            }   
    }
    else {
        # Report download error
        Write-Log "Office download failed!"
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write("Download failed or file size does not match.")
        [Console]::ResetColor()
        [Console]::WriteLine()
        Start-Sleep -Seconds 10
        Remove-Item -Path $OfficePath -force -ErrorAction SilentlyContinue
    }
}