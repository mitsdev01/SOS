Clear-Host

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

Write-Host "SOS - Workstation Baseline Complete Report"
Write-Output " "
# Instal Common Stuff 
$moduleName = "CommonStuff"
$WarningPreference = "SilentlyContinue"
# Check if the module is installed
if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    #Write-Host "Module '$moduleName' is not installed. Attempting to install..."

    # Attempt to install the module from the PowerShell Gallery
    # This requires administrative privileges
    try {
        Install-Module -Name $moduleName -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
        #Write-Host "Module '$moduleName' installed successfully."
    } catch {
        Write-Error "Failed to install module '$moduleName': $_"
        exit
    }
} else {
    #Write-Host "Module '$moduleName' is already installed."
}
try {
    Import-Module -Name $moduleName -ErrorAction Stop
    #Write-Host "Module '$moduleName' imported successfully."
} catch {
    Write-Error "Failed to import module '$moduleName': $_"
}

Import-Module -Name CommonStuff
Write-Host "Installed Software Report:"
$Software = Get-InstalledSoftware | select DisplayName, DisplayVersion
$Software | ft -HideTableHeaders
Write-Host "Bitlocker Encryption Configuration:"
$BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
        if ($BitLockerVolume.KeyProtector) {
            Write-Host "Recovery ID:" -NoNewLine 
            Write-Host " $($BitLockerVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | ForEach-Object { $_.KeyProtectorId.Trim('{', '}') })"
            Write-Host "Recovery Password:" -NoNewLine
            Write-Host " $($BitLockerVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | Select-Object -ExpandProperty RecoveryPassword)"
        } else {
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            Write-Delayed "Bitlocker disk encryption is not configured." -NewLine:$true
            [Console]::ResetColor()
            [Console]::WriteLine()  
        }
Write-Host " "
$AzureADJoined = ((dsregcmd /status | select-string -Pattern "AzureAdJoined").Line).Trim()
$AzureADJoined
$DomainJoined = ((dsregcmd /status | select-string -Pattern "DomainJoined").Line).Trim()
$DomainJoined
Write-Output " "
$antivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct

# If more than one antivirus product is returned, filter out "Windows Defender"
if ($antivirusProducts.Count -gt 1) {
    $antivirusProduct = $antivirusProducts | Where-Object { $_.displayName -ne "Windows Defender" } | Select-Object -First 1
} else {
    $antivirusProduct = $antivirusProducts | Select-Object -First 1
}

Write-Host "Detected Antivirus: " -NoNewline
# Output the name of the active antivirus product
$antivirusProduct.displayName
Write-Output " "
Read-Host -Prompt "Press Enter to exit..."
