############################################################################################################
#                                     SOS - Workstation Baseline Verification                               #
#                                                 Version 1.1.0                                             #
############################################################################################################
#region Synopsis
<#
.SYNOPSIS
    Verifies and displays the configuration status of a workstation after baseline setup.

.DESCRIPTION
    This script provides a comprehensive verification report for Windows workstations, including:
    - System information (OS, uptime, installation date)
    - Installed software inventory
    - BitLocker encryption status and recovery keys
    - Domain/Azure AD join status
    - Security status (antivirus, Windows Update)
    - Power configuration
    - Overall baseline compliance score

    It displays detailed information with color-coded status indicators for quick assessment.

.PARAMETER None
    This script does not accept parameters.

.NOTES
    Version:        1.1.0
    Author:         Bill Ulrich
    Creation Date:  3/25/2025
    Requires:       Administrator privileges
                    Windows 10/11 Professional
                    CommonStuff PowerShell module
    
.EXAMPLE
    .\BaselineComplete.ps1
    
    Run the script with administrator privileges to generate a comprehensive baseline verification report.

.LINK
    https://github.com/mitsdev01/SOS
#>

Clear-Host

$ScriptVersion = "1.1.0"
$ProgressPreference = "SilentlyContinue" 
$WarningPreference = "SilentlyContinue"
$ErrorActionPreference = "Continue"

function Print-Middle($Message, $Color = "White") {
    # Get the console width
    $consoleWidth = [System.Console]::BufferWidth
    
    # Calculate padding - ensure it doesn't result in negative numbers
    $padding = [Math]::Max(0, [Math]::Floor(($consoleWidth / 2) - ($Message.Length / 2)))
    
    # Create padded string
    $paddedMessage = " " * $padding + $Message
    
    # Ensure we don't exceed buffer width
    if ($paddedMessage.Length -gt $consoleWidth) {
        $paddedMessage = $paddedMessage.Substring(0, $consoleWidth - 1)
    }
    
    # Output with given color
    Write-Host $paddedMessage -ForegroundColor $Color
}


# Title Display using Print-Middle
$Padding = ("=" * [System.Console]::BufferWidth)
Write-Host -ForegroundColor Green $Padding
Print-Middle "SOS - Workstation Baseline Verification" "Yellow"
Print-Middle "Version $ScriptVersion" "Yellow"
Write-Host -ForegroundColor Green $Padding
Write-Host ""

# Check definitions status early
Write-Host "Definitions: " -NoNewline
try {
    $avCheck = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop | Select-Object -First 1
    if ($avCheck) {
        # Decode status based on SecurityCenter2 standard codes
        $statusCode = $avCheck.productState
        $statusHex = $statusCode.ToString("X6")
        $dStatus = $statusHex.Substring(4, 2)
        
        $upToDate = if ($dStatus -eq "00") { $true } else { $false }
        
        if ($upToDate) {
            Write-Host "Up to date" -ForegroundColor Green
        }
        else {
            Write-Host "Out of date" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Unknown" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "Unknown" -ForegroundColor Yellow
}

# Function definitions
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

function Write-TaskComplete {
    Start-Sleep -Milliseconds 500
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
}

function Write-TaskFailed {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" failed.")
    [Console]::ResetColor()
    [Console]::WriteLine()
}

function Write-SectionHeader {
    param (
        [string]$Title
    )
    
    Write-Host "`n"
    $headerLine = "-" * [System.Console]::BufferWidth
    Write-Host -ForegroundColor Green $headerLine
    Print-Middle $Title "Yellow"
    Write-Host -ForegroundColor Green $headerLine
}

# Add the required Win32 API functions
Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    
    namespace Win32 {
        public class User32 {
            [DllImport("user32.dll", SetLastError = true)]
            public static extern bool SetWindowPos(IntPtr hWnd, int hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
        }
    }
"@ -ErrorAction SilentlyContinue

function Move-ProcessWindowToTopRight {
    param (
        [Parameter(Mandatory = $true)]
        [string]$processName
    )
    
    try {
        Add-Type -AssemblyName System.Windows.Forms
        
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
        $processes = Get-Process | Where-Object { $_.ProcessName -eq $processName }
        
        foreach ($process in $processes) {
            $hwnd = $process.MainWindowHandle
            if ($hwnd -eq [IntPtr]::Zero) { continue }
            
            $x = $screen.Right - 800
            $y = $screen.Top
            
            [void][Win32.User32]::SetWindowPos($hwnd, -1, $x, $y, 800, 600, 0x0040)
        }
    }
    catch {
        Write-Host "Warning: Could not position window - $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Show-SpinningWait {
    param (
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$DoneMessage = "done."
    )
    
    Write-Delayed "$Message" -NewLine:$false
    $spinner = @('/', '-', '\', '|')
    $spinnerIndex = 0
    $jobName = [Guid]::NewGuid().ToString()
    
    # Start the script block as a job
    $job = Start-Job -Name $jobName -ScriptBlock $ScriptBlock
    
    # Display spinner while job is running
    while ($job.State -eq 'Running') {
        [Console]::Write($spinner[$spinnerIndex])
        Start-Sleep -Milliseconds 50
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    }
    
    # Get the job result
    $result = Receive-Job -Name $jobName
    Remove-Job -Name $jobName
    
    # Replace spinner with done message
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write($DoneMessage)
    [Console]::ResetColor()
    [Console]::WriteLine()
    
    return $result
}

# Replace the Set-SafeCursorPosition function with this simpler spinner implementation
function Show-SimpleSpinner {
    param (
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,
        [int]$Milliseconds = 100
    )
    
    # Spinner characters
    $spinner = @('/', '-', '\', '|')
    $spinnerIndex = 0
    
    # Start the script block as a job
    $jobName = [Guid]::NewGuid().ToString()
    $null = Start-Job -Name $jobName -ScriptBlock $ScriptBlock
    
    # Display spinner while job is running
    while ((Get-Job -Name $jobName).State -eq 'Running') {
        Write-Host "`r$($spinner[$spinnerIndex])" -NoNewline
        Start-Sleep -Milliseconds $Milliseconds
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    }
    
    # Clear the spinner
    Write-Host "`r " -NoNewline
    Write-Host "`r" -NoNewline
    
    # Get the job result
    $result = Receive-Job -Name $jobName
    Remove-Job -Name $jobName -Force
    
    return $result
}

function dattoInstalled {
    if (Test-Path "C:\Program Files (x86)\CentraStage\CagService.exe") {
        return $true
    }
    else {
        return $false
    }
}

# Main Script Logic
# Install and import CommonStuff module
$moduleNames = @("CommonStuff", "FancyClearHost")
Write-Host "Checking for required modules..." -NoNewline

try {
    foreach ($moduleName in $moduleNames) {
        # Check if the module is installed
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Install-Module -Name $moduleName -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop | Out-Null
        }
        
        # Import the module
        Import-Module -Name $moduleName -ErrorAction Stop
    }
    Write-TaskComplete
}
catch {
    Write-TaskFailed
    Write-Host "Error: Failed to install/import module '$moduleName': $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Some reporting features may not be available." -ForegroundColor Yellow
}

# System Information
Write-SectionHeader "System Information"

Write-Host "Collecting system information..." -NoNewline
$spinnerIndex = 0
$spinner = @('/', '-', '\', '|')

try {
    # Show spinner while collecting data
    for ($i = 0; $i -lt 10; $i++) {
        Write-Host "`b$($spinner[$spinnerIndex % 4])" -NoNewline
        $spinnerIndex++
        Start-Sleep -Milliseconds 100
    }
    
    # Collect data
    $computerInfo = Get-ComputerInfo
    $os = $computerInfo.OsName + " " + $computerInfo.OsVersion
    $installDate = $computerInfo.OsInstallDate
    $lastBoot = $computerInfo.OsLastBootUpTime
    $uptime = (Get-Date) - $lastBoot
    
    $formattedUptime = "{0} days, {1} hours, {2} minutes" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
    
    # Clear the spinner and write output on a new line
    Write-Host "`b " -NoNewline
    Write-Host " " -ForegroundColor Green
    
    Write-Host "Computer Name: " -NoNewline
    Write-Host $env:COMPUTERNAME -ForegroundColor Green
    Write-Host "Operating System: " -NoNewline
    Write-Host $os -ForegroundColor Green
    Write-Host "OS Install Date: " -NoNewline
    Write-Host $installDate -ForegroundColor Green
    Write-Host "Last Boot: " -NoNewline
    Write-Host $lastBoot -ForegroundColor Green
    Write-Host "Uptime: " -NoNewline
    Write-Host $formattedUptime -ForegroundColor Green
}
catch {
    # Clear the spinner and show error
    Write-Host "`b " -NoNewline
    Write-Host " ERROR" -ForegroundColor Red
    Write-Host "Could not retrieve complete system information: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Installed Software
Write-SectionHeader "Installed Software Report"

Write-Host "Collecting software information..." -NoNewline
$spinnerIndex = 0

try {
    # Show spinner while collecting data
    for ($i = 0; $i -lt 8; $i++) {
        Write-Host "`b$($spinner[$spinnerIndex % 4])" -NoNewline
        $spinnerIndex++
        Start-Sleep -Milliseconds 100
    }
    
    $Software = Get-InstalledSoftware | Where-Object { $_.DisplayName -ne $null } | 
                Select-Object DisplayName, DisplayVersion |
                Sort-Object DisplayName
    
    # Clear the spinner and write output on a new line
    Write-Host "`b " -NoNewline
    Write-Host " " -ForegroundColor Green
    
    # Create a clean table without any headers
    $format = "{0,-50} {1,-25}"
    
    # Print a divider line at the beginning
    Write-Host ""
    
    # Skip the headers and separator lines - go straight to content
    $Software | ForEach-Object {
        Write-Host $($format -f $_.DisplayName, $_.DisplayVersion)
    }
    
    if ($Software.Count -gt 15) {
        Write-Host "...and $($Software.Count - 15) more applications" -ForegroundColor Gray
    }
}
catch {
    # Clear the spinner and show error
    Write-Host "`b " -NoNewline
    Write-Host " ERROR" -ForegroundColor Red
    Write-Host "Error retrieving installed software: $($_.Exception.Message)" -ForegroundColor Red
}

# BitLocker Status
Write-SectionHeader "BitLocker Encryption Configuration"

Write-Host "Checking BitLocker status..." -NoNewline
$spinnerIndex = 0

try {
    # Show spinner while collecting data
    for ($i = 0; $i -lt 6; $i++) {
        Write-Host "`b$($spinner[$spinnerIndex % 4])" -NoNewline
        $spinnerIndex++
        Start-Sleep -Milliseconds 100
    }
    
    $BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    
    # Clear the spinner and write output on a new line
    Write-Host "`b " -NoNewline
    Write-Host " " -ForegroundColor Green
    
    if ($BitLockerVolume.ProtectionStatus -eq "On") {
        Write-Host "BitLocker Status: " -NoNewline
        Write-Host "ENABLED" -ForegroundColor Green
        
        $recoveryId = $BitLockerVolume.KeyProtector | 
            Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'} | 
            ForEach-Object { $_.KeyProtectorId.Trim('{', '}') }
        
        $recoveryPassword = $BitLockerVolume.KeyProtector | 
            Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'} | 
            Select-Object -ExpandProperty RecoveryPassword
        
        Write-Host "Recovery ID: " -NoNewline
        Write-Host $recoveryId -ForegroundColor Cyan
        Write-Host "Recovery Password: " -NoNewline
        Write-Host $recoveryPassword -ForegroundColor Cyan
        Write-Host "Encryption Method: " -NoNewline
        Write-Host $BitLockerVolume.EncryptionMethod -ForegroundColor Cyan
        Write-Host "Encryption Percentage: " -NoNewline
        Write-Host "$($BitLockerVolume.EncryptionPercentage)%" -ForegroundColor Cyan
    }
    else {
        Write-Host "BitLocker Status: " -NoNewline
        Write-Host "NOT ENABLED" -ForegroundColor Red
        Write-Host "Protection Status: $($BitLockerVolume.ProtectionStatus)"
    }
}
catch {
    # Clear the spinner and show error
    Write-Host "`b " -NoNewline
    Write-Host " ERROR" -ForegroundColor Red
    Write-Host "Error retrieving BitLocker status: $($_.Exception.Message)" -ForegroundColor Red
}

# Domain/Azure AD Status
Write-SectionHeader "Network Authentication Status"

Write-Host "Checking domain status..." -NoNewline
$spinnerIndex = 0

try {
    # Show spinner while collecting data
    for ($i = 0; $i -lt 8; $i++) {
        Write-Host "`b$($spinner[$spinnerIndex % 4])" -NoNewline
        $spinnerIndex++
        Start-Sleep -Milliseconds 100
    }
    
    # Clear the spinner and write output on a new line
    Write-Host "`b " -NoNewline
    Write-Host " " -ForegroundColor Green
    
    # Get Domain Join Status
    Write-Host "Domain Status" -ForegroundColor Cyan
    
    $dsregOutput = dsregcmd /status
    $AzureADJoined = (($dsregOutput | Select-String -Pattern "AzureAdJoined").Line).Trim()
    $DomainJoined = (($dsregOutput | Select-String -Pattern "DomainJoined").Line).Trim()
    
    Write-Host "Domain Joined: " -NoNewline
    if ($DomainJoined -like "*YES*") {
        Write-Host "YES" -ForegroundColor Green
        $domainName = (Get-WmiObject Win32_ComputerSystem).Domain
        Write-Host "Domain Name: $domainName"
    }
    else {
        Write-Host "NO" -ForegroundColor Yellow
    }
    
    Write-Host "Azure AD Joined: " -NoNewline
    if ($AzureADJoined -like "*YES*") {
        Write-Host "YES" -ForegroundColor Green
        $tenantName = (($dsregOutput | Select-String -Pattern "TenantName").Line).Trim()
        Write-Host $tenantName
    }
    else {
        Write-Host "NO" -ForegroundColor Yellow
    }
}
catch {
    # Clear the spinner and show error
    Write-Host "`b " -NoNewline
    Write-Host " ERROR" -ForegroundColor Red
    Write-Host "Error retrieving domain/Azure AD information: $($_.Exception.Message)" -ForegroundColor Red
}

# Security Status
Write-SectionHeader "Security Status"

Write-Host "Checking antivirus status..." -NoNewline
$spinnerIndex = 0

try {
    # Show spinner while collecting data
    for ($i = 0; $i -lt 8; $i++) {
        Write-Host "`b$($spinner[$spinnerIndex % 4])" -NoNewline
        $spinnerIndex++
        Start-Sleep -Milliseconds 100
    }
    
    # Clear the spinner and write output on a new line
    Write-Host "`b " -NoNewline
    Write-Host " " -ForegroundColor Green
    
    # Antivirus Products
    Write-Host "Antivirus Products" -ForegroundColor Cyan
    $antivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop
    
    if ($antivirusProducts) {
        foreach ($av in $antivirusProducts) {
            Write-Host "Product: " -NoNewline
            Write-Host $av.displayName -ForegroundColor Green
            
            # Decode status based on SecurityCenter2 standard codes
            $statusCode = $av.productState
            $statusHex = $statusCode.ToString("X6")
            $eStatus = $statusHex.Substring(0, 2)
            $rStatus = $statusHex.Substring(2, 2)
            $dStatus = $statusHex.Substring(4, 2)
            
            $enabled = if ($eStatus -eq "10") { $true } else { $false }
            $upToDate = if ($dStatus -eq "00") { $true } else { $false }
            
            Write-Host "Status: " -NoNewline
            if ($enabled) {
                Write-Host "Enabled" -ForegroundColor Green
            }
            else {
                Write-Host "Disabled" -ForegroundColor Red
            }
            
            Write-Host "Definitions: " -NoNewline
            if ($upToDate) {
                Write-Host "Up to date" -ForegroundColor Green
            }
            else {
                Write-Host "Out of date" -ForegroundColor Red
            }
            Write-Host ""
        }
    }
    else {
        Write-Host "No antivirus products detected!" -ForegroundColor Red
    }
}
catch {
    # Clear the spinner and show error
    Write-Host "`b " -NoNewline
    Write-Host " ERROR" -ForegroundColor Red
    Write-Host "Error retrieving antivirus information: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Windows Update section
Write-SectionHeader "Windows Update Status"
Write-Host "Checking for Windows Updates..." -NoNewline
$spinnerIndex = 0

try {
    # Show spinner while collecting data
    for ($i = 0; $i -lt 6; $i++) {
        Write-Host "`b$($spinner[$spinnerIndex % 4])" -NoNewline
        $spinnerIndex++
        Start-Sleep -Milliseconds 100
    }
    
    # Collect Windows Update data
    $updateService = Get-Service -Name wuauserv
    $updatesSession = $null
    $pendingUpdates = $null
    
    if ($updateService.Status -eq "Running") {
        try {
            $updatesSession = New-Object -ComObject Microsoft.Update.Session
            $updatesSearcher = $updatesSession.CreateUpdateSearcher()
            
            # Continue spinner while searching for updates
            for ($i = 0; $i -lt 10; $i++) {
                Write-Host "`b$($spinner[$spinnerIndex % 4])" -NoNewline
                $spinnerIndex++
                Start-Sleep -Milliseconds 100
            }
            
            $pendingUpdates = $updatesSearcher.Search("IsInstalled=0").Updates
        }
        catch {
            # Just capture the error but continue with the script
            $updateError = $_.Exception.Message
        }
    }
    
    # Clear the spinner and write output on a new line
    Write-Host "`b " -NoNewline
    Write-Host " " -ForegroundColor Green
    
    Write-Host "Windows Update Service: " -NoNewline
    if ($updateService.Status -eq "Running") {
        Write-Host "Running" -ForegroundColor Green
    }
    else {
        Write-Host $updateService.Status -ForegroundColor Red
    }
    
    Write-Host "Startup Type: " -NoNewline
    Write-Host $updateService.StartType
    
    # Get pending updates if the service is running and we have results
    if ($updateService.Status -eq "Running") {
        if ($updateError) {
            Write-Host "Could not check for updates: $updateError" -ForegroundColor Yellow
        }
        elseif ($pendingUpdates -ne $null) {
            Write-Host "Pending Updates: " -NoNewline
            if ($pendingUpdates.Count -gt 0) {
                Write-Host "$($pendingUpdates.Count) updates available" -ForegroundColor Yellow
                
                for ($i = 0; $i -lt [Math]::Min(5, $pendingUpdates.Count); $i++) {
                    Write-Host "  - $($pendingUpdates.Item($i).Title)"
                }
                
                if ($pendingUpdates.Count -gt 5) {
                    Write-Host "  - ...and $($pendingUpdates.Count - 5) more"
                }
            }
            else {
                Write-Host "None" -ForegroundColor Green
            }
        }
        else {
            Write-Host "Pending Updates: " -NoNewline
            Write-Host "Unknown" -ForegroundColor Yellow
        }
    }
}
catch {
    # Clear the spinner and show error
    Write-Host "`b " -NoNewline
    Write-Host " ERROR" -ForegroundColor Red
    Write-Host "Error retrieving Windows Update information: $($_.Exception.Message)" -ForegroundColor Red
}

# Power Configuration
Write-SectionHeader "Power Configuration"

try {
    # Use a simpler approach for this section
    Write-Host "Collecting power plan information..." -ForegroundColor Gray
    
    $powerCfg = powercfg /list
    $activePlan = ($powerCfg | Select-String -Pattern "\*").Line
    Write-Host $activePlan.Trim() -ForegroundColor Cyan
    
    # Check sleep settings with error handling
    $hibernateCheck = powercfg /a
    if ($hibernateCheck) {
        $hibernateStatus = if ($hibernateCheck | Select-String -Pattern "Hibernation" -ErrorAction SilentlyContinue | Select-String -Pattern "disabled" -ErrorAction SilentlyContinue) { 
            "Disabled" 
        } 
        else { 
            "Enabled" 
        }
        
        Write-Host "Hibernation: " -NoNewline
        if ($hibernateStatus -eq "Disabled") {
            Write-Host "Disabled" -ForegroundColor Green
        }
        else {
            Write-Host "Enabled" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "Hibernation: " -NoNewline
        Write-Host "Unable to determine status" -ForegroundColor Yellow
    }
    
    # Fast startup with error handling
    try {
        $fastStartupReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -ErrorAction Stop
        $fastStartup = if ($fastStartupReg -and $fastStartupReg.HiberbootEnabled -eq 0) { "Disabled" } else { "Enabled" }
        
        Write-Host "Fast Startup: " -NoNewline
        if ($fastStartup -eq "Disabled") {
            Write-Host "Disabled" -ForegroundColor Green
        }
        else {
            Write-Host "Enabled" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Fast Startup: " -NoNewline
        Write-Host "Unable to determine status" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "Error retrieving power configuration: $($_.Exception.Message)" -ForegroundColor Red
}

# Final Summary
Write-SectionHeader "Baseline Completion Status"

Write-Host "Calculating baseline score..." -NoNewline
$spinnerIndex = 0

# Show spinner while calculating
for ($i = 0; $i -lt 10; $i++) {
    Write-Host "`b$($spinner[$spinnerIndex % 4])" -NoNewline
    $spinnerIndex++
    Start-Sleep -Milliseconds 100
}

# Clear the spinner and write output on a new line
Write-Host "`b " -NoNewline
Write-Host " " -ForegroundColor Green

# Determine overall status
$totalTests = 6 # BitLocker, RMM, Office, Antivirus, Windows Update, Power Settings
$passedTests = 0

# BitLocker
if (($BitLockerVolume -ne $null) -and ($BitLockerVolume.ProtectionStatus -eq "On")) {
    $passedTests++
}

# RMM
if ($dattoInstalled) {
    $passedTests++
}

# Office
if ($office365) {
    $passedTests++
}

# Antivirus
if ($antivirusProducts -and 
    ($antivirusProducts | Where-Object { 
        $statusHex = $_.productState.ToString("X6")
        $eStatus = $statusHex.Substring(0, 2)
        $eStatus -eq "10" # Enabled
    })) {
    $passedTests++
}

# Windows Update
if ($updateService -and $updateService.Status -eq "Running" -and $updateService.StartType -ne "Disabled") {
    $passedTests++
}

# Power Settings
if ($hibernateStatus -eq "Disabled" -and $fastStartup -eq "Disabled") {
    $passedTests++
}

# Calculate score
$score = [Math]::Round(($passedTests / $totalTests) * 100)

Write-Host "Baseline Score: " -NoNewline
if ($score -ge 90) {
    Write-Host "$score%" -ForegroundColor Green
    Write-Host "Status: " -NoNewline
    Write-Host "EXCELLENT" -ForegroundColor Green
}
elseif ($score -ge 70) {
    Write-Host "$score%" -ForegroundColor Yellow
    Write-Host "Status: " -NoNewline
    Write-Host "GOOD" -ForegroundColor Yellow
}
else {
    Write-Host "$score%" -ForegroundColor Red
    Write-Host "Status: " -NoNewline
    Write-Host "NEEDS ATTENTION" -ForegroundColor Red
}

Write-Host "`nReport generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Read-Host -Prompt "Press enter to exit"
Clear-HostFancily -Mode Falling -Speed 3.0
Stop-Process -Id $PID -Force