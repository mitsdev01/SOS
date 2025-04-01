Clear-Host

$ScriptVersion = "1.0.1"

# Add Print-Middle function from SOS-Baseline3.ps1
function Print-Middle($Message, $Color = "White") {
    Write-Host (" " * [System.Math]::Floor(([System.Console]::BufferWidth / 2) - ($Message.Length / 2))) -NoNewline
    Write-Host -ForegroundColor $Color $Message
}

# Title Display using Print-Middle
$Padding = ("=" * [System.Console]::BufferWidth)
Write-Host -ForegroundColor Green $Padding
Print-Middle "SOS - Workstation Baseline Verification" "Cyan"
Print-Middle "Version $ScriptVersion" "Yellow"
Write-Host -ForegroundColor Green $Padding
Write-Host ""

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
        Start-Sleep -Milliseconds 100
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

# Main Script Logic
# Set up variables and preferences
$WarningPreference = "SilentlyContinue"
$ErrorActionPreference = "Continue"

# Install and import CommonStuff module
$moduleName = "CommonStuff"
Write-Host "Checking for required modules..." -NoNewline

try {
    # Check if the module is installed
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Install-Module -Name $moduleName -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop | Out-Null
    }
    
    # Import the module
    Import-Module -Name $moduleName -ErrorAction Stop
    Write-TaskComplete
}
catch {
    Write-TaskFailed
    Write-Host "Error: Failed to install/import module '$moduleName': $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Some reporting features may not be available." -ForegroundColor Yellow
}

# System Information
Write-SectionHeader "System Information"

try {
    $computerInfo = Get-ComputerInfo
    $os = $computerInfo.OsName + " " + $computerInfo.OsVersion
    $installDate = $computerInfo.OsInstallDate
    $lastBoot = $computerInfo.OsLastBootUpTime
    $uptime = (Get-Date) - $lastBoot
    
    $formattedUptime = "{0} days, {1} hours, {2} minutes" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
    
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
    Write-Host "Could not retrieve complete system information: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Installed Software
Write-SectionHeader "Installed Software Report"

try {
    $Software = Get-InstalledSoftware | Where-Object { $_.DisplayName -ne $null } | 
                Select-Object DisplayName, DisplayVersion |
                Sort-Object DisplayName
    
    # Get Datto RMM status
    $dattoInstalled = $Software | Where-Object { $_.DisplayName -like "*Datto*" -or $_.DisplayName -like "*CentraStage*" }
    if ($dattoInstalled) {
        Write-Host "Datto RMM Agent: " -NoNewline
        Write-Host "INSTALLED" -ForegroundColor Green
        foreach ($agent in $dattoInstalled) {
            Write-Host "  $($agent.DisplayName) v$($agent.DisplayVersion)"
        }
    }
    else {
        Write-Host "Datto RMM Agent: " -NoNewline
        Write-Host "NOT INSTALLED" -ForegroundColor Red
    }
    
    # Check Microsoft 365
    $office365 = $Software | Where-Object { $_.DisplayName -like "*Microsoft 365*" -or $_.DisplayName -like "*Office 365*" }
    if ($office365) {
        Write-Host "Microsoft 365: " -NoNewline
        Write-Host "INSTALLED" -ForegroundColor Green
        foreach ($app in $office365) {
            Write-Host "  $($app.DisplayName) v$($app.DisplayVersion)"
        }
    }
    else {
        Write-Host "Microsoft 365: " -NoNewline
        Write-Host "NOT INSTALLED" -ForegroundColor Red
    }
    
    # Check Adobe Reader
    $adobeReader = $Software | Where-Object { $_.DisplayName -like "*Adobe*Reader*" -or $_.DisplayName -like "*Acrobat*Reader*" }
    if ($adobeReader) {
        Write-Host "Adobe Reader: " -NoNewline
        Write-Host "INSTALLED" -ForegroundColor Green
        foreach ($app in $adobeReader) {
            Write-Host "  $($app.DisplayName) v$($app.DisplayVersion)"
        }
    }
    else {
        Write-Host "Adobe Reader: " -NoNewline
        Write-Host "NOT INSTALLED" -ForegroundColor Red
    }
    
    # Other notable software
    Write-Host "`nOther Notable Software:" -ForegroundColor Cyan
    $Software | Select-Object -First 15 | Format-Table -AutoSize
    
    if ($Software.Count -gt 15) {
        Write-Host "...and $($Software.Count - 15) more applications" -ForegroundColor Gray
    }
}
catch {
    Write-Host "Error retrieving installed software: $($_.Exception.Message)" -ForegroundColor Red
}

# BitLocker Status
Write-SectionHeader "BitLocker Encryption Configuration"

try {
    $BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
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
    Write-Host "Error retrieving BitLocker status: $($_.Exception.Message)" -ForegroundColor Red
}

# Domain/Azure AD Status
Write-SectionHeader "Network Authentication Status"

try {
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
    Write-Host "Error retrieving domain/Azure AD information: $($_.Exception.Message)" -ForegroundColor Red
}

# Security Status
Write-SectionHeader "Security Status"

# Antivirus Products
try {
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
    Write-Host "Error retrieving antivirus information: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Windows Update
try {
    Write-Host "Windows Update Status" -ForegroundColor Cyan
    $updateService = Get-Service -Name wuauserv
    
    Write-Host "Windows Update Service: " -NoNewline
    if ($updateService.Status -eq "Running") {
        Write-Host "Running" -ForegroundColor Green
    }
    else {
        Write-Host $updateService.Status -ForegroundColor Red
    }
    
    Write-Host "Startup Type: " -NoNewline
    Write-Host $updateService.StartType
    
    # Get pending updates if the service is running
    if ($updateService.Status -eq "Running") {
        try {
            $updatesSession = New-Object -ComObject Microsoft.Update.Session
            $updatesSearcher = $updatesSession.CreateUpdateSearcher()
            $pendingUpdates = $updatesSearcher.Search("IsInstalled=0").Updates
            
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
        catch {
            Write-Host "Could not check for updates: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}
catch {
    Write-Host "Error retrieving Windows Update information: $($_.Exception.Message)" -ForegroundColor Red
}

# Power Configuration
Write-SectionHeader "Power Configuration"

try {
    $powerCfg = powercfg /list
    $activePlan = ($powerCfg | Select-String -Pattern "\*").Line
    Write-Host "Power Plan: " -NoNewline
    Write-Host $activePlan.Trim() -ForegroundColor Cyan
    
    # Check sleep settings
    $hibernateStatus = if (powercfg /a | Select-String -Pattern "Hibernation" | Select-String -Pattern "disabled") { "Disabled" } else { "Enabled" }
    Write-Host "Hibernation: " -NoNewline
    if ($hibernateStatus -eq "Disabled") {
        Write-Host "Disabled" -ForegroundColor Green
    }
    else {
        Write-Host "Enabled" -ForegroundColor Yellow
    }
    
    # Fast startup
    $fastStartupReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -ErrorAction SilentlyContinue
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
    Write-Host "Error retrieving power configuration: $($_.Exception.Message)" -ForegroundColor Red
}

# Final Summary
Write-SectionHeader "Baseline Completion Status"

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
Stop-Process -Id $PID -Force
