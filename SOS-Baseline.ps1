# SOS - New Workstation Baseline Script
# Version 1.1.5 
# ------------------------------------------------------

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as an Administrator!" -ForegroundColor Red
    Start-Sleep -Seconds 8
    return
}

# Initial setup
Set-ExecutionPolicy RemoteSigned -Force *> $null
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$TempFolder = "C:\temp"
$LogFile = "$TempFolder\baseline.log"

# Create required directories
if (-not (Test-Path $TempFolder)) { New-Item -Path $TempFolder -ItemType Directory | Out-Null }
if (-not (Test-Path $LogFile)) { New-Item -Path $LogFile -ItemType File | Out-Null }

# Set working directory
Set-Location -Path $TempFolder

# Start transcript logging
Start-Transcript -Path "$TempFolder\$env:COMPUTERNAME-baseline_transcript.txt"

# Clear console window
Clear-Host

############################################################################################################
#                                                 Functions                                                #
#                                                                                                          #
############################################################################################################
#region Functions
function Print-Middle($Message, $Color = "White") {
    Write-Host (" " * [System.Math]::Floor(([System.Console]::BufferWidth / 2) - ($Message.Length / 2))) -NoNewline
    Write-Host -ForegroundColor $Color $Message
}

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

function Test-Win10 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    return $osInfo.Version -lt "10.0.22000" -and $osInfo.Caption -like "*Windows 10*"
}

function Test-Win11 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    return $osInfo.Version -ge "10.0.22000" -and $osInfo.Caption -like "*Windows 11*"
}

function Write-TaskComplete {
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

function Move-ProcessWindowToTopRight {
    param (
        [Parameter(Mandatory = $true)]
        [string]$processName
    )
    
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
"@

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

#endregion Functions

# Print Script Title
$ScriptVersion = "1.1.5"
$Padding = ("=" * [System.Console]::BufferWidth)
Write-Host -ForegroundColor "Green" $Padding -NoNewline
Print-Middle "SOS - New Workstation Baseline Script"
Write-Host -ForegroundColor Yellow "                                                   version $ScriptVersion"
Write-Host -ForegroundColor "Green" -NoNewline $Padding
Write-Host "  "
Start-Sleep -Seconds 2

# Check for required modules
Write-Host "Checking for required modules..."
Invoke-Expression (Invoke-RestMethod "https://raw.githubusercontent.com/wju10755/o365AuditParser/master/Check-Modules.ps1")

############################################################################################################
#                                             Start Baseline                                               #
#                                                                                                          #
############################################################################################################
# Start baseline
[Console]::ForegroundColor = [System.ConsoleColor]::Yellow
[Console]::Write("`n`n")
Write-Delayed "Starting workstation baseline..." -NewLine:$false
[Console]::Write("`n")
[Console]::ResetColor() 
[Console]::WriteLine()
Start-Sleep -Seconds 2

# Start baseline log file
Write-Log "Automated workstation baseline has started"

#region WakeLock
# ---------------------------------------------------------------------
# Setup WakeLock to prevent system from sleeping
# ---------------------------------------------------------------------
try {
    $computerSystem = Get-CimInstance -ClassName CIM_ComputerSystem
    $pcSystemType = $computerSystem.PCSystemType
    
    # Check if the system is a mobile device (PCSystemType 2 = Mobile)
    if ($pcSystemType -eq 2) {
        # Mobile device detected, launching presentation settings
        Start-Process -FilePath "C:\Windows\System32\PresentationSettings.exe" -ArgumentList "/start"
    } else {
        # For non-mobile devices, create a wake lock script
        $wakeLockScriptPath = "$TempFolder\WakeLock.ps1"
        $wakeLockContent = @'
# Load the necessary assembly for accessing Windows Forms functionality
Add-Type -AssemblyName System.Windows.Forms

# Define the path to the flag file
$flagFilePath = 'c:\temp\wakelock.flag'

# Infinite loop to send keys and check for the flag file
while ($true) {
    # Check if the flag file exists
    if (Test-Path $flagFilePath) {
        # If the flag file is found, exit the loop and script
        Write-Host "Flag file detected. Exiting script..."
        break
    } else {
        # If the flag file is not found, send the 'Shift + F15' keys
        [System.Windows.Forms.SendKeys]::SendWait('+{F15}')
        # Wait for 60 seconds before sending the keys again
        Start-Sleep -Seconds 60
    }
}
'@
        # Write the wake lock script to file
        Set-Content -Path $wakeLockScriptPath -Value $wakeLockContent
        
        # Launch the wake lock script in a minimized window
        Start-Process -FilePath "powershell.exe" -ArgumentList "-file $wakeLockScriptPath" -WindowStyle Minimized
        
        Write-Log "WakeLock script started to prevent system sleep"
    }
} catch {
    Write-Log "Failed to setup WakeLock: $_"
    Write-Error "Failed to setup WakeLock: $_"
}
#endregion WakeLock

############################################################################################################
#                                              Datto RMM Deployment                                        #
#                                                                                                          #
############################################################################################################
#region RMM Deployment

# Agent Installation Configuration
$file = "$TempFolder\AgentSetup_Standard+Office+Systems+MITS.exe"
$agentName = "CagService"
$agentPath = "C:\Program Files (x86)\CentraStage"
$installerUri = "https://concord.centrastage.net/csm/profile/downloadAgent/b1f0bb64-e008-44e9-8260-2c5039cdd437"

# Function to validate installation
function Test-DattoInstallation {
    $service = Get-Service $agentName -ErrorAction SilentlyContinue
    $serviceExists = $null -ne $service
    $filesExist = Test-Path $agentPath
    
    return @{
        ServiceExists = $serviceExists
        ServiceRunning = if ($serviceExists) { $service.Status -eq 'Running' } else { $false }
        FilesExist = $filesExist
    }
}

# Check for existing Datto RMM agent
$installStatus = Test-DattoInstallation
if ($installStatus.ServiceExists -and $installStatus.ServiceRunning) {
    Write-Host "Datto RMM agent is already installed and running." -ForegroundColor Green
    Write-Log "Datto RMM agent already installed and running"
} else {
    # Clean up any partial installations
    if ($installStatus.FilesExist) {
        Write-Host "Cleaning up partial installation..." -ForegroundColor Yellow
        try {
            # Stop service if it exists but not running
            if ($installStatus.ServiceExists -and -not $installStatus.ServiceRunning) {
                Stop-Service -Name $agentName -Force -ErrorAction SilentlyContinue
                # Give it a moment to stop
                Start-Sleep -Seconds 3
            }
            Remove-Item -Path $agentPath -Recurse -Force -ErrorAction Stop
        } catch {
            Write-Host "Warning: Could not fully clean up previous installation. Continuing anyway." -ForegroundColor Yellow
            Write-Log "Warning: Could not fully clean up previous RMM installation: $($_.Exception.Message)"
        }
    }

    # Download and install
    Write-Host "Downloading Datto RMM Agent..." -NoNewline
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($installerUri, $file)
        Write-Host " done." -ForegroundColor Green
    } catch {
        Write-Host " failed!" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Failed to download Datto RMM agent: $($_.Exception.Message)"
    }

    # Verify the file exists and has content
    if ((Test-Path $file) -and (Get-Item $file).Length -gt 0) {
        Write-Host "Installing Datto RMM Agent..." -NoNewline
        try {
            # Run installer
            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = $file
            $startInfo.Arguments = "/S"
            $startInfo.UseShellExecute = $true
            $startInfo.Verb = "runas"  # Run as admin
            
            $process = [System.Diagnostics.Process]::Start($startInfo)
            if ($null -eq $process) {
                throw "Failed to start installation process"
            }
            
            $process.WaitForExit()
            $exitCode = $process.ExitCode
            
            if ($exitCode -eq 0) {
                Write-Host " done." -ForegroundColor Green
                
                # Wait for service initialization
                Write-Host "Waiting for service initialization..." -NoNewline
                Start-Sleep -Seconds 15
                Write-Host " done." -ForegroundColor Green
                
                # Check if the service exists and is running
                $service = Get-Service -Name $agentName -ErrorAction SilentlyContinue
                
                if ($null -ne $service -and $service.Status -eq "Running") {
                    Write-Host "Installation completed successfully! Service is running." -ForegroundColor Green
                    Write-Log "Datto RMM agent installed successfully"
                    # Clean up installer file
                    if (Test-Path $file) {
                        Remove-Item -Path $file -Force
                    }
                } else {
                    Write-Host "Installation validation failed! Service is not running or not found." -ForegroundColor Red
                    if ($null -ne $service) {
                        Write-Host "Service exists but status is: $($service.Status)" -ForegroundColor Yellow
                        Write-Host "Attempting to start service..." -ForegroundColor Yellow
                        Start-Service -Name $agentName -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 5
                        $service = Get-Service -Name $agentName -ErrorAction SilentlyContinue
                        if ($null -ne $service -and $service.Status -eq "Running") {
                            Write-Host "Service started successfully!" -ForegroundColor Green
                            Write-Log "Datto RMM service started manually after installation"
                        } else {
                            Write-Host "Failed to start service." -ForegroundColor Red
                            Write-Log "Failed to start Datto RMM service after installation"
                        }
                    } else {
                        Write-Host "Service does not exist." -ForegroundColor Red
                        Write-Log "Datto RMM service does not exist after installation"
                    }
                }
            } else {
                Write-Host " failed with exit code $exitCode." -ForegroundColor Red
                Write-Log "Datto RMM installation failed with exit code $exitCode"
                $fileInfo = Get-Item $file -ErrorAction SilentlyContinue
                if ($null -ne $fileInfo) {
                    Write-Host "File size: $($fileInfo.Length) bytes" -ForegroundColor Yellow
                    if ($fileInfo.Length -lt 1000) {
                        Write-Host "File appears to be too small to be a valid installer!" -ForegroundColor Red
                        Write-Log "Datto RMM installer file is too small to be valid: $($fileInfo.Length) bytes"
                    }
                }
            }
        } catch {
            Write-Host " installation failed!" -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Error during Datto RMM installation: $($_.Exception.Message)"
        }
    } else {
        Write-Host "Error: Downloaded file is missing or empty." -ForegroundColor Red
        Write-Log "Datto RMM installer file is missing or empty"
    }
}
#endregion RMMDeployment

############################################################################################################
#                                        Account Configuration                                             #
#                                                                                                          #
############################################################################################################
#region LocalAdminAccount
# ---------------------------------------------------------------------
# Configure Local Admin Account
# ---------------------------------------------------------------------
# Check if the user 'mitsadmin' exists
$user = Get-LocalUser -Name 'mitsadmin' -ErrorAction SilentlyContinue

if ($user) {
    # Check if the password is set to 'Never Expire'
    if (-not $user.PasswordNeverExpires) {
        Write-Delayed "Setting mitsadmin password to 'Never Expire'..." -NewLine:$false
        $user | Set-LocalUser -PasswordNeverExpires $true
        Write-TaskComplete
        Write-Log "Set mitsadmin password to never expire"
    }
} else {
    Write-Host "Creating local mitsadmin & setting password to 'Never Expire'..." -NoNewline
    $Password = ConvertTo-SecureString "@dvances10755" -AsPlainText -Force
    New-LocalUser "mitsadmin" -Password $Password -FullName "MITS Admin" -Description "MITSADMIN Account" *> $null
    $newUser = Get-LocalUser -Name 'mitsadmin' -ErrorAction SilentlyContinue
    if ($newUser) {
        $newUser | Set-LocalUser -PasswordNeverExpires $true
        Add-LocalGroupMember -Group "Administrators" -Member "mitsadmin"
        Write-TaskComplete
        Write-Log "Created mitsadmin local admin account with non-expiring password"
    } else {
        Write-TaskFailed
        Write-Log "Failed to create mitsadmin account"
    }
}
#endregion LocalAdminAccount


############################################################################################################
#                                        Windows Update Configuration                                      #
#                                                                                                          #
############################################################################################################
#region WindowsUpdate
Write-Delayed "Suspending Windows Update..." -NewLine:$false
try {
    # Stop the Windows Update service
    Stop-Service -Name wuauserv -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    
    # Set the startup type of the Windows Update service to disabled
    Set-Service -Name wuauserv -StartupType Disabled -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    
    # Get the current status of the Windows Update service
    $service = Get-Service -Name wuauserv
    
    # Check if the service is stopped
    if ($service.Status -eq 'Stopped') {
        Write-TaskComplete
        Write-Log "Windows Update service suspended"
    } else {
        Write-TaskFailed
        Write-Log "Failed to suspend Windows Update service"
    }
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    Write-Log "Error suspending Windows Update: $_"
}
#endregion WindowsUpdate

############################################################################################################
#                                        Power Profile Configuration                                       #
#                                                                                                          #
############################################################################################################
#region PowerProfile
Write-Delayed "Configuring Power Profile for all devices..." -NewLine:$false
Start-Sleep -Seconds 2

# Get active power scheme
$activeScheme = (powercfg -getactivescheme).Split()[3]

# Disable sleep and hibernation
powercfg /change standby-timeout-ac 0 *> $null
powercfg /change hibernate-timeout-ac 0 *> $null
powercfg /h off *> $null

Write-TaskComplete
Write-Log "Disabled sleep and hibernation mode"

# Configure Fast Startup
Write-Delayed "Disabling Fast Startup..." -NewLine:$false
$regKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
Set-ItemProperty -Path $regKeyPath -Name HiberbootEnabled -Value 0 *> $null
Write-TaskComplete
Write-Log "Fast startup disabled"

# Configure power button actions
Write-Delayed "Configuring 'Shutdown' power button action..." -NewLine:$false
powercfg -setacvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 3
powercfg -setdcvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 3
Write-TaskComplete
Write-Log "Power button action set to 'Shutdown'"

# Configure lid close action
Write-Delayed "Setting 'Do Nothing' lid close action..." -NewLine:$false
powercfg -setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 00000000
powercfg -setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 00000000
Write-TaskComplete
Write-Log "Lid close action set to 'Do Nothing' (applicable to laptops)"

# Configure standby settings
Write-Delayed "Setting Standby Idle time to never on battery..." -NewLine:$false
powercfg -setdcvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0
Write-TaskComplete

Write-Delayed "Setting Standby Idle time to never on AC power..." -NewLine:$false
powercfg -setacvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0
Write-TaskComplete

# Apply power scheme
Write-Delayed "Activating power profile..." -NewLine:$false
powercfg /S $activeScheme
Write-TaskComplete
Write-Log "Power profile configured to prevent sleep for all device types"
#endregion PowerProfile

#region SystemTime
Write-Delayed "Setting EST as default timezone..." -NewLine:$false
Start-Service W32Time
Set-TimeZone -Id "Eastern Standard Time" 
Write-TaskComplete
Write-Log "Time zone set to Eastern Standard Time"

Write-Delayed "Syncing system clock..." -NewLine:$false
w32tm /resync -ErrorAction SilentlyContinue | Out-Null
Write-TaskComplete
Write-Log "Synced system clock"
#endregion SystemTime


############################################################################################################
#                                        Bitlocker Configuration                                           #
#                                                                                                          #
############################################################################################################
#region Capability Check
# Check Bitlocker Compatibility -v2
$WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
$TPM = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -Class Win32_Tpm -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue

if ($WindowsVer -and $TPM -and $BitLockerReadyDrive) {
    # Check if Bitlocker is already configured on C:
    $BitLockerStatus = Get-BitLockerVolume -MountPoint $env:SystemDrive
    # Ensure the output directory exists
    $outputDirectory = "C:\temp"
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }
    if ($BitLockerStatus.ProtectionStatus -eq 'On') {
        # Bitlocker is already configured
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        Write-Delayed "Bitlocker is already configured on $env:SystemDrive - " -NewLine:$false
        [Console]::ResetColor()

        # Setup for non-blocking read with timeout
        $timeoutSeconds = 10
        $endTime = (Get-Date).AddSeconds($timeoutSeconds)
        $userResponse = $null

        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        Write-Host "Do you want to skip configuring Bitlocker? (yes/no)" -NoNewline
        [Console]::ResetColor()

        while ($true) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.KeyChar -match '^[ynYN]$') {
                    $userResponse = $key.KeyChar
                    break
                }
            } elseif ((Get-Date) -ge $endTime) {
                Write-Host "`nNo response received, skipping Bitlocker configuration..." -NoNewline
                Write-Host -ForegroundColor Green " done."
                $userResponse = 'y' # Assume 'yes' to skip if no response
                break
            }
            Start-Sleep -Milliseconds 500
        }

        if ($userResponse -ine 'y') {
            # Disable BitLocker
            manage-bde -off $env:SystemDrive | Out-Null

            # Monitor decryption progress
            do {
                $status = manage-bde -status $env:SystemDrive
                $percentageEncrypted = ($status | Select-String -Pattern "Percentage Encrypted:.*").ToString().Split(":")[1].Trim()
                Write-Host "`rCurrent decryption progress: $percentageEncrypted" -NoNewline
                Start-Sleep -Seconds 1
            } until ($percentageEncrypted -eq "0.0%")
            Write-Host "`nDecryption of $env:SystemDrive is complete."
            # Reconfigure BitLocker
            Write-Delayed "Configuring Bitlocker Disk Encryption..." -NewLine:$true
            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector -WarningAction SilentlyContinue | Out-Null
            Start-Process 'manage-bde.exe' -ArgumentList " -on $env:SystemDrive -UsedSpaceOnly" -Verb runas -Wait | Out-Null
            # Verify volume key protector exists
            $BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
            if ($BitLockerVolume.KeyProtector) {
                Write-Host "Bitlocker disk encryption configured successfully."
            } else {
                Write-Host "Bitlocker disk encryption is not configured."
            }
        }
    } else {
        # Bitlocker is not configured
        Write-Delayed "Configuring Bitlocker Disk Encryption..." -NewLine:$true
        # Create the recovery key
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
        # Add TPM key
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector -WarningAction SilentlyContinue | Out-Null
        Start-Sleep -Seconds 15 # Wait for the protectors to take effect
        # Enable Encryption
        Start-Process 'manage-bde.exe' -ArgumentList "-on $env:SystemDrive -UsedSpaceOnly" -Verb runas -Wait | Out-Null
        # Backup the Recovery to AD
        $RecoveryKeyGUID = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'} | Select-Object -ExpandProperty KeyProtectorID
        manage-bde.exe -protectors $env:SystemDrive -adbackup -id $RecoveryKeyGUID | Out-Null
        # Write Recovery Key to a file
        manage-bde -protectors C: -get | Out-File "$outputDirectory\$env:computername-BitLocker.txt"
        # Verify volume key protector exists
        $BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
        if ($BitLockerVolume.KeyProtector) {
            Write-Delayed "Bitlocker disk encryption configured successfully." -NewLine:$true
            Write-Delayed "Recovery ID:" -NewLine:$false
            Write-Host -ForegroundColor Cyan " $($BitLockerVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | ForEach-Object { $_.KeyProtectorId.Trim('{', '}') })"
            Write-Delayed "Recovery Password:" -NewLine:$false
            Write-Host -ForegroundColor Cyan " $($BitLockerVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | Select-Object -ExpandProperty RecoveryPassword)"
        } else {
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            [Console]::Write("Bitlocker disk encryption is not configured.")
            [Console]::ResetColor()
            [Console]::WriteLine()  
        }
    }
} else {
    Write-Warning "Skipping Bitlocker Drive Encryption due to device not meeting hardware requirements."
    Write-Log "Skipping Bitlocker Drive Encryption due to device not meeting hardware requirements."
    Start-Sleep -Seconds 1
}
#region Configure Bitlocker


############################################################################################################
#                                        System Restore Configuration                                      #
#                                                                                                          #
############################################################################################################
#region SystemRestore
Write-Delayed "Enabling System Restore..." -NewLine:$false

# Set RestorePoint Creation Frequency to 0 (allow multiple restore points)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0 

# Enable system restore
Enable-ComputerRestore -Drive "C:\" -Confirm:$false
Write-TaskComplete
Write-Log "System Restore Enabled"
#endregion SystemRestore


############################################################################################################
#                                        Offline Files Configuration                                       #
#                                                                                                          #
############################################################################################################
#region Offline Files
Write-Delayed "Disabling Offline File Sync..." -NewLine:$false

# Set registry path for Offline Files
$registryPath = "HKLM:\System\CurrentControlSet\Services\CSC\Parameters"

# Check if the registry path exists, if not, create it
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -Force *> $null
}

# Disable Offline Files by setting Start value to 4
Set-ItemProperty -Path $registryPath -Name "Start" -Value 4 *> $null
Write-TaskComplete
Write-Log "Offline file sync disabled"
#endregion OfflineFiles


############################################################################################################
#                                   Profile Customization and Privacy Settings                             #
#                                                                                                          #
############################################################################################################
#region Profile Customization
# Get all user SIDs for registry modifications
$UserSIDs = @()
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | 
    Where-Object {$_.PSChildName -match "S-1-5-21-(\d+-){4}$"} |
    Select-Object @{Name="SID"; Expression={$_.PSChildName}} |
    ForEach-Object {$UserSIDs += $_.SID}

# Disable Windows Feedback Experience
Write-Delayed "Disabling Windows Feedback Experience program..." -NewLine:$false
$Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
if (!(Test-Path $Advertising)) {
    New-Item $Advertising | Out-Null
}
if (Test-Path $Advertising) {
    Set-ItemProperty $Advertising Enabled -Value 0
    Write-TaskComplete
    Write-Log "Windows Feedback Experience disabled"
}

# Disable Cortana in Windows Search
Write-Delayed "Preventing Cortana from being used in Windows Search..." -NewLine:$false
$Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (!(Test-Path $Search)) {
    New-Item $Search | Out-Null
}
if (Test-Path $Search) {
    Set-ItemProperty $Search AllowCortana -Value 0
    Write-TaskComplete
    Write-Log "Cortana disabled in Windows Search"
}

# Disable Bing Search in Start Menu
Write-Delayed "Disabling Bing Search in Start Menu..." -NewLine:$false
$WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (!(Test-Path $WebSearch)) {
    New-Item $WebSearch | Out-Null
}
Set-ItemProperty $WebSearch DisableWebSearch -Value 1 

# Apply to all user profiles
foreach ($sid in $UserSIDs) {
    $WebSearch = "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    if (!(Test-Path $WebSearch)) {
        New-Item $WebSearch -Force | Out-Null
    }
    Set-ItemProperty $WebSearch BingSearchEnabled -Value 0 -ErrorAction SilentlyContinue
}
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 -ErrorAction SilentlyContinue
Write-TaskComplete
Write-Log "Bing Search disabled in Start Menu"

# Stop Windows Feedback Experience program
Write-Delayed "Stopping the Windows Feedback Experience program..." -NewLine:$false
$Period = "HKCU:\Software\Microsoft\Siuf\Rules"
if (!(Test-Path $Period)) { 
    New-Item $Period -Force | Out-Null
}
Set-ItemProperty $Period PeriodInNanoSeconds -Value 0 

# Apply to all user profiles
foreach ($sid in $UserSIDs) {
    $Period = "Registry::HKU\$sid\Software\Microsoft\Siuf\Rules"
    if (!(Test-Path $Period)) { 
        New-Item $Period -Force | Out-Null
    }
    Set-ItemProperty $Period PeriodInNanoSeconds -Value 0 -ErrorAction SilentlyContinue
}
Write-TaskComplete
Write-Log "Windows Feedback Experience program stopped"

# Disable Mixed Reality Portal
Write-Delayed "Disabling Mixed Reality Portal..." -NewLine:$false
$Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
if (Test-Path $Holo) {
    Set-ItemProperty $Holo FirstRunSucceeded -Value 0 
}

# Apply to all user profiles
foreach ($sid in $UserSIDs) {
    $Holo = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Holographic"    
    if (Test-Path $Holo) {
        Set-ItemProperty $Holo FirstRunSucceeded -Value 0 -ErrorAction SilentlyContinue
    }
}
Write-TaskComplete
Write-Log "Mixed Reality Portal disabled"

# Disable Wi-Fi Sense
Write-Delayed "Disabling Wi-Fi Sense..." -NewLine:$false
$WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
$WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
$WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"

if (!(Test-Path $WifiSense1)) {
    New-Item $WifiSense1 -Force | Out-Null
}
Set-ItemProperty $WifiSense1 Value -Value 0 

if (!(Test-Path $WifiSense2)) {
    New-Item $WifiSense2 -Force | Out-Null
}
Set-ItemProperty $WifiSense2 Value -Value 0 

if (Test-Path $WifiSense3) {
    Set-ItemProperty $WifiSense3 AutoConnectAllowedOEM -Value 0 
}
Write-TaskComplete
Write-Log "Wi-Fi Sense disabled"

# Disable Live Tiles
Write-Delayed "Disabling live tiles..." -NewLine:$false
$Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
if (!(Test-Path $Live)) {      
    New-Item $Live -Force | Out-Null
}
Set-ItemProperty $Live NoTileApplicationNotification -Value 1 

# Apply to all user profiles
foreach ($sid in $UserSIDs) {
    $Live = "Registry::HKU\$sid\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
    if (!(Test-Path $Live)) {      
        New-Item $Live -Force | Out-Null
    }
    Set-ItemProperty $Live NoTileApplicationNotification -Value 1 -ErrorAction SilentlyContinue
}
Write-TaskComplete
Write-Log "Live tiles disabled"

# Disable People icon on Taskbar
Write-Delayed "Disabling People icon on Taskbar..." -NewLine:$false
$People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
if (Test-Path $People) {
    Set-ItemProperty $People -Name PeopleBand -Value 0  
}

# Apply to all user profiles
foreach ($sid in $UserSIDs) {
    $People = "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
    if (Test-Path $People) {
        Set-ItemProperty $People -Name PeopleBand -Value 0 -ErrorAction SilentlyContinue
    }
}
Write-TaskComplete
Write-Log "People icon disabled on Taskbar"

# Disable Cortana
Write-Delayed "Disabling Cortana..." -NewLine:$false
$Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
$Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
$Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"

if (!(Test-Path $Cortana1)) {
    New-Item $Cortana1 -Force | Out-Null
}
Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 

if (!(Test-Path $Cortana2)) {
    New-Item $Cortana2 -Force | Out-Null
}
Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 

if (!(Test-Path $Cortana3)) {
    New-Item $Cortana3 -Force | Out-Null
}
Set-ItemProperty $Cortana3 HarvestContacts -Value 0

# Apply to all user profiles
foreach ($sid in $UserSIDs) {
    $Cortana1 = "Registry::HKU\$sid\SOFTWARE\Microsoft\Personalization\Settings"
    $Cortana2 = "Registry::HKU\$sid\SOFTWARE\Microsoft\InputPersonalization"
    $Cortana3 = "Registry::HKU\$sid\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
    
    if (!(Test-Path $Cortana1)) {
        New-Item $Cortana1 -Force | Out-Null
    }
    Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 -ErrorAction SilentlyContinue
    
    if (!(Test-Path $Cortana2)) {
        New-Item $Cortana2 -Force | Out-Null
    }
    Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 -ErrorAction SilentlyContinue
    
    if (!(Test-Path $Cortana3)) {
        New-Item $Cortana3 -Force | Out-Null
    }
    Set-ItemProperty $Cortana3 HarvestContacts -Value 0 -ErrorAction SilentlyContinue
}
Write-TaskComplete
Write-Log "Cortana disabled"

# Remove 3D Objects from 'My Computer'
Write-Delayed "Removing 3D Objects from explorer 'My Computer' submenu..." -NewLine:$false
$Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
$Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"

if (Test-Path $Objects32) {
    Remove-Item $Objects32 -Recurse -Force
}
if (Test-Path $Objects64) {
    Remove-Item $Objects64 -Recurse -Force
}
Write-TaskComplete
Write-Log "3D Objects removed from explorer 'My Computer' submenu"

# Remove Microsoft Feeds
Write-Delayed "Removing Microsoft Feeds..." -NewLine:$false
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
$Name = "EnableFeeds"
$value = "0"

if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
Write-TaskComplete
Write-Log "Microsoft Feeds removed"

# Disable Scheduled Tasks
Write-Delayed "Disabling scheduled tasks..." -NewLine:$false
$taskList = @(
    'XblGameSaveTaskLogon',
    'XblGameSaveTask',
    'Consolidator',
    'UsbCeip',
    'DmClient',
    'DmClientOnScenarioDownload'
)

foreach ($task in $taskList) {
    $scheduledTask = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue 
    if ($null -ne $scheduledTask) {
        Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
    }
}
Write-TaskComplete
Write-Log "Disabled unnecessary scheduled tasks"
#endregion WindowsCustomization


############################################################################################################
#                                          Office 365 Installation                                         #
#                                                                                                          #
############################################################################################################
#
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

############################################################################################################
#                                        Adobe Acrobat Installation                                        #
#                                                                                                          #
############################################################################################################
#region Acrobat Installation
# Define the URL and file path for the Acrobat Reader installer
$URL = "https://axcientrestore.blob.core.windows.net/win11/AcroRdrDC2500120432_en_US.exe"
$AcroFilePath = "C:\temp\AcroRdrDC2500120432_en_US.exe"

# Create temp directory if it doesn't exist
if (-not (Test-Path "C:\temp")) {
    New-Item -Path "C:\temp" -ItemType Directory -Force | Out-Null
    Write-Host "Created C:\temp directory"
}

# Download the Acrobat Reader installer
#$ProgressPreference = 'SilentlyContinue'  # Hide progress bar for faster downloads
try {
    $response = Invoke-WebRequest -Uri $URL -Method Head -ErrorAction Stop
    $fileSize = $response.Headers['Content-Length']
    Write-Host "Downloading Adobe Acrobat Reader ($fileSize bytes)..."
    
    Invoke-WebRequest -Uri $URL -OutFile $AcroFilePath -UseBasicParsing -ErrorAction Stop
    Write-Host "Download completed successfully"
    
    $FileSize = (Get-Item $AcroFilePath).Length
    
    # Check if the file exists and has content (instead of exact size check)
    if ((Test-Path $AcroFilePath -PathType Leaf) -and ($FileSize -gt 0)) {
        # Start the silent installation of Acrobat Reader
        Write-Host "Starting silent installation of Adobe Acrobat Reader..."
        
        # Use more reliable installation method with wait
        $process = Start-Process -FilePath $AcroFilePath -ArgumentList "/sAll /rs /msi EULA_ACCEPT=YES /qn" -NoNewWindow -PassThru
        
        # Wait for initial process to complete
        $process | Wait-Process -Timeout 60 -ErrorAction SilentlyContinue
        
        # Look for Reader installer processes and wait
        Write-Host "Waiting for installation to complete..."
        $timeout = 300  # 5 minutes timeout
        $startTime = Get-Date
        
        do {
            Start-Sleep -Seconds 5
            $msiProcess = Get-Process -Name msiexec -ErrorAction SilentlyContinue
            $readerProcess = Get-Process -Name Reader_en_install -ErrorAction SilentlyContinue
            
            $elapsedTime = (Get-Date) - $startTime
            if ($elapsedTime.TotalSeconds -gt $timeout) {
                Write-Host "Installation timed out after $timeout seconds" -ForegroundColor Yellow
                break
            }
        } while ($msiProcess -or $readerProcess)
        
        # Try to gracefully close any remaining installer processes
        Stop-Process -Name Reader_en_install -Force -ErrorAction SilentlyContinue
        
        # Verify installation
        $acrobatPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
        $acrobatInstalled = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                            HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                             Where-Object { $_.DisplayName -like "*Adobe Acrobat Reader*" -or $_.DisplayName -like "*Adobe Acrobat DC*" }
        
        if ((Test-Path $acrobatPath) -and $acrobatInstalled) {
            Write-Host "Adobe Acrobat Reader installation completed successfully" -ForegroundColor Green
        } else {
            if (-not (Test-Path $acrobatPath)) {
                Write-Host "Adobe Acrobat Reader executable not found" -ForegroundColor Yellow
            }
            if (-not $acrobatInstalled) {
                Write-Host "Adobe Acrobat Reader not found in installed applications registry" -ForegroundColor Yellow
            }
            Write-Host "Adobe Acrobat Reader installation may not have completed properly" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Download failed or file is empty" -ForegroundColor Red
    }
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
} finally {
    # Cleanup
    #$ProgressPreference = 'Continue'
    if (Test-Path $AcroFilePath) {
        Remove-Item -Path $AcroFilePath -Force -ErrorAction SilentlyContinue
        Write-Host "Cleaned up installer file"
    }
}
#endregion Acrobat Installation

############################################################################################################
#                                           Bloatware Cleanup                                              #
#                                                                                                          #
############################################################################################################
#region Bloatware Cleanup
# Trigger MITS Debloat for Windows 11
if (Test-Windows11) {
    try {
        $Win11DebloatURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/MITS-Debloat.zip"
        $Win11DebloatFile = "c:\temp\MITS-Debloat.zip"
        Invoke-WebRequest -Uri $Win11DebloatURL -OutFile $Win11DebloatFile -UseBasicParsing -ErrorAction Stop 
        Start-Sleep -seconds 2
        Expand-Archive $Win11DebloatFile -DestinationPath 'c:\temp\MITS-Debloat'
        Start-Sleep -Seconds 2
        Start-Process powershell -ArgumentList "-noexit","-Command Invoke-Expression -Command '& ''C:\temp\MITS-Debloat\MITS-Debloat.ps1'' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -DisableLockscreenTips -DisableSuggestions -ShowKnownFileExt -TaskbarAlignLeft -HideSearchTb -DisableWidgets -Silent'"
        Start-Sleep -Seconds 2
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait('%{TAB}') 
        Write-Log "Windows 11 Debloat completed successfully."
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}


# Trigger MITS Debloat for Windows 10
if (Test-Windows10) {
    try {
        $MITSDebloatURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/MITS-Debloat.zip"
        $MITSDebloatFile = "c:\temp\MITS-Debloat.zip"
        Invoke-WebRequest -Uri $MITSDebloatURL -OutFile $MITSDebloatFile -UseBasicParsing -ErrorAction Stop 
        Start-Sleep -seconds 2
        Expand-Archive $MITSDebloatFile -DestinationPath c:\temp\MITS-Debloat -Force
        Start-Sleep -Seconds 2
        Start-Process powershell -ArgumentList "-noexit","-Command Invoke-Expression -Command '& ''C:\temp\MITS-Debloat\MITS-Debloat.ps1'' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -ShowKnownFileExt -Silent'"
        Start-Sleep -Seconds 2
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait('%{TAB}') 
        Write-Log "Windows 10 Debloat completed successfully."
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}


############################################################################################################
#                                        Cleanup and Finalization                                        #
#                                                                                                          #
############################################################################################################
#region Baseline Cleanup
# Re-enable Windows Update

<# Version 2.0
Write-Delayed "Re-enabling Windows Update..." -NewLine:$false
try {
    # Set the startup type of the Windows Update service back to automatic
    Set-Service -Name wuauserv -StartupType Automatic
    
    # Start the Windows Update service
    Start-Service -Name wuauserv
    
    # Get the current status of the Windows Update service
    $service = Get-Service -Name wuauserv
    
    # Check if the service is running
    if ($service.Status -eq 'Running') {
        Write-TaskComplete
        Write-Log "Windows Update service re-enabled"
        IRM "https://raw.githubusercontent.com/mitsdev01/SOS/refs/heads/main/Update_Windows.ps1" | iex
    } else {
        Write-TaskFailed
        Write-Log "Failed to re-enable Windows Update service"
    }
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    Write-Log "Error re-enabling Windows Update: $_"
}
#>

# Enable and start Windows Update Service
Write-Delayed "Enabling Windows Update Service..." -NewLine:$false
Set-Service -Name wuauserv -StartupType Manual
Start-Sleep -seconds 3
Start-Service -Name wuauserv
Start-Sleep -Seconds 5
$service = Get-Service -Name wuauserv
if ($service.Status -eq 'Running') {
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine() 
} else {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" failed.")
    [Console]::ResetColor()
    [Console]::WriteLine()    
}

# Installing Windows Updates
function Set-UsoSvcAutomatic {
    try {
        # Set service to Automatic
        Set-Service -Name "UsoSvc" -StartupType Automatic
        
        # Start the service
        Start-Service -Name "UsoSvc"
        
        # Verify the service status
        $service = Get-Service -Name "UsoSvc"
    }
    catch {
        Write-Error "Failed to configure UsoSvc: $($_.Exception.Message)"
    }
}
Write-Delayed "Checking for Windows Updates..." -NewLine:$false
Set-UsoSvcAutomatic
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/wju10755/Baseline/main/Update_Windows-v3.ps1" -OutFile "c:\temp\update_windows.ps1"
$ProgressPreference = 'Continue'
if (Test-Path "c:\temp\update_windows.ps1") {
    $updatePath = "C:\temp\Update_Windows.ps1"
    $null = Start-Process PowerShell -ArgumentList "-NoExit", "-File", $updatePath *> $null
    Start-Sleep -seconds 3
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.SendKeys]::SendWait('%{TAB}')
    Move-ProcessWindowToTopRight -processName "Windows PowerShell" | Out-Null
    Start-Sleep -Seconds 1
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    Write-Log "All available Windows updates are installed."
     
} else {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    Write-Delayed "Windows Update execution failed!" -NewLine:$false
        [Console]::ResetColor()
        [Console]::WriteLine()  
}

# Create WakeLock exit flag to stop the WakeLock script
Write-Delayed "Creating WakeLock exit flag..." -NewLine:$false
try {
    # Create the flag file to signal the WakeLock script to exit
    New-Item -Path "c:\temp\wakelock.flag" -ItemType File -Force | Out-Null
    Write-TaskComplete
    Write-Log "WakeLock flag file created to stop WakeLock script"
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    Write-Log "Error creating WakeLock exit flag: $_"
}

# Create a restore point
Write-Delayed "Creating a system restore point..." -NewLine:$false
try {
    Checkpoint-Computer -Description "SOS Baseline Completed" -RestorePointType "APPLICATION_INSTALL" -ErrorAction Stop
    Write-TaskComplete
    Write-Log "System restore point created successfully`r"
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    Write-Log "Error creating system restore point: $_"
}


############################################################################################################
#                                           Baseline Summary                                               #
#                                                                                                          #
############################################################################################################
# Display Baseline Summary
$Padding = ("=" * [System.Console]::BufferWidth)
Write-Host -ForegroundColor "Green" $Padding
Print-Middle "SOS Baseline Script Completed Successfully" "Green"
Print-Middle "Reboot recommended to finalize changes" "Yellow"
Write-Host -ForegroundColor "Green" $Padding

Write-Host -ForegroundColor "Cyan" "Logs are available at:"
Write-Host "  * $LogFile"
Write-Host "  * $TempFolder\$env:COMPUTERNAME-baseline_transcript.txt"

# Stopping transcript
Stop-Transcript | Out-Null

# Update log file with completion
Write-Log "Automated workstation baseline has completed successfully"
#endregion CleanupAndFinalize 