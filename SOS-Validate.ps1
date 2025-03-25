# SOS - Baseline Validation Script
# Version 1.1.0
# ------------------------------------------------------
# This script validates that changes made by the SOS Baseline script 
# were applied successfully to the system.

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as an Administrator!" -ForegroundColor Red
    Start-Sleep -Seconds 5
    return
}

# Initial setup
$TempFolder = "C:\temp"
$LogFile = "$TempFolder\baseline-validation.log"
$ValidationSummary = @()
$FailCount = 0
$PassCount = 0

# Create required directories
if (-not (Test-Path $TempFolder)) { New-Item -Path $TempFolder -ItemType Directory | Out-Null }
if (-not (Test-Path $LogFile)) { New-Item -Path $LogFile -ItemType File | Out-Null }

# Set working directory
Set-Location -Path $TempFolder

# Start transcript logging
Start-Transcript -Path "$TempFolder\$env:COMPUTERNAME-baseline-validation_transcript.txt"

# Clear console window
Clear-Host

#region Functions
# ---------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------
function Print-Middle($Message, $Color = "White") {
    Write-Host (" " * [System.Math]::Floor(([System.Console]::BufferWidth / 2) - ($Message.Length / 2))) -NoNewline
    Write-Host -ForegroundColor $Color $Message
}

function Write-Log {
    param ([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date) - $Message"
}

function Test-Setting {
    param (
        [string]$Name,
        [scriptblock]$Test,
        [string]$SuccessMessage,
        [string]$FailureMessage
    )
    
    try {
        Write-Host "Validating $Name... " -NoNewline
        $result = & $Test
        
        if ($result) {
            Write-Host "PASS" -ForegroundColor Green
            Write-Log "PASS: $SuccessMessage"
            $script:PassCount++
            $ValidationSummary += [PSCustomObject]@{
                Setting = $Name
                Status = "PASS"
                Details = $SuccessMessage
            }
        } else {
            Write-Host "FAIL" -ForegroundColor Red
            Write-Log "FAIL: $FailureMessage"
            $script:FailCount++
            $ValidationSummary += [PSCustomObject]@{
                Setting = $Name
                Status = "FAIL"
                Details = $FailureMessage
            }
        }
    } catch {
        Write-Host "ERROR" -ForegroundColor Yellow
        Write-Log "ERROR: $Name validation failed with error: $_"
        $script:FailCount++
        $ValidationSummary += [PSCustomObject]@{
            Setting = $Name
            Status = "ERROR"
            Details = "Validation failed with error: $_"
        }
    }
}

function Test-Win10 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    return $osInfo.Version -lt "10.0.22000" -and $osInfo.Caption -like "*Windows 10*"
}

function Test-Win11 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    return $osInfo.Version -ge "10.0.22000" -and $osInfo.Caption -like "*Windows 11*"
}

function Test-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        $Value
    )
    if (!(Test-Path $Path)) {
        return $false
    }
    
    $regValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    
    if ($null -eq $regValue) {
        return $false
    }
    
    return $regValue.$Name -eq $Value
}

function Test-ScheduledTaskDisabled {
    param ([string]$TaskName)
    
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        return $true  # Task doesn't exist, so no need to disable
    }
    
    return $task.State -eq "Disabled"
}

function Test-SettingWithNA {
    param (
        [string]$Name,
        [scriptblock]$Test,
        [string]$SuccessMessage,
        [string]$FailureMessage,
        [bool]$ApplyTest = $true
    )
    
    try {
        Write-Host "Validating $Name... " -NoNewline
        
        if (-not $ApplyTest) {
            Write-Host "N/A" -ForegroundColor Yellow
            Write-Log "N/A: $Name - Not applicable for this device type"
            $ValidationSummary += [PSCustomObject]@{
                Setting = $Name
                Status = "N/A"
                Details = "Not applicable for this device type"
            }
        } else {
            $result = & $Test
            
            if ($result) {
                Write-Host "PASS" -ForegroundColor Green
                Write-Log "PASS: $SuccessMessage"
                $script:PassCount++
                $ValidationSummary += [PSCustomObject]@{
                    Setting = $Name
                    Status = "PASS"
                    Details = $SuccessMessage
                }
            } else {
                Write-Host "FAIL" -ForegroundColor Red
                Write-Log "FAIL: $FailureMessage"
                $script:FailCount++
                $ValidationSummary += [PSCustomObject]@{
                    Setting = $Name
                    Status = "FAIL"
                    Details = $FailureMessage
                }
            }
        }
    } catch {
        Write-Host "ERROR" -ForegroundColor Yellow
        Write-Log "ERROR: $Name validation failed with error: $_"
        $script:FailCount++
        $ValidationSummary += [PSCustomObject]@{
            Setting = $Name
            Status = "ERROR"
            Details = "Validation failed with error: $_"
        }
    }
}
#endregion Functions

# Print Script Title
$Padding = ("=" * [System.Console]::BufferWidth)
Write-Host -ForegroundColor "Cyan" $Padding -NoNewline
Print-Middle "SOS Baseline Validation Script" "Cyan"
Write-Host -ForegroundColor "Cyan" -NoNewline $Padding
Write-Host "  "
Start-Sleep -Seconds 1

Write-Host "This script will validate that the SOS Baseline settings have been applied correctly.`n" -ForegroundColor Yellow
Write-Log "Starting baseline validation"

#region LocalAdminAccount
Write-Host "`n[Checking Local Admin Account]" -ForegroundColor Cyan
Test-Setting -Name "Local mitsadmin Account" -Test {
    $user = Get-LocalUser -Name 'mitsadmin' -ErrorAction SilentlyContinue
    return $null -ne $user
} -SuccessMessage "Local mitsadmin account exists" -FailureMessage "Local mitsadmin account not found"

Test-Setting -Name "mitsadmin Password Never Expires" -Test {
    $user = Get-LocalUser -Name 'mitsadmin' -ErrorAction SilentlyContinue
    return $null -ne $user -and $user.PasswordNeverExpires
} -SuccessMessage "mitsadmin password set to never expire" -FailureMessage "mitsadmin password not set to never expire"

Test-Setting -Name "mitsadmin in Administrators Group" -Test {
    $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -like "*\mitsadmin" -or $_.Name -eq "mitsadmin" }
    return $null -ne $adminGroup
} -SuccessMessage "mitsadmin is in the Administrators group" -FailureMessage "mitsadmin is not in the Administrators group"
#endregion LocalAdminAccount

#region PowerSettings
Write-Host "`n[Checking Power Settings]" -ForegroundColor Cyan
Test-Setting -Name "Hibernation Disabled" -Test {
    # Check if hibernation is off
    $hibernationStatus = powercfg /a | Select-String "Hibernation"
    return $null -ne $hibernationStatus -and $hibernationStatus -like "*Hibernation is not available*"
} -SuccessMessage "Hibernation is disabled" -FailureMessage "Hibernation is not disabled"

Test-Setting -Name "Fast Startup Disabled" -Test {
    $regKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
    $value = (Get-ItemProperty -Path $regKeyPath -Name "HiberbootEnabled" -ErrorAction SilentlyContinue).HiberbootEnabled
    return $value -eq 0
} -SuccessMessage "Fast Startup is disabled" -FailureMessage "Fast Startup is not disabled"

# Check if machine is a laptop (PCSystemType 2 = Mobile device)
$computerSystem = Get-CimInstance -ClassName CIM_ComputerSystem
$isLaptop = $computerSystem.PCSystemType -eq 2

# Check standby settings in active power scheme
$activeScheme = (powercfg -getactivescheme).Split()[3]

Test-SettingWithNA -Name "AC Standby Timeout" -Test {
    $acStandbyTime = powercfg /query $activeScheme SUB_SLEEP STANDBYIDLE | 
        Select-String "Current AC Power Setting Index: 0x" | 
        ForEach-Object { $_.ToString() -replace ".*: 0x", "" -replace "[^0-9a-f]", "" }
    return $acStandbyTime -eq "0"
} -SuccessMessage "AC Standby Timeout set to never" -FailureMessage "AC Standby Timeout not set to never" -ApplyTest $isLaptop

Test-SettingWithNA -Name "DC Standby Timeout" -Test {
    $dcStandbyTime = powercfg /query $activeScheme SUB_SLEEP STANDBYIDLE | 
        Select-String "Current DC Power Setting Index: 0x" | 
        ForEach-Object { $_.ToString() -replace ".*: 0x", "" -replace "[^0-9a-f]", "" }
    return $dcStandbyTime -eq "0"
} -SuccessMessage "DC Standby Timeout set to never" -FailureMessage "DC Standby Timeout not set to never" -ApplyTest $isLaptop
#endregion PowerSettings

#region SystemTime
Write-Host "`n[Checking System Time Settings]" -ForegroundColor Cyan
Test-Setting -Name "Time Zone Set to EST" -Test {
    $timeZone = Get-TimeZone
    return $timeZone.Id -eq "Eastern Standard Time"
} -SuccessMessage "Time Zone is set to Eastern Standard Time" -FailureMessage "Time Zone is not set to Eastern Standard Time"

Test-Setting -Name "Windows Time Service" -Test {
    $service = Get-Service -Name "W32Time"
    return $service.Status -eq "Running" -and $service.StartType -ne "Disabled"
} -SuccessMessage "Windows Time Service is running" -FailureMessage "Windows Time Service is not running"
#endregion SystemTime

#region SystemRestore
Write-Host "`n[Checking System Restore]" -ForegroundColor Cyan
Test-Setting -Name "System Restore Enabled" -Test {
    $ComputerRestoreStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    return $null -ne $ComputerRestoreStatus -or (vssadmin list shadowstorage | Select-String "C:") 
} -SuccessMessage "System Restore is enabled" -FailureMessage "System Restore is not enabled or no restore points exist"

Test-Setting -Name "Restore Point Creation Frequency" -Test {
    $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -ErrorAction SilentlyContinue
    return $null -ne $regValue -and $regValue.SystemRestorePointCreationFrequency -eq 0
} -SuccessMessage "Restore Point Creation Frequency set to 0" -FailureMessage "Restore Point Creation Frequency not set to 0"
#endregion SystemRestore

#region OfflineFiles
Write-Host "`n[Checking Offline Files]" -ForegroundColor Cyan
Test-Setting -Name "Offline Files Disabled" -Test {
    $registryPath = "HKLM:\System\CurrentControlSet\Services\CSC\Parameters"
    $value = (Get-ItemProperty -Path $registryPath -Name "Start" -ErrorAction SilentlyContinue).Start
    return $value -eq 4
} -SuccessMessage "Offline Files are disabled" -FailureMessage "Offline Files are not disabled"
#endregion OfflineFiles

#region WindowsCustomization
Write-Host "`n[Checking Windows Customization]" -ForegroundColor Cyan
Test-Setting -Name "Windows Feedback Experience" -Test {
    Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
} -SuccessMessage "Windows Feedback Experience is disabled" -FailureMessage "Windows Feedback Experience is not disabled"

Test-Setting -Name "Cortana in Windows Search" -Test {
    Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0
} -SuccessMessage "Cortana in Windows Search is disabled" -FailureMessage "Cortana in Windows Search is not disabled"

Test-Setting -Name "Bing Search in Start Menu" -Test {
    Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1
} -SuccessMessage "Bing Search in Start Menu is disabled" -FailureMessage "Bing Search in Start Menu is not disabled"

Test-Setting -Name "Windows Feedback Experience Program" -Test {
    Test-RegistryValue -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0
} -SuccessMessage "Windows Feedback Experience program is stopped" -FailureMessage "Windows Feedback Experience program is not stopped"

Test-Setting -Name "Wi-Fi Sense (HotSpot Reporting)" -Test {
    Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Value 0
} -SuccessMessage "Wi-Fi Sense HotSpot Reporting is disabled" -FailureMessage "Wi-Fi Sense HotSpot Reporting is not disabled"

Test-Setting -Name "Wi-Fi Sense (Auto Connect)" -Test {
    Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Value 0
} -SuccessMessage "Wi-Fi Sense Auto Connect is disabled" -FailureMessage "Wi-Fi Sense Auto Connect is not disabled"

Test-Setting -Name "Live Tiles" -Test {
    Test-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Value 1
} -SuccessMessage "Live Tiles are disabled" -FailureMessage "Live Tiles are not disabled"

Test-Setting -Name "People Icon on Taskbar" -Test {
    $peoplePath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
    if (Test-Path $peoplePath) {
        return (Get-ItemProperty -Path $peoplePath -Name "PeopleBand" -ErrorAction SilentlyContinue).PeopleBand -eq 0
    }
    return $true  # If the path doesn't exist, assume it's configured correctly (newer Windows versions)
} -SuccessMessage "People icon on Taskbar is disabled" -FailureMessage "People icon on Taskbar is not disabled"

Test-Setting -Name "Cortana Privacy Settings" -Test {
    $test1 = Test-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0
    $test2 = Test-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1
    $test3 = Test-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1
    return $test1 -and $test2 -and $test3
} -SuccessMessage "Cortana privacy settings are configured correctly" -FailureMessage "Cortana privacy settings are not configured correctly"

Test-Setting -Name "3D Objects in Explorer" -Test {
    $objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    $objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    return -not (Test-Path $objects32) -and -not (Test-Path $objects64)
} -SuccessMessage "3D Objects are removed from Explorer" -FailureMessage "3D Objects are still present in Explorer"

Test-Setting -Name "Microsoft Feeds" -Test {
    Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0
} -SuccessMessage "Microsoft Feeds are disabled" -FailureMessage "Microsoft Feeds are not disabled"
#endregion WindowsCustomization

#region ScheduledTasks
Write-Host "`n[Checking Scheduled Tasks]" -ForegroundColor Cyan
$taskList = @(
    'XblGameSaveTaskLogon',
    'XblGameSaveTask',
    'Consolidator',
    'UsbCeip',
    'DmClient',
    'DmClientOnScenarioDownload'
)

foreach ($task in $taskList) {
    Test-Setting -Name "Scheduled Task: $task" -Test {
        Test-ScheduledTaskDisabled -TaskName $task
    } -SuccessMessage "Scheduled task $task is disabled" -FailureMessage "Scheduled task $task is not disabled"
}
#endregion ScheduledTasks

#region DattoRMM
Write-Host "`n[Checking Datto RMM]" -ForegroundColor Cyan
Test-Setting -Name "Datto RMM Service" -Test {
    $service = Get-Service -Name "CagService" -ErrorAction SilentlyContinue
    return $null -ne $service -and $service.Status -eq "Running"
} -SuccessMessage "Datto RMM service is running" -FailureMessage "Datto RMM service is not running"

Test-Setting -Name "Datto RMM Files" -Test {
    Test-Path "C:\Program Files (x86)\CentraStage"
} -SuccessMessage "Datto RMM files are installed" -FailureMessage "Datto RMM files are not installed"
#endregion DattoRMM

#region WindowsUpdate
Write-Host "`n[Checking Windows Update]" -ForegroundColor Cyan
Test-Setting -Name "Windows Update Service" -Test {
    $service = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    return $null -ne $service -and $service.Status -eq "Running" -and $service.StartType -eq "Automatic"
} -SuccessMessage "Windows Update service is running and set to Automatic" -FailureMessage "Windows Update service is not running or not set to Automatic"
#endregion WindowsUpdate

#region WakeLock
Write-Host "`n[Checking WakeLock]" -ForegroundColor Cyan
Test-Setting -Name "WakeLock Script" -Test {
    Test-Path "$TempFolder\WakeLock.ps1"
} -SuccessMessage "WakeLock script exists" -FailureMessage "WakeLock script does not exist"

Test-Setting -Name "WakeLock Exit Flag" -Test {
    Test-Path "$TempFolder\wakelock.flag"
} -SuccessMessage "WakeLock exit flag exists" -FailureMessage "WakeLock exit flag does not exist"
#endregion WakeLock

# Display Summary
$naCount = ($ValidationSummary | Where-Object { $_.Status -eq "N/A" }).Count
$totalChecks = $PassCount + $FailCount
$passPercentage = if ($totalChecks -gt 0) { [math]::Round(($PassCount / $totalChecks) * 100, 2) } else { 100 }

$Padding = ("=" * [System.Console]::BufferWidth)
Write-Host "`n$Padding" -ForegroundColor Cyan
Print-Middle "Validation Summary" "Cyan"
Write-Host "$Padding" -ForegroundColor Cyan

Write-Host "`nTotal Checks: $($totalChecks + $naCount)" -ForegroundColor White
Write-Host "Passed: $PassCount ($passPercentage%)" -ForegroundColor Green
Write-Host "Failed: $FailCount" -ForegroundColor $(if ($FailCount -gt 0) {"Red"} else {"Green"})
Write-Host "Not Applicable: $naCount" -ForegroundColor Yellow

if ($FailCount -gt 0) {
    Write-Host "`nFailed Checks:" -ForegroundColor Red
    $ValidationSummary | Where-Object { $_.Status -eq "FAIL" -or $_.Status -eq "ERROR" } | Format-Table -AutoSize
}

if ($naCount -gt 0) {
    Write-Host "`nNot Applicable Checks:" -ForegroundColor Yellow
    $ValidationSummary | Where-Object { $_.Status -eq "N/A" } | Format-Table -AutoSize
}

# Stop transcript
Stop-Transcript

# Final message
Write-Host "`nValidation complete. Results are available in:" -ForegroundColor Yellow
Write-Host "  * $LogFile" -ForegroundColor Cyan
Write-Host "  * $TempFolder\$env:COMPUTERNAME-baseline-validation_transcript.txt" -ForegroundColor Cyan
Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") 