############################################################################################################
#                                     SOS - New Workstation Baseline Script                                #
#                                                 Version 1.7.1                                           #
############################################################################################################
#region Synopsis
<#
.SYNOPSIS
    Automates the configuration and deployment of a standardized Windows workstation environment.

.DESCRIPTION
    This script performs a comprehensive baseline setup for new Windows 10/11 workstations including:
    - Datto RMM agent deployment
    - Power profile optimization
    - System configuration and hardening
    - Windows Update management
    - Microsoft 365 and Adobe Acrobat installation
    - Removal of bloatware and unnecessary features
    - BitLocker encryption configuration
    - Sophos Endpoint Security installation
    - System restore point creation

.PARAMETER None
    This script does not accept parameters.

.NOTES
    Version:        1.7.1
    Author:         Bill Ulrich
    Creation Date:  3/25/2025
    Requires:       Administrator privileges
                    Windows 10/11 Professional
    
.EXAMPLE
    .\SOS-Baseline.ps1
    
    Run the script with administrator privileges to execute the full baseline configuration.

.LINK
    https://github.com/mitsdev01/SOS
#>

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as an Administrator!" -ForegroundColor Red
    Start-Sleep -Seconds 8
    return
}

# Initial setup and version
$ScriptVersion = "1.7.1"
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$TempFolder = "C:\temp"
$LogFile = "$TempFolder\$env:COMPUTERNAME-baseline.log"

#Write-Delayed "Stage installer links..." -NewLine:$false
try {
    # Create temp directory if it doesn't exist
    if (-not (Test-Path "C:\temp")) {
        New-Item -Path "C:\temp" -ItemType Directory -Force | Out-Null
    }
    # Download links
    Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/SEPLinks.enc" -OutFile "c:\temp\SEPLinks.enc" -ErrorAction Stop | Out-Null
    Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/urls.enc" -OutFile "c:\temp\urls.enc" -ErrorAction Stop | Out-Null
    # Verify file exists and has content
    if (-not (Test-Path "c:\temp\SEPLinks.enc")) {
        throw "Failed to download encrypted links file"
    }
    
    $fileSize = (Get-Item "c:\temp\SEPLinks.enc").Length
    if ($fileSize -eq 0) {
        throw "Downloaded encrypted links file is empty"
    }
    Write-TaskComplete
    Write-Log "Successfully downloaded installer links"
}
catch {
    Write-TaskFailed
    Write-Log "Failed to download installer links: $_"
    [System.Windows.Forms.MessageBox]::Show(
        "Failed to download installer links. The script may not function correctly.`n`nError: $_",
        "Download Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
}




# Function to decrypt files using AES
function Decrypt-SoftwareURLs {
    param (
        [string]$FilePath = "$TempFolder\\urls.enc", # Default to urls.enc
        [switch]$ShowDebug
    )
    
    try {
        # Create a fixed encryption key (32 bytes for AES-256)
        $key = [byte[]]@(
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
        )

        # Read the encrypted file
        if (-not (Test-Path $FilePath)) {
            throw "Encrypted file not found: $FilePath"
        }

        $encryptedData = [System.IO.File]::ReadAllBytes($FilePath)

        # Extract IV (first 16 bytes)
        $iv = $encryptedData[0..15]

        # Extract encrypted data (remaining bytes)
        $encryptedBytes = $encryptedData[16..($encryptedData.Length - 1)]

        # Create AES object
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        try {
            # Create decryptor
            $decryptor = $aes.CreateDecryptor()
            
            # Decrypt the data
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
            
            # Convert bytes to string
            $json = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

            if ($ShowDebug) {
                Write-Host "`nDecrypted JSON from $FilePath :" | Out-Null
                Write-Host $json | Out-Null
            }
            
            # Convert JSON to PowerShell object
            $result = $json | ConvertFrom-Json

            # Debug: Show object type and properties
            if ($ShowDebug) {
                Write-Host "`nObject Type: $($result.GetType().FullName)" | Out-Null
                Write-Host "Available Properties:" | Out-Null
                $result.PSObject.Properties | ForEach-Object {
                    Write-Host "  $($_.Name) = $($_.Value)" | Out-Null
                }
            }

            return $result
        }
        finally {
            if ($decryptor) { $decryptor.Dispose() }
            if ($aes) { $aes.Dispose() }
        }
    }
    catch {
        Write-Error "Failed to decrypt file $FilePath : $_" | Out-Null
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to load installer links from $FilePath.`n`nError: $_",
            "Decryption Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return $null
    }
}

# Function to decrypt Sophos links file using AES
function Decrypt-SophosLinks {
    param (
        [string]$FilePath = "$TempFolder\\SEPLinks.enc", # Default to SEPLinks.enc
        [switch]$ShowDebug
    )

    try {
        # Create a fixed encryption key (32 bytes for AES-256) - Ensure this matches the encryption key
        $key = [byte[]]@(
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
        )

        # Read the encrypted file
        if (-not (Test-Path $FilePath)) {
            throw "Encrypted Sophos links file not found: $FilePath"
        }

        $encryptedData = [System.IO.File]::ReadAllBytes($FilePath)

        # Extract IV (first 16 bytes)
        $iv = $encryptedData[0..15]

        # Extract encrypted data (remaining bytes)
        $encryptedBytes = $encryptedData[16..($encryptedData.Length - 1)]

        # Create AES object
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        try {
            # Create decryptor
            $decryptor = $aes.CreateDecryptor()

            # Decrypt the data
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)

            # Convert bytes to string
            $json = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

            if ($ShowDebug) {
                Write-Host "`nDecrypted JSON from $FilePath :" | Out-Null
                Write-Host $json | Out-Null
            }

            # Convert JSON to PowerShell object (should be an OrderedDictionary structure)
            $result = $json | ConvertFrom-Json # REMOVED -AsHashtable for PS 5.1 compatibility

            # Debug: Show object type and properties
            if ($ShowDebug) {
                Write-Host "`nObject Type: $($result.GetType().FullName)" | Out-Null
                Write-Host "Available Properties/Keys:" | Out-Null
                # Iterate PSCustomObject properties correctly
                $result.PSObject.Properties | ForEach-Object {
                    Write-Host "  $($_.Name) = $($_.Value)" | Out-Null
                }
            }

            # Return the Hashtable/Dictionary
            return $result
        }
        finally {
            if ($decryptor) { $decryptor.Dispose() }
            if ($aes) { $aes.Dispose() }
        }
    }
    catch {
        Write-Error "Failed to decrypt Sophos links file $FilePath : $_" | Out-Null
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to load Sophos links from $FilePath.`n`nError: $_",
            "Decryption Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return $null
    }
}

# Function to safely get URL from decrypted data
function Get-DecryptedURL {
    param (
        [Parameter(Mandatory=$true)]
        [object]$Data,
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [string]$Description = "URL"
    )

    if ($null -eq $Data) {
        throw "Decrypted data is null"
    }

    if (-not $Data.PSObject.Properties.Name.Contains($Key)) {
        throw "Key '$Key' not found in decrypted data"
    }

    $value = $Data.$Key
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$Description is empty or null"
    }

    return $value
}

function Decrypt-InstallerLinks {
    param (
        [string]$InputFile = "c:\temp\SEPLinks.enc"
    )

    # Read the encrypted file
    $encryptedData = [System.IO.File]::ReadAllBytes($InputFile)

    # Extract IV (first 16 bytes)
    $iv = $encryptedData[0..15]

    # Extract encrypted data (remaining bytes)
    $encryptedBytes = $encryptedData[16..($encryptedData.Length - 1)]

    # Create a fixed encryption key (32 bytes for AES-256)
    $key = [byte[]]@(
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
    )

    # Create AES object
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    # Create decryptor
    $decryptor = $aes.CreateDecryptor()

    # Decrypt the data
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)

    # Convert bytes to string
    $json = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

    # Convert JSON to PowerShell object
    $InstallerLinks = $json | ConvertFrom-Json

    # Return the decrypted links
    return $InstallerLinks
}

# Function to get client-specific Sophos URL
function Get-SophosClientURL {
    param (
        [string]$ClientName,
        # Remove Hashtable constraint, accept PSCustomObject
        [object]$SophosLinksData
    )

    if ($null -eq $SophosLinksData) {
        Write-Error "Sophos Links data is null. Cannot retrieve URL for '$ClientName'." | Out-Null
        return $null
    }

    # Access the URL directly using the client name as the key
    # Use PSObject.Properties for robust checking on PSCustomObject
    $prop = $SophosLinksData.PSObject.Properties[$ClientName]
    if ($null -eq $prop) {
        Write-Error "Client '$ClientName' not found as a property in decrypted Sophos Links data." | Out-Null
        return $null
    }

    # Return the value of the property
    return $prop.Value
}

try {
    # Decrypt software download URLs first
    $softwareLinks = Decrypt-SoftwareURLs -FilePath "$TempFolder\urls.enc" -ShowDebug:$false | Out-Null
    if ($null -eq $softwareLinks) {
        throw "Failed to decrypt software URLs"
    }

    # Assign URLs from decrypted data
    $CheckModules = $softwareLinks.CheckModules
    $DattoRMM = $softwareLinks.DattoRMM
    $OfficeURL = $softwareLinks.OfficeURL
    $AdobeURL = $softwareLinks.AdobeURL
    $Win11DebloatURL = $softwareLinks.Win11DebloatURL
    $Win10DebloatURL = $softwareLinks.Win10DebloatURL
    $SOSDebloatURL = $softwareLinks.SOSDebloatURL
    $UpdateWindowsURL = $softwareLinks.UpdateWindowsURL
    $BaselineCompleteURL = $softwareLinks.BaselineCompleteURL

    # Verify all URLs are available
    $requiredUrls = @{
        'CheckModules' = $CheckModules
        'DattoRMM' = $DattoRMM
        'OfficeURL' = $OfficeURL
        'AdobeURL' = $AdobeURL
        'Win11DebloatURL' = $Win11DebloatURL
        'Win10DebloatURL' = $Win10DebloatURL
        'SOSDebloatURL' = $SOSDebloatURL
        'UpdateWindowsURL' = $UpdateWindowsURL
        'BaselineCompleteURL' = $BaselineCompleteURL
    }

    $missingUrls = $requiredUrls.GetEnumerator() | Where-Object { [string]::IsNullOrEmpty($_.Value) } | Select-Object -ExpandProperty Key
    if ($missingUrls) {
        throw "The following URLs are missing or empty:`n$($missingUrls -join "`n")"
    }

    # Now decrypt Sophos installer links
    $sepLinks = Decrypt-SophosLinks -FilePath "$TempFolder\SEPLinks.enc" -ShowDebug:$false | Out-Null
    if ($null -eq $sepLinks) {
        throw "Failed to decrypt Sophos installer links"
    }

    $DefaultClientName = 'Atlanta Family Law Immigration' # CHANGE THIS AS NEEDED
    $SophosAV = Get-SophosClientURL -ClientName $DefaultClientName -SophosLinksData $sepLinks
    if ([string]::IsNullOrWhiteSpace($SophosAV)) {
        throw "Failed to retrieve the Sophos AV URL for '$DefaultClientName'. Check SEPLinks.enc and the client name."
    }

    Write-Host "Using Sophos AV URL for '$DefaultClientName': $SophosAV" | Out-Null
    Write-Host "`nSuccessfully loaded all required URLs" | Out-Null
}
catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Failed to process URLs.`n`nError: $_",
        "URL Processing Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit 1
}

# Store system type for use in termination handler
$global:IsMobileDevice = $false

Set-ExecutionPolicy RemoteSigned -Force *> $null

# Set up termination handler for Ctrl+C and window closing
$null = [Console]::TreatControlCAsInput = $true
# Register termination handler
$null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    Write-Host "`n`nScript termination detected. Performing cleanup..." -ForegroundColor Yellow
    # Create WakeLock exit flag to stop the WakeLock script if it's running
    if (-not (Test-Path "c:\temp\wakelock.flag")) {
        try {
            New-Item -Path "c:\temp\wakelock.flag" -ItemType File -Force | Out-Null
            Write-Host "WakeLock flag created to stop background script." -ForegroundColor Cyan
        }
        catch {
            Write-Host "Failed to create WakeLock flag: $_" -ForegroundColor Red
        }
    }
    
    # If mobile device, stop presentation settings
    if ($global:IsMobileDevice) {
        try {
            $presentationProcess = Get-Process | Where-Object { $_.Path -eq "C:\Windows\System32\PresentationSettings.exe" } -ErrorAction SilentlyContinue
            if ($presentationProcess) {
                Stop-Process -InputObject $presentationProcess -Force -ErrorAction SilentlyContinue
                Write-Host "Stopped presentation settings." -ForegroundColor Cyan
            }
        }
        catch {
            Write-Host "Failed to stop presentation settings: $_" -ForegroundColor Red
        }
    }
    
    # Re-enable Windows Update service if it was disabled
    try {
        $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        if ($wuService -and $wuService.StartType -eq 'Disabled') {
            Set-Service -Name wuauserv -StartupType Manual -ErrorAction SilentlyContinue
            Start-Service -Name wuauserv -ErrorAction SilentlyContinue
            Write-Host "Re-enabled Windows Update service." -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "Failed to re-enable Windows Update service: $_" -ForegroundColor Red
    }
    
    # Log termination
    Add-Content -Path $LogFile -Value "$(Get-Date) - Script terminated by user." -ErrorAction SilentlyContinue
    
    Write-Host "Cleanup completed. Exiting script." -ForegroundColor Yellow
}

# Create required directories
if (-not (Test-Path $TempFolder)) { New-Item -Path $TempFolder -ItemType Directory | Out-Null }
if (-not (Test-Path $LogFile)) { New-Item -Path $LogFile -ItemType File | Out-Null }

# Add log file header
$headerBorder = "=" * 80
$header = @"
$headerBorder
                        SOS WORKSTATION BASELINE LOG
                             Version $ScriptVersion
                         $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
$headerBorder

Computer: $env:COMPUTERNAME
User: $env:USERNAME
Windows: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
$headerBorder

"@
Add-Content -Path $LogFile -Value $header

# Set working directory
Set-Location -Path $TempFolder

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

# Function to decrypt installer links

# Clear console window
Clear-Host

############################################################################################################
#                                                 Functions                                                #
#                                                                                                           #
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
    
    # Add to log file
    Write-Log "$Text"
    
    # Write to transcript in one go (not character by character)
    Write-Host $Text -NoNewline -ForegroundColor $Color
    if ($NewLine) {
        Write-Host ""
    }
    
    # Clear the line where we just wrote to avoid duplication in console
    $originalColor = [Console]::ForegroundColor
    [Console]::ForegroundColor = $Color
    [Console]::SetCursorPosition(0, [Console]::CursorTop)
    [Console]::Write("".PadRight([Console]::BufferWidth - 1))  # Clear the line
    [Console]::SetCursorPosition(0, [Console]::CursorTop)
    
    # Now do the visual character-by-character animation for the console only
    foreach ($char in $Text.ToCharArray()) {
        [Console]::Write($char)
        Start-Sleep -Milliseconds 25
    }
    
    # Add newline if requested
    if ($NewLine) {
        [Console]::WriteLine()
    }
    
    # Restore original color
    [Console]::ForegroundColor = $originalColor
}

function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "[$timestamp] $Message"
}

function Write-TaskComplete {
    # Log to file
    Write-Log "Task completed successfully"
    
    # Write to both transcript and console without creating a new line
    Write-Host " done." -ForegroundColor Green -NoNewline
    
    # Add the newline after the "done." message
    Write-Host ""
}

function Write-TaskFailed {
    # Log to file
    Write-Log "Task failed"
    
    # Write to both transcript and console without creating a new line
    Write-Host " failed." -ForegroundColor Red -NoNewline
    
    # Add the newline after the "failed." message
    Write-Host ""
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

function Is-Windows11 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption
    # Check for Windows 11
    return $osVersion -ge "10.0.22000" -and $osProduct -like "*Windows 11*"
}

function Is-Windows10 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption
    # Check for Windows 10
    return $osVersion -lt "10.0.22000" -and $osProduct -like "*Windows 10*"
}

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

function Show-SpinningWait {
    param (
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$DoneMessage = "done.",
        [Parameter(ValueFromRemainingArguments = $true)]
        [object[]]$ArgumentList,
        [switch]$SuppressOutput = $false
    )
    
    # Visual delayed writing (will also be included in transcript)
    Write-Delayed "$Message" -NewLine:$false
    $spinner = @('/', '-', '\', '|')
    $spinnerIndex = 0
    $jobName = [Guid]::NewGuid().ToString()
    
    # Start the script block as a job
    $job = Start-Job -Name $jobName -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    
    # Display spinner while job is running
    while ($job.State -eq 'Running') {
        [Console]::Write($spinner[$spinnerIndex])
        Start-Sleep -Milliseconds 100
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    }
    
    # Get the job result - Get job output first for transcript
    $jobOutput = Receive-Job -Name $jobName
    
    # Log job output to transcript if there is any
    if ($jobOutput -and -not $SuppressOutput) {
        Write-Host "`nJob output: $($jobOutput -join "`n")" -ForegroundColor Gray
    }
    
    Remove-Job -Name $jobName
    
    # Write done message once (will be captured in transcript)
    # and handle visual formatting
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write($DoneMessage)
    [Console]::ResetColor()
    [Console]::WriteLine()
    
    # Log completion to the log file
    Write-Log "Completed: $Message"
    
    return $jobOutput
}

function Show-SpinnerWithProgressBar {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $true)]
        [string]$URL,
        [Parameter(Mandatory = $true)]
        [string]$OutFile,
        [string]$DoneMessage = "done."
    )
    
    # Visual delayed writing (will also be included in transcript)
    Write-Delayed "$Message" -NewLine:$false
    
    # Create parent directory for output file if it doesn't exist
    $outDir = Split-Path -Parent $OutFile
    if (-not (Test-Path $outDir)) {
        New-Item -Path $outDir -ItemType Directory -Force | Out-Null
    }
    
    $spinner = @('/', '-', '\', '|')
    $spinnerIndex = 0
    $done = $false
    
    # Start download in a separate runspace
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $powerShell = [powershell]::Create()
    $powerShell.Runspace = $runspace
    
    # Add script to download file
    [void]$powerShell.AddScript({
        param($URL, $OutFile)
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($URL, $OutFile)
    }).AddArgument($URL).AddArgument($OutFile)
    
    # Start the download asynchronously
    $handle = $powerShell.BeginInvoke()
    
    # Display spinner while downloading
    try {
        while (-not $handle.IsCompleted) {
            # Write the current spinner character
            [Console]::Write($spinner[$spinnerIndex])
            Start-Sleep -Milliseconds 100
            [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
            $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
        }
        
        # Complete the async operation
        $powerShell.EndInvoke($handle) | Out-String | Write-Debug
    }
    catch {
        # Ensure errors are written to transcript
        Write-Host "`nError during download: $_" -ForegroundColor Red
    }
    finally {
        # Clean up resources
        $powerShell.Dispose()
        $runspace.Dispose()
        
        # Write done message once (will be captured in transcript)
        # and handle visual formatting
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write($DoneMessage)
        [Console]::ResetColor()
        [Console]::WriteLine()
        
        # Ensure it's in the transcript too
        #Write-Verbose "Finished: $Message $DoneMessage" -Verbose
    }
}

function Show-SpinnerAnimation {
    param (
        [ScriptBlock]$ScriptBlock,
        [string]$Message,
        [System.ConsoleColor]$SuccessColor = [System.ConsoleColor]::Green
    )
    
    $spinChars = '/', '-', '\', '|'
    $pos = 0
    $originalCursorVisible = [Console]::CursorVisible
    [Console]::CursorVisible = $false
    
    # Visual delayed writing (will also be included in transcript)
    Write-Delayed $Message -NewLine:$false
    
    $job = Start-Job -ScriptBlock $ScriptBlock
    
    try {
        while ($job.State -eq 'Running') {
            [Console]::Write($spinChars[$pos])
            Start-Sleep -Milliseconds 100
            [Console]::Write("`b")
            $pos = ($pos + 1) % 4
        }
        
        # Get the job result
        $result = Receive-Job -Job $job
        
        # Display completion status
        [Console]::ForegroundColor = $SuccessColor
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()
        
        return $result
    }
    finally {
        Remove-Job -Job $job -Force
        [Console]::CursorVisible = $originalCursorVisible
    }
}

function Show-Spinner {
    param (
        [int]$SpinnerIndex,
        [string[]]$SpinnerChars = @('/', '-', '\', '|'),
        [int]$CursorLeft,
        [int]$CursorTop
    )
    
    # Use only Console methods to avoid writing to transcript
    [Console]::SetCursorPosition($CursorLeft, $CursorTop)
    [Console]::Write($SpinnerChars[$SpinnerIndex % $SpinnerChars.Length])
}

# Function to decrypt and load installer links
function Get-InstallerLinks {
    param (
        [string]$EncryptedFile = "c:\temp\SEPLinks.enc"
    )

    try {
        # Read the encrypted bytes from the file
        $allBytes = [System.IO.File]::ReadAllBytes($EncryptedFile)

        # Extract IV and encrypted data
        $iv = $allBytes[0..15]
        $encryptedBytes = $allBytes[16..($allBytes.Length - 1)]

        # Create a fixed encryption key (32 bytes for AES-256)
        $key = [byte[]]@(
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
        )

        # Create AES object
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        # Create decryptor
        $decryptor = $aes.CreateDecryptor()

        # Decrypt the data
        $bytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)

        # Convert bytes to JSON string
        $json = [System.Text.Encoding]::UTF8.GetString($bytes)

        # Convert JSON to PSObject
        $InstallerLinks = $json | ConvertFrom-Json

        # Convert to OrderedDictionary to maintain order
        $orderedDict = New-Object Collections.Specialized.OrderedDictionary
        $InstallerLinks.PSObject.Properties | ForEach-Object {
            $orderedDict.Add($_.Name, $_.Value)
        }

        return $orderedDict
    }
    catch {
        Write-Error "Failed to load installer links: $_"
        return $null
    }
}


function Get-DecryptedURL {
    param (
        [string]$Key
    )
    
    try {
        # Check if file exists
        if (-not (Test-Path "c:\temp\SEPLinks.enc")) {
            throw "Encrypted file not found at c:\temp\SEPLinks.enc"
        }
        
        # Check if file has content
        $fileSize = (Get-Item "c:\temp\SEPLinks.enc").Length
        if ($fileSize -eq 0) {
            throw "Encrypted file is empty"
        }
        
        # Read the encrypted file
        $encryptedBytes = [System.IO.File]::ReadAllBytes("c:\temp\SEPLinks.enc")
        
        # Verify minimum file size for key, IV, and some data
        if ($encryptedBytes.Length -lt 64) { # 32 bytes key + 16 bytes IV + at least 16 bytes data
            throw "Encrypted file is too small to be valid"
        }
        
        # Extract key, IV, and encrypted data
        $keyBytes = $encryptedBytes[0..31]
        $ivBytes = $encryptedBytes[32..47]
        $encryptedData = $encryptedBytes[48..($encryptedBytes.Length - 1)]
        
        # Create AES decryptor
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.Key = $keyBytes
        $aes.IV = $ivBytes
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        try {
            # Create decryptor
            $decryptor = $aes.CreateDecryptor()
            
            # Decrypt the data
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
            
            # Convert to JSON
            $json = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
            
            # Validate JSON
            if (-not ($json -match '^{.*}$')) {
                throw "Decrypted data is not valid JSON"
            }
            
            # Convert to PowerShell object
            $links = $json | ConvertFrom-Json
            
            # Check if key exists
            if (-not $links.PSObject.Properties.Name.Contains($Key)) {
                throw "Key '$Key' not found in decrypted data"
            }
            
            # Return the requested URL
            return $links.$Key
        }
        finally {
            if ($decryptor) { $decryptor.Dispose() }
            if ($aes) { $aes.Dispose() }
        }
    }
    catch {
        Write-Log "Error decrypting URL for key '$Key': $_"
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to load installer links. Please ensure the encrypted file exists and is accessible.`n`nError: $_",
            "Decryption Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return $null
    }
}

function Decrypt-SetupLinks {
    param (
        [string]$InputFile = "c:\temp\urls.enc"
    )

    # Read the encrypted file
    $encryptedData = [System.IO.File]::ReadAllBytes($InputFile)

    # Extract IV (first 16 bytes)
    $iv = $encryptedData[0..15]

    # Extract encrypted data (remaining bytes)
    $encryptedBytes = $encryptedData[16..($encryptedData.Length - 1)]

    # Create a fixed encryption key (32 bytes for AES-256)
    $key = [byte[]]@(
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
    )

    # Create AES object
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    # Create decryptor
    $decryptor = $aes.CreateDecryptor()

    # Decrypt the data
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)

    # Convert bytes to string
    $json = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

    # Convert JSON to PowerShell object
    $InstallerLinks = $json | ConvertFrom-Json

    # Return the decrypted links
    return $InstallerLinks
}

function Start-VssService {
    $vss = Get-Service -Name 'VSS' -ErrorAction SilentlyContinue
    if ($vss.Status -ne 'Running') {
        Write-Delayed "Starting Volume Shadow Copy service for restore point creation..." -NewLine:$false
        Start-Service VSS
        Write-TaskComplete
    }
}

function Remove-RestorePointFrequencyLimit {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "SystemRestorePointCreationFrequency" -Value 0
}

function Create-RestorePoint-WithTimeout {
    param (
        [string]$Description,
        [int]$TimeoutSeconds = 60
    )

    $job = Start-Job { Checkpoint-Computer -Description $using:Description -RestorePointType "MODIFY_SETTINGS" }
    $completed = Wait-Job $job -Timeout $TimeoutSeconds

    if (-not $completed) {
        Write-Error "  [-] Restore point creation timed out after $TimeoutSeconds seconds. Stopping job..."
        Stop-Job $job -Force
        Remove-Job $job
    } else {
        Receive-Job $job
        Write-Host "  [+] Restore point created successfully." -ForegroundColor Green
        Remove-Job $job
    }
}

function Start-CleanTranscript {
    param (
        [string]$Path
    )
    
    try {
        # Stop any existing transcript
        try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
        
        # Start new transcript
        Start-Transcript -Path $Path -Force -ErrorAction Stop
        
        # Don't write the header here anymore, it will be displayed in the Title Screen section
        return $true
    }
    catch {
        Write-Warning "Failed to start transcript: $_"
        return $false
    }
}

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

#endregion Functions


############################################################################################################
#                                                Transcript Logging                                        #
#                                                                                                          #
############################################################################################################
#region Logging
# Start transcript logging  
Start-CleanTranscript -Path "$TempFolder\$env:COMPUTERNAME-baseline_transcript.txt" | Out-Null
$links = Decrypt-SophosLinks

Clear-Host
#endregion Logging

############################################################################################################
#                                             Title Screen                                                 #
#                                                                                                          #
############################################################################################################
#region Title Screen

# Print Script Title - This will be displayed and captured in the transcript
$Padding = ("=" * [System.Console]::BufferWidth)
Write-Host -ForegroundColor "Green" $Padding -NoNewline
Print-Middle "SOS - Workstation Baseline Script"
Write-Host -ForegroundColor Yellow "                                                   version $ScriptVersion"
Write-Host -ForegroundColor "Green" -NoNewline $Padding
Write-Host "  "
Start-Sleep -Seconds 2


############################################################################################################
#                                             Start Baseline                                               #
#                                                                                                          #
############################################################################################################
# Start baseline

# Baseline log file
Write-Log "Automated workstation baseline has started"

$ProgressPreference = "SilentlyContinue"


# Check for required modules
Write-Delayed "Preparing required modules..." -NewLine:$false
$spinner = @('/', '-', '\', '|')
$spinnerIndex = 0
$originalCursorLeft = [Console]::CursorLeft
$originalCursorTop = [Console]::CursorTop

#  Run the module check in the background and show spinner
try {
    $job = Start-Job -ScriptBlock {
        param($moduleUrl)
        Invoke-Expression (Invoke-RestMethod $moduleUrl)
    } -ArgumentList $CheckModules
    
    # Display the spinner while the job is running
    while ($job.State -eq 'Running') {
        Show-Spinner -SpinnerIndex $spinnerIndex -CursorLeft $originalCursorLeft -CursorTop $originalCursorTop
        Start-Sleep -Milliseconds 100
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    }
    
    # Get the job result and clean up
    $result = Receive-Job -Job $job
    Remove-Job -Job $job -Force
    
    # Clear the spinner character
    [Console]::SetCursorPosition($originalCursorLeft, $originalCursorTop)
    [Console]::Write(" ")
    
    # Show completion
    [Console]::SetCursorPosition($originalCursorLeft, $originalCursorTop)
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write("done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    
    # Write to transcript
    #Write-Host "Module check completed successfully" -ForegroundColor Green
    #Write-Log "Module check completed successfully"
}
catch {
    # Handle errors
    if ($job -and $job.State -eq 'Running') {
        Stop-Job -Job $job
        Remove-Job -Job $job -Force
    }
    
    # Clear the spinner character
    [Console]::SetCursorPosition($originalCursorLeft, $originalCursorTop)
    [Console]::Write(" ")
    
    # Show error
    [Console]::SetCursorPosition($originalCursorLeft, $originalCursorTop)
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write("failed.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    
    # Ensure error is written to transcript
    Write-Host "Module check failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "Module check failed: $($_.Exception.Message)"
}


############################################################################################################
#                                            Wakelock Configuration                                        #
#                                                                                                          #
############################################################################################################
#region WakeLock
try {
    $computerSystem = Get-CimInstance -ClassName CIM_ComputerSystem
    $pcSystemType = $computerSystem.PCSystemType
    
    # Check if the system is a mobile device (PCSystemType 2 = Mobile)
    if ($pcSystemType -eq 2) {
        # Set global flag for termination handler
        $global:IsMobileDevice = $true
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


<# Uncomment and change $user value to the user you want to use as the local admin account
############################################################################################################
#                                        Account Configuration                                             #
#                                                                                                          #
############################################################################################################
#region Local Admin 
# ---------------------------------------------------------------------
# Configure Local Admin Account
# ---------------------------------------------------------------------
# Check if the user 'sossetup' exists
$user = Get-LocalUser -Name 'sossetup' -ErrorAction SilentlyContinue

if ($user) {
    # Check if the password is set to 'Never Expire'
    if (-not $user.PasswordNeverExpires) {
        Write-Delayed "Setting sossetup password to 'Never Expire'..." -NewLine:$false
        $user | Set-LocalUser -PasswordNeverExpires $true
        Write-TaskComplete
        Write-Log "Set sossetup password to never expire"
    }
} else {
    Write-Host "Creating local sossetup & setting password to 'Never Expire'..." -NoNewline
    $Password = ConvertTo-SecureString "ChangeMe!" -AsPlainText -Force
    New-LocalUser "sossetup" -Password $Password -FullName "SOSS Admin" -Description "sossetup Account" *> $null
    $newUser = Get-LocalUser -Name 'sossetup' -ErrorAction SilentlyContinue
    if ($newUser) {
        $newUser | Set-LocalUser -PasswordNeverExpires $true
        Add-LocalGroupMember -Group "Administrators" -Member "sossetup"
        Write-TaskComplete
        Write-Log "Created sossetup local admin account with non-expiring password"
    } else {
        Write-TaskFailed
        Write-Log "Failed to create sossetup account"
    }
}
#endregion LocalAdminAccount
#>

############################################################################################################
#                                        Windows Update Configuration                                      #
#                                                                                                          #
############################################################################################################
#region Windows Update
# Skip writing to transcript/output directly, just use console methods
# This prevents duplicate "Suspending Windows Update..." messages
[Console]::ForegroundColor = [System.ConsoleColor]::White
[Console]::Write("Suspending Windows Update...")
[Console]::ResetColor()

# Add to log file
Write-Log "Suspending Windows Update service"

# Initialize spinner
$spinner = @('/', '-', '\', '|')
$spinnerIndex = 0
[Console]::Write($spinner[$spinnerIndex])

# Stop the service first
try {
    # Update spinner
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
    
    Stop-Service -Name wuauserv -Force -ErrorAction Stop
    $stopSuccess = $true
    
    # Update spinner
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
} catch {
    $stopSuccess = $false
    Write-Log "Error stopping Windows Update service: $_"
}

# Then set startup type to disabled
try {
    # Update spinner
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
    
    Set-Service -Name wuauserv -StartupType Disabled -ErrorAction Stop
    $disableSuccess = $true
    
    # Update spinner
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
} catch {
    $disableSuccess = $false
    Write-Log "Error disabling Windows Update service: $_"
}

# Add a short delay for visual effect
Start-Sleep -Milliseconds 100

# Check both operations succeeded
$service = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if ($stopSuccess -and $disableSuccess -and $service.Status -eq 'Stopped') {
    # Clear the spinner character by moving cursor position back
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    
    # Use Write-Host for both transcript and console display
    Write-Host " done." -ForegroundColor Green
    
    Write-Log "Windows Update service suspended successfully"
} else {
    # Clear the spinner character by moving cursor position back
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    
    # Use Write-Host for both transcript and console display
    Write-Host " failed." -ForegroundColor Red
    
    Write-Log "Failed to suspend Windows Update service completely"
}
#endregion WindowsUpdate

############################################################################################################
#                                        Power Profile Configuration                                       #
#                                                                                                          #
############################################################################################################
#region Power Profile
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
Write-Delayed "Setting Standby idle time to never on battery..." -NewLine:$false
powercfg -setdcvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0
Write-TaskComplete

Write-Delayed "Setting Standby idle time to never on AC power..." -NewLine:$false
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
#endregion System Time


############################################################################################################
#                                        Bitlocker Configuration                                           #
#                                                                                                          #
############################################################################################################
#region Bitlocker
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
        # Write to transcript
        Write-Host "Bitlocker is already configured on $env:SystemDrive - " -ForegroundColor Red -NoNewline
        
        # Setup for non-blocking read with timeout
        $timeoutSeconds = 10
        $endTime = (Get-Date).AddSeconds($timeoutSeconds)
        $userResponse = $null

        # Write prompt to transcript
        #Write-Host "Do you want to skip configuring Bitlocker? (yes/no)" -NoNewline
        
        # For visual appearance
        Write-Host -ForegroundColor Red "Do you want to skip configuring Bitlocker? (yes/no)" -NoNewline

        while ($true) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.KeyChar -match '^[ynYN]$') {
                    $userResponse = $key.KeyChar
                    # Log response for transcript
                    Write-Host "`nUser selected: $userResponse to skip Bitlocker configuration."
                    break
                }
            } elseif ((Get-Date) -ge $endTime) {
                # Log timeout for transcript
                #Write-Host "`nNo response received, skipping Bitlocker configuration..." -NoNewline
                #Write-Host " done." -ForegroundColor Green
                
                # For visual appearance
                Write-Host "`nNo response received, skipping Bitlocker configuration..." -NoNewline
                Write-Host -ForegroundColor Green " done."
                $userResponse = 'y' # Assume 'yes' to skip if no response
                break
            }
            Start-Sleep -Milliseconds 100
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
            Write-Delayed "Configuring Bitlocker Disk Encryption..." -NewLine:$false
            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector -WarningAction SilentlyContinue | Out-Null
            Start-Process 'manage-bde.exe' -ArgumentList " -on $env:SystemDrive -UsedSpaceOnly" -Verb runas -Wait | Out-Null
            Write-Host " done." -ForegroundColor Green
            # Verify volume key protector exists
            $BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
            if ($BitLockerVolume.KeyProtector) {
                #Write-Host "Bitlocker disk encryption configured successfully."
            } else {
                Write-Host "Bitlocker disk encryption is not configured."
            }
        }
    } else {
        # Bitlocker is not configured
        Write-Delayed "Configuring Bitlocker Disk Encryption..." -NewLine:$false
        
        # Initialize spinner
        $spinner = @('/', '-', '\', '|')
        $spinnerIndex = 0
        
        # Create the recovery key
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
        
        # Start showing spinner
        [Console]::Write($spinner[$spinnerIndex])
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
        
        # Add TPM key
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector -WarningAction SilentlyContinue | Out-Null
        
        # Update spinner
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        [Console]::Write($spinner[$spinnerIndex])
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
        
        # Wait for the protectors to take effect
        Start-Sleep -Seconds 5
        
        # Update spinner
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        [Console]::Write($spinner[$spinnerIndex])
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
        
        # Enable Encryption
        $encryptionProcess = Start-Process 'manage-bde.exe' -ArgumentList "-on $env:SystemDrive -UsedSpaceOnly" -Verb runas -PassThru -Wait
        
        # Update spinner during encryption wait
        for ($i = 0; $i -lt 10; $i++) {
            [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
            [Console]::Write($spinner[$spinnerIndex])
            $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
            Start-Sleep -Milliseconds 100
        }
        
        # Backup the Recovery to AD
        $RecoveryKeyGUID = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | 
                            Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'} | 
                            Select-Object -ExpandProperty KeyProtectorID
        
        # Update spinner
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        [Console]::Write($spinner[$spinnerIndex])
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
        
        # Try AD backup (may fail in non-domain environments)
        try {
            manage-bde.exe -protectors $env:SystemDrive -adbackup -id $RecoveryKeyGUID | Out-Null
        }
        catch {
            Write-Log "Failed to backup BitLocker recovery key to AD: $_"
        }
        
        # Write Recovery Key to a file
        manage-bde -protectors C: -get | Out-File "$outputDirectory\$env:computername-BitLocker.txt"
        
        # Verify volume key protector exists
        $BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
        
        # Replace spinner with done message
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        # Use Write-Host instead of Console method to ensure proper transcript logging
        Write-Host " done." -ForegroundColor Green
        
        if ($BitLockerVolume.KeyProtector) {
            # Get recovery information
            $recoveryId = $BitLockerVolume.KeyProtector | 
                Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | 
                ForEach-Object { $_.KeyProtectorId.Trim('{', '}') }
            
            $recoveryPassword = $BitLockerVolume.KeyProtector | 
                Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | 
                Select-Object -ExpandProperty RecoveryPassword
            
            # Display recovery info
            Write-Delayed "Bitlocker has been successfully configured." -NewLine:$true
            # Display recovery details
            Write-Host -ForegroundColor Cyan "Recovery ID: $recoveryId"
            Write-Host -ForegroundColor Cyan "Recovery Password: $recoveryPassword"
            
            # Log success
            Write-Log "BitLocker encryption configured successfully with Recovery ID: $recoveryId"
        } else {
            Write-Host -ForegroundColor Red "Bitlocker disk encryption is not configured."
            
            # Log failure
            Write-Log "Failed to configure BitLocker encryption"
        }
    }
} else {
    Write-Warning "Skipping Bitlocker Drive Encryption due to device not meeting hardware requirements."
    Write-Log "Skipping Bitlocker Drive Encryption due to device not meeting hardware requirements."
    Start-Sleep -Seconds 1
}
#endregion Bitlocker


############################################################################################################
#                                        System Restore Configuration                                      #
#                                                                                                          #
############################################################################################################
#region System Restore
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
#region Profile Config
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
    New-Item $Search -Force | Out-Null
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
    New-Item $WebSearch -Force | Out-Null
}
Set-ItemProperty $WebSearch DisableWebSearch -Value 1
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 -ErrorAction SilentlyContinue
Write-TaskComplete
Write-Log "Bing Search disabled in Start Menu"

# Disable Mixed Reality Portal
Write-Delayed "Disabling Mixed Reality Portal..." -NewLine:$false
$Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
if (Test-Path $Holo) {
    Set-ItemProperty $Holo FirstRunSucceeded -Value 0 -ErrorAction SilentlyContinue
}
if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic")) {
    New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic" -Force | Out-Null
}
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic" FirstRunSucceeded -Value 0 -ErrorAction SilentlyContinue
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

if (!(Test-Path $WifiSense3)) {
    New-Item $WifiSense3 -Force | Out-Null
}
Set-ItemProperty $WifiSense3 AutoConnectAllowedOEM -Value 0 
Write-TaskComplete
Write-Log "Wi-Fi Sense disabled"

# Disable Live Tiles
Write-Delayed "Disabling live tiles..." -NewLine:$false
$Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
if (!(Test-Path $Live)) {      
    New-Item $Live -Force | Out-Null
}  
if (Test-Path $Live) {
    Set-ItemProperty $Live NoTileApplicationNotification -Value 1 -ErrorAction SilentlyContinue
}
Write-TaskComplete
Write-Log "Live tiles disabled"

# Disable People icon on Taskbar
Write-Delayed "Disabling People icon on Taskbar..." -NewLine:$false
$People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
if (Test-Path $People) {
    Set-ItemProperty $People PeopleBand -Value 0 -ErrorAction SilentlyContinue
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

# Initialize spinner
$spinner = @('/', '-', '\', '|')
$spinnerIndex = 0
[Console]::Write($spinner[$spinnerIndex])

$taskList = @(
    'XblGameSaveTaskLogon',
    'XblGameSaveTask',
    'Consolidator',
    'UsbCeip',
    'DmClient',
    'DmClientOnScenarioDownload'
)

foreach ($task in $taskList) {
    # Update spinner before checking each task
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
    
    $scheduledTask = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue 
    if ($null -ne $scheduledTask) {
        # Update spinner before disabling task
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
        [Console]::Write($spinner[$spinnerIndex])
        
        Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
    }
    
    # Small delay for visual effect
    Start-Sleep -Milliseconds 100
}

# Replace spinner with done message
[Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
# Use Write-Host instead of Console methods
Write-Host " done." -ForegroundColor Green

Write-Log "Disabled unnecessary scheduled tasks"

# Trigger SOS Debloat for Windows 10
if (Is-Windows10) {
    try {
        # $SOSDebloatURL = Get-DecryptedURL -Key "Win10DebloatURL" # REMOVED (Uses Win10DebloatURL variable now)
        $SOSDebloatFile = "c:\temp\SOS-Debloat.zip"
        Invoke-WebRequest -Uri $Win10DebloatURL -OutFile $SOSDebloatFile -UseBasicParsing -ErrorAction Stop # Use Win10DebloatURL
        Start-Sleep -seconds 2
        Expand-Archive $SOSDebloatFile -DestinationPath c:\temp\SOS-Debloat -Force
        Start-Sleep -Seconds 2
        Start-Process powershell -ArgumentList "-noexit","-Command Invoke-Expression -Command '& ''C:\temp\SOS-Debloat\SOS-Debloat.ps1'' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -ShowKnownFileExt -Silent'"
        Start-Sleep -Seconds 2
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait('%{TAB}')
        Start-Sleep -Seconds 30
        Write-Log "Windows 10 Debloat completed successfully."
        Write-TaskComplete
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}

############################################################################################################
#                                               Domain Join                                                #
#                                                                                                          #
############################################################################################################
#region DomainJoin
# Domain Join Process
#Write-Delayed "`nChecking if domain join is required..." -NewLine:$true

# Create a console-based input prompt while maintaining visual style
Write-Host -ForegroundColor Yellow "Do you want to join this computer to a domain? (Y/N): " -NoNewline
$joinDomain = Read-Host

# Check if the user wants to join the domain
if ($joinDomain -eq 'Y' -or $joinDomain -eq 'y') {
    # Prompt for domain information
    Write-Host -ForegroundColor Cyan "Enter the domain name"
    $domainName = Read-Host "Enter the domain name"
   
    Write-Host -ForegroundColor Cyan "Enter the domain admin username"
    $adminUser = Read-Host "Enter the domain admin username"
    
    Write-Host -ForegroundColor Cyan "Enter the password"
    $securePassword = Read-Host "Enter the password" -AsSecureString
    
    # Create a PSCredential object
    $credential = New-Object System.Management.Automation.PSCredential ($adminUser, $securePassword)
    
    # Show spinner while attempting domain join
    Write-Delayed "Attempting to join domain '$domainName'..." -NewLine:$false
    
    # Initialize spinner
    $spinner = @('/', '-', '\', '|')
    $spinnerIndex = 0
    [Console]::Write($spinner[$spinnerIndex])
    
    # Attempt to join the computer to the domain in a background job
    $joinJob = Start-Job -ScriptBlock {
        param($domainName, $credential)
        try {
            Add-Computer -DomainName $domainName -Credential $credential -Force -ErrorAction Stop
            return @{ Success = $true; Message = "Successfully joined the computer to the domain: $domainName" }
        } catch {
            return @{ Success = $false; Message = "Failed to join the domain: $_" }
        }
    } -ArgumentList $domainName, $credential
    
    # Show spinner while waiting for the domain join to complete
    while ($joinJob.State -eq 'Running') {
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        [Console]::Write($spinner[$spinnerIndex])
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
        Start-Sleep -Milliseconds 100
    }
    
    # Get the result of the domain join operation
    $result = Receive-Job -Job $joinJob
    Remove-Job -Job $joinJob
    
    # Display the result
    if ($result.Success) {
        # Replace spinner with success message
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()
        
        Write-Log "Successfully joined the computer to domain: $domainName"
        
        # Inform user about restart requirement
        [System.Windows.Forms.MessageBox]::Show(
            "Successfully joined domain '$domainName'. A restart is required to complete the process.",
            "Domain Join Successful",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    } else {
        # Replace spinner with failure message
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write(" failed.")
        [Console]::ResetColor()
        [Console]::WriteLine()
        
        Write-Log "Failed to join domain: $($result.Message)"
        
        # Show error message
        [System.Windows.Forms.MessageBox]::Show(
            $result.Message,
            "Domain Join Failed",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
} else {
    # User chose to skip domain join
    #Write-Host "Domain join process skipped." -ForegroundColor Yellow
    Write-Log "Domain join process skipped by user"
}

#endregion DomainJoin


############################################################################################################
#                                        Cleanup and Finalization                                        #
#                                                                                                          #
############################################################################################################
#region Baseline Cleanup
#Start-Sleep -seconds 60
# Enable and start Windows Update Service
Write-Delayed "Enabling Windows Update Service..." -NewLine:$false
Set-Service -Name wuauserv -StartupType Manual
Start-Sleep -seconds 3
Start-Service -Name wuauserv
Start-Sleep -Seconds 5
$service = Get-Service -Name wuauserv
if ($service.Status -eq 'Running') {
    # Use a single Write-Host for both transcript and console display
    Write-Host " done." -ForegroundColor Green
    
    Write-Log "Windows Update Service enabled and started successfully."
} else {
    # Use a single Write-Host for both transcript and console display
    Write-Host " failed." -ForegroundColor Red
    
    Write-Log "Windows Update Service failed to enable and start."
}

# Installing Windows Updates
Write-Delayed "Checking for Windows Updates..." -NewLine:$false
Set-UsoSvcAutomatic
$ProgressPreference = 'SilentlyContinue'
# $WindowsUpdateURL = Get-DecryptedURL -Key "WindowsUpdate" # REMOVED - Use variable loaded earlier
if ([string]::IsNullOrWhiteSpace($UpdateWindowsURL)) { throw "UpdateWindowsURL is not loaded." } # Added check
Invoke-WebRequest -Uri $UpdateWindowsURL -OutFile "c:\temp\update_windows.ps1" # Use UpdateWindowsURL

$ProgressPreference = 'Continue'
if (Test-Path "c:\temp\update_windows.ps1") {
    $updatePath = "C:\temp\Update_Windows.ps1"
    $null = Start-Process PowerShell -ArgumentList "-NoExit", "-File", $updatePath *> $null
    Start-Sleep -seconds 3
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.SendKeys]::SendWait('%{TAB}')
    Move-ProcessWindowToTop -processName "Windows PowerShell" | Out-Null
    Start-Sleep -Seconds 1
    
    # Use a single Write-Host for both transcript and console display
    Write-Host " done." -ForegroundColor Green
    
    Write-Log "All available Windows updates are installed."
     
} else {
    # Use a single Write-Host for both transcript and console display
    Write-Host "Windows Update execution failed!" -ForegroundColor Red
    
    Write-Log "Windows Update execution failed!"
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

############################################################################################################
#                                            Rename Machine                                                #
#                                                                                                          #
############################################################################################################
#region Rename Machine

# Check if rename has already been performed by the launcher
$trackerFilePath = "C:\temp\sos-rename-complete.flag"
if (Test-Path -Path $trackerFilePath) {
    Write-Host "Machine rename already performed via launcher, skipping..." -NoNewline
    Write-TaskComplete
    Write-Log "Machine rename skipped - tracker file found at $trackerFilePath"
} 
else {
    # Rename machine functionality with GUI prompt
    Write-Delayed "Prompting for new machine rename..." -NewLine:$false
    try {
        # Load required assemblies for GUI
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing

        # Add P/Invoke declarations for setting window position and foreground
        Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        
        public class ForegroundWindow {
            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool SetForegroundWindow(IntPtr hWnd);
            
            [DllImport("user32.dll")]
            public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
            
            [DllImport("user32.dll", SetLastError = true)]
            public static extern bool BringWindowToTop(IntPtr hWnd);
            
            [DllImport("user32.dll")]
            public static extern IntPtr GetForegroundWindow();
            
            [DllImport("user32.dll")]
            public static extern bool FlashWindow(IntPtr hwnd, bool bInvert);

            [DllImport("user32.dll")]
            public static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
            
            public const int GWL_EXSTYLE = -20;
            public const int WS_EX_TOPMOST = 0x0008;
        }
"@

        # Create form
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Rename Machine"
        $form.Size = New-Object System.Drawing.Size(400, 200)
        $form.StartPosition = "CenterScreen"
        $form.FormBorderStyle = "FixedDialog"
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false
        $form.TopMost = $true
        
        # Create label
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10, 20)
        $label.Size = New-Object System.Drawing.Size(380, 20)
        $label.Text = "Enter new machine name (15 characters max, no spaces):"
        $form.Controls.Add($label)

        # Create textbox
        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Location = New-Object System.Drawing.Point(10, 50)
        $textBox.Size = New-Object System.Drawing.Size(360, 20)
        $textBox.MaxLength = 15
        $textBox.Text = $env:COMPUTERNAME
        $form.Controls.Add($textBox)

        # Create status label
        $statusLabel = New-Object System.Windows.Forms.Label
        $statusLabel.Location = New-Object System.Drawing.Point(10, 80)
        $statusLabel.Size = New-Object System.Drawing.Size(380, 20)
        $statusLabel.ForeColor = [System.Drawing.Color]::Red
        $form.Controls.Add($statusLabel)

        # Create OK button
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(75, 120)
        $okButton.Size = New-Object System.Drawing.Size(100, 30)
        $okButton.Text = "Rename"
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Controls.Add($okButton)
        $form.AcceptButton = $okButton

        # Create Cancel button
        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(225, 120)
        $cancelButton.Size = New-Object System.Drawing.Size(100, 30)
        $cancelButton.Text = "Skip"
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Controls.Add($cancelButton)
        $form.CancelButton = $cancelButton

        # Validate name when text changes
        $textBox.Add_TextChanged({
            $newName = $textBox.Text
            if ($newName -match '\s') {
                $statusLabel.Text = "Machine name cannot contain spaces"
                $okButton.Enabled = $false
            } elseif ($newName.Length -eq 0) {
                $statusLabel.Text = "Machine name cannot be empty"
                $okButton.Enabled = $false
            } elseif ($newName -notmatch '^[a-zA-Z0-9\-]+$') {
                $statusLabel.Text = "Only letters, numbers, and hyphens are allowed"
                $okButton.Enabled = $false
            } else {
                $statusLabel.Text = ""
                $okButton.Enabled = $true
            }
        })

        # Additional form setup before showing
        $form.Add_Shown({
            # Set focus to the form
            $form.Activate()
            $form.Focus()
            
            # Delay to ensure other operations are complete
            Start-Sleep -Milliseconds 100
            
            # These force the window to be on top and active
            [ForegroundWindow]::BringWindowToTop($form.Handle)
            [ForegroundWindow]::SetForegroundWindow($form.Handle)
            [ForegroundWindow]::ShowWindow($form.Handle, 5) # SW_SHOW
            
            # Flash the window to get attention
            [ForegroundWindow]::FlashWindow($form.Handle, $true)
            
            # Set window as topmost via the Windows API
            [ForegroundWindow]::SetWindowLong($form.Handle, [ForegroundWindow]::GWL_EXSTYLE, 
                [ForegroundWindow]::WS_EX_TOPMOST)
        })

        # Show the form
        $result = $form.ShowDialog()

        # If OK was clicked and the name is different
        if ($result -eq [System.Windows.Forms.DialogResult]::OK -and $textBox.Text -ne $env:COMPUTERNAME) {
            $newName = $textBox.Text
            
            # Validate name
            if ($newName -match '^[a-zA-Z0-9\-]{1,15}$') {
                # Rename the machine
                Rename-Computer -NewName $newName -Force
                Write-Log "Machine renamed to: $newName (requires restart)"
                
                # Create a topmost message box for confirmation
                $confirmBox = New-Object System.Windows.Forms.Form
                $confirmBox.TopMost = $true
                [System.Windows.Forms.MessageBox]::Show(
                    $confirmBox,
                    "Computer has been renamed to '$newName'. Changes will take effect after restart.",
                    "Rename Successful",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
                Write-TaskComplete
            } else {
                Write-Log "Invalid Machine name entered: $newName"
                
                # Create a topmost message box for error
                $errorBox = New-Object System.Windows.Forms.Form
                $errorBox.TopMost = $true
                [System.Windows.Forms.MessageBox]::Show(
                    $errorBox,
                    "Invalid Machine name. Rename skipped.", 
                    "Rename Failed", 
                    [System.Windows.Forms.MessageBoxButtons]::OK, 
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
                Write-Host " skipped - invalid name." -ForegroundColor Yellow
            }
        } else {
            Write-Log "Machine rename skipped by user"
            Write-Host " skipped." -ForegroundColor Yellow
        }
    } catch {
        Write-Host " failed: $_" -ForegroundColor Red
        Write-Log "Error in computer rename process: $_"
    }
}


# Define temp files to clean up
$TempFiles = @(
    "c:\temp\SOS-Debloat.zip",
    "c:\temp\SOS-Debloat",
    "c:\temp\update_windows.ps1",
    "c:\temp\BaselineComplete.ps1",
    "c:\temp\DRMM-Install.log",
    "C:\temp\AcroRdrDC2500120432_en_US.exe",
    "c:\temp\$env:COMPUTERNAME-baseline.txt",
    "c:\temp\sos-rename-complete.flag",
    "c:\temp\SEPLinks.enc",
    "C:\temp\urls.enc"
)

Write-Delayed "Cleaning up temporary files..." -NewLine:$false

# Keep track of success for all deletions
$allSuccessful = $true

# Delete only specific temp files
foreach ($file in $TempFiles) {
    if (Test-Path $file) {
        try {
            if ((Get-Item $file) -is [System.IO.DirectoryInfo]) {
                # It's a directory, use -Recurse
                Remove-Item -Path $file -Recurse -Force -ErrorAction Stop
            } else {
                # It's a file
                Remove-Item -Path $file -Force -ErrorAction Stop
            }
            Write-Log "Removed temporary file/folder: $file"
        } catch {
            $allSuccessful = $false
            Write-Log "Failed to remove: $file - $($_.Exception.Message)"
        }
    }
}

# Don't remove the wakelock.flag until the very end
if (Test-Path "c:\temp\wakelock.flag") {
    Remove-Item -Path "c:\temp\wakelock.flag" -Force -ErrorAction SilentlyContinue
}

# Report success in console and log
if ($allSuccessful) {
    Write-TaskComplete
} else {
    Write-Host " completed with some errors." -ForegroundColor Yellow
}

Write-Log "Temporary file cleanup completed successfully."
#endregion Baseline Cleanup

############################################################################################################
#                                           Baseline Summary                                               #
#                                                                                                          #
############################################################################################################
#region Summary
# Display Baseline Summary
Write-Host ""
$Padding = ("=" * [System.Console]::BufferWidth)
# Visual formatting
Write-Host -ForegroundColor "Green" $Padding
Print-Middle "SOS Baseline Script Completed Successfully" "Green"
Print-Middle "Reboot recommended to finalize changes" "Yellow"
Write-Host -ForegroundColor "Green" $Padding

# Visual formatting
Write-Host -ForegroundColor "Cyan" "Logs are available at:"
Write-Host "  * $LogFile"
Write-Host "  * $TempFolder\$env:COMPUTERNAME-baseline_transcript.txt"
# $BaselineCompleteURL = Get-DecryptedURL -Key "BaselineComplete" # REMOVED - Use variable loaded earlier
if ([string]::IsNullOrWhiteSpace($BaselineCompleteURL)) { throw "BaselineCompleteURL is not loaded." } # Added check
Invoke-WebRequest -uri $BaselineCompleteURL -OutFile "c:\temp\BaselineComplete.ps1"
$scriptPath = "c:\temp\BaselineComplete.ps1"
Invoke-Expression "start powershell -ArgumentList '-noexit','-File $scriptPath'"
Write-Host " "
Write-Host " "
#endregion Summary

# Stopping transcript
Stop-Transcript *> $null

# Update log file with completion
Write-Log "Automated workstation baseline has completed successfully"

# Add footer to log file
$footerBorder = "=" * 80
$footer = @"
$footerBorder
                Baseline Configuration Completed Successfully
                      $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
$footerBorder
"@
Add-Content -Path $LogFile -Value $footer

Read-Host -Prompt "Press enter to exit"
Clear-HostFancily -Mode Falling -Speed 3.0
Stop-Process -Id $PID -Force

# Cleanup section
Remove-item -path "C:\temp\SEPLinks.enc" -ErrorAction SilentlyContinue | Out-Null
$ProgressPreference = "Continue"
