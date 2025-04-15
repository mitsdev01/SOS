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
    Test

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
$ScriptVersion = "1.7.1b"
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$TempFolder = "C:\temp"
$LogFile = "$TempFolder\$env:COMPUTERNAME-baseline.log"

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

############################################################################################################
#                                                 Functions                                                #
#                                                                                                          #
############################################################################################################
#region Functions

# Function to print a message in the middle of the console
function Print-Middle($Message, $Color = "White") {
    Write-Host (" " * [System.Math]::Floor(([System.Console]::BufferWidth / 2) - ($Message.Length / 2))) -NoNewline
    Write-Host -ForegroundColor $Color $Message
}

# Function to write a message to the console with a delay
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

# Function to write a message to the log file
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "[$timestamp] $Message"
}

# Function to write a message to the console when a task is completed
function Write-TaskComplete {
    # Log to file
    Write-Log "Task completed successfully"
    
    # Write to both transcript and console without creating a new line
    Write-Host " done." -ForegroundColor Green -NoNewline
    
    # Add the newline after the "done." message
    Write-Host ""
}

# Function to write a message to the console when a task fails
function Write-TaskFailed {
    # Log to file
    Write-Log "Task failed"
    
    # Write to both transcript and console without creating a new line
    Write-Host " failed." -ForegroundColor Red -NoNewline
    
    # Add the newline after the "failed." message
    Write-Host ""
}

# Function to move a process window to the top right corner of the screen
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

# Function to check if the current OS is Windows 11
function Is-Windows11 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption
    # Check for Windows 11
    return $osVersion -ge "10.0.22000" -and $osProduct -like "*Windows 11*"
}

# Function to check if the current OS is Windows 10
function Is-Windows10 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption
    # Check for Windows 10
    return $osVersion -lt "10.0.22000" -and $osProduct -like "*Windows 10*"
}

# Function to test if the DattoRMM agent is installed
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

# Function to show a spinning wait
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

# Function to show a spinning wait with a progress bar
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

# Function to show a spinning wait animation
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

# Function to show a spinning wait animation
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

# Function to start the Volume Shadow Copy service
function Start-VssService {
    $vss = Get-Service -Name 'VSS' -ErrorAction SilentlyContinue
    if ($vss.Status -ne 'Running') {
        Write-Delayed "Starting Volume Shadow Copy service for restore point creation..." -NewLine:$false
        Start-Service VSS
        Write-TaskComplete
    }
}

# Function to remove the restore point frequency limit
function Remove-RestorePointFrequencyLimit {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "SystemRestorePointCreationFrequency" -Value 0
}

# Function to create a restore point with a timeout
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

# Function to start a clean transcript
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

# Function to set the UsoSvc service to automatic
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
                Write-Host "`nDecrypted JSON from $FilePath :"  | Out-Null
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
        Write-Error "Failed to decrypt file $FilePath : $_"
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
        Write-Error "Failed to decrypt Sophos links file $FilePath : $_"
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

# Function to decrypt installer links
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
        Write-Error "Sophos Links data is null. Cannot retrieve URL for '$ClientName'."
        return $null
    }

    # Access the URL directly using the client name as the key
    # Use PSObject.Properties for robust checking on PSCustomObject
    $prop = $SophosLinksData.PSObject.Properties[$ClientName]
    if ($null -eq $prop) {
        Write-Error "Client '$ClientName' not found as a property in decrypted Sophos Links data."
        return $null
    }

    # Return the value of the property
    return $prop.Value
}

#endregion Functions

############################################################################################################
#                                             Integrity Check                                              #
#                                                                                                          #
############################################################################################################
#region Integrity Check
# Command to Update Script Hash: .\SOS-Baseline.ps1 -Command "Update-ScriptHash" -ScriptPath "c:\temp\SOS-Baseline.ps1"
# Immediate execution block for hash updates
if ($args -contains "-Command" -and $args -contains "Update-ScriptHash") {
    $scriptPath = $args[$args.IndexOf("-ScriptPath") + 1]
    Write-Host "Updating script hash..." -ForegroundColor Cyan
    
    try {
        # Define a standardized hash calculation function
        function Get-StandardizedFileHash {
            param (
                [Parameter(Mandatory = $true)]
                [string]$FilePath,
                [switch]$ExcludeHashLine
            )
            
            # Read file with UTF8 encoding without BOM
            $content = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::UTF8)
            
            # If we need to exclude the hash line, do it with a consistent regex pattern
            if ($ExcludeHashLine) {
                $contentLines = $content -split "`n"
                $contentLines = $contentLines | Where-Object { $_ -notmatch '\$validScriptHash\s*=\s*"[A-F0-9]+"' }
                $content = $contentLines -join "`n"
            }
            
            # Normalize all line endings to LF only
            $content = $content.Replace("`r`n", "`n").Replace("`r", "`n")
            
            # Convert to byte array with UTF8 encoding
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
            
            # Calculate hash
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $hashBytes = $sha256.ComputeHash($bytes)
            $sha256.Dispose()
            
            # Convert to uppercase hex string
            $hashString = [BitConverter]::ToString($hashBytes).Replace("-", "")
            return $hashString
        }
        
        # Calculate hash using our standardized function
        $newHash = Get-StandardizedFileHash -FilePath $scriptPath -ExcludeHashLine
        
        Write-Host "New hash calculated: $newHash" -ForegroundColor Yellow
        
        # Read the entire file content
        $allContent = Get-Content -Path $scriptPath -Raw
        
        # Update hash in script file (for fallback/offline verification)
        $updatedContent = $allContent -replace '\$validScriptHash\s*=\s*"[A-F0-9]+"', "`$validScriptHash = `"$newHash`""
        [System.IO.File]::WriteAllText($scriptPath, $updatedContent, [System.Text.Encoding]::UTF8)
        Write-Host "Local script hash updated successfully!" -ForegroundColor Green
        
        # Create a hash file for manual upload to Azure Blob Storage
        $hashFilePath = "$PSScriptRoot\SOS-Baseline.hash"
        Set-Content -Path $hashFilePath -Value $newHash -Force -NoNewline
        
        Write-Host "Hash file created at: $hashFilePath" -ForegroundColor Green
        Write-Host "Please upload this file to https://axcientrestore.blob.core.windows.net/win11/ manually through the Azure portal." -ForegroundColor Cyan
        
        exit 0
    }
    catch {
        Write-Host "Error updating script hash: $_" -ForegroundColor Red
        exit 1
    }
}

# Parse command line parameters
param(
    [string]$Command,
    [string]$ScriptPath
)

# Script integrity verification - fallback local hash
$validScriptHash = "76DE47E966AF115B6F6F69566BC1A9DF56F2954933DA10B48F40B39DACDAF931"

# Define the standardized hash calculation function again for verification
function Get-StandardizedFileHash {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [switch]$ExcludeHashLine
    )
    
    # Read file with UTF8 encoding without BOM
    $content = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::UTF8)
    
    # If we need to exclude the hash line, do it with a consistent regex pattern
    if ($ExcludeHashLine) {
        $contentLines = $content -split "`n"
        $contentLines = $contentLines | Where-Object { $_ -notmatch '\$validScriptHash\s*=\s*"[A-F0-9]+"' }
        $content = $contentLines -join "`n"
    }
    
    # Normalize all line endings to LF only
    $content = $content.Replace("`r`n", "`n").Replace("`r", "`n")
    
    # Convert to byte array with UTF8 encoding
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    
    # Calculate hash
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($bytes)
    $sha256.Dispose()
    
    # Convert to uppercase hex string
    $hashString = [BitConverter]::ToString($hashBytes).Replace("-", "")
    return $hashString
}

function Test-ScriptIntegrity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ScriptPath,
        [switch]$SkipRemoteCheck
    )

    try {
        # First try to get the hash from Azure Blob Storage unless skipRemoteCheck is specified
        $remoteHashValid = $false
        $remoteHash = $null
        
        if (-not $SkipRemoteCheck) {
            try {
                # Download the hash file from Azure
                $hashFileUrl = "https://axcientrestore.blob.core.windows.net/win11/SOS-Baseline.hash"
                $tempHashFile = [System.IO.Path]::GetTempFileName()
                
                Write-Host "Checking integrity against remote hash..." -ForegroundColor Cyan
                Invoke-WebRequest -Uri $hashFileUrl -OutFile $tempHashFile -UseBasicParsing -TimeoutSec 15
                
                if (Test-Path $tempHashFile) {
                    # Read without adding a newline
                    $remoteHash = [System.IO.File]::ReadAllText($tempHashFile).Trim()
                    
                    if (-not [string]::IsNullOrWhiteSpace($remoteHash)) {
                        $remoteHashValid = $true
                        Write-Host "Retrieved remote hash: $remoteHash" -ForegroundColor Gray
                    }
                    
                    # Clean up temp file
                    Remove-Item -Path $tempHashFile -Force
                }
            }
            catch {
                Write-Host "Could not retrieve remote hash, falling back to local validation: $_" -ForegroundColor Yellow
                $remoteHashValid = $false
            }
        }
        
        # Use our standardized hash calculation
        $currentHash = Get-StandardizedFileHash -FilePath $ScriptPath -ExcludeHashLine

        # Get the stored local hash (excluding quotes) for fallback
        $storedHash = $validScriptHash

        # Debug output to help diagnose issues
        Write-Host "Calculated current hash: $currentHash" -ForegroundColor Gray

        # Check against remote hash first if available
        if ($remoteHashValid) {
            if ($currentHash -ne $remoteHash) {
                Write-Host "`r`nWARNING: Script integrity check failed against remote hash!" -ForegroundColor Red
                Write-Host "The script appears to have been modified from its original state." -ForegroundColor Red
                Write-Host "Expected hash (remote): $remoteHash" -ForegroundColor Yellow
                Write-Host "Current hash:           $currentHash" -ForegroundColor Yellow
                Write-Host "`r`nExiting for security...`r`n" -ForegroundColor Red
                return $false
            }
            Write-Host "Script integrity verified against remote hash." -ForegroundColor Green
            return $true
        }
        # Fallback to local hash check
        else {
            if ($storedHash -eq "PLACEHOLDER_HASH") {
                Write-Host "`r`nScript hash not initialized. Please run Update-ScriptHash to set the initial hash." -ForegroundColor Red
                return $false
            }

            if ($currentHash -ne $storedHash) {
                Write-Host "`r`nWARNING: Script integrity check failed!" -ForegroundColor Red
                Write-Host "The script appears to have been modified from its original state." -ForegroundColor Red
                Write-Host "Expected hash (local): $storedHash" -ForegroundColor Yellow
                Write-Host "Current hash:          $currentHash" -ForegroundColor Yellow
                Write-Host "`r`nExiting for security...`r`n" -ForegroundColor Red
                return $false
            }
            Write-Host "Script integrity verified against local hash." -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Host "`r`nError during integrity check: $_" -ForegroundColor Red
        return $false
    }
}

# Only verify integrity if we're not updating the hash
if ($Command -ne "Update-ScriptHash") {
    if (-not (Test-ScriptIntegrity -ScriptPath $MyInvocation.MyCommand.Path)) {
        exit 1
    }
}
#endregion Integrity Check

############################################################################################################
#                                             Application Links                                            #
#                                                                                                          #
############################################################################################################
#region Application Links
try {
    # Create temp directory if it doesn't exist
    if (-not (Test-Path "C:\temp")) {
        New-Item -Path "C:\temp" -ItemType Directory -Force | Out-Null
    }
    
    # Download the encrypted links file
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/SEPLinks.enc" -OutFile "c:\temp\SEPLinks.enc" -ErrorAction Stop | Out-Null
    Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/urls.enc" -OutFile "c:\temp\urls.enc" -ErrorAction Stop | Out-Null
    $ProgressPreference = 'Continue'
    # Verify file exists and has content
    if (-not (Test-Path "c:\temp\SEPLinks.enc")) {
        throw "Failed to download encrypted links file"
    }
    
    $fileSize = (Get-Item "c:\temp\SEPLinks.enc").Length
    if ($fileSize -eq 0) {
        throw "Downloaded encrypted links file is empty"
    }
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

# Decrypt application links
try {
    
    #Write-Host "`nLoading software URLs..."
    $softwareLinks = Decrypt-SoftwareURLs -FilePath "$TempFolder\urls.enc"  -ShowDebug:$false
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

    # Decrypt Sophos installer links
    $sepLinks = Decrypt-SophosLinks -FilePath "$TempFolder\SEPLinks.enc" -ShowDebug:$false # Call new function
    if ($null -eq $sepLinks) {
        throw "Failed to decrypt Sophos installer links"
    }

    # Example: Get a specific Sophos URL (replace 'YourClientName' with actual logic if needed)
    # $SophosAV = Get-SophosClientURL -ClientName 'YourClientName' -SophosLinksData $sepLinks
    # if ($null -eq $SophosAV) {
    #    throw "Failed to get Sophos AV URL for 'YourClientName'"
    # }
    # For now, assuming you might need a default or specific one - This needs clarification based on how you pick the client
    # Placeholder: Using a default key if one exists, otherwise error
    # This section needs refinement based on how you determine WHICH Sophos link to use.
    # For the example, let's assume you need the 'Atlanta Family Law Immigration' link for testing
    $DefaultClientName = 'Atlanta Family Law Immigration' # CHANGE THIS AS NEEDED
    $SophosAV = Get-SophosClientURL -ClientName $DefaultClientName -SophosLinksData $sepLinks
    if ([string]::IsNullOrWhiteSpace($SophosAV)) {
        throw "Failed to retrieve the Sophos AV URL for '$DefaultClientName'. Check SEPLinks.enc and the client name."
    }
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

#endregion Application Links

############################################################################################################
#                                            Transcript Logging                                            #
#                                                                                                          #
############################################################################################################
#region Logging

# Create required directories
if (-not (Test-Path $TempFolder)) { New-Item -Path $TempFolder -ItemType Directory | Out-Null }
if (-not (Test-Path $LogFile)) { New-Item -Path $LogFile -ItemType File | Out-Null }

# Set working directory
Set-Location -Path $TempFolder

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

# Start transcript logging  
Start-CleanTranscript -Path "$TempFolder\$env:COMPUTERNAME-baseline_transcript.txt"
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
#region Power Settings
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


Write-Delayed "Setting EST as default timezone..." -NewLine:$false
Start-Service W32Time
Set-TimeZone -Id "Eastern Standard Time" 
Write-TaskComplete
Write-Log "Time zone set to Eastern Standard Time"

Write-Delayed "Syncing system clock..." -NewLine:$false
w32tm /resync -ErrorAction SilentlyContinue | Out-Null
Write-TaskComplete
Write-Log "Synced system clock"

# Wait for the Sophos installation to complete
Write-Delayed "Installing Sophos AV..." -NewLine:$false

# Animation characters for the spinner
$spinChars = '|', '/', '-', '\'
$spinIndex = 0
$initialCursorPosition = $host.UI.RawUI.CursorPosition

# Create a timer for the spinner animation
$timer = New-Object System.Timers.Timer
$timer.Interval = 250 # Update every 250ms
$timer.AutoReset = $true

# Timer event to update the spinner
$timer.Add_Elapsed({
    # Capture current cursor position
    $currentPosition = $host.UI.RawUI.CursorPosition
    
    # Return to the spinner position
    $host.UI.RawUI.CursorPosition = $initialCursorPosition
    
    # Display the next spinner character
    Write-Host $spinChars[$spinIndex] -NoNewline
    
    # Update spinner index
    $spinIndex = ($spinIndex + 1) % $spinChars.Length
    
    # Restore cursor position
    $host.UI.RawUI.CursorPosition = $currentPosition
})

# Start the spinner animation
$timer.Start()

# Wait for the Sophos installation job to complete
$sophosJob | Wait-Job | Out-Null

# Stop the spinner animation
$timer.Stop()
$timer.Dispose()

# Go back to the spinner position and replace it with "done"
$host.UI.RawUI.CursorPosition = $initialCursorPosition
Write-Host " done." -ForegroundColor Green -NoNewline

# Retrieve and remove the job
Receive-Job -Job $sophosJob
Remove-Job -Job $sophosJob -Force
Remove-item -path "C:\temp\SEPLinks.enc" | Out-Null
$ProgressPreference = "Continue"
# Start a new line
Write-Host ""
#endregion Sophos Install


############################################################################################################
#                                           System Restore Point                                           #
#                                                                                                          #
############################################################################################################
#region System Restore
# Create a restore point
Start-VssService
Remove-RestorePointFrequencyLimit
Write-Delayed "Creating a system restore point..." -NewLine:$false

# Initialize spinner
$spinner = @('/', '-', '\', '|')
$spinnerIndex = 0
[Console]::Write($spinner[$spinnerIndex])

# Set up the job to create the restore point
$job = Start-Job -ScriptBlock { 
    Checkpoint-Computer -Description "MITS New Workstation Baseline Completed - $(Get-Date -Format 'MM-dd-yyyy HH:mm:t')" -RestorePointType "MODIFY_SETTINGS" 
}

# Display spinner while job is running (max 90 seconds)
$timeout = 90
$startTime = Get-Date
$success = $false

while (($job.State -eq 'Running') -and (((Get-Date) - $startTime).TotalSeconds -lt $timeout)) {
    Start-Sleep -Milliseconds 100
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
}

# Check if job completed or timed out
if ($job.State -eq 'Running') {
    # Job timed out
    Stop-Job $job
    $success = $false
} else {
    # Job completed, check result
    $result = Receive-Job $job
    $success = $true
}

# Remove the job
Remove-Job $job -Force

# Clear the spinner character
[Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)

# Display result
if ($success) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" created successfully.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    Write-Log "System restore point created successfully"
} else {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" Failed to create restore point.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    Write-Log "Failed to create system restore point"
}
#endregion System Restore Point


############################################################################################################
#                                           Bloatware Cleanup                                              #
#                                                                                                          #
############################################################################################################
#region Bloatware Cleanup

Write-Delayed "Initiating cleaning up of Windows bloatware... " -NoNewline -NewLine:$false

# Use variables loaded earlier
if ([string]::IsNullOrWhiteSpace($Win11DebloatURL)) { throw "Win11DebloatURL is not loaded." }
if ([string]::IsNullOrWhiteSpace($Win10DebloatURL)) { throw "Win10DebloatURL is not loaded." } # Note: Currently points to same zip as Win11

# Trigger SOS Debloat for Windows 11
if (Is-Windows11) {
    try {
        # $Win11DebloatURL = Get-DecryptedURL -Key "Win11DebloatURL" # REMOVED
        $Win11DebloatFile = "c:\temp\SOS-Debloat.zip"
        Invoke-WebRequest -Uri $Win11DebloatURL -OutFile $Win11DebloatFile -UseBasicParsing -ErrorAction Stop 
        Start-Sleep -seconds 2
        Expand-Archive $Win11DebloatFile -DestinationPath 'c:\temp\SOS-Debloat' -Force # Added -Force
        Start-Sleep -Seconds 2
        Start-Process powershell -ArgumentList "-noexit","-Command Invoke-Expression -Command '& ''C:\temp\SOS-Debloat\SOS-Debloat.ps1'' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -DisableLockscreenTips -DisableSuggestions -ShowKnownFileExt -TaskbarAlignLeft -HideSearchTb -DisableWidgets -Silent'"
        Start-Sleep -Seconds 2
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait('%{TAB}') 
        
        # Display spinning character for 30 seconds
        $spinner = @('|', '/', '-', '\')
        $spinnerPos = 0
        $endTime = (Get-Date).AddSeconds(35)
        $message = "Initiating cleaning up of Windows bloatware..."
        
        while ((Get-Date) -lt $endTime) {
            Write-Host "`r$message$($spinner[$spinnerPos])" -NoNewline
            $spinnerPos = ($spinnerPos + 1) % $spinner.Length
            Start-Sleep -Milliseconds 100
        }
        Write-Host "`r$message" -NoNewline 
        # Clear the spinner and show completion
        Write-Host " done." -ForegroundColor Green # Clear the spinner and show completion
        Write-Log "Windows 11 Debloat completed successfully."
        #Write-TaskComplete
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}
else {
    #Write-Log "This script is intended to run only on Windows 11."
}

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
        
        # Display spinning character for 30 seconds
        $spinner = @('|', '/', '-', '\')
        $spinnerPos = 0
        $endTime = (Get-Date).AddSeconds(30)
        $message = "Initiating cleaning up of Windows bloatware..."
        
        while ((Get-Date) -lt $endTime) {
            Write-Host "`r$message $($spinner[$spinnerPos])" -NoNewline
            $spinnerPos = ($spinnerPos + 1) % $spinner.Length
            Start-Sleep -Milliseconds 200
        }
        Write-Host "`r$message" -NoNewline
        Write-Host " done." -ForegroundColor Green # Clear the spinner and show completion
        Write-Log "Windows 10 Debloat completed successfully."
        #Write-TaskComplete
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
#                                                   Finalization                                           #
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
#endregion Rename Machine


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

############################################################################################################
#                                           Cleanup Temporary Files                                           #
#                                                                                                          #
############################################################################################################
#region Cleanup Temporary Files

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
    "C:\temp\urls.enc",
    "C:\temp\Wakelock.ps1",
    "C:\temp\wakelock.flag"
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

# Stopping transcript
Stop-Transcript *> $null

try {
    Read-Host -Prompt "Press enter to exit"
    Clear-HostFancily -Mode Falling -Speed 3.4
    Stop-Process -Id $PID -Force
}
catch {
    Write-Host "Error during cleanup: $_" -ForegroundColor Red
    exit 1
}
