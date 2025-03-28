Clear-Host

Write-Host "SOS - Workstation Baseline Complete Verification"
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

function Write-TaskComplete {
    Start-Sleep -Seconds 1
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
    Start-Sleep -Seconds 1
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write($DoneMessage)
    [Console]::ResetColor()
    [Console]::WriteLine()
    
    return $result
}
