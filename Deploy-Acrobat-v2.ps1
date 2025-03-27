############################################################################################################
#                                        Adobe Acrobat Installation                                        #
#                                                                                                          #
############################################################################################################

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
        $powerShell.EndInvoke($handle)
    }
    catch {
        Write-Host "`nError during download: $_" -ForegroundColor Red
    }
    finally {
        # Clean up resources
        $powerShell.Dispose()
        $runspace.Dispose()
        
        # Display completion message
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write($DoneMessage)
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
}

#region Acrobat Installation
# Initialize log file if not already defined
if (-not (Get-Variable -Name LogFile -ErrorAction SilentlyContinue)) {
    $LogFile = "$env:TEMP\AcrobatInstallation.log"
}

# Define the URL and file path for the Acrobat Reader installer
$URL = "https://axcientrestore.blob.core.windows.net/win11/AcroRdrDC2500120432_en_US.exe"
$AcroFilePath = "C:\temp\AcroRdrDC2500120432_en_US.exe"

# First, check if Adobe Acrobat Reader is already installed
$acrobatPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
$acrobatInstalled = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                      HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                     Where-Object { $_.DisplayName -like "*Adobe Acrobat Reader*" -or $_.DisplayName -like "*Adobe Acrobat DC*" }

if ((Test-Path $acrobatPath) -and $acrobatInstalled) {
    Write-Host "Adobe Acrobat Reader is already installed. Skipping installation." -ForegroundColor Green
    Write-Log "Adobe Acrobat Reader already installed, skipped installation."
} else {
    # Create temp directory if it doesn't exist
    if (-not (Test-Path "C:\temp")) {
        New-Item -Path "C:\temp" -ItemType Directory -Force | Out-Null
        Write-Host "Created C:\temp directory"
    } 

    try {
        # Get the file size first
        $response = Invoke-WebRequest -Uri $URL -Method Head -ErrorAction Stop
        $fileSize = $response.Headers['Content-Length']
        
        # Download the Acrobat Reader installer with spinner AND progress bar
        Show-SpinnerWithProgressBar -Message "Downloading Adobe Acrobat Reader ($fileSize bytes)..." -URL $URL -OutFile $AcroFilePath -DoneMessage " done."
        
        $FileSize = (Get-Item $AcroFilePath).Length
        
        # Check if the file exists and has content
        if ((Test-Path $AcroFilePath -PathType Leaf) -and ($FileSize -gt 0)) {
            # Install Acrobat Reader with spinner
            $installResult = Show-SpinningWait -Message "Installing Adobe Acrobat Reader..." -ScriptBlock {
                # Start the installation process
                $process = Start-Process -FilePath "C:\temp\AcroRdrDC2500120432_en_US.exe" -ArgumentList "/sAll /rs /msi EULA_ACCEPT=YES /qn" -NoNewWindow -PassThru
                
                # Wait for initial process to complete
                $process | Wait-Process -Timeout 60 -ErrorAction SilentlyContinue
                
                # Look for Reader installer processes and wait
                $timeout = 300  # 5 minutes timeout
                $startTime = Get-Date
                
                do {
                    Start-Sleep -Seconds 5
                    $msiProcess = Get-Process -Name msiexec -ErrorAction SilentlyContinue
                    $readerProcess = Get-Process -Name Reader_en_install -ErrorAction SilentlyContinue
                    
                    $elapsedTime = (Get-Date) - $startTime
                    if ($elapsedTime.TotalSeconds -gt $timeout) {
                        break
                    }
                } while ($msiProcess -or $readerProcess)
                
                # Try to gracefully close any remaining installer processes
                Stop-Process -Name Reader_en_install -Force -ErrorAction SilentlyContinue
            }
            
            # Verify installation
            $acrobatPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
            $acrobatInstalled = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                                HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                                 Where-Object { $_.DisplayName -like "*Adobe Acrobat Reader*" -or $_.DisplayName -like "*Adobe Acrobat DC*" }
            
            if ((Test-Path $acrobatPath) -and $acrobatInstalled) {
                Write-Host "Adobe Acrobat Reader installation completed successfully" -ForegroundColor Green
                Write-Log "Adobe Acrobat Reader installed successfully"
            } else {
                if (-not (Test-Path $acrobatPath)) {
                    Write-Host "Adobe Acrobat Reader executable not found" -ForegroundColor Yellow
                }
                if (-not $acrobatInstalled) {
                    Write-Host "Adobe Acrobat Reader not found in installed applications registry" -ForegroundColor Yellow
                }
                Write-Host "Adobe Acrobat Reader installation may not have completed properly" -ForegroundColor Yellow
                Write-Log "Adobe Acrobat Reader installation may not have completed properly"
            }
        } else {
            Write-Host "Download failed or file is empty" -ForegroundColor Red
            Write-Log "Adobe Acrobat Reader download failed or file is empty"
        }
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
        Write-Log "Error installing Adobe Acrobat Reader: $_"
    } finally {
        # Cleanup
        if (Test-Path $AcroFilePath) {
            Remove-Item -Path $AcroFilePath -Force -ErrorAction SilentlyContinue
            Write-Host "Cleaned up installer file"
        }
    }
}
#endregion Acrobat Installation