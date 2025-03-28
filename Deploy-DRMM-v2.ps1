############################################################################################################
#                                              Datto RMM Deployment                                        #
#                                                                                                          #
############################################################################################################
#region RMM Install
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
    # Also write to transcript for better logging
    #Write-Verbose "LOG: $Message" -Verbose
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

# Agent Installation Configuration
$TempFolder = "c:\temp"
$file = "$TempFolder\AgentInstall.exe"
$LogFile = "c:\temp\DRMM-Install.log"
$agentName = "CagService"
$agentPath = "C:\Program Files (x86)\CentraStage"
$installerUri = "https://concord.centrastage.net/csm/profile/downloadAgent/ce8a0a8d-84bd-4baa-850a-6f46e9c37dfc"

# Check for existing Datto RMM agent
$installStatus = Test-DattoInstallation
if ($installStatus.ServiceExists -and $installStatus.ServiceRunning) {
    #Write-Host "Datto RMM agent is already installed and running." -ForegroundColor Green
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

    # Download and install using spinner animation
    Show-SpinnerWithProgressBar -Message "Downloading Datto RMM Agent..." -URL $installerUri -OutFile $file -DoneMessage " done."
    
    # Verify the file exists and has content
    if ((Test-Path $file) -and (Get-Item $file).Length -gt 0) {
        # Install with spinner animation
        $fileToInstall = $file  # Create a copy of the path
        $installResult = Show-SpinningWait -Message "Installing Datto RMM Agent..." -DoneMessage " done." -ScriptBlock {
            param ($InstallerPath)  # Accept the file path as a parameter
            
            try {
                Write-Output "Using installer file: $InstallerPath"  # Debug output
                
                # Verify file exists before attempting to run
                if (!(Test-Path $InstallerPath)) {
                    return @{
                        Success = $false
                        Error = "Installer file not found at path: $InstallerPath"
                    }
                }
                
                # Run installer
                $startInfo = New-Object System.Diagnostics.ProcessStartInfo
                $startInfo.FileName = $InstallerPath
                $startInfo.Arguments = "/S"
                $startInfo.UseShellExecute = $true
                $startInfo.Verb = "runas"  # Run as admin
                
                $process = [System.Diagnostics.Process]::Start($startInfo)
                if ($null -eq $process) {
                    throw "Failed to start installation process"
                }
                
                $process.WaitForExit()
                $exitCode = $process.ExitCode
                
                return @{
                    Success = $exitCode -eq 0
                    ExitCode = $exitCode
                }
            } catch {
                return @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        } -ArgumentList $fileToInstall -SuppressOutput
        
        if ($installResult.Success) {
            # Wait for service initialization
            Show-SpinningWait -Message "Waiting for service initialization..." -DoneMessage " done." -ScriptBlock {
                Start-Sleep -Seconds 15
            } -SuppressOutput
            
            # Check if the service exists and is running
            $service = Get-Service -Name $agentName -ErrorAction SilentlyContinue
            
            if ($null -ne $service -and $service.Status -eq "Running") {
                #Write-Host "Installation completed successfully! Service is running." -ForegroundColor Green
                Write-Log "Datto RMM agent installed successfully"
                # Clean up installer file
                if (Test-Path $file) {
                    Remove-Item -Path $file -Force
                }
            } else {
                if ($null -ne $service) {
                    Write-Host "Datto RMM Service exists but status is: $($service.Status)" -ForegroundColor Yellow
                    Show-SpinningWait -Message "Attempting to start Datto RMM Service..." -DoneMessage " done." -ScriptBlock {
                        Start-Service -Name $agentName -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 5
                    } -SuppressOutput
                    
                    $service = Get-Service -Name $agentName -ErrorAction SilentlyContinue
                    if ($null -ne $service -and $service.Status -eq "Running") {
                        Write-Log "Datto RMM service started manually after installation"
                    } else {
                        Write-Host "Failed to start Datto RMM service." -ForegroundColor Red
                        Write-Log "Failed to start Datto RMM service after installation"
                    }
                } else {
                    Write-Host "Datto RMM Service does not exist." -ForegroundColor Red
                    Write-Log "Datto RMM service does not exist after installation"
                }
            }
        } else {
            Write-Host "Installation failed with exit code $($installResult.ExitCode)." -ForegroundColor Red
            Write-Log "Datto RMM installation failed with exit code $($installResult.ExitCode)"
            
            if ($installResult.Error) {
                Write-Host "Error: $($installResult.Error)" -ForegroundColor Red
                Write-Log "Error during Datto RMM installation: $($installResult.Error)"
            }
            
            $fileInfo = Get-Item $file -ErrorAction SilentlyContinue
            if ($null -ne $fileInfo) {
                Write-Host "File size: $($fileInfo.Length) bytes" -ForegroundColor Yellow
                if ($fileInfo.Length -lt 1000) {
                    Write-Host "File appears to be too small to be a valid installer!" -ForegroundColor Red
                    Write-Log "Datto RMM installer file is too small to be valid: $($fileInfo.Length) bytes"
                }
            }
        }
    } else {
        Write-Host "Error: Downloaded file is missing or empty." -ForegroundColor Red
        Write-Log "Datto RMM installer file is missing or empty"
    }
}
#endregion RMMDeployment