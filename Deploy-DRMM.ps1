############################################################################################################
#                                            RMM Deployment                                                  #
############################################################################################################

# Datto RMM Agent Installation Configuration
$file = 'c:\temp\AgentSetup_Standard+Office+Systems+MITS.exe'
$agentName = "CagService"  # Changed from CagService.exe to just CagService for Get-Service
$agentPath = "C:\Program Files (x86)\CentraStage"
$installerUri = "https://concord.centrastage.net/csm/profile/downloadAgent/b1f0bb64-e008-44e9-8260-2c5039cdd437"

# Create temp directory if it doesn't exist
if (-not (Test-Path "c:\temp")) {
    New-Item -ItemType Directory -Path "c:\temp" -Force | Out-Null
}

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
    Write-Host "Datto RMM agent is already installed and running." -ForegroundColor Cyan
    exit 0
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
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
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
        exit 1
    }

    # Verify the file exists and has content
    if (-not (Test-Path $file) -or (Get-Item $file).Length -eq 0) {
        Write-Host "Error: Downloaded file is missing or empty." -ForegroundColor Red
        exit 1
    }

    Write-Host "Installing Datto RMM Agent..." -NoNewline
    try {
        # Run installer with more verbosity and as admin
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
            
            # Wait for 10 seconds before checking service
            Write-Host "Waiting for service initialization..." -NoNewline
            Start-Sleep -Seconds 15  # Increased to 15 seconds for more time
            Write-Host " done." -ForegroundColor Green
            
            # Check if the service exists and is running
            $service = Get-Service -Name $agentName -ErrorAction SilentlyContinue
            
            if ($null -ne $service -and $service.Status -eq "Running") {
                Write-Host "Installation completed successfully! Service is running." -ForegroundColor Green
                # Clean up installer file
                if (Test-Path $file) {
                    Remove-Item -Path $file -Force
                }
                exit 0
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
                        exit 0
                    } else {
                        Write-Host "Failed to start service." -ForegroundColor Red
                    }
                } else {
                    Write-Host "Service does not exist." -ForegroundColor Red
                }
                exit 1
            }
        } else {
            Write-Host " failed with exit code $exitCode." -ForegroundColor Red
            Write-Host "Checking if installer file is valid..." -ForegroundColor Yellow
            $fileInfo = Get-Item $file -ErrorAction SilentlyContinue
            if ($null -ne $fileInfo) {
                Write-Host "File size: $($fileInfo.Length) bytes" -ForegroundColor Yellow
                if ($fileInfo.Length -lt 1000) {
                    Write-Host "File appears to be too small to be a valid installer!" -ForegroundColor Red
                }
            }
            exit 1
        }
    } catch {
        Write-Host " installation failed!" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}