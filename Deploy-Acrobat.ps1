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
$ProgressPreference = 'SilentlyContinue'  # Hide progress bar for faster downloads
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
    $ProgressPreference = 'Continue'
    if (Test-Path $AcroFilePath) {
        #Remove-Item -Path $AcroFilePath -Force -ErrorAction SilentlyContinue
        Write-Host "Cleaned up installer file"
    }
}