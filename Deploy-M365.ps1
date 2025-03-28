############################################################################################################
#                                          Office 365 Installation                                         #
#                                                                                                          #
############################################################################################################
#
$LogFile = "C:\temp\M365-Installation.log"
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
        [string]$DoneMessage = "done.",
        [switch]$RunInBackground = $true
    )
    
    Write-Delayed "$Message" -NewLine:$false
    $spinner = @('/', '-', '\', '|')
    $spinnerIndex = 0
    
    if ($RunInBackground) {
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
    }
    else {
        # Create a runspace for the spinner
        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.Open()
        $spinnerPowerShell = [powershell]::Create()
        $spinnerPowerShell.Runspace = $runspace
        
        $spinnerScript = {
            param ($spinner)
            $spinnerIndex = 0
            while ($true) {
                [Console]::Write($spinner[$spinnerIndex])
                Start-Sleep -Milliseconds 100
                [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
                $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
            }
        }
        
        $spinnerPowerShell.AddScript($spinnerScript).AddArgument($spinner) | Out-Null
        $handle = $spinnerPowerShell.BeginInvoke()
        
        # Run the main script block in the current thread
        $result = & $ScriptBlock
        
        # Stop the spinner
        $spinnerPowerShell.Stop()
        $spinnerPowerShell.Dispose()
        $runspace.Close()
        $runspace.Dispose()
    }
    
    # Replace spinner with done message
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write($DoneMessage)
    [Console]::ResetColor()
    [Console]::WriteLine()
    
    return $result
}


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
        Show-SpinningWait -ScriptBlock {
            $ProgressPreference = 'SilentlyContinue'  # Hide progress bar for faster downloads
            Invoke-WebRequest -OutFile $using:OfficePath -Uri $using:OfficeURL -UseBasicParsing
        } -Message "Downloading Microsoft Office 365..." -DoneMessage " done."
    }
    
    # Validate successful download by checking the file size
    $ProgressPreference = 'Continue'  # reset display of downloads
    $FileSize = (Get-Item $OfficePath).Length
    $ExpectedSize = 7733536 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        Show-SpinningWait -ScriptBlock {
            taskkill /f /im OfficeClickToRun.exe *> $null
            taskkill /f /im OfficeC2RClient.exe *> $null
            Start-Sleep -Seconds 10
            Start-Process -FilePath $OfficePath -ArgumentList "/silent", "/forceclose" -Wait
            Start-Sleep -Seconds 15
        } -Message "Installing Microsoft Office 365..." -DoneMessage " done." -RunInBackground:$false
        
        if (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "Microsoft 365 Apps for enterprise - en-us"}) {
            Write-Log "Office 365 Installation Completed Successfully."
            Start-Sleep -Seconds 10
            taskkill /f /im OfficeClickToRun.exe *> $null
            taskkill /f /im OfficeC2RClient.exe *> $null
            Remove-Item -Path $OfficePath -force -ErrorAction SilentlyContinue
        } else {
            Write-Log "Office 365 installation failed."
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            [Console]::Write("Microsoft Office 365 installation failed.")
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