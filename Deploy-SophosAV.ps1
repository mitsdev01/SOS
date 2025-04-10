############################################################################################################
#                                   SOS - Sophos AV Installer                                              #
#                                           Version 1.0.8                                                  #
############################################################################################################
#region Synopsis
<#
.SYNOPSIS
    Initiates computer rename and schedules the SOS baseline script to run after reboot.

.DESCRIPTION
    This script performs the following operations in sequence:
    - Prompts the user to rename the computer
    - Creates a scheduled task to run the SOS baseline script after the next login
    - Triggers an automatic system reboot
    
    After reboot, the script will automatically launch the SOS baseline configuration
    when the specified user logs in.

.NOTES
    Version:        1.0.8
    Author:         Seth Gullion / Bill Ulrich
    Creation Date:  4/4/2025
    Requires:       Administrator privileges
                    Windows 10/11 Professional
    
.EXAMPLE
    .\Deploy-SophosAV.ps1
    
    Run the script with administrator privileges to install Sophos AV.

.EXAMPLE
    .\Deploy-SophosAV.ps1 

    Select the related company from the dropdown list and click Install.

.LINK
    https://github.com/mitsdev01/SOS
#>

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$ScriptVersion = "1.0.8"
$ProgressPreference = 'SilentlyContinue'

# Function to decrypt and load installer links
function Get-InstallerLinks {
    param (
        [string]$EncryptedFile = "C:\temp\SEPLinks.enc"
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

# Load installer links from encrypted file
$InstallerLinks = Get-InstallerLinks

if ($null -eq $InstallerLinks) {
    [System.Windows.Forms.MessageBox]::Show(
        "Failed to load installer links. Please ensure the encrypted file exists and is accessible.",
        "Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit
}

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Sophos AV Installer"
$form.Size = New-Object System.Drawing.Size(500, 200)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# Create a label for the dropdown
$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(20, 20)
$label.Size = New-Object System.Drawing.Size(360, 20)
$label.Text = "Select an installer source:"
$form.Controls.Add($label)

# Create a dropdown list (ComboBox)
$comboBox = New-Object System.Windows.Forms.ComboBox
$comboBox.Location = New-Object System.Drawing.Point(20, 50)
$comboBox.Size = New-Object System.Drawing.Size(440, 20)
$comboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$form.Controls.Add($comboBox)

# Add items to the dropdown
foreach ($key in $InstallerLinks.Keys) {
    [void]$comboBox.Items.Add($key)
}

# Select the first item by default
$comboBox.SelectedIndex = 0

# Create an Install button
$installButton = New-Object System.Windows.Forms.Button
$installButton.Location = New-Object System.Drawing.Point(150, 90)
$installButton.Size = New-Object System.Drawing.Size(100, 30)
$installButton.Text = "Install"
$installButton.Add_Click({
    $selectedItem = $comboBox.SelectedItem
    
    if ($selectedItem) {
        $InstallerSource = $InstallerLinks[$selectedItem]
        
        # Check if Sophos is already installed
        $SophosInstalled = Test-Path -Path "C:\Program Files\Sophos"
        $temp = "C:\temp\"
        $destination = "$temp\SophosSetup.exe"

        # If Sophos is already installed, show message
        If ($SophosInstalled) {
            $statusLabel.Text = "Existing Sophos installation detected."
            [System.Windows.Forms.MessageBox]::Show("Sophos is already installed.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            
        } 
        Else {
            $statusLabel.Text = "Beginning the installation..."
            
            # Check if the temp directory exists, otherwise create it
            If (-Not (Test-Path -Path $temp -PathType Container)) {
                $statusLabel.Text = "Creating $temp directory..."
                New-Item -Path $temp -ItemType directory | Out-Null
            }

            # Download the installer
            $statusLabel.Text = "Downloading installer..."
            try {
                # Create a spinner for download progress
                $spinChars = '/', '-', '\', '|'
                $spinIndex = 0
                $downloadJob = Start-Job -ScriptBlock {
                    param($source, $dest)
                    # Set progress preference in job scope
                    $ProgressPreference = 'SilentlyContinue'
                    try {
                        Invoke-WebRequest -Uri $source -OutFile $dest
                    }
                    catch {
                        Write-Error $_.Exception.Message
                        return $false
                    }
                    return $true
                } -ArgumentList $InstallerSource, $destination

                # Monitor download progress with spinner
                while ($downloadJob.State -eq 'Running' -or $downloadJob.State -eq 'Completing') {
                    $statusLabel.Text = "Downloading installer...$($spinChars[$spinIndex])"
                    $spinIndex = ($spinIndex + 1) % 4
                    Start-Sleep -Milliseconds 50
                    [System.Windows.Forms.Application]::DoEvents()
                }

                # Wait for download to complete and clear spinner
                Wait-Job $downloadJob
                $result = Receive-Job $downloadJob
                Remove-Job $downloadJob

                # Verify the file exists and has content
                if (!$result -or !(Test-Path $destination) -or (Get-Item $destination).Length -eq 0) {
                    throw "Download failed or file is empty"
                }

                # Restore progress preference
                $ProgressPreference = 'Continue'

                $statusLabel.Text = "Initializing Sophos installation..."
                Start-Process -FilePath $destination -ArgumentList "--quiet"
                $statusLabel.Text = "Installing Sophos Endpoint Protection..."
                
                # Create script-level variables for job monitoring
                $script:monitorJob = $null
                $script:timer = New-Object System.Windows.Forms.Timer
                $script:timer.Interval = 25  # Check every 25ms instead of 1000ms
                
                # Start monitoring in a background job
                $script:monitorJob = Start-Job -ScriptBlock {
                    $processes = @("Setup", "SophosSetup", "SophosSetup_Stage2")
                    $running = $true
                    $installComplete = $false
                    $spinChars = '/', '-', '\', '|'
                   
                    $spinIndex = 0
                    
                    # List of expected Sophos services
                    $sophosServices = @(
                        "Sophos MCS Agent",
                        "Sophos Endpoint Defense Service",
                        "Sophos File Scanner Service",
                        "Sophos Network Threat Protection",
                        "Sophos System Protection Service"
                    )
                    
                    while ($running -or -not $installComplete) {
                        # Check if any setup processes are still running
                        $processesRunning = @(Get-Process | Where-Object { $processes -contains $_.Name } -ErrorAction SilentlyContinue)
                        $running = $processesRunning.Count -gt 0
                        
                        # If processes are done, verify installation
                        if (-not $running -and -not $installComplete) {
                            # Wait while showing spinner animation
                            $waitStart = Get-Date
                            while (((Get-Date) - $waitStart).TotalSeconds -lt 30) {
                                Write-Output @{
                                    Status = "Progress"
                                    Message = "Waiting for services to initialize...$($spinChars[$spinIndex])"
                                }
                                $spinIndex = ($spinIndex + 1) % 4
                                Start-Sleep -Milliseconds 50
                            }
                            
                            # Check installation path
                            $installPath = Test-Path "C:\Program Files\Sophos"
                            if (-not $installPath) {
                                Write-Output @{
                                    Status = "Progress"
                                    Message = "Verifying Sophos installation...$($spinChars[$spinIndex])"
                                }
                                $spinIndex = ($spinIndex + 1) % 4
                                Start-Sleep -Milliseconds 50
                                continue
                            }
                            
                            # Check if all required services are running
                            $serviceStatus = @()
                            foreach ($serviceName in $sophosServices) {
                                Write-Output @{
                                    Status = "Progress"
                                    Message = "Verifying Sophos services...$($spinChars[$spinIndex])"
                                }
                                $spinIndex = ($spinIndex + 1) % 4
                                Start-Sleep -Milliseconds 50
                                
                                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                                if ($service) {
                                    $serviceStatus += @{
                                        Name = $serviceName
                                        Status = $service.Status
                                    }
                                }
                            }
                            
                            # Count running services
                            $runningServices = $serviceStatus | Where-Object { $_.Status -eq 'Running' }
                            
                            if ($runningServices.Count -eq $sophosServices.Count) {
                                $installComplete = $true
                                Write-Output @{
                                    Status = "Complete"
                                    Message = "Installation Complete!"
                                    Services = $serviceStatus
                                }
                            } else {
                                Write-Output @{
                                    Status = "Progress"
                                    Message = "Waiting for services to start...$($spinChars[$spinIndex])"
                                }
                                $spinIndex = ($spinIndex + 1) % 4
                                Start-Sleep -Milliseconds 50
                            }
                        } else {
                            Write-Output @{
                                Status = "Progress"
                                Message = "Installing Sophos Endpoint Protection...$($spinChars[$spinIndex])"
                            }
                            $spinIndex = ($spinIndex + 1) % 4
                            Start-Sleep -Milliseconds 50
                        }
                    }
                }

                # Add timer event handler
                $script:timer.Add_Tick({
                    if ($script:monitorJob -and $script:monitorJob.State -eq "Completed") {
                        $result = Receive-Job -Job $script:monitorJob
                        if ($result.Status -eq "Complete") {
                            # Ensure we're on the UI thread for all form operations
                            $form.Invoke([Action]{
                                $statusLabel.Text = "Installation Complete!"
                                $completionMessage = @"
Sophos Endpoint Protection Installation Complete

Installation completed successfully √
All services configured and running √

Your system is now protected by Sophos Endpoint Security.
"@
                                # Create a completion form
                                $completionForm = New-Object System.Windows.Forms.Form
                                $completionForm.Text = "Installation Complete"
                                $completionForm.Size = New-Object System.Drawing.Size(400, 200)
                                $completionForm.StartPosition = "CenterScreen"
                                $completionForm.FormBorderStyle = "FixedDialog"
                                $completionForm.MaximizeBox = $false

                                # Create a label for the completion message
                                $completionLabel = New-Object System.Windows.Forms.Label
                                $completionLabel.Location = New-Object System.Drawing.Point(20, 20)
                                $completionLabel.Size = New-Object System.Drawing.Size(360, 100)
                                $completionLabel.Text = $completionMessage
                                $completionForm.Controls.Add($completionLabel)

                                # Create an OK button
                                $okButton = New-Object System.Windows.Forms.Button
                                $okButton.Location = New-Object System.Drawing.Point(150, 130)
                                $okButton.Size = New-Object System.Drawing.Size(100, 30)
                                $okButton.Text = "OK"
                                $okButton.Add_Click({ $completionForm.Close() })
                                $completionForm.Controls.Add($okButton)

                                # Create a timer for auto-closing
                                $autoCloseTimer = New-Object System.Windows.Forms.Timer
                                $autoCloseTimer.Interval = 30000  # 30 seconds
                                $autoCloseTimer.Add_Tick({
                                    try {
                                        $autoCloseTimer.Stop()
                                        # Close completion form first
                                        $completionForm.BeginInvoke([Action]{
                                            $completionForm.Close()
                                        })
                                        
                                        # Create a second timer for main form closure
                                        $mainFormTimer = New-Object System.Windows.Forms.Timer
                                        $mainFormTimer.Interval = 5000  # 5 seconds
                                        $mainFormTimer.Add_Tick({
                                            try {
                                                $mainFormTimer.Stop()
                                                $form.BeginInvoke([Action]{
                                                    $form.Close()
                                                })
                                                Start-Sleep -Milliseconds 500
                                                [System.Windows.Forms.Application]::Exit()
                                            }
                                            catch {
                                                [System.Windows.Forms.Application]::Exit()
                                            }
                                        })
                                        $mainFormTimer.Start()
                                    }
                                    catch {
                                        # Silently exit if forms are already closed
                                        [System.Windows.Forms.Application]::Exit()
                                    }
                                })
                                $autoCloseTimer.Start()

                                # Show the completion form
                                $completionForm.ShowDialog()
                            })

                            $script:timer.Stop()
                            Remove-Job -Job $script:monitorJob
                            $script:monitorJob = $null
                        }
                    } elseif ($script:monitorJob) {
                        $result = Receive-Job -Job $script:monitorJob -Keep
                        if ($result -and $result[-1].Status -eq "Progress") {
                            $form.Invoke([Action]{
                                $statusLabel.Text = $result[-1].Message
                            })
                        }
                    }
                })

                # Start the timer
                $script:timer.Start()
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "An error occurred during the Sophos installation process. Please try again or contact support.",
                    "Installation Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
                $statusLabel.Text = "Installation failed. Please try again."
            }
        }
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Please select an installer source.", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
})
$form.Controls.Add($installButton)

# Create a status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point(20, 130)
$statusLabel.Size = New-Object System.Drawing.Size(440, 20)
$statusLabel.Text = "Ready"
$statusLabel.Font = New-Object System.Drawing.Font("Consolas", 9)
$form.Controls.Add($statusLabel)

# Create an Exit button
$exitButton = New-Object System.Windows.Forms.Button
$exitButton.Location = New-Object System.Drawing.Point(260, 90)
$exitButton.Size = New-Object System.Drawing.Size(100, 30)
$exitButton.Text = "Exit"
$exitButton.Add_Click({ $form.Close() })
$form.Controls.Add($exitButton)

# Show the form
[void]$form.ShowDialog() 
