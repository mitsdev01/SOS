# Sophos Connect Deployment Script for Datto RMM

# Define variables

$installerUrl = "https://servername.com/SophosConnect_2.3.27.msi"  # Replace with your MSI URL

$configUrl = "https://servername.com/vpn_config.scx"              # Replace with your .scx URL

$installerPath = "c:\temp\SophosConnect.msi"

$configPath = "c:\temp\vpn_config.scx"

$installDir = "C:\Program Files (x86)\Sophos\Connect"
 
# Function to download files

function Download-File {

    param ($url, $output)

    try {

        Invoke-WebRequest -Uri $url -OutFile $output -ErrorAction Stop

        Write-Output "Downloaded $url to $output"

    } catch {

        Write-Error "Failed to download $url. Error: $_"

        exit 1

    }

}
 
# Download the installer and config file

Download-File -url $installerUrl -output $installerPath

Download-File -url $configUrl -output $configPath
 
# Install Sophos Connect silently

try {

    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" /qn /norestart" -Wait -NoNewWindow

    Write-Output "Sophos Connect installed successfully."

} catch {

    Write-Error "Installation failed. Error: $_"

    exit 1

}
 
# Wait for installation to complete and verify

Start-Sleep -Seconds 10

if (Test-Path "$installDir\scgui.exe") {

    Write-Output "Installation verified."

} else {

    Write-Error "Sophos Connect not found after installation."

    exit 1

}
 
# Import the VPN configuration

try {

    Start-Process -FilePath "$installDir\sccli.exe" -ArgumentList "import `"$configPath`"" -Wait -NoNewWindow

    Write-Output "VPN configuration imported successfully."

} catch {

    Write-Error "Failed to import VPN configuration. Error: $_"

    exit 1

}
 
# Clean up temporary files

Remove-Item -Path $installerPath -Force

Remove-Item -Path $configPath -Force
 
Write-Output "Sophos Connect deployment completed."

exit 0
 