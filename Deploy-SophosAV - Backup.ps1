############################################################################################################
#                                   SOS - Sophos AV Installer                                              #
#                                           Version 1.0.7                                                  #
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
    Version:        1.0.7
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

$ScriptVersion = "1.0.7"

# Use OrderedDictionary instead of hashtable to maintain item order
$InstallerLinks = New-Object Collections.Specialized.OrderedDictionary

# Add items in the desired order
$InstallerLinks.Add('Atlanta Family Law Immigration', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/7e0de62726ddb7f47ed8458fd0b3b41d/SophosSetup.exe")
$InstallerLinks.Add('Affiliated Resources Group', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/fdcc52e2a8c06d03db0c0868d010a4ff/SophosSetup.exe")
$InstallerLinks.Add('Alex Rousch', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/4aae93e82d96bc5eafd0698fa31c1d29/SophosSetup.exe")
$InstallerLinks.Add('American Wealth Management', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/10cbc593cd0d912d9ce016d4a39f57e7/SophosSetup.exe")
$InstallerLinks.Add('Atlanta Custom Brokers', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/ee027dc2ebcfe77aed6c2dd4775c3053/SophosSetup.exe")
$InstallerLinks.Add('Baskin Law Group', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/8c920477f47e29828551596180706130/SophosSetup.exe")
$InstallerLinks.Add('Bestar Steel Group', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/d16d9d253829a03246654bf6dae7e593/SophosSetup.exe")
$InstallerLinks.Add('Bloom''n Gardens Landscape', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/6d662f4f64caa1c4bc7d84fa2934421e/SophosSetup.exe")
$InstallerLinks.Add('Breedlove Land Planning Inc', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/0d4bf34215ce16a2adcc0cd92ad0d3e9/SophosSetup.exe")
$InstallerLinks.Add('Canton First Baptist', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/675116c2c6a720eafca56f80df3d798a/SophosSetup.exe")
$InstallerLinks.Add('Community Housing Capital', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/0564d375396e9f955e1b41e28068fcb9/SophosSetup.exe")
$InstallerLinks.Add('Corvaglia Closures USA Inc', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/95a91e546201f57d4efa838a293a951a/SophosSetup.exe")
$InstallerLinks.Add('Dawson Jones', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/e47da497f62233858e5102f23ccb82ed/SophosSetup.exe")
$InstallerLinks.Add('Disc O Bed', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/0c83bf865394c34887c5f4a70eb4d2d1/SophosSetup.exe")
$InstallerLinks.Add('Ehrisman Law Firm, P.C.', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/2f8c3aae70c9de934a0d367f3af24fd9/SophosSetup.exe")
$InstallerLinks.Add('Electric Cities of Georgia Inc', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/c0dee0b7cff466b9809225f1ed04dbd8/SophosSetup.exe")
$InstallerLinks.Add('Elks Aidmore', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/4df2f95a0cf0589e5b1ce46217b2f3ac/SophosSetup.exe")
$InstallerLinks.Add('EM Concrete Services', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/892dcbd9ab7bc141c73f03e2b8953e21/SophosSetup.exe")
$InstallerLinks.Add('Fidlock USA, Inc', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/a2fdb0ce5743290c2898ef6b25b9769a/SophosSetup.exe")
$InstallerLinks.Add('gatc LP', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/b742a091a43a1806732ef405323384c5/SophosSetup.exe")
$InstallerLinks.Add('Georgia Health Care Association', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/e110d37e3b1d0dbc6d72224efd4bc8e4/SophosSetup.exe")
$InstallerLinks.Add('Georgia Optometric Association', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/9a43249f8594df944fe9fc003b0fc9bf/SophosSetup.exe")
$InstallerLinks.Add('Harris Door & Drawer', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/c84d726e619022d4e7a2335bd18957c8/SophosSetup.exe")
$InstallerLinks.Add('Harrison Law Firm', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/de0a047bc2f84cf46642d5d39ac15055/SophosSetup.exe")
$InstallerLinks.Add('HighGrove Partners LLC', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/9a02e952daf1c5b7f47b3e216b3e4b20/SophosSetup.exe")
$InstallerLinks.Add('Hinton Auto Sales', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/6caf5a304b350615a88b02e082ff66a2/SophosSetup.exe")
$InstallerLinks.Add('Hughes White Kralicek', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/a344928ab733720cea23a17e26572e03/SophosSetup.exe")
$InstallerLinks.Add('Inform Software Corporation', "https://api-cloudstation-eu-central-1.prod.hydra.sophos.com/api/download/c521471ef66682f099aff299f1ddc050/SophosSetup.exe")
$InstallerLinks.Add('Isakson Living', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/e970c2eadc1cf0119bf862010cde3f4c/SophosSetup.exe")
$InstallerLinks.Add('Jarrard & Davis Law Firm', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/7d75c5b1cec502159a8e815c743ab25c/SophosSetup.exe")
$InstallerLinks.Add('LMG Insurance Services Inc', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/53354205cd6580f691d331f835152b28/SophosSetup.exe")
$InstallerLinks.Add('ML Ball', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/e9793c017ba2866a981a4ca1a1fa229f/SophosSetup.exe")
$InstallerLinks.Add('Network Twenty One International Inc', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/f03d79b4a606b8b7b81e057b7d1c078b/SophosSetup.exe")
$InstallerLinks.Add('Omega Bio-Tek Inc', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/dc412d45a11277f4160d14a8f452f5cc/SophosSetup.exe")
$InstallerLinks.Add('Oxford Properties', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/794ae74d4ebcaaea07f8905026fdef2c/SophosSetup.exe")
$InstallerLinks.Add('Peachtree Distributing Inc', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/3523f6529ec805fa5b247b9d041ba13e/SophosSetup.exe")
$InstallerLinks.Add('Peachtree Hill Place', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/ddc32e9114f222faa224ee669d084215/SophosSetup.exe")
$InstallerLinks.Add('Philanthropy Southeast', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/62a3d1bb9191c980af3683be9791a31e/SophosSetup.exe")
$InstallerLinks.Add('Pye Barker', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/1d51018005ac6d6fa605ecc22b9d99de/SophosSetup.exe")
$InstallerLinks.Add('Rehabilitation Physicians of Georgia', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/7b8c87b7bb9267587ee3b72ac7680ed7/SophosSetup.exe")
$InstallerLinks.Add('Remediation Group Inc', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/aae123310254c4ac70076c7d2a8574f9/SophosSetup.exe")
$InstallerLinks.Add('Spirac USA Inc', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/a0f496e600cd255f05cee20e5db4cd05/SophosSetup.exe")
$InstallerLinks.Add('Storz Medical America, LLC', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/b48486f06b7d93be0cf087606db1db63/SophosSetup.exe")
$InstallerLinks.Add('Strategic Contract Resources', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/03d48ce203c7febaf30fc3f4e289ca3c/SophosSetup.exe")
$InstallerLinks.Add('Street Smart Youth Project', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/499bb1599cee8ae996f2e83cb0e7766f/SophosSetup.exe")
$InstallerLinks.Add('Tek-Rail, Inc.', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/17e220fa130ea7f2bedb68751fa7ae49/SophosSetup.exe")
$InstallerLinks.Add('The Carter Treatment Center', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/9161ebe32b0cdda56c98a1d21327ec6a/SophosSetup.exe")
$InstallerLinks.Add('The Law Office of Cameron Hawkins', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/90cbaf778ae05929057290c89fc286fb/SophosSetup.exe")
$InstallerLinks.Add('The Mabra Firm LLC', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/113f6e218cfa751fbe980504a8c2c77d/SophosSetup.exe")
$InstallerLinks.Add('The Redcliffe Group LLC - DBA Bridge', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/54c5a5fcb595a986bbb98d3fea85fe61/SophosSetup.exe")
$InstallerLinks.Add('To Our Shores, Inc', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/e2fe9276d71639c9cf05fb21d662b809/SophosSetup.exe")
$InstallerLinks.Add('United Cerebral Palsy', "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/6c083c044fa03ba0b694a4c920f564a9/SophosSetup.exe")
$InstallerLinks.Add('Vann Whipple Milligan, P.C.', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/08491ea58d082199aa7c4ca56416eba6/SophosSetup.exe")
$InstallerLinks.Add('Visiting Angels', "https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/52b73c08408d08615db479f699cc4843/SophosSetup.exe")

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
                Invoke-WebRequest -Uri $InstallerSource -OutFile $destination
                $statusLabel.Text = "Starting installation..."
                #Start-Process -FilePath $destination -ArgumentList "--quiet"
                $statusLabel.Text = "Installation started."
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Error: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                $statusLabel.Text = "Installation failed."
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