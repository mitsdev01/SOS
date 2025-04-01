# SOS - Standardized Operating System Baseline

A comprehensive automated solution for standardizing and configuring Windows workstations for customer environments.

## Overview

The SOS Baseline Suite provides a collection of PowerShell scripts designed to automate the configuration and deployment of standardized Windows workstation environments. These scripts streamline the deployment processes by standardizing configurations, enhancing security, and ensuring consistency across all workstation setups.

## Key Features

- **Complete Workstation Baseline**: Automates the setup of new machines with best practice configurations
- **Security Hardening**: Implements security best practices including BitLocker encryption, Windows Update management, and removal of unnecessary features
- **Software Deployment**: Automates installation of essential software like Microsoft 365 and Adobe Acrobat
- **System Optimization**: Configures power settings, system restore, and other performance optimizations
- **Bloatware Removal**: Removes unnecessary pre-installed applications for a cleaner experience
- **Detailed Verification**: Provides comprehensive reports on system status and configuration

## Getting Started

### Prerequisites

- Windows 10/11 Professional
- PowerShell 5.1 or higher
- Administrator privileges
- Internet connectivity

### Installation

1. Clone this repository or download the scripts directly from GitHub:
   ```
   git clone https://github.com/mitsdev01/SOS.git
   ```

2. Ensure PowerShell execution policy allows running the scripts:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

### Basic Usage

#### Option 1: Full Baseline Setup (Recommended for New Deployments)

1. Open PowerShell as Administrator
2. Navigate to the directory containing the scripts
3. Run the main baseline script:
   ```powershell
   .\SOS-Baseline.ps1
   ```

This will perform the complete baseline process including:
- Datto RMM agent deployment
- Power profile optimization
- BitLocker encryption
- Windows Update configuration
- Software installation
- System hardening
- Bloatware removal

#### Option 2: Individual Components

Each script can be run independently to perform specific tasks:

- **Baseline Verification**: `.\BaselineComplete.ps1`
- **Windows Updates**: `.\Update_Windows.ps1`
- **Module Dependencies**: `.\Check-Modules.ps1`
- **Sophos VPN Deployment**: `.\Deploy-SophosConnect.ps1`

## Script Descriptions

### SOS-Baseline.ps1 (Main Script)

The primary script that performs all baseline operations. It includes comprehensive workstation configuration and ensures systems are properly secured and optimized.

### BaselineComplete.ps1

Generates a detailed verification report showing the current state of a workstation, including:
- System information
- Installed software
- BitLocker status
- Domain/Azure AD join status
- Security and antivirus status
- Power configuration
- Overall baseline score

### Update_Windows.ps1

Automates the process of checking for and installing Windows updates using the PSWindowsUpdate module.

### Check-Modules.ps1

Ensures all required PowerShell modules are properly installed and configured.

### Deploy-SophosConnect.ps1

Automates the deployment and configuration of Sophos Connect VPN client.

## Customization

These scripts can be customized for your environment:

1. **Software Deployment**: Modify URLs in deployment sections to point to your internal resources
2. **Domain Settings**: Update domain information to match your organization
3. **Security Policies**: Adjust security settings based on your organization's requirements

## Troubleshooting

If you encounter issues during script execution:

1. Check the logs in `C:\temp\[COMPUTERNAME]-baseline.log`
2. Review the transcript file in `C:\temp\[COMPUTERNAME]-baseline_transcript.txt`
3. Ensure all prerequisites are met
4. Verify Internet connectivity for downloading components

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Bill Ulrich

## Acknowledgments

- Thanks to all contributors who have helped improve these scripts
- Special thanks to the PowerShell community for providing valuable resources and modules 