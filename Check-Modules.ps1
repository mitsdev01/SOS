# Set execution policy to bypass for this session
$originalExecutionPolicy = Get-ExecutionPolicy
Set-ExecutionPolicy Bypass -Scope Process -Force
$WarningPreference = "SilentlyContinue"
# Configure NuGet to install without prompts
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null

# Install and import the PowerShellGet module
Install-Module PowerShellGet -Force -AllowClobber -Scope CurrentUser | Out-Null
Import-Module PowerShellGet -Force

# Restore the original execution policy
Set-ExecutionPolicy $originalExecutionPolicy -Scope Process -Force

# Verify NuGet installation
if (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue) {
    Write-Output "NuGet package provider is installed successfully."
} else {
    Write-Output "Failed to install NuGet package provider."
}
