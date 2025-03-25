cls

# Check if NuGet provider is installed
if (!(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    # Install NuGet provider
    Install-PackageProvider -Name NuGet -Force
}

# Ensure PSWindowsUpdate module is installed
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Install-Module -Name PSWindowsUpdate -Force -Confirm:$false -AllowClobber
}

try {
    Import-Module PSWindowsUpdate -ErrorAction Stop
} catch {
    Write-Host "Error importing PSWindowsUpdate module: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Check for updates
Write-Host "Checking for updates..." -ForegroundColor Cyan
try {
    $availableUpdates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
    
    # Display the total number of updates found
    $totalUpdates = $availableUpdates.Count
    Write-Host "Total Updates available: $totalUpdates" -ForegroundColor Yellow
    Start-Sleep -Seconds 3

    # Install updates
    if ($totalUpdates -gt 0) {
        Write-Host "Starting Windows Update installation..." -ForegroundColor Cyan
        try {
            # Install all updates at once instead of one by one
            Install-WindowsUpdate -AcceptAll -IgnoreReboot -AutoReboot:$false -Confirm:$false -ErrorAction Stop
            Write-Host "Windows Update installation completed successfully!" -ForegroundColor Green
        } catch {
            Write-Host "Error during update installation: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "No updates available." -ForegroundColor Green
    }
} catch {
    Write-Host "Error checking for updates: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host " "
Write-Host "`nScript completed. Please restart your computer if required." -ForegroundColor Cyan
