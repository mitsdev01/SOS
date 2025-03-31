# Prompt asking if the computer needs to be joined to the domain
$joinDomain = Read-Host "Do you want to join this computer to the domain? (Y/N)"
 
# Check if the user wants to join the domain
if ($joinDomain -eq 'Y' -or $joinDomain -eq 'y') {
    # Prompt for domain name
    $domainName = Read-Host "Enter the domain name"
 
    # Prompt for username
    $adminUser = Read-Host "Enter the domain admin username"
 
    # Prompt for password as a secure string
    $securePassword = Read-Host "Enter the password" -AsSecureString
 
    # Create a PSCredential object
    $credential = New-Object System.Management.Automation.PSCredential ($adminUser, $securePassword)
 
    # Attempt to join the computer to the domain
    Try {
        Add-Computer -DomainName $domainName -Credential $credential -Force
        Write-Output "Successfully joined the computer to the domain: $domainName"
    } Catch {
        Write-Output "Failed to join the computer to the domain. Error: $_"
    }
} else {
    Write-Output "Domain join process skipped."
}