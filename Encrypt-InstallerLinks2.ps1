import time

from playwright.sync_api import Playwright, sync_playwright, expect


def run(playwright: Playwright) -> None:
    browser = playwright.chromium.launch(headless=False)
    context = browser.new_context()
    page = context.new_page()
    page.goto("https://status.advancestuff.com/")
    page.get_by_placeholder("Enter the password...").click()
    page.get_by_placeholder("Enter the password...").fill("@dvance10755")
    page.get_by_placeholder("Enter the password...").press("Enter")
    input("Press Enter to exit...")  # This will pause the script at the end

    # ---------------------
    context.close()
    browser.close()

with sync_playwright() as playwright:
    run(playwright)

# Function to encrypt installer links
function Encrypt-InstallerLinks {
    param (
        [string]$OutputFile = "urls.enc"
    )

    # Create the installer links dictionary
    $InstallerLinks = New-Object Collections.Specialized.OrderedDictionary

    # Add all installer links
    $InstallerLinks.Add('SophosAV', "https://raw.githubusercontent.com/mitsdev01/SOS/refs/heads/main/Deploy-SophosAV.ps1")
    $InstallerLinks.Add('CheckModules', "https://raw.githubusercontent.com/mitsdev01/SOS/refs/heads/main/Check-Modules.ps1")
    $InstallerLinks.Add('OfficeURL', "https://axcientrestore.blob.core.windows.net/win11/OfficeSetup.exe")
    $InstallerLinks.Add('AdobeURL', "https://axcientrestore.blob.core.windows.net/win11/AcroRdrDC2500120432_en_US.exe")
    $InstallerLinks.Add('Win11DebloatURL', "https://axcientrestore.blob.core.windows.net/win11/SOS-Debloat.zip")
    $InstallerLinks.Add('SOSDebloatURL', "https://axcientrestore.blob.core.windows.net/win11/SOS-Debloat.zip")
    $InstallerLinks.Add('UpdateWindowsURL', "https://raw.githubusercontent.com/mitsdev01/SOS/refs/heads/main/Update_Windows.ps1")
    $InstallerLinks.Add('BaselineCompleteURL', "https://raw.githubusercontent.com/mitsdev01/SOS/main/BaselineComplete.ps1")

    # Convert the dictionary to JSON
    $json = $InstallerLinks | ConvertTo-Json -Compress

    # Convert the JSON to bytes
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)

    # Create a fixed encryption key (32 bytes for AES-256)
    $key = [byte[]]@(
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
    )

    # Create a fixed IV (16 bytes)
    $iv = [byte[]]@(
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
    )

    # Create AES object
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    # Create encryptor
    $encryptor = $aes.CreateEncryptor()

    # Encrypt the data
    $encryptedBytes = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)

    # Combine IV and encrypted data
    $result = $iv + $encryptedBytes

    # Save to file
    [System.IO.File]::WriteAllBytes($OutputFile, $result)

    Write-Host "Installer links have been encrypted and saved to $OutputFile"
}

# Call the function to create the encrypted file
Encrypt-InstallerLinks

