# Function to encrypt data using AES
function Encrypt-Data {
    param (
        [Parameter(Mandatory=$true)]
        [string]$JsonData,
        [Parameter(Mandatory=$true)]
        [string]$OutputFile
    )

    try {
        # Create output directory if it doesn't exist
        $outputDir = Split-Path -Parent $OutputFile
        if (-not (Test-Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        }

        # Convert string to bytes
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($JsonData)

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

        try {
            # Create encryptor
            $encryptor = $aes.CreateEncryptor()

            # Encrypt the data
            $encryptedBytes = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)

            # Combine IV and encrypted data
            $result = $iv + $encryptedBytes

            # Save to file
            [System.IO.File]::WriteAllBytes($OutputFile, $result)

            Write-Host "Data has been encrypted and saved to $OutputFile" -ForegroundColor Green
        }
        finally {
            if ($encryptor) { $encryptor.Dispose() }
            if ($aes) { $aes.Dispose() }
        }
    }
    catch {
        Write-Error "Failed to encrypt data: $_"
    }
}

# Create software URLs data
$softwareLinks = @{
    CheckModules = "https://raw.githubusercontent.com/mitsdev01/SOS/refs/heads/main/Check-Modules.ps1"
    OfficeURL = "https://axcientrestore.blob.core.windows.net/win11/OfficeSetup.exe"
    AdobeURL = "https://axcientrestore.blob.core.windows.net/win11/AcroRdrDC2500120432_en_US.exe"
    Win11DebloatURL = "https://axcientrestore.blob.core.windows.net/win11/SOS-Debloat.zip"
    Win10DebloatURL = "https://axcientrestore.blob.core.windows.net/win11/SOS-Debloat.zip"
    SOSDebloatURL = "https://axcientrestore.blob.core.windows.net/win11/SOS-Debloat.zip"
    UpdateWindowsURL = "https://raw.githubusercontent.com/mitsdev01/SOS/refs/heads/main/Update_Windows.ps1"
    BaselineCompleteURL = "https://raw.githubusercontent.com/mitsdev01/SOS/main/BaselineComplete.ps1"
}

# Debug: Show data before encryption
Write-Host "`nData to be encrypted:"
$softwareLinks | ConvertTo-Json | Write-Host

# Convert to JSON and encrypt
$softwareLinksJson = $softwareLinks | ConvertTo-Json -Compress
Write-Host "`nJSON to be encrypted:"
Write-Host $softwareLinksJson

# Encrypt the data
Write-Host "`nEncrypting data..."
Encrypt-Data -JsonData $softwareLinksJson -OutputFile "C:\temp\urls.enc"

# Function to decrypt installer links
function Decrypt-InstallerLinks {
    param (
        [string]$InputFile = "c:\temp\urls.enc"
    )

    # Read the encrypted file
    $encryptedData = [System.IO.File]::ReadAllBytes($InputFile)

    # Extract IV (first 16 bytes)
    $iv = $encryptedData[0..15]

    # Extract encrypted data (remaining bytes)
    $encryptedBytes = $encryptedData[16..($encryptedData.Length - 1)]

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
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)

    # Convert bytes to string
    $json = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

    # Convert JSON to PowerShell object
    $InstallerLinks = $json | ConvertFrom-Json

    # Return the decrypted links
    return $InstallerLinks
}

# Example of how to use the decryption function in another script:
# $links = Decrypt-InstallerLinks
# $SophosAV = $links.SophosAV
# $CheckModules = $links.CheckModules
# $OfficeURL = $links.OfficeURL
# $AdobeURL = $links.AdobeURL
# $Win11DebloatURL = $links.Win11DebloatURL
# $SOSDebloatURL = $links.SOSDebloatURL
# $UpdateWindowsURL = $links.UpdateWindowsURL
# $BaselineCompleteURL = $links.BaselineCompleteURL

