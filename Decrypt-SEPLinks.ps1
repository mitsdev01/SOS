# Function to decrypt the SEPLinks.enc file
function Decrypt-SEPLinks {
    param (
        [string]$InputFile = "c:\temp\SEPLinks.enc"
    )

    try {
        # Check if file exists
        if (-not (Test-Path $InputFile)) {
            Write-Host "File not found: $InputFile" -ForegroundColor Red
            return
        }

        # Display file info
        $fileInfo = Get-Item $InputFile
        Write-Host "File: $InputFile" -ForegroundColor Cyan
        Write-Host "Size: $($fileInfo.Length) bytes" -ForegroundColor Cyan
        Write-Host "Last Modified: $($fileInfo.LastWriteTime)" -ForegroundColor Cyan

        # Read the encrypted file
        $encryptedData = [System.IO.File]::ReadAllBytes($InputFile)
        Write-Host "Read $($encryptedData.Length) bytes of encrypted data" -ForegroundColor Yellow

        # Display first 32 bytes for debugging
        Write-Host "First 32 bytes of encrypted data:" -ForegroundColor Yellow
        for ($i = 0; $i -lt [Math]::Min(32, $encryptedData.Length); $i++) {
            Write-Host -NoNewline "$($encryptedData[$i].ToString('X2')) "
            if (($i + 1) % 16 -eq 0) { Write-Host "" }
        }
        Write-Host ""

        # Extract IV (first 16 bytes)
        $iv = $encryptedData[0..15]
        Write-Host "Extracted IV:" -ForegroundColor Yellow
        $iv | ForEach-Object { Write-Host -NoNewline "$($_.ToString('X2')) " }
        Write-Host ""

        # Extract encrypted data (remaining bytes)
        $encryptedBytes = $encryptedData[16..($encryptedData.Length - 1)]
        Write-Host "Extracted $($encryptedBytes.Length) bytes of actual encrypted data" -ForegroundColor Yellow

        # Create a fixed encryption key (32 bytes for AES-256)
        $key = [byte[]]@(
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
        )

        # Display decryption key
        Write-Host "Decryption Key:" -ForegroundColor Yellow
        $key | ForEach-Object { Write-Host -NoNewline "$($_.ToString('X2')) " }
        Write-Host ""

        # Create AES object
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        try {
            # Create decryptor
            $decryptor = $aes.CreateDecryptor()
            
            # Decrypt the data
            Write-Host "Attempting to decrypt data..." -ForegroundColor Yellow
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
            Write-Host "Successfully decrypted $($decryptedBytes.Length) bytes" -ForegroundColor Green
            
            # Convert bytes to string
            $json = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
            Write-Host "Decrypted JSON:" -ForegroundColor Green
            Write-Host $json
            
            # Convert JSON to PowerShell object
            $installerLinks = $json | ConvertFrom-Json
            Write-Host "Successfully converted JSON to object" -ForegroundColor Green
            
            # Display object type and properties
            Write-Host "Object Type: $($installerLinks.GetType().FullName)" -ForegroundColor Cyan
            Write-Host "Properties:" -ForegroundColor Cyan
            $installerLinks.PSObject.Properties | ForEach-Object {
                Write-Host "  $($_.Name) : $($_.Value)"
            }
            
            return $installerLinks
        }
        finally {
            if ($decryptor) { $decryptor.Dispose() }
            if ($aes) { $aes.Dispose() }
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Exception details: $($_)" -ForegroundColor Red
    }
}

# Call the function to decrypt and analyze the file
Decrypt-SEPLinks 