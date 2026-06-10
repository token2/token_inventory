#Requires -Version 7.0
<#
.SYNOPSIS
    Generates a self-signed certificate for the TOTP Token Inventory app
    (certificate-based authentication to Microsoft Entra ID).

.DESCRIPTION
    Produces the two files described in README section 6.F:

      token2_public.cer  - public certificate (DER) to upload to your
                           App Registration (Certificates & secrets ->
                           Certificates -> Upload certificate)
      private_key.pem    - matching private key (unencrypted PKCS#8 PEM)
                           for the app's "Private key file path" setting

    It also prints the certificate thumbprint (hex) to paste into the app.

    The key is generated with the Microsoft software provider
    ("Microsoft Enhanced RSA and AES Cryptographic Provider") on purpose:
    if a SafeNet / Thales (or other hardware token) dialog would normally
    appear, that means a hardware provider is the default on your machine.
    Hardware-token-stored keys cannot be exported to PEM and are not
    supported by this app.

.NOTES
    Requires PowerShell 7+ on Windows. For Windows PowerShell 5.1 use
    Generate-Token2Cert-51.ps1 (uses OpenSSL).

    Treat private_key.pem like a password - anyone with it can
    authenticate as your app. Store it outside the web root.

.EXAMPLE
    pwsh -ExecutionPolicy Bypass -File .\Generate-Token2Cert.ps1
#>
[CmdletBinding()]
param(
    [string]$SubjectName  = 'Token2 Inventory App',
    [int]   $ValidityDays = 730,
    [string]$CerPath      = (Join-Path (Get-Location) 'token2_public.cer'),
    [string]$PemPath      = (Join-Path (Get-Location) 'private_key.pem'),
    # Keep the certificate (and key) in the CurrentUser\My store after export.
    # By default it is removed, since the app only needs the PEM file.
    [switch]$KeepInStore
)

$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    Write-Error ("New-SelfSignedCertificate is only available on Windows. " +
        "On Linux/macOS use OpenSSL instead:`n" +
        '  openssl req -x509 -newkey rsa:2048 -keyout private_key.pem -out token2_public.cer -days 730 -nodes -subj "/CN=Token2 Inventory App"')
    exit 1
}

Write-Host "Generating self-signed certificate (CN=$SubjectName, valid $ValidityDays days)..."

# -Provider forces the Microsoft software CSP so no hardware-token (SafeNet/
# Thales) dialog appears and the key stays exportable to PEM.
$cert = New-SelfSignedCertificate `
    -Subject           "CN=$SubjectName" `
    -KeyAlgorithm      RSA `
    -KeyLength         2048 `
    -HashAlgorithm     SHA256 `
    -KeySpec           Signature `
    -KeyExportPolicy   Exportable `
    -Provider          'Microsoft Enhanced RSA and AES Cryptographic Provider' `
    -NotAfter          (Get-Date).AddDays($ValidityDays) `
    -CertStoreLocation 'Cert:\CurrentUser\My'

try {
    # Public certificate (DER .cer) for Entra ID
    Export-Certificate -Cert $cert -FilePath $CerPath | Out-Null

    # Private key as unencrypted PKCS#8 PEM (-----BEGIN PRIVATE KEY-----)
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    try {
        $pkcs8 = $rsa.ExportPkcs8PrivateKey()
    }
    catch {
        # Some Windows key providers only allow encrypted export; round-trip
        # through an encrypted blob to obtain the plain PKCS#8 bytes.
        $pbe = [System.Security.Cryptography.PbeParameters]::new(
            [System.Security.Cryptography.PbeEncryptionAlgorithm]::Aes256Cbc,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            100000)
        $tempPwd   = [Guid]::NewGuid().ToString()
        $encrypted = $rsa.ExportEncryptedPkcs8PrivateKey($tempPwd, $pbe)
        $plainRsa  = [System.Security.Cryptography.RSA]::Create()
        $bytesRead = 0
        $plainRsa.ImportEncryptedPkcs8PrivateKey($tempPwd, $encrypted, [ref]$bytesRead)
        $pkcs8 = $plainRsa.ExportPkcs8PrivateKey()
        $plainRsa.Dispose()
    }

    $b64 = [Convert]::ToBase64String($pkcs8, [System.Base64FormattingOptions]::InsertLineBreaks)
    $pem = "-----BEGIN PRIVATE KEY-----`n$b64`n-----END PRIVATE KEY-----`n"
    Set-Content -Path $PemPath -Value $pem -Encoding ascii -NoNewline
}
finally {
    if (-not $KeepInStore) {
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host 'Done.'
Write-Host "  Public certificate : $CerPath  (upload this to Entra ID)"
Write-Host "  Private key (PEM)  : $PemPath  (path goes into the app settings)"
Write-Host "  Thumbprint         : $($cert.Thumbprint)"
Write-Host ''
Write-Host 'Next steps:'
Write-Host '  1. Azure Portal -> App registrations -> your app -> Certificates & secrets'
Write-Host '     -> Certificates -> Upload certificate -> select token2_public.cer'
Write-Host '  2. Confirm the thumbprint shown by Entra ID matches the one above.'
Write-Host '  3. In the app, set Authentication method = Certificate, enter the'
Write-Host '     private key path and the thumbprint.'
Write-Host ''
Write-Host 'Keep private_key.pem secret and outside the web root.'
