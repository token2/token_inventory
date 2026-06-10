<#
.SYNOPSIS
    Generates a self-signed certificate for the TOTP Token Inventory app
    (certificate-based authentication to Microsoft Entra ID).
    Windows PowerShell 5.1 variant - uses OpenSSL.

.DESCRIPTION
    Produces the two files described in README section 6.F:

      token2_public.cer  - public certificate to upload to your App
                           Registration (Certificates & secrets ->
                           Certificates -> Upload certificate)
      private_key.pem    - matching private key (unencrypted PEM) for the
                           app's "Private key file path" setting

    It also prints the certificate SHA-1 thumbprint (hex) to paste into
    the app.

    OpenSSL generates the key directly in software, so no SafeNet /
    Thales hardware-token dialog can appear. openssl.exe must be in PATH
    (it ships with Git for Windows: C:\Program Files\Git\usr\bin).

.NOTES
    Treat private_key.pem like a password - anyone with it can
    authenticate as your app. Store it outside the web root.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Generate-Token2Cert-51.ps1
#>
[CmdletBinding()]
param(
    [string]$SubjectName  = 'Token2 Inventory App',
    [int]   $ValidityDays = 730,
    [string]$CerPath      = (Join-Path (Get-Location) 'token2_public.cer'),
    [string]$PemPath      = (Join-Path (Get-Location) 'private_key.pem')
)

$ErrorActionPreference = 'Stop'

$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {
    Write-Error ("openssl.exe was not found in PATH. Install OpenSSL or add it to PATH " +
        "(Git for Windows bundles it under C:\Program Files\Git\usr\bin), " +
        "or use Generate-Token2Cert.ps1 with PowerShell 7+ instead.")
    exit 1
}

Write-Host "Generating self-signed certificate (CN=$SubjectName, valid $ValidityDays days)..."

& $openssl.Source req -x509 -newkey rsa:2048 -sha256 -days $ValidityDays -nodes `
    -keyout $PemPath -out $CerPath -subj "/CN=$SubjectName" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Error "OpenSSL failed to generate the certificate (exit code $LASTEXITCODE)."
    exit 1
}

# SHA-1 fingerprint, e.g. "sha1 Fingerprint=A1:B2:..." -> "A1B2..."
$fingerprintLine = & $openssl.Source x509 -in $CerPath -noout -fingerprint -sha1
$thumbprint = ($fingerprintLine -split '=', 2)[1] -replace ':', ''

Write-Host ''
Write-Host 'Done.'
Write-Host "  Public certificate : $CerPath  (upload this to Entra ID)"
Write-Host "  Private key (PEM)  : $PemPath  (path goes into the app settings)"
Write-Host "  Thumbprint         : $thumbprint"
Write-Host ''
Write-Host 'Next steps:'
Write-Host '  1. Azure Portal -> App registrations -> your app -> Certificates & secrets'
Write-Host '     -> Certificates -> Upload certificate -> select token2_public.cer'
Write-Host '  2. Confirm the thumbprint shown by Entra ID matches the one above.'
Write-Host '  3. In the app, set Authentication method = Certificate, enter the'
Write-Host '     private key path and the thumbprint.'
Write-Host ''
Write-Host 'Keep private_key.pem secret and outside the web root.'
