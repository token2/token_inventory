<#
    Generate-Token2Cert-51.ps1  (Windows PowerShell 5.1 compatible)
    Generates a self-signed cert, exports the public .cer for Entra,
    and converts the private key to private_key.pem using OpenSSL.
    Auto-detects OpenSSL from PATH or Git for Windows.
#>

$subject   = "CN=Token2 Inventory App"
$years     = 2
$outFolder = (Get-Location).Path
$pfxPass   = "TempPfx123!"   # temporary, only used during conversion

Write-Host "Generating certificate..." -ForegroundColor Cyan

$cert = New-SelfSignedCertificate `
    -Subject $subject `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
    -NotAfter (Get-Date).AddYears($years)

$cerPath = Join-Path $outFolder "token2_public.cer"
$pfxPath = Join-Path $outFolder "token2_temp.pfx"
$pemPath = Join-Path $outFolder "private_key.pem"

# Public cert for Entra
Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null

# Temporary PFX (contains the private key)
$secure = ConvertTo-SecureString -String $pfxPass -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $secure | Out-Null

# Locate OpenSSL
$openssl = $null
$cmd = Get-Command openssl -ErrorAction SilentlyContinue
if ($cmd) { $openssl = $cmd.Source }
if (-not $openssl) {
    foreach ($p in @(
        "C:\Program Files\Git\usr\bin\openssl.exe",
        "C:\Program Files\Git\mingw64\bin\openssl.exe",
        "C:\Program Files (x86)\Git\usr\bin\openssl.exe"
    )) { if (Test-Path $p) { $openssl = $p; break } }
}

if ($openssl) {
    Write-Host "Converting key to PEM using: $openssl" -ForegroundColor Cyan
    & $openssl pkcs12 -in $pfxPath -nocerts -nodes -passin "pass:$pfxPass" -out $pemPath 2>$null
    Remove-Item $pfxPath -Force
    Write-Host "Private key PEM (for the app) : $pemPath" -ForegroundColor Green
} else {
    Write-Host "OpenSSL not found. PFX left at: $pfxPath" -ForegroundColor Yellow
    Write-Host "Convert it manually with:" -ForegroundColor Yellow
    Write-Host "    openssl pkcs12 -in `"$pfxPath`" -nocerts -nodes -passin pass:$pfxPass -out `"$pemPath`""
}

Write-Host ""
Write-Host "Public cert (upload to Entra) : $cerPath"
Write-Host "Thumbprint (paste into app)   : $($cert.Thumbprint)" -ForegroundColor Yellow
Write-Host "Passphrase in app             : leave blank"
