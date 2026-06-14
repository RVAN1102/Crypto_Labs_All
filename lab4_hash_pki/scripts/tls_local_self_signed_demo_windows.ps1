param(
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $PSCommandPath
$Lab4Root = Split-Path -Parent $ScriptDir
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $Lab4Root "demos\tls\local"
}

$TlsDir = Split-Path -Parent $OutDir
$CertInfo = Join-Path $TlsDir "cert_chain_info.txt"
$TestLog = Join-Path $TlsDir "tls_test_log.txt"
$KeyPath = Join-Path $OutDir "localhost_ecdsa_key.pem"
$CertPath = Join-Path $OutDir "localhost_self_signed_cert.pem"
$CnfPath = Join-Path $OutDir "localhost_openssl.cnf"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (!(Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw "OpenSSL CLI not found on PATH. Install OpenSSL or use the MSYS2 MinGW OpenSSL package."
}

@"
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no

[dn]
CN = localhost

[v3_req]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
"@ | Set-Content -LiteralPath $CnfPath -Encoding ASCII

& openssl ecparam -name prime256v1 -genkey -noout -out $KeyPath
if ($LASTEXITCODE -ne 0) {
    throw "openssl ecparam failed"
}

& openssl req -new -x509 -sha256 -key $KeyPath -out $CertPath -days 30 -config $CnfPath
if ($LASTEXITCODE -ne 0) {
    throw "openssl req self-signed certificate generation failed"
}

& openssl x509 -in $CertPath -noout -text | Set-Content -LiteralPath $CertInfo -Encoding ASCII

@"
TLS local self-signed practice run: PASS

Generated:
- $KeyPath
- $CertPath

This certificate is self-signed and valid only for local configuration practice.
It includes SAN DNS:localhost and IP:127.0.0.1.
No admin privileges were required.
No public trusted-root TLS deployment is claimed.
Trusted-root evidence remains pending until an owned domain and CA-issued certificate chain are available.
"@ | Set-Content -LiteralPath $TestLog -Encoding ASCII

Write-Host "Local self-signed TLS practice files created under: $OutDir"
Write-Host "No public trust is claimed."

