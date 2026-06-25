param(
  [Parameter(Mandatory=$true)]
  [string]$Domain,

  [string]$OpenSSL = "C:\msys64\mingw64\bin\openssl.exe",
  [string]$ApacheRoot = "D:\Apache24",
  [string]$RootCA = "D:\https-lab\chain\Sectigo_Public_Server_Authentication_Root_E46.crt"
)

$ErrorActionPreference = "Continue"

$Repo = (Resolve-Path ".").Path
$Lab = Join-Path $Repo "lab4_hash_pki"
$Logs = Join-Path $Lab "artifacts\windows\logs"
$TlsDir = Join-Path $Lab "artifacts\windows\tls_public_trust"
$Report = Join-Path $Lab "report"

New-Item -ItemType Directory -Force $Logs, $TlsDir, $Report | Out-Null

$SClientLog = Join-Path $Logs "public_trust_tls_windows_s_client.log"
$CurlLog = Join-Path $Logs "public_trust_tls_windows_curl.log"
$ApacheLog = Join-Path $Logs "public_trust_tls_windows_apache.log"
$LeafInfo = Join-Path $Logs "public_trust_tls_windows_leaf_cert.log"

$ChainPem = Join-Path $TlsDir "public_trust_chain_windows.pem"
$LeafPem = Join-Path $TlsDir "public_trust_leaf_windows.pem"
$RootCopy = Join-Path $TlsDir "public_trust_root_windows.pem"
$Sanitized = Join-Path $TlsDir "apache_public_trust_vhost_windows_sanitized.conf"
$Capture = Join-Path $Report "capture_commands_public_tls_windows.md"

Remove-Item -Force $SClientLog, $CurlLog, $ApacheLog, $LeafInfo, $ChainPem, $LeafPem, $RootCopy, $Sanitized, $Capture -ErrorAction SilentlyContinue

if (!(Test-Path $OpenSSL)) { throw "OpenSSL not found: $OpenSSL" }
if (!(Test-Path $RootCA)) { throw "Root CA not found: $RootCA" }

$ConfiguredFullChain = Join-Path $ApacheRoot "conf\ssl\lab4_bavan_fullchain.pem"
if (!(Test-Path $ConfiguredFullChain)) {
  $ConfiguredFullChain = Join-Path $ApacheRoot "conf\ssl\fullchain.pem"
}
if (!(Test-Path $ConfiguredFullChain)) {
  throw "Apache configured fullchain not found."
}

Copy-Item $RootCA $RootCopy -Force
Copy-Item $ConfiguredFullChain $ChainPem -Force

$chainText = Get-Content $ChainPem -Raw
$matches = [regex]::Matches(
  $chainText,
  "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
  [System.Text.RegularExpressions.RegexOptions]::Singleline
)

if ($matches.Count -lt 1) {
  throw "No certificate PEM block found in Apache fullchain file."
}

$matches[0].Value.Trim() | Set-Content $LeafPem -Encoding ascii

"Lab 4 Public Trust TLS Evidence - Windows" | Out-File $SClientLog -Encoding utf8
"Domain: $Domain" | Tee-Object -FilePath $SClientLog -Append
"RootCA: $RootCA" | Tee-Object -FilePath $SClientLog -Append
"Partial chain mode: enabled" | Tee-Object -FilePath $SClientLog -Append
"Apache fullchain: $ConfiguredFullChain" | Tee-Object -FilePath $SClientLog -Append
"Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Tee-Object -FilePath $SClientLog -Append
& $OpenSSL version 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $SClientLog -Append

$ShowCmd = 'echo Q| "' + $OpenSSL + '" s_client -connect 127.0.0.1:443 -servername "' + $Domain + '" -verify_hostname "' + $Domain + '" -verify_return_error -partial_chain -CAfile "' + $RootCA + '" -showcerts'
$BriefCmd = 'echo Q| "' + $OpenSSL + '" s_client -connect 127.0.0.1:443 -servername "' + $Domain + '" -verify_hostname "' + $Domain + '" -verify_return_error -partial_chain -CAfile "' + $RootCA + '" -brief'

"`n==== OpenSSL local Apache verification, SNI + hostname check ====" | Tee-Object -FilePath $SClientLog -Append
cmd.exe /d /c $ShowCmd 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $SClientLog -Append

"`n==== OpenSSL brief verification ====" | Tee-Object -FilePath $SClientLog -Append
cmd.exe /d /c $BriefCmd 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $SClientLog -Append

"`n==== Apache configured certificate chain PEM ====" | Tee-Object -FilePath $SClientLog -Append
Get-Content $ChainPem | Tee-Object -FilePath $SClientLog -Append

& $OpenSSL x509 -in $LeafPem -noout -subject -issuer -dates -fingerprint -sha256 -ext subjectAltName 2>&1 |
  ForEach-Object { "$_" } |
  Tee-Object -FilePath $LeafInfo

"`n==== curl local Apache connection via --resolve ====" | Out-File $CurlLog -Encoding utf8
$CurlCmd = 'curl.exe -Iv --resolve "' + $Domain + ':443:127.0.0.1" "https://' + $Domain + '/"'
cmd.exe /d /c $CurlCmd 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $CurlLog -Append

"`n==== Apache syntax and vhost evidence ====" | Out-File $ApacheLog -Encoding utf8
$Httpd = Join-Path $ApacheRoot "bin\httpd.exe"

if (Test-Path $Httpd) {
  $HttpdCmd = '"' + $Httpd + '" -t'
  cmd.exe /d /c $HttpdCmd 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $ApacheLog -Append

  $HttpdSCmd = '"' + $Httpd + '" -S'
  cmd.exe /d /c $HttpdSCmd 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $ApacheLog -Append
} else {
  "Apache httpd.exe not found at $Httpd" | Tee-Object -FilePath $ApacheLog -Append
}

$ApacheConf = Join-Path $ApacheRoot "conf\extra\lab4-public-trust-ssl.conf"
if (Test-Path $ApacheConf) {
  Get-Content $ApacheConf |
    ForEach-Object {
      $_ -replace '(SSLCertificateKeyFile\s+).+', '$1"[REDACTED_PRIVATE_KEY_PATH]"'
    } |
    Set-Content $Sanitized -Encoding utf8
}

@"
# Lab 4 Public Trust TLS capture commands - Windows

openssl s_client -connect 127.0.0.1:443 -servername $Domain -verify_hostname $Domain -verify_return_error -partial_chain -CAfile "$RootCA" -showcerts

openssl s_client -connect 127.0.0.1:443 -servername $Domain -verify_hostname $Domain -verify_return_error -partial_chain -CAfile "$RootCA" -brief

curl.exe -Iv --resolve "${Domain}:443:127.0.0.1" "https://${Domain}/"

D:\Apache24\bin\httpd.exe -t
D:\Apache24\bin\httpd.exe -S
"@ | Set-Content $Capture -Encoding utf8

$GateLog = Join-Path $Logs "public_trust_tls_windows_gate_brief.log"
Remove-Item -Force $GateLog -ErrorAction SilentlyContinue

$GateCmd = 'echo Q| "' + $OpenSSL + '" s_client -connect 127.0.0.1:443 -servername "' + $Domain + '" -verify_hostname "' + $Domain + '" -verify_return_error -partial_chain -CAfile "' + $RootCA + '" -brief > "' + $GateLog + '" 2>&1'
cmd.exe /d /c $GateCmd | Out-Null

"`n==== Gate brief verification output ====" | Tee-Object -FilePath $SClientLog -Append
Get-Content $GateLog | Tee-Object -FilePath $SClientLog -Append

$gateText = Get-Content $GateLog -Raw

$verifyOk = $gateText -match "Verification:\s*OK"
$peerOk = $gateText -match "Verified peername:\s*$([regex]::Escape($Domain))" -or
          $gateText -match "Peer certificate:\s*CN=$([regex]::Escape($Domain))"

Write-Host "Gate verifyOk: $verifyOk"
Write-Host "Gate peerOk: $peerOk"

if (!$verifyOk) {
  Get-Content $GateLog
  throw "TLS verification gate failed."
}

if (!$peerOk) {
  Get-Content $GateLog
  throw "TLS peer-name gate failed."
}
"PUBLIC TRUST TLS WINDOWS CHECK PASS"
"Logs:"
$SClientLog
$CurlLog
$ApacheLog
$LeafInfo
"Artifacts:"
$ChainPem
$LeafPem
$RootCopy

