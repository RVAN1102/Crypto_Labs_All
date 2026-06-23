param(
    [string]$Exe = "lab5_signatures\build\sigtool.exe"
)

$ErrorActionPreference = "Continue"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Lab = Join-Path $Root "lab5_signatures"
$Work = Join-Path $Lab "artifacts\windows\manual"
$LogDir = Join-Path $Lab "artifacts\windows\logs"
New-Item -ItemType Directory -Force $Work, $LogDir | Out-Null

$exePath = Join-Path $Root $Exe
[System.IO.File]::WriteAllBytes((Join-Path $Work "msg.bin"), [byte[]](0,1,2,3,4,5,250,255))

& $exePath keygen --algo ecdsa-p256 --pub (Join-Path $Work "ecdsa_pub.pem") --priv (Join-Path $Work "ecdsa_priv.pem") --meta (Join-Path $Work "ecdsa_meta.json")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $exePath sign --algo ecdsa-p256 --priv (Join-Path $Work "ecdsa_priv.pem") --in (Join-Path $Work "msg.bin") --out (Join-Path $Work "ecdsa_sig.der") --hash sha256 --encode der
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $exePath verify --algo ecdsa-p256 --pub (Join-Path $Work "ecdsa_pub.pem") --in (Join-Path $Work "msg.bin") --sig (Join-Path $Work "ecdsa_sig.der") --hash sha256 --encode der
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $exePath keygen --algo rsa-pss-3072 --pub (Join-Path $Work "rsa_pub.pem") --priv (Join-Path $Work "rsa_priv.pem") --meta (Join-Path $Work "rsa_meta.json")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $exePath sign --algo rsa-pss-3072 --priv (Join-Path $Work "rsa_priv.pem") --in (Join-Path $Work "msg.bin") --out (Join-Path $Work "rsa_sig.bin") --hash sha256 --encode raw
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $exePath verify --algo rsa-pss-3072 --pub (Join-Path $Work "rsa_pub.pem") --in (Join-Path $Work "msg.bin") --sig (Join-Path $Work "rsa_sig.bin") --hash sha256 --encode raw
exit $LASTEXITCODE
