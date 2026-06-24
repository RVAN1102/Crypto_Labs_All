param(
    [Parameter(Mandatory = $true)]
    [string]$Exe
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Work = Join-Path $Root "artifacts\windows\negative"
New-Item -ItemType Directory -Force $Work | Out-Null

function Run-Ok {
    param([string[]]$ToolArgs)
    & $Exe @ToolArgs
    if ($LASTEXITCODE -ne 0) {
        throw "expected success: $Exe $($ToolArgs -join ' ')"
    }
}

function Run-Fail {
    param([string[]]$ToolArgs)
    & $Exe @ToolArgs
    if ($LASTEXITCODE -eq 0) {
        throw "expected failure: $Exe $($ToolArgs -join ' ')"
    }
}

function Write-Bytes {
    param([string]$Path, [byte[]]$Bytes)
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
}

Write-Bytes (Join-Path $Work "msg.bin") ([byte[]](0x6c,0x61,0x62,0x35,0x00,0x6d,0x73,0x67))
Write-Bytes (Join-Path $Work "msg_tampered.bin") ([byte[]](0x6c,0x61,0x62,0x35,0x01,0x6d,0x73,0x67))
Set-Content -Path (Join-Path $Work "malformed.pem") -Value "not a key" -Encoding ascii
Set-Content -Path (Join-Path $Work "malformed.sig") -Value "not a signature" -Encoding ascii

$msg = Join-Path $Work "msg.bin"
$badMsg = Join-Path $Work "msg_tampered.bin"
$badKey = Join-Path $Work "malformed.pem"
$badSig = Join-Path $Work "malformed.sig"

foreach ($algo in @("ecdsa-p256", "rsa-pss-3072")) {
    $prefix = if ($algo -eq "ecdsa-p256") { "ecdsa" } else { "rsa" }
    $enc = if ($algo -eq "ecdsa-p256") { "der" } else { "raw" }
    $priv = Join-Path $Work "$prefix.priv.pem"
    $pub = Join-Path $Work "$prefix.pub.pem"
    $wrongPriv = Join-Path $Work "$prefix.wrong.priv.pem"
    $wrongPub = Join-Path $Work "$prefix.wrong.pub.pem"
    $sig = Join-Path $Work "$prefix.sig"
    $sigBad = Join-Path $Work "$prefix.sig.bad"

    Run-Ok @("keygen", "--algo", $algo, "--priv", $priv, "--pub", $pub, "--meta", (Join-Path $Work "$prefix.meta.json"))
    Run-Ok @("keygen", "--algo", $algo, "--priv", $wrongPriv, "--pub", $wrongPub)
    Run-Ok @("sign", "--algo", $algo, "--priv", $priv, "--in", $msg, "--out", $sig, "--hash", "sha256", "--encode", $enc)
    Run-Ok @("verify", "--algo", $algo, "--pub", $pub, "--in", $msg, "--sig", $sig, "--hash", "sha256", "--encode", $enc)

    Copy-Item $sig $sigBad -Force
    $bytes = [System.IO.File]::ReadAllBytes($sigBad)
    $bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -bxor 0x01
    [System.IO.File]::WriteAllBytes($sigBad, $bytes)

    Run-Fail @("verify", "--algo", $algo, "--pub", $pub, "--in", $badMsg, "--sig", $sig, "--hash", "sha256", "--encode", $enc)
    Run-Fail @("verify", "--algo", $algo, "--pub", $pub, "--in", $msg, "--sig", $sigBad, "--hash", "sha256", "--encode", $enc)
    Run-Fail @("verify", "--algo", $algo, "--pub", $wrongPub, "--in", $msg, "--sig", $sig, "--hash", "sha256", "--encode", $enc)
    Run-Fail @("verify", "--algo", $(if ($algo -eq "ecdsa-p256") { "rsa-pss-3072" } else { "ecdsa-p256" }), "--pub", $pub, "--in", $msg, "--sig", $sig, "--hash", "sha256", "--encode", $enc)
    Run-Fail @("verify", "--algo", $algo, "--pub", $pub, "--in", $msg, "--sig", $sig, "--hash", "sha512", "--encode", $enc)
    Run-Fail @("sign", "--algo", $algo, "--priv", $badKey, "--in", $msg, "--out", (Join-Path $Work "$prefix.badkey.sig"), "--hash", "sha256", "--encode", $enc)
    Run-Fail @("verify", "--algo", $algo, "--pub", $pub, "--in", $msg, "--sig", $badSig, "--hash", "sha256", "--encode", $enc)
}

$b64 = Join-Path $Work "ecdsa.b64"
Run-Ok @("sign", "--algo", "ecdsa-p256", "--priv", (Join-Path $Work "ecdsa.priv.pem"), "--in", $msg, "--out", $b64, "--hash", "sha256", "--encode", "base64")
Run-Ok @("verify", "--algo", "ecdsa-p256", "--pub", (Join-Path $Work "ecdsa.pub.pem"), "--in", $msg, "--sig", $b64, "--hash", "sha256", "--encode", "base64")

$manifest = Join-Path $Work "batch_manifest.csv"
$sig2 = Join-Path $Work "ecdsa2.sig"
Run-Ok @("sign", "--algo", "ecdsa-p256", "--priv", (Join-Path $Work "ecdsa.priv.pem"), "--in", $msg, "--out", $sig2, "--hash", "sha256", "--encode", "der")
Set-Content -Path $manifest -Value "$msg,$sig2" -Encoding ascii
Run-Ok @("batch-verify", "--algo", "ecdsa-p256", "--pub", (Join-Path $Work "ecdsa.pub.pem"), "--manifest", $manifest, "--hash", "sha256", "--encode", "der")

Write-Host "negative tests passed"
