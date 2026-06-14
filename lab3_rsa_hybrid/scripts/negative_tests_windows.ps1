param(
    [string]$Exe = ".\build\rsatool.exe"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Stamp = Get-Date -Format "yyyyMMdd_HHmmss_ffff"
$Work = Join-Path $Root "tmp_negative_tests\$Stamp"
New-Item -ItemType Directory -Force -Path $Work | Out-Null

$Pass = 0
$Fail = 0

function Write-Pass($Name) {
    Write-Host "[PASS] $Name" -ForegroundColor Green
    $script:Pass++
}

function Write-Fail($Name, $Reason) {
    Write-Host "[FAIL] $Name :: $Reason" -ForegroundColor Red
    $script:Fail++
}

function Run-Cmd($ArgsArray) {
    $OldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $Output = & $Exe @ArgsArray 2>&1 | ForEach-Object { $_.ToString() }
        return @{
            Code = $LASTEXITCODE
            Output = ($Output -join "`n")
        }
    } finally {
        $ErrorActionPreference = $OldErrorActionPreference
    }
}

function Expect-Success($Name, $ArgsArray) {
    try {
        $R = Run-Cmd $ArgsArray
        if ($R.Code -eq 0) {
            Write-Pass $Name
        } else {
            Write-Fail $Name "expected success, exit=$($R.Code), output=$($R.Output)"
        }
    } catch {
        Write-Fail $Name "exception: $($_.Exception.Message)"
    }
}

function Expect-Fail($Name, $ArgsArray) {
    try {
        $R = Run-Cmd $ArgsArray
        if ($R.Code -ne 0) {
            Write-Pass $Name
        } else {
            Write-Fail $Name "expected failure, command succeeded"
        }
    } catch {
        Write-Pass $Name
    }
}

function Write-Bytes($Path, [byte[]]$Bytes) {
    [IO.File]::WriteAllBytes($Path, $Bytes)
}

function Tamper-FirstByte($InputPath, $OutputPath) {
    $B = [IO.File]::ReadAllBytes($InputPath)
    if ($B.Length -lt 1) { throw "Cannot tamper empty file" }
    $B[0] = $B[0] -bxor 1
    [IO.File]::WriteAllBytes($OutputPath, $B)
}

function Tamper-EnvelopeHexField($InputPath, $OutputPath, $Field) {
    $Text = Get-Content $InputPath -Raw
    $Pattern = '"' + $Field + '"\s*:\s*"([0-9a-fA-F]+)"'
    if ($Text -notmatch $Pattern) {
        throw "Field not found: $Field"
    }
    $Old = $Matches[1]
    if ($Old[0] -eq '0') { $New = '1' + $Old.Substring(1) } else { $New = '0' + $Old.Substring(1) }
    $Out = $Text -replace [regex]::Escape($Old), $New
    Set-Content -Path $OutputPath -Value $Out -Encoding ASCII
}

function Assert-BytesEqual($Name, $A, $B) {
    $BA = [IO.File]::ReadAllBytes($A)
    $BB = [IO.File]::ReadAllBytes($B)
    if ($BA.Length -ne $BB.Length) {
        Write-Fail $Name "length mismatch"
        return
    }
    for ($i = 0; $i -lt $BA.Length; $i++) {
        if ($BA[$i] -ne $BB[$i]) {
            Write-Fail $Name "byte mismatch at $i"
            return
        }
    }
    Write-Pass $Name
}

Write-Host "Running Lab 3 negative tests with: $Exe"
Write-Host "Working directory: $Work"
Write-Host ""

if (!(Test-Path $Exe)) {
    throw "Executable not found: $Exe"
}

$priv = Join-Path $Work "private.der"
$pub = Join-Path $Work "public.der"
$wrongPriv = Join-Path $Work "wrong_private.der"
$wrongPub = Join-Path $Work "wrong_public.der"
$pemPriv = Join-Path $Work "private.pem"
$pemPub = Join-Path $Work "public.pem"
$pemMeta = Join-Path $Work "key_metadata.json"
$badPemPub = Join-Path $Work "bad_public.pem"
$pt = Join-Path $Work "plain.bin"
$rsaCt = Join-Path $Work "direct.rsa"
$rsaOut = Join-Path $Work "direct.out"
$pemRsaCt = Join-Path $Work "direct_pem.rsa"
$pemRsaOut = Join-Path $Work "direct_pem.out"
$ct = Join-Path $Work "hybrid.ct"
$env = Join-Path $Work "hybrid.env.json"
$out = Join-Path $Work "hybrid.out"
$pemCt = Join-Path $Work "hybrid_pem.ct"
$pemEnv = Join-Path $Work "hybrid_pem.env.json"
$pemOut = Join-Path $Work "hybrid_pem.out"
$autoSmallCt = Join-Path $Work "auto_small.ct"
$autoSmallOut = Join-Path $Work "auto_small.out"
$autoLargeCt = Join-Path $Work "auto_large.ct"
$autoLargeOut = Join-Path $Work "auto_large.out"
$autoLargeMalformedEnv = Join-Path $Work "auto_large_malformed.env.json"

Write-Bytes $pt ([Text.Encoding]::UTF8.GetBytes("Lab 3 negative tests plaintext"))

Expect-Success "keygen RSA-3072" @("keygen", "--bits", "3072", "--private", $priv, "--public", $pub)
Expect-Success "keygen wrong RSA-3072" @("keygen", "--bits", "3072", "--private", $wrongPriv, "--public", $wrongPub)
Expect-Success "keygen RSA-3072 PEM aliases with metadata" @("keygen", "--bits", "3072", "--priv", $pemPriv, "--pub", $pemPub, "--meta", $pemMeta)
Expect-Fail "keygen RSA-2048 rejected" @("keygen", "--bits", "2048", "--private", (Join-Path $Work "bad.der"), "--public", (Join-Path $Work "badpub.der"))

if ((Test-Path $pemMeta) -and ((Get-Content $pemMeta -Raw) -match '"mgf"\s*:\s*"MGF1-SHA256"')) {
    Write-Pass "key metadata records MGF1-SHA256"
} else {
    Write-Fail "key metadata records MGF1-SHA256" "metadata missing or malformed"
}

Expect-Success "OAEP encrypt baseline" @("oaep-encrypt", "--pub", $pub, "--in", $pt, "--out", $rsaCt, "--label-text", "right")
Expect-Success "OAEP decrypt baseline" @("oaep-decrypt", "--priv", $priv, "--in", $rsaCt, "--out", $rsaOut, "--label-text", "right")
Assert-BytesEqual "OAEP plaintext recovered" $pt $rsaOut
Expect-Fail "OAEP wrong label rejected" @("oaep-decrypt", "--priv", $priv, "--in", $rsaCt, "--out", (Join-Path $Work "wrong_label.out"), "--label-text", "wrong")
Expect-Fail "OAEP wrong private key rejected" @("oaep-decrypt", "--priv", $wrongPriv, "--in", $rsaCt, "--out", (Join-Path $Work "wrong_key.out"), "--label-text", "right")

Expect-Success "OAEP PEM encrypt baseline" @("oaep-encrypt", "--pub", $pemPub, "--in", $pt, "--out", $pemRsaCt, "--label-text", "pem")
Expect-Success "OAEP PEM decrypt baseline" @("oaep-decrypt", "--priv", $pemPriv, "--in", $pemRsaCt, "--out", $pemRsaOut, "--label-text", "pem")
Assert-BytesEqual "OAEP PEM plaintext recovered" $pt $pemRsaOut

Set-Content -Path $badPemPub -Value "-----BEGIN RSA PUBLIC KEY-----`nnot-valid-base64`n-----END RSA PUBLIC KEY-----`n" -Encoding ASCII
Expect-Fail "corrupted PEM public key rejected" @("oaep-encrypt", "--pub", $badPemPub, "--in", $pt, "--out", (Join-Path $Work "bad_pem.rsa"))

$tooLarge = Join-Path $Work "too_large.bin"
Write-Bytes $tooLarge ([byte[]](0..255 + 0..62))
Expect-Fail "OAEP oversized plaintext rejected" @("oaep-encrypt", "--pub", $pub, "--in", $tooLarge, "--out", (Join-Path $Work "too_large.rsa"))

Expect-Success "hybrid encrypt baseline" @("seal", "--pub", $pub, "--in", $pt, "--out", $ct, "--envelope", $env, "--label-text", "right")
Expect-Success "hybrid decrypt baseline" @("open", "--priv", $priv, "--in", $ct, "--envelope", $env, "--out", $out, "--label-text", "right")
Assert-BytesEqual "hybrid plaintext recovered" $pt $out

Expect-Success "hybrid PEM encrypt baseline" @("hybrid-encrypt", "--pub", $pemPub, "--in", $pt, "--out", $pemCt, "--envelope", $pemEnv, "--label-text", "pem")
Expect-Success "hybrid PEM decrypt baseline" @("hybrid-decrypt", "--priv", $pemPriv, "--in", $pemCt, "--envelope", $pemEnv, "--out", $pemOut, "--label-text", "pem")
Assert-BytesEqual "hybrid PEM plaintext recovered" $pt $pemOut

Expect-Fail "hybrid wrong label rejected" @("open", "--priv", $priv, "--in", $ct, "--envelope", $env, "--out", (Join-Path $Work "hybrid_wrong_label.out"), "--label-text", "wrong")
Expect-Fail "hybrid wrong private key rejected" @("open", "--priv", $wrongPriv, "--in", $ct, "--envelope", $env, "--out", (Join-Path $Work "hybrid_wrong_key.out"), "--label-text", "right")

$badCt = Join-Path $Work "hybrid_tampered.ct"
Tamper-FirstByte $ct $badCt
Expect-Fail "hybrid tampered ciphertext rejected" @("open", "--priv", $priv, "--in", $badCt, "--envelope", $env, "--out", (Join-Path $Work "tampered_ct.out"), "--label-text", "right")

$badTagEnv = Join-Path $Work "bad_tag.env.json"
Tamper-EnvelopeHexField $env $badTagEnv "tag_hex"
Expect-Fail "hybrid tampered GCM tag rejected" @("open", "--priv", $priv, "--in", $ct, "--envelope", $badTagEnv, "--out", (Join-Path $Work "bad_tag.out"), "--label-text", "right")

$badKeyEnv = Join-Path $Work "bad_key.env.json"
Tamper-EnvelopeHexField $env $badKeyEnv "encrypted_key_hex"
Expect-Fail "hybrid tampered encrypted AES key rejected" @("open", "--priv", $priv, "--in", $ct, "--envelope", $badKeyEnv, "--out", (Join-Path $Work "bad_key.out"), "--label-text", "right")

$malformedEnv = Join-Path $Work "malformed.env.json"
(Get-Content $env -Raw) -replace '"nonce_hex"\s*:\s*"[0-9a-fA-F]+",\s*', '' | Set-Content -Path $malformedEnv -Encoding ASCII
Expect-Fail "hybrid malformed envelope rejected" @("open", "--priv", $priv, "--in", $ct, "--envelope", $malformedEnv, "--out", (Join-Path $Work "malformed.out"), "--label-text", "right")

$versionEnv = Join-Path $Work "bad_version.env.json"
(Get-Content $env -Raw) -replace '"version"\s*:\s*1', '"version": 99' | Set-Content -Path $versionEnv -Encoding ASCII
Expect-Fail "hybrid unsupported version rejected" @("open", "--priv", $priv, "--in", $ct, "--envelope", $versionEnv, "--out", (Join-Path $Work "bad_version.out"), "--label-text", "right")

$algEnv = Join-Path $Work "bad_alg.env.json"
(Get-Content $env -Raw) -replace 'AES-256-GCM', 'AES-128-GCM' | Set-Content -Path $algEnv -Encoding ASCII
Expect-Fail "hybrid algorithm mismatch rejected" @("open", "--priv", $priv, "--in", $ct, "--envelope", $algEnv, "--out", (Join-Path $Work "bad_alg.out"), "--label-text", "right")

$labelIndicatorEnv = Join-Path $Work "bad_label_indicator.env.json"
(Get-Content $env -Raw) -replace '"oaep_label_present"\s*:\s*true', '"oaep_label_present": false' | Set-Content -Path $labelIndicatorEnv -Encoding ASCII
Expect-Fail "hybrid label indicator mismatch rejected" @("open", "--priv", $priv, "--in", $ct, "--envelope", $labelIndicatorEnv, "--out", (Join-Path $Work "bad_label_indicator.out"), "--label-text", "right")

$smallPlain = Join-Path $Work "auto_small_plain.bin"
Write-Bytes $smallPlain ([Text.Encoding]::UTF8.GetBytes("small assignment-compatible message"))
Expect-Success "auto encrypt small uses OAEP" @("encrypt", "--pub", $pub, "--in", $smallPlain, "--out", $autoSmallCt, "--label-text", "auto")
if (([IO.File]::ReadAllBytes($autoSmallCt)).Length -eq 384 -and !(Test-Path "$autoSmallCt.envelope.json")) {
    Write-Pass "auto small output is direct RSA ciphertext"
} else {
    Write-Fail "auto small output is direct RSA ciphertext" "unexpected length or envelope sidecar"
}
Expect-Success "auto decrypt small OAEP" @("decrypt", "--priv", $priv, "--in", $autoSmallCt, "--out", $autoSmallOut, "--label-text", "auto")
Assert-BytesEqual "auto small plaintext recovered" $smallPlain $autoSmallOut
Expect-Fail "auto decrypt wrong label rejected" @("decrypt", "--priv", $priv, "--in", $autoSmallCt, "--out", (Join-Path $Work "auto_wrong_label.out"), "--label-text", "wrong")

Expect-Success "auto encrypt large switches to hybrid" @("encrypt", "--pub", $pub, "--in", $tooLarge, "--out", $autoLargeCt, "--label-text", "auto")
if (Test-Path "$autoLargeCt.envelope.json") {
    Write-Pass "auto large envelope sidecar created"
} else {
    Write-Fail "auto large envelope sidecar created" "missing default envelope"
}
Expect-Success "auto decrypt large discovers envelope" @("decrypt", "--priv", $priv, "--in", $autoLargeCt, "--out", $autoLargeOut, "--label-text", "auto")
Assert-BytesEqual "auto large plaintext recovered" $tooLarge $autoLargeOut
(Get-Content "$autoLargeCt.envelope.json" -Raw) -replace '"tag_hex"\s*:\s*"[0-9a-fA-F]+"', '"tag_hex": "00"' | Set-Content -Path $autoLargeMalformedEnv -Encoding ASCII
Expect-Fail "auto decrypt malformed envelope rejected" @("decrypt", "--priv", $priv, "--in", $autoLargeCt, "--envelope", $autoLargeMalformedEnv, "--out", (Join-Path $Work "auto_malformed.out"), "--label-text", "auto")

Write-Host ""
Write-Host "Negative test summary: pass=$Pass fail=$Fail"

if ($Fail -ne 0) {
    exit 1
}

exit 0
