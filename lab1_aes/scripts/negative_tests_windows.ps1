param(
    [string]$Exe = ".\build\aestool.exe"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (!(Test-Path -LiteralPath $Exe)) {
    throw "Executable not found: $Exe"
}
$Exe = (Resolve-Path -LiteralPath $Exe).Path

$Work = Join-Path $Root "tmp_negative_tests"
if (Test-Path $Work) {
    Remove-Item $Work -Recurse -Force
}
New-Item -ItemType Directory -Path $Work | Out-Null

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
        $Output = & $Exe @ArgsArray 2>&1 | ForEach-Object {
            $_.ToString()
        }

        $Code = $LASTEXITCODE

        return @{
            Code = $Code
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
            Write-Fail $Name "expected failure, but command succeeded. output=$($R.Output)"
        }
    } catch {
        Write-Pass $Name
    }
}

function Read-Utf8($Path) {
    $Bytes = [IO.File]::ReadAllBytes($Path)
    return [Text.Encoding]::UTF8.GetString($Bytes)
}

function Assert-TextEquals($Name, $Path, $Expected) {
    try {
        $Actual = Read-Utf8 $Path

        if ($Actual -eq $Expected) {
            Write-Pass $Name
        } else {
            Write-Fail $Name "plaintext mismatch. actual='$Actual', expected='$Expected'"
        }
    } catch {
        Write-Fail $Name "exception: $($_.Exception.Message)"
    }
}

function Assert-TextNotEquals($Name, $Path, $Expected) {
    try {
        $Actual = Read-Utf8 $Path

        if ($Actual -ne $Expected) {
            Write-Pass $Name
        } else {
            Write-Fail $Name "expected corrupted plaintext, but plaintext is unchanged"
        }
    } catch {
        Write-Fail $Name "exception: $($_.Exception.Message)"
    }
}

function Expect-SuccessAndTextNotEquals($Name, $Path, $Expected, $ArgsArray) {
    try {
        $R = Run-Cmd $ArgsArray

        if ($R.Code -ne 0) {
            Write-Fail $Name "expected unauthenticated decrypt success, exit=$($R.Code), output=$($R.Output)"
            return
        }

        $Actual = Read-Utf8 $Path

        if ($Actual -ne $Expected) {
            Write-Pass $Name
        } else {
            Write-Fail $Name "expected corrupted plaintext, but plaintext is unchanged"
        }
    } catch {
        Write-Fail $Name "exception: $($_.Exception.Message)"
    }
}

function Invoke-Setup($ArgsArray) {
    $R = Run-Cmd $ArgsArray

    if ($R.Code -ne 0) {
        throw "Setup failed: $($ArgsArray -join ' '). Output=$($R.Output)"
    }
}

function Write-Bytes($Path, [byte[]]$Bytes) {
    [IO.File]::WriteAllBytes($Path, $Bytes)
}

function Tamper-FirstByte($InputPath, $OutputPath) {
    $B = [IO.File]::ReadAllBytes($InputPath)

    if ($B.Length -lt 1) {
        throw "Cannot tamper empty file: $InputPath"
    }

    $B[0] = $B[0] -bxor 1
    [IO.File]::WriteAllBytes($OutputPath, $B)
}

function Tamper-TagInMeta($InputMeta, $OutputMeta) {
    $Text = Get-Content $InputMeta -Raw

    if ($Text -notmatch '"tag_hex"\s*:\s*"([0-9a-fA-F]+)"') {
        throw "tag_hex not found in metadata"
    }

    $OldTag = $Matches[1]

    if ($OldTag[0] -eq '0') {
        $NewTag = '1' + $OldTag.Substring(1)
    } else {
        $NewTag = '0' + $OldTag.Substring(1)
    }

    $NewText = $Text -replace [regex]::Escape($OldTag), $NewTag
    Set-Content -Path $OutputMeta -Value $NewText -Encoding ASCII
}

Write-Host "Running negative tests with: $Exe"
Write-Host "Working directory: $Work"
Write-Host ""

$key = Join-Path $Work "key.bin"
$wrongKey = Join-Path $Work "wrong_key.bin"
$xtsKey = Join-Path $Work "xts_key.bin"
$badKey = Join-Path $Work "bad_key.bin"

Invoke-Setup @("keygen", "--bits", "512", "--out", $xtsKey, "--encode", "raw")

Expect-Success "Generate AES-256 key" @("keygen", "--bits", "256", "--out", $key, "--encode", "raw")
Expect-Success "Generate wrong AES-256 key" @("keygen", "--bits", "256", "--out", $wrongKey, "--encode", "raw")

Write-Bytes $badKey ([byte[]](1,2,3,4,5))

$gcmCt = Join-Path $Work "gcm_ct.bin"
$gcmPt = Join-Path $Work "gcm_pt.txt"
$gcmBadCt = Join-Path $Work "gcm_ct_tampered.bin"
$gcmBadTagMeta = Join-Path $Work "gcm_badtag.meta.json"
$gcmMalformedMeta = Join-Path $Work "gcm_malformed.meta.json"

$gcmText = "GCM negative testing message"

Expect-Success "GCM encrypt" @(
    "encrypt", "--mode", "gcm",
    "--key", $key,
    "--text", $gcmText,
    "--out", $gcmCt,
    "--aad-text", "aad-ok",
    "--nonce-registry", (Join-Path $Work "gcm_registry.jsonl")
)

Expect-Success "GCM decrypt" @(
    "decrypt", "--mode", "gcm",
    "--key", $key,
    "--in", $gcmCt,
    "--out", $gcmPt,
    "--aad-text", "aad-ok"
)

Assert-TextEquals "GCM recovered plaintext equals original" $gcmPt $gcmText

Expect-Fail "GCM wrong key rejected" @(
    "decrypt", "--mode", "gcm",
    "--key", $wrongKey,
    "--in", $gcmCt,
    "--out", (Join-Path $Work "gcm_wrongkey.txt"),
    "--aad-text", "aad-ok"
)

Expect-Fail "GCM wrong AAD rejected" @(
    "decrypt", "--mode", "gcm",
    "--key", $key,
    "--in", $gcmCt,
    "--out", (Join-Path $Work "gcm_wrongaad.txt"),
    "--aad-text", "aad-wrong"
)

Tamper-FirstByte $gcmCt $gcmBadCt
Copy-Item "$gcmCt.meta.json" "$gcmBadCt.meta.json" -Force

Expect-Fail "GCM tampered ciphertext rejected" @(
    "decrypt", "--mode", "gcm",
    "--key", $key,
    "--in", $gcmBadCt,
    "--out", (Join-Path $Work "gcm_tampered.txt"),
    "--aad-text", "aad-ok"
)

Tamper-TagInMeta "$gcmCt.meta.json" $gcmBadTagMeta

Expect-Fail "GCM tampered tag rejected" @(
    "decrypt", "--mode", "gcm",
    "--key", $key,
    "--in", $gcmCt,
    "--out", (Join-Path $Work "gcm_badtag.txt"),
    "--aad-text", "aad-ok",
    "--meta", $gcmBadTagMeta
)

$Malformed = (Get-Content "$gcmCt.meta.json" -Raw) -replace '"nonce_hex"\s*:\s*"[0-9a-fA-F]+",\s*', ''
Set-Content -Path $gcmMalformedMeta -Value $Malformed -Encoding ASCII

Expect-Fail "GCM malformed metadata rejected" @(
    "decrypt", "--mode", "gcm",
    "--key", $key,
    "--in", $gcmCt,
    "--out", (Join-Path $Work "gcm_malformed.txt"),
    "--aad-text", "aad-ok",
    "--meta", $gcmMalformedMeta
)

Expect-Fail "GCM invalid AES key length rejected" @(
    "encrypt", "--mode", "gcm",
    "--key", $badKey,
    "--text", "bad key",
    "--out", (Join-Path $Work "badkey_ct.bin")
)

Expect-Fail "GCM invalid GCM nonce length rejected" @(
    "encrypt", "--mode", "gcm",
    "--key", $key,
    "--nonce-hex", "001122",
    "--text", "bad nonce",
    "--out", (Join-Path $Work "badnonce_ct.bin")
)

$reuseRegistry = Join-Path $Work "reuse_registry.jsonl"

Expect-Success "GCM first fixed nonce accepted" @(
    "encrypt", "--mode", "gcm",
    "--key", $key,
    "--nonce-hex", "00112233445566778899aabb",
    "--text", "first",
    "--out", (Join-Path $Work "reuse1.bin"),
    "--nonce-registry", $reuseRegistry
)

Expect-Fail "GCM second fixed nonce rejected" @(
    "encrypt", "--mode", "gcm",
    "--key", $key,
    "--nonce-hex", "00112233445566778899aabb",
    "--text", "second",
    "--out", (Join-Path $Work "reuse2.bin"),
    "--nonce-registry", $reuseRegistry
)

$ccmCt = Join-Path $Work "ccm_ct.bin"
$ccmBadCt = Join-Path $Work "ccm_ct_tampered.bin"
$ccmPt = Join-Path $Work "ccm_pt.txt"
$ccmText = "CCM negative testing message"

Expect-Success "CCM encrypt" @(
    "encrypt", "--mode", "ccm",
    "--key", $key,
    "--text", $ccmText,
    "--out", $ccmCt,
    "--aad-text", "ccm-aad",
    "--nonce-registry", (Join-Path $Work "ccm_registry.jsonl")
)

Expect-Success "CCM decrypt baseline" @(
    "decrypt", "--mode", "ccm",
    "--key", $key,
    "--in", $ccmCt,
    "--out", $ccmPt,
    "--aad-text", "ccm-aad"
)

Assert-TextEquals "CCM recovered plaintext equals original" $ccmPt $ccmText

Tamper-FirstByte $ccmCt $ccmBadCt
Copy-Item "$ccmCt.meta.json" "$ccmBadCt.meta.json" -Force

Expect-Fail "CCM tampered ciphertext rejected" @(
    "decrypt", "--mode", "ccm",
    "--key", $key,
    "--in", $ccmBadCt,
    "--out", (Join-Path $Work "ccm_tampered.txt"),
    "--aad-text", "ccm-aad"
)

$ctrCt = Join-Path $Work "ctr_ct.bin"
$ctrBadCt = Join-Path $Work "ctr_ct_tampered.bin"
$ctrBadPt = Join-Path $Work "ctr_tampered.txt"
$ctrText = "CTR mode has no authentication, so tampering corrupts plaintext."

Expect-Success "CTR encrypt" @(
    "encrypt", "--mode", "ctr",
    "--key", $key,
    "--iv-hex", "00112233445566778899aabbccddeeff",
    "--text", $ctrText,
    "--out", $ctrCt,
    "--nonce-registry", (Join-Path $Work "ctr_registry_a.jsonl")
)

Tamper-FirstByte $ctrCt $ctrBadCt
Copy-Item "$ctrCt.meta.json" "$ctrBadCt.meta.json" -Force

Expect-Success "CTR decrypt baseline" @(
    "decrypt", "--mode", "ctr",
    "--key", $key,
    "--in", $ctrCt,
    "--out", (Join-Path $Work "ctr_pt.txt")
)

Assert-TextEquals "CTR recovered plaintext equals original" (Join-Path $Work "ctr_pt.txt") $ctrText

Invoke-Setup @(
    "decrypt", "--mode", "ctr",
    "--key", $key,
    "--in", $ctrBadCt,
    "--out", $ctrBadPt
)

Assert-TextNotEquals "CTR tampering produces corrupted plaintext" $ctrBadPt $ctrText

$ctrReuseRegistry = Join-Path $Work "ctr_reuse_registry.jsonl"

Expect-Success "CTR first IV accepted" @(
    "encrypt", "--mode", "ctr",
    "--key", $key,
    "--iv-hex", "11112222333344445555666677778888",
    "--text", "first ctr",
    "--out", (Join-Path $Work "ctr_reuse1.bin"),
    "--nonce-registry", $ctrReuseRegistry
)

Expect-Fail "CTR reused IV rejected" @(
    "encrypt", "--mode", "ctr",
    "--key", $key,
    "--iv-hex", "11112222333344445555666677778888",
    "--text", "second ctr",
    "--out", (Join-Path $Work "ctr_reuse2.bin"),
    "--nonce-registry", $ctrReuseRegistry
)

$bigFile = Join-Path $Work "big_plain.bin"
$bigBytes = New-Object byte[] 20000
for ($i = 0; $i -lt $bigBytes.Length; $i++) {
    $bigBytes[$i] = 65
}
[IO.File]::WriteAllBytes($bigFile, $bigBytes)

Expect-Fail "ECB large file blocked by default" @(
    "encrypt", "--mode", "ecb",
    "--key", $key,
    "--in", $bigFile,
    "--out", (Join-Path $Work "big_ecb.bin")
)

Expect-Success "ECB large file allowed with allow flag" @(
    "encrypt", "--mode", "ecb",
    "--key", $key,
    "--in", $bigFile,
    "--out", (Join-Path $Work "big_ecb_allowed.bin"),
    "--allow-ecb"
)

Expect-Fail "XTS short input rejected" @(
    "encrypt", "--mode", "xts",
    "--key", $xtsKey,
    "--text", "short",
    "--out", (Join-Path $Work "short_xts.bin")
)

$xtsCt = Join-Path $Work "xts_ct.bin"
$xtsBadCt = Join-Path $Work "xts_ct_tampered.bin"
$xtsBadPt = Join-Path $Work "xts_tampered.txt"
$xtsText = "This is a valid AES-XTS data unit for negative testing."

Expect-Success "XTS encrypt valid data unit" @(
    "encrypt", "--mode", "xts",
    "--key", $xtsKey,
    "--text", $xtsText,
    "--out", $xtsCt
)

Tamper-FirstByte $xtsCt $xtsBadCt
Copy-Item "$xtsCt.meta.json" "$xtsBadCt.meta.json" -Force

Expect-SuccessAndTextNotEquals "XTS tampering produces corrupted plaintext without authentication" $xtsBadPt $xtsText @(
    "decrypt", "--mode", "xts",
    "--key", $xtsKey,
    "--in", $xtsBadCt,
    "--out", $xtsBadPt
)

Write-Host ""
Write-Host "Windows negative test summary: pass=$Pass fail=$Fail total=$($Pass + $Fail)"

if ($Fail -ne 0) {
    exit 1
}

exit 0
