param(
    [string]$Exe = ".\build\hashtool.exe"
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

Write-Host "Running Lab 4 negative tests with: $Exe"
Write-Host "Working directory: $Work"
Write-Host ""

if (!(Test-Path $Exe)) {
    throw "Executable not found: $Exe"
}

$inputFile = Join-Path $Work "input.bin"
[IO.File]::WriteAllBytes($inputFile, [Text.Encoding]::UTF8.GetBytes("abc"))

Expect-Fail "unsupported algorithm rejected" @("hash", "--algo", "md5", "--text", "abc")
Expect-Fail "SHAKE without outlen rejected" @("hash", "--algo", "shake256", "--text", "abc")
Expect-Fail "fixed hash with outlen rejected" @("hash", "--algo", "sha256", "--outlen", "64", "--text", "abc")
Expect-Fail "missing input rejected" @("hash", "--algo", "sha256")
Expect-Fail "both in and text rejected" @("hash", "--algo", "sha256", "--in", $inputFile, "--text", "abc")
Expect-Fail "invalid encoding rejected" @("hash", "--algo", "sha256", "--text", "abc", "--encode", "base32")
Expect-Fail "file not found rejected" @("hash", "--algo", "sha256", "--in", (Join-Path $Work "missing.bin"))
Expect-Fail "wrong HMAC fails verification" @("hmac-verify", "--algo", "sha256", "--key-hex", "001122", "--text", "hello", "--mac-hex", "00")
Expect-Fail "malformed key hex rejected" @("hmac", "--algo", "sha256", "--key-hex", "00112", "--text", "hello")

Expect-Success "valid hash still works" @("hash", "--algo", "sha256", "--text", "abc")

$certDir = Join-Path $Root "tests\certs"
$leafValid = Join-Path $certDir "leaf_valid.pem"
$testCa = Join-Path $certDir "test_ca.pem"
$wrongCa = Join-Path $certDir "wrong_ca.pem"
$malformedCert = Join-Path $certDir "malformed_cert.pem"
$leafNoSan = Join-Path $certDir "leaf_no_san.pem"
$expiredLeaf = Join-Path $certDir "expired_leaf.pem"

Expect-Fail "malformed certificate rejected" @("cert-info", "--cert", $malformedCert)
Expect-Fail "wrong issuer fails certificate verification" @("cert-verify", "--cert", $leafValid, "--issuer", $wrongCa)
Expect-Success "correct issuer verifies certificate" @("cert-verify", "--cert", $leafValid, "--issuer", $testCa)

$NoSanPolicy = Run-Cmd @("cert-policy", "--cert", $leafNoSan)
if ($NoSanPolicy.Code -eq 0 -and $NoSanPolicy.Output -like "*CHECK tls_server_san FAIL*") {
    Write-Pass "missing SAN flagged"
} else {
    Write-Fail "missing SAN flagged" "exit=$($NoSanPolicy.Code), output=$($NoSanPolicy.Output)"
}

if (Test-Path $expiredLeaf) {
    $ExpiredPolicy = Run-Cmd @("cert-policy", "--cert", $expiredLeaf)
    if ($ExpiredPolicy.Code -eq 0 -and $ExpiredPolicy.Output -like "*CHECK validity_not_after FAIL*") {
        Write-Pass "expired certificate flagged"
    } else {
        Write-Fail "expired certificate flagged" "exit=$($ExpiredPolicy.Code), output=$($ExpiredPolicy.Output)"
    }
}

$benchRaw = Join-Path $Work "bench_raw.csv"
$benchSummary = Join-Path $Work "bench_summary.csv"
Expect-Fail "unsupported benchmark algorithm rejected" @("bench", "--out", $benchRaw, "--summary", $benchSummary, "--runs", "1", "--ops", "1", "--warmup-ms", "0", "--sizes", "1m", "--algos", "sha256,md5", "--platform", "windows11-mingw64")
Expect-Fail "invalid benchmark size rejected" @("bench", "--out", $benchRaw, "--summary", $benchSummary, "--runs", "1", "--ops", "1", "--warmup-ms", "0", "--sizes", "2m", "--algos", "sha256", "--platform", "windows11-mingw64")
Expect-Fail "missing benchmark output rejected" @("bench", "--summary", $benchSummary, "--runs", "1", "--ops", "1", "--warmup-ms", "0", "--sizes", "1m", "--algos", "sha256", "--platform", "windows11-mingw64")

Write-Host ""
Write-Host "Negative test summary: pass=$Pass fail=$Fail"

if ($Fail -ne 0) {
    exit 1
}

exit 0
