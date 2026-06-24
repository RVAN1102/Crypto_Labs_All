param(
    [switch]$Run1G = $false
)

$ErrorActionPreference = "Stop"

$Repo = "D:\Newfolder\Crypto_Labs_All"
$Lab = Join-Path $Repo "lab4_hash_pki"
$Build = Join-Path $Lab "build"
$Logs = Join-Path $Lab "artifacts\windows\logs"
$Bench = Join-Path $Lab "artifacts\windows\bench"
$Bin = Join-Path $Lab "artifacts\windows\binaries"
$Report = Join-Path $Lab "report"
$Exe = Join-Path $Build "hashtool.exe"

New-Item -ItemType Directory -Force $Logs, $Bench, $Bin, $Report | Out-Null

function Run-Step {
    param(
        [string]$Name,
        [scriptblock]$Block,
        [string]$LogPath
    )

    Write-Host "==== $Name ===="
    $global:LASTEXITCODE = 0

    try {
        $output = & $Block 2>&1
        $code = $global:LASTEXITCODE
        $output | Set-Content -Encoding UTF8 $LogPath

        if ($null -ne $code -and $code -ne 0) {
            throw "$Name failed with exit code $code"
        }

        Write-Host "[PASS] $Name"
    } catch {
        $_ | Out-String | Add-Content -Encoding UTF8 $LogPath
        Write-Host "[FAIL] $Name"
        Write-Host "Log: $LogPath"
        throw
    }
}

function Require-Text {
    param(
        [string]$Path,
        [string]$Pattern,
        [string]$Message
    )

    $text = Get-Content $Path -Raw
    if ($text -notmatch $Pattern) {
        throw "$Message. File: $Path"
    }
}

Set-Location $Repo

$branch = git branch --show-current
if ($branch -ne "master") {
    throw "Wrong branch: $branch. Expected master."
}

git status -sb | Set-Content -Encoding UTF8 (Join-Path $Logs "git_status_before_windows_final.log")

Remove-Item -Recurse -Force $Build -ErrorAction SilentlyContinue

Run-Step "configure_windows" {
    $args = @(
        "-S", $Lab,
        "-B", $Build,
        "-G", "MinGW Makefiles",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_PREFIX_PATH=C:/msys64/mingw64",
        "-DOPENSSL_ROOT_DIR=C:/msys64/mingw64",
        "-DOPENSSL_INCLUDE_DIR=C:/msys64/mingw64/include",
        "-DOPENSSL_CRYPTO_LIBRARY=C:/msys64/mingw64/lib/libcrypto.dll.a",
        "-DOPENSSL_SSL_LIBRARY=C:/msys64/mingw64/lib/libssl.dll.a"
    )
    cmake @args
} (Join-Path $Logs "configure_windows_final.log")

Run-Step "build_windows" {
    cmake --build $Build -j12
} (Join-Path $Logs "build_windows_final.log")

Run-Step "help_windows" {
    & $Exe --help
} (Join-Path $Logs "help_windows_final.log")

Run-Step "ctest_windows" {
    ctest --test-dir $Build --output-on-failure
} (Join-Path $Logs "ctest_windows_final.log")

Require-Text (Join-Path $Logs "ctest_windows_final.log") "100% tests passed, 0 tests failed out of 17" "CTest did not pass 17/17"

Run-Step "negative_tests_windows" {
    powershell -NoProfile -ExecutionPolicy Bypass -File "$Lab\scripts\negative_tests_windows.ps1" -Exe $Exe
} (Join-Path $Logs "negative_tests_windows_final.log")

Require-Text (Join-Path $Logs "negative_tests_windows_final.log") "fail=0" "Negative tests did not report fail=0"

Run-Step "kat_hash_windows" {
    & $Exe kat --kat "$Lab\vectors\hash_kat.json"
} (Join-Path $Logs "kat_hash_windows_final.log")

Require-Text (Join-Path $Logs "kat_hash_windows_final.log") "KAT summary: pass=16 fail=0 total=16" "Hash KAT did not pass 16/16"

Run-Step "kat_shake_windows" {
    & $Exe kat --kat "$Lab\vectors\shake_kat.json"
} (Join-Path $Logs "kat_shake_windows_final.log")

Require-Text (Join-Path $Logs "kat_shake_windows_final.log") "KAT summary: pass=4 fail=0 total=4" "SHAKE KAT did not pass 4/4"

Run-Step "hash_suite_windows" {
    & $Exe hash --algo sha224 --text abc
    & $Exe hash --algo sha256 --text abc
    & $Exe hash --algo sha384 --text abc
    & $Exe hash --algo sha512 --text abc
    & $Exe hash --algo sha3-224 --text abc
    & $Exe hash --algo sha3-256 --text abc
    & $Exe hash --algo sha3-384 --text abc
    & $Exe hash --algo sha3-512 --text abc
    & $Exe hash --algo shake128 --outlen 64 --text abc
    & $Exe hash --algo shake256 --outlen 64 --text abc
} (Join-Path $Logs "hash_suite_windows_final.log")

Run-Step "pki_x509_windows" {
    & $Exe cert-info --cert "$Lab\tests\certs\leaf_valid.pem"
    & $Exe cert-info --cert "$Lab\tests\certs\leaf_valid.der" --format der
    & $Exe cert-verify --cert "$Lab\tests\certs\leaf_valid.pem" --issuer "$Lab\tests\certs\test_ca.pem"
    & $Exe cert-policy --cert "$Lab\tests\certs\leaf_no_san.pem"
    & $Exe cert-policy --cert "$Lab\tests\certs\leaf_weak.pem"
    & $Exe cert-policy --cert "$Lab\tests\certs\expired_leaf.pem"
} (Join-Path $Logs "pki_x509_windows_final.log")

Run-Step "pki_wrong_issuer_windows_expected_fail" {
    $oldEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $wrongIssuerOutput = & $Exe cert-verify --cert "$Lab\tests\certs\leaf_valid.pem" --issuer "$Lab\tests\certs\wrong_ca.pem" 2>&1
    $wrongIssuerCode = $global:LASTEXITCODE

    $ErrorActionPreference = $oldEap

    $wrongIssuerOutput | ForEach-Object { $_.ToString() }
    "exit_code=$wrongIssuerCode"

    if ($wrongIssuerCode -eq 0) {
        throw "Wrong issuer unexpectedly verified"
    }

    "Wrong issuer rejected as expected with exit code $wrongIssuerCode"
    $global:LASTEXITCODE = 0
} (Join-Path $Logs "pki_wrong_issuer_windows_final.log")

Run-Step "length_extension_windows" {
    & $Exe length-extension-demo --out-dir "$Lab\demos\length_extension"
    Get-Content "$Lab\demos\length_extension\verification_result.txt"
} (Join-Path $Logs "length_extension_windows_final.log")

Require-Text "$Lab\demos\length_extension\verification_result.txt" "naive_original_verify=PASS" "Original naive MAC verification did not pass"
Require-Text "$Lab\demos\length_extension\verification_result.txt" "naive_forged_verify=PASS" "Forged naive MAC did not pass"
Require-Text "$Lab\demos\length_extension\verification_result.txt" "hmac_forged_verify=FAIL" "Forged HMAC was not rejected"

Run-Step "md5_collision_verify_windows" {
    powershell -NoProfile -ExecutionPolicy Bypass -File "$Lab\scripts\verify_md5_collision_windows.ps1" -Dir "$Lab\demos\md5_collision"
    certutil -hashfile "$Lab\demos\md5_collision\collision_a.bin" MD5
    certutil -hashfile "$Lab\demos\md5_collision\collision_b.bin" MD5
    certutil -hashfile "$Lab\demos\md5_collision\collision_a.bin" SHA256
    certutil -hashfile "$Lab\demos\md5_collision\collision_b.bin" SHA256
} (Join-Path $Logs "md5_collision_verify_windows_final.log")

Require-Text (Join-Path $Logs "md5_collision_verify_windows_final.log") "PASS" "MD5 collision verification did not pass"

Run-Step "tls_local_self_signed_windows" {
    powershell -NoProfile -ExecutionPolicy Bypass -File "$Lab\scripts\tls_local_self_signed_demo_windows.ps1"
    Get-Content "$Lab\demos\tls\tls_test_log.txt"
    Get-Content "$Lab\demos\tls\cert_chain_info.txt"
} (Join-Path $Logs "tls_local_self_signed_windows_final.log")

Run-Step "bench_windows_1m" {
    & $Exe bench --out "$Bench\bench_windows_1m_raw.csv" --summary "$Bench\bench_windows_1m_summary.csv" --runs 30 --ops 100 --warmup-ms 1000 --sizes 1m --algos sha256,sha512,sha3-256,sha3-512 --platform windows11-mingw64
} (Join-Path $Logs "bench_windows_1m_final.log")

Run-Step "bench_windows_100m" {
    & $Exe bench --out "$Bench\bench_windows_100m_raw.csv" --summary "$Bench\bench_windows_100m_summary.csv" --runs 30 --ops 1 --warmup-ms 1000 --sizes 100m --algos sha256,sha512,sha3-256,sha3-512 --platform windows11-mingw64
} (Join-Path $Logs "bench_windows_100m_final.log")

if ($Run1G) {
    Run-Step "bench_windows_1g" {
        & $Exe bench --out "$Bench\bench_windows_1g_raw.csv" --summary "$Bench\bench_windows_1g_summary.csv" --runs 3 --ops 1 --warmup-ms 500 --sizes 1g --algos sha256,sha512,sha3-256,sha3-512 --platform windows11-mingw64
    } (Join-Path $Logs "bench_windows_1g_final.log")
}

Copy-Item -Force $Exe "$Bin\hashtool.exe"
Copy-Item -Force "$Build\libhashtool_core.a" "$Bin\libhashtool_core.a"

$envText = @"
Lab 4 Windows Environment
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
OS: Windows 11 25H2
Compiler: $(g++ --version | Select-Object -First 1)
CMake: $(cmake --version | Select-Object -First 1)
OpenSSL: $(openssl version)
g++ path: $((Get-Command g++).Source)
cmake path: $((Get-Command cmake).Source)
openssl path: $((Get-Command openssl).Source)
Build type: Release
Generator: MinGW Makefiles
OpenSSL root: C:/msys64/mingw64
Tool: lab4_hash_pki/build/hashtool.exe
Core library bonus artifact: lab4_hash_pki/artifacts/windows/binaries/libhashtool_core.a
"@

$envText | Set-Content -Encoding UTF8 "$Repo\lab4_windows_environment.txt"

$captureText = @"
# Lab 4 Windows capture commands

Run final CTest screenshot:
ctest --test-dir lab4_hash_pki\build --output-on-failure

Run final negative tests screenshot:
powershell -NoProfile -ExecutionPolicy Bypass -File lab4_hash_pki\scripts\negative_tests_windows.ps1 -Exe "D:\Newfolder\Crypto_Labs_All\lab4_hash_pki\build\hashtool.exe"

Run MD5 collision verification screenshot:
powershell -NoProfile -ExecutionPolicy Bypass -File lab4_hash_pki\scripts\verify_md5_collision_windows.ps1 -Dir lab4_hash_pki\demos\md5_collision
certutil -hashfile lab4_hash_pki\demos\md5_collision\collision_a.bin MD5
certutil -hashfile lab4_hash_pki\demos\md5_collision\collision_b.bin MD5
certutil -hashfile lab4_hash_pki\demos\md5_collision\collision_a.bin SHA256
certutil -hashfile lab4_hash_pki\demos\md5_collision\collision_b.bin SHA256

Run length-extension screenshot:
lab4_hash_pki\build\hashtool.exe length-extension-demo --out-dir lab4_hash_pki\demos\length_extension
type lab4_hash_pki\demos\length_extension\verification_result.txt

Run TLS local evidence screenshot:
powershell -NoProfile -ExecutionPolicy Bypass -File lab4_hash_pki\scripts\tls_local_self_signed_demo_windows.ps1
type lab4_hash_pki\demos\tls\tls_test_log.txt
"@

$captureText | Set-Content -Encoding UTF8 "$Report\capture_commands_windows.md"

$ZipRoot = "D:\Newfolder\Crypto_Labs_Report_Zips"
$Stage = Join-Path $env:TEMP "lab4_windows_report_input_standardized"
$Zip = Join-Path $ZipRoot "lab4_windows_report_input_standardized.zip"

Remove-Item -Recurse -Force $Stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Stage, $ZipRoot | Out-Null

Copy-Item "$Lab\README.md" "$Stage\README.md" -Force
Copy-Item "$Lab\CMakeLists.txt" "$Stage\CMakeLists.txt" -Force
Copy-Item "$Lab\scripts\report\run_lab4_windows_evidence.ps1" "$Stage\run_lab4_windows_evidence.ps1" -Force
Copy-Item "$Report\capture_commands_windows.md" "$Stage\capture_commands_windows.md" -Force
Copy-Item "$Repo\lab4_windows_environment.txt" "$Stage\lab4_windows_environment.txt" -Force

New-Item -ItemType Directory -Force "$Stage\logs", "$Stage\bench", "$Stage\demos", "$Stage\binaries", "$Stage\certs", "$Stage\vectors" | Out-Null

Get-ChildItem $Logs -Filter "*_final.log" | Copy-Item -Destination "$Stage\logs\" -Force
Get-ChildItem $Bench -Filter "bench_windows_*.csv" | Copy-Item -Destination "$Stage\bench\" -Force

Copy-Item "$Bin\hashtool.exe" "$Stage\binaries\" -Force
Copy-Item "$Bin\libhashtool_core.a" "$Stage\binaries\" -Force

Copy-Item "$Lab\vectors\*.json" "$Stage\vectors\" -Force
Copy-Item "$Lab\tests\certs\*.pem" "$Stage\certs\" -Force
Copy-Item "$Lab\tests\certs\*.der" "$Stage\certs\" -Force

Copy-Item "$Lab\demos\length_extension" "$Stage\demos\length_extension" -Recurse -Force
Copy-Item "$Lab\demos\md5_collision" "$Stage\demos\md5_collision" -Recurse -Force
Copy-Item "$Lab\demos\tls" "$Stage\demos\tls" -Recurse -Force

Remove-Item -Force $Zip -ErrorAction SilentlyContinue
Compress-Archive -Path "$Stage\*" -DestinationPath $Zip -Force

Write-Host ""
Write-Host "==== WINDOWS LAB 4 EVIDENCE COMPLETE ===="
Write-Host "Zip: $Zip"
Write-Host "CTest: 17/17 PASS"
Write-Host "KAT: hash 16/16 PASS, SHAKE 4/4 PASS"
Write-Host "Length extension: naive forged PASS, HMAC forged FAIL"
Write-Host "Bonus core library: libhashtool_core.a copied"
Write-Host ""
git status -sb

