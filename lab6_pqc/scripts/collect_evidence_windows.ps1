[CmdletBinding()]
param([string]$BuildDir = "build-windows-mingw", [string]$OpenSSLRoot = "")
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "_common_windows.ps1")
$OpenSSLRoot = Initialize-PqOpenSSL $OpenSSLRoot
$Exe = Resolve-Pqtool $Root $BuildDir
$Logs = Join-Path $Root "artifacts\windows\logs"
New-Item -ItemType Directory -Force $Logs | Out-Null
& {
    "=== OpenSSL ==="; & (Join-Path $OpenSSLRoot "bin\openssl.exe") version -a
    "=== CMake ==="; cmake --version
    "=== Git ==="; git -C (Split-Path -Parent $Root) branch --show-current; git -C (Split-Path -Parent $Root) status --short
    "=== pqtool SHA-256 ==="; Get-FileHash -Algorithm SHA256 $Exe
    "=== Quality logs ==="
    foreach ($name in "ctest_windows.log","demo_windows.log","negative_tests_windows.log","benchmark_windows.log") {
        $path = Join-Path $Logs $name
        if (-not (Test-Path $path)) { throw "Missing evidence log: $path" }
        $path
    }
    "=== Benchmark CSVs ==="
    Get-ChildItem (Join-Path $Root "artifacts\windows\benchmarks") -Filter *.csv | Select-Object -ExpandProperty FullName
    "No private key or shared-secret bytes are included in this log."
} 2>&1 | Tee-Object (Join-Path $Logs "evidence_windows.log")

