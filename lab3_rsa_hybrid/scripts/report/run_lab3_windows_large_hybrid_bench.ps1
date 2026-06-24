$ErrorActionPreference = "Stop"

$Repo = "D:\Newfolder\Crypto_Labs_All"
$Lab = Join-Path $Repo "lab3_rsa_hybrid"

Set-Location $Lab

$LogDir = Join-Path $Lab "artifacts\windows\logs"
$BenchDir = Join-Path $Lab "artifacts\windows\bench"
$Tool = Join-Path $Lab "build-windows\rsatool.exe"

New-Item -ItemType Directory -Force $LogDir, $BenchDir | Out-Null

if (!(Test-Path $Tool)) {
    Write-Host "rsatool.exe not found, rebuilding first."

    Remove-Item -Recurse -Force build-windows -ErrorAction SilentlyContinue

    & cmake -S . -B build-windows `
        -G "MinGW Makefiles" `
        -DCMAKE_BUILD_TYPE=Release `
        -DCMAKE_CXX_COMPILER="C:/msys64/mingw64/bin/g++.exe" `
        -DCRYPTOPP_INCLUDE_DIR="D:/Newfolder/Crypto++" `
        -DCRYPTOPP_LIBRARY="D:/Newfolder/Crypto++/libcryptopp.a" `
        *> "$LogDir\configure_windows_large_bench.log"

    & cmake --build build-windows -j $env:NUMBER_OF_PROCESSORS `
        *> "$LogDir\build_windows_large_bench.log"
}

if (!(Test-Path $Tool)) {
    throw "Cannot find Lab 3 executable: $Tool"
}

Write-Host "===== Lab 3 Windows large Hybrid benchmark ====="
Write-Host "Tool: $Tool"
Write-Host "Protocol: runs=30, ops=1, Hybrid payload=100 MiB"
Write-Host "Output raw CSV: artifacts\windows\bench\bench_windows_hybrid_100m_raw.csv"
Write-Host "Output summary CSV: artifacts\windows\bench\bench_windows_hybrid_100m_summary.csv"

& $Tool bench `
    --out artifacts\windows\bench\bench_windows_hybrid_100m_raw.csv `
    --summary artifacts\windows\bench\bench_windows_hybrid_100m_summary.csv `
    --runs 30 `
    --ops 1 `
    --sizes 100m `
    --rsa-sizes 32 `
    --rsa-bits 3072,4096 `
    *> "$LogDir\bench_windows_hybrid_100m.log"

Write-Host "===== Large Hybrid benchmark log ====="
Get-Content "$LogDir\bench_windows_hybrid_100m.log"

Write-Host "===== Large Hybrid benchmark summary ====="
Import-Csv "$BenchDir\bench_windows_hybrid_100m_summary.csv" |
    Where-Object { $_.family -eq "hybrid" -and $_.payload_bytes -eq "104857600" } |
    Format-Table platform, rsa_bits, family, operation, payload_bytes, runs, ops_per_run, mean_ms_per_op, mean_mib_s -AutoSize

Write-Host "===== Lab 3 Windows large Hybrid benchmark completed ====="