[CmdletBinding()]
param([string]$BuildDir = "build-windows-mingw", [string]$OpenSSLRoot = "", [switch]$Quick)
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "_common_windows.ps1")
[void](Initialize-PqOpenSSL $OpenSSLRoot)
$Exe = Resolve-Pqtool $Root $BuildDir
$Out = Join-Path $Root "artifacts\windows\benchmarks"
$Logs = Join-Path $Root "artifacts\windows\logs"
New-Item -ItemType Directory -Force -Path $Out, $Logs | Out-Null
$runs = if ($Quick) { 3 } else { 30 }
& {
    foreach ($alg in "mldsa-44","mldsa-65") {
        Invoke-Pq $Exe @("bench","--algo",$alg,"--ops","keygen,sign,verify","--sizes","1024,16384,1048576,8388608","--runs","$runs","--out",(Join-Path $Out "$alg.csv"))
    }
    foreach ($alg in "mlkem-512","mlkem-768") {
        Invoke-Pq $Exe @("bench","--algo",$alg,"--ops","keygen,encaps,decaps","--runs","$runs","--out",(Join-Path $Out "$alg.csv"))
    }
    Invoke-Pq $Exe @("timing-variance","--algo","mldsa-44","--case","verify-valid-vs-invalid","--runs","$runs","--out",(Join-Path $Out "timing_variance_mldsa44.csv"))
    Invoke-Pq $Exe @("timing-variance","--algo","mlkem-512","--case","decaps-valid-vs-invalid","--runs","$runs","--out",(Join-Path $Out "timing_variance_mlkem512.csv"))
    "BENCHMARK PASS ($runs runs)"
} 2>&1 | Tee-Object (Join-Path $Logs "benchmark_windows.log")
