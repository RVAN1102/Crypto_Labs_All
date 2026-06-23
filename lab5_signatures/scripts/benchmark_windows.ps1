param(
    [string]$Exe = "lab5_signatures\build\sigtool.exe",
    [int]$Runs = 30,
    [int]$Ops = 1,
    [string]$Sizes = "1k,16k,1m,8m"
)

$ErrorActionPreference = "Continue"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Lab = Join-Path $Root "lab5_signatures"
$LogDir = Join-Path $Lab "artifacts\windows\logs"
$BenchDir = Join-Path $Lab "artifacts\windows\bench"
New-Item -ItemType Directory -Force $LogDir, $BenchDir | Out-Null

$exePath = Join-Path $Root $Exe
$log = Join-Path $LogDir "bench_windows.log"
& $exePath bench `
    --out (Join-Path $BenchDir "bench_windows_raw.csv") `
    --summary (Join-Path $BenchDir "bench_windows_summary.csv") `
    --runs "$Runs" `
    --ops "$Ops" `
    --sizes "$Sizes" `
    --algos "ecdsa-p256,rsa-pss-3072" `
    --platform "windows-mingw64" 2>&1 | Tee-Object -FilePath $log
exit $LASTEXITCODE
