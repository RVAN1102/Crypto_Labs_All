param(
    [string]$Exe = "lab5_signatures\build\sigtool.exe",
    [int]$Runs = 30,
    [int]$Ops = 1,
    [string]$Sizes = "1k,16k,1m,8m"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Lab = Join-Path $Root "lab5_signatures"
$LogDir = Join-Path $Lab "artifacts\windows\logs"
$BenchDir = Join-Path $Lab "artifacts\windows\bench"
New-Item -ItemType Directory -Force $LogDir, $BenchDir | Out-Null

if ($Runs -lt 30) {
    throw "The final Lab 5 benchmark requires Runs >= 30."
}
if ($Sizes -ne "1k,16k,1m,8m") {
    throw "The final Lab 5 benchmark requires Sizes=1k,16k,1m,8m."
}

$exePath = if ([System.IO.Path]::IsPathRooted($Exe)) { $Exe } else { Join-Path $Root $Exe }
$log = Join-Path $LogDir "bench_windows.log"
& $exePath bench `
    --out (Join-Path $BenchDir "bench_windows_raw.csv") `
    --summary (Join-Path $BenchDir "bench_windows_summary.csv") `
    --runs "$Runs" `
    --ops "$Ops" `
    --sizes "$Sizes" `
    --algos "ecdsa-p256,rsa-pss-3072" `
    --platform "windows-mingw64" 2>&1 | Tee-Object -FilePath $log
if ($LASTEXITCODE -ne 0) {
    throw "Lab 5 Windows benchmark failed with exit code $LASTEXITCODE."
}
