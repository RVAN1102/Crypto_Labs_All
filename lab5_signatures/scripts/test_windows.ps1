param(
    [string]$BuildDir = "lab5_signatures\build"
)

$ErrorActionPreference = "Continue"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Lab = Join-Path $Root "lab5_signatures"
$LogDir = Join-Path $Lab "artifacts\windows\logs"
New-Item -ItemType Directory -Force $LogDir | Out-Null

$ctestLog = Join-Path $LogDir "ctest_windows.log"
ctest --test-dir (Join-Path $Root $BuildDir) --output-on-failure 2>&1 | Tee-Object -FilePath $ctestLog
exit $LASTEXITCODE
