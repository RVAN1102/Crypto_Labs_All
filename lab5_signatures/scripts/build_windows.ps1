param(
    [string]$BuildDir = "lab5_signatures\build",
    [string]$Generator = "MinGW Makefiles",
    [string]$OpenSslRoot = ""
)

$ErrorActionPreference = "Continue"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Lab = Join-Path $Root "lab5_signatures"
$LogDir = Join-Path $Lab "artifacts\windows\logs"
New-Item -ItemType Directory -Force $LogDir | Out-Null

$configureLog = Join-Path $LogDir "configure_windows.log"
$buildLog = Join-Path $LogDir "build_windows.log"

$configureArgs = @("-S", $Lab, "-B", (Join-Path $Root $BuildDir), "-G", $Generator, "-DCMAKE_BUILD_TYPE=Release")
if ($OpenSslRoot -ne "") {
    $configureArgs += "-DOPENSSL_ROOT_DIR=$OpenSslRoot"
}

cmake @configureArgs 2>&1 | Tee-Object -FilePath $configureLog
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cmake --build (Join-Path $Root $BuildDir) 2>&1 | Tee-Object -FilePath $buildLog
exit $LASTEXITCODE
