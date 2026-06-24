[CmdletBinding()]
param([string]$OpenSSLRoot = "")
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "_common_windows.ps1")
$OpenSSLRoot = Initialize-PqOpenSSL $OpenSSLRoot
foreach ($tool in "cmake", "g++") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool is not available in PATH." }
}
$LogDir = Join-Path $Root "artifacts\windows\logs"
New-Item -ItemType Directory -Force $LogDir | Out-Null
$Build = Join-Path $Root "build-windows-mingw"
& cmake -S $Root -B $Build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release "-DOPENSSL_ROOT_DIR=$OpenSSLRoot" 2>&1 |
    Tee-Object (Join-Path $LogDir "build_windows_mingw.log")
if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed." }
& cmake --build $Build -j 2 2>&1 | Tee-Object -Append (Join-Path $LogDir "build_windows_mingw.log")
if ($LASTEXITCODE -ne 0) { throw "MinGW build failed." }

