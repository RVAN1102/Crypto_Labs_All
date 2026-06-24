[CmdletBinding()]
param([string]$OpenSSLRoot = "")
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "_common_windows.ps1")
$OpenSSLRoot = Initialize-PqOpenSSL $OpenSSLRoot
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) { throw "CMake is not available in PATH." }
$LogDir = Join-Path $Root "artifacts\windows\logs"
New-Item -ItemType Directory -Force $LogDir | Out-Null
$Build = Join-Path $Root "build-windows-msvc"
& cmake -S $Root -B $Build -G "Visual Studio 17 2022" -A x64 "-DOPENSSL_ROOT_DIR=$OpenSSLRoot" 2>&1 |
    Tee-Object (Join-Path $LogDir "build_windows_msvc.log")
if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed." }
& cmake --build $Build --config Release -j 2 2>&1 | Tee-Object -Append (Join-Path $LogDir "build_windows_msvc.log")
if ($LASTEXITCODE -ne 0) { throw "MSVC build failed." }

