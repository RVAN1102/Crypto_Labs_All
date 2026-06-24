[CmdletBinding()]
param([string]$BuildDir = "build-windows-mingw", [string]$OpenSSLRoot = "")
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "_common_windows.ps1")
[void](Initialize-PqOpenSSL $OpenSSLRoot)
$LogDir = Join-Path $Root "artifacts\windows\logs"
New-Item -ItemType Directory -Force $LogDir | Out-Null
$Config = @()
if ($BuildDir -match "msvc") { $Config = @("-C", "Release") }
& ctest --test-dir (Join-Path $Root $BuildDir) @Config --output-on-failure 2>&1 |
    Tee-Object (Join-Path $LogDir "ctest_windows.log")
if ($LASTEXITCODE -ne 0) { throw "CTest failed." }

