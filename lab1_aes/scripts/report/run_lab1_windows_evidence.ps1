$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

Set-StrictMode -Version Latest

$Repo = "D:\Newfolder\Crypto_Labs_All"
$Lab = Join-Path $Repo "lab1_aes"

Set-Location $Lab

$WinArtifacts = Join-Path $Lab "artifacts\windows"
$LogDir = Join-Path $WinArtifacts "logs"
$BenchDir = Join-Path $WinArtifacts "bench"
$BinDir = Join-Path $WinArtifacts "binaries"
$ReportDir = Join-Path $Lab "report"

New-Item -ItemType Directory -Force -Path $LogDir, $BenchDir, $BinDir, $ReportDir | Out-Null

Write-Host "===== Lab 1 Windows evidence run started ====="

Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force tmp_negative_tests -ErrorAction SilentlyContinue

Write-Host "===== Configure ====="
$ConfigureLog = Join-Path $LogDir "configure_windows.log"

& cmake -S . -B build `
  -G "MinGW Makefiles" `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_CXX_COMPILER="C:\msys64\mingw64\bin\g++.exe" `
  *> $ConfigureLog

Get-Content $ConfigureLog

if ($LASTEXITCODE -ne 0) {
  throw "CMake configure failed. See artifacts\windows\logs\configure_windows.log"
}

Write-Host "===== Build ====="
$BuildLog = Join-Path $LogDir "build_windows.log"

& cmake --build build --parallel *> $BuildLog

Get-Content $BuildLog

if ($LASTEXITCODE -ne 0) {
  throw "CMake build failed. See artifacts\windows\logs\build_windows.log"
}

$ToolCandidates = @(
  (Join-Path $Lab "build\aestool.exe"),
  (Join-Path $Lab "build\Release\aestool.exe")
)

$Tool = $ToolCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Tool) {
  throw "Cannot find aestool.exe in build output."
}

$UnitCandidates = @(
  (Join-Path $Lab "build\aestool_unit_tests.exe"),
  (Join-Path $Lab "build\Release\aestool_unit_tests.exe")
)

$UnitTool = $UnitCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

Copy-Item $Tool (Join-Path $BinDir "aestool.exe") -Force
if ($UnitTool) {
  Copy-Item $UnitTool (Join-Path $BinDir "aestool_unit_tests.exe") -Force
}

Write-Host "===== Environment ====="
@"
===== OS =====
"@ | Out-File (Join-Path $Repo "lab1_windows_environment.txt") -Encoding utf8

Get-ComputerInfo |
  Select-Object WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture |
  Format-List |
  Out-File (Join-Path $Repo "lab1_windows_environment.txt") -Append -Encoding utf8

"`n===== CPU =====" | Out-File (Join-Path $Repo "lab1_windows_environment.txt") -Append -Encoding utf8
Get-CimInstance Win32_Processor |
  Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed |
  Format-List |
  Out-File (Join-Path $Repo "lab1_windows_environment.txt") -Append -Encoding utf8

"`n===== RAM =====" | Out-File (Join-Path $Repo "lab1_windows_environment.txt") -Append -Encoding utf8
Get-CimInstance Win32_ComputerSystem |
  Select-Object TotalPhysicalMemory |
  Format-List |
  Out-File (Join-Path $Repo "lab1_windows_environment.txt") -Append -Encoding utf8

"`n===== DISK =====" | Out-File (Join-Path $Repo "lab1_windows_environment.txt") -Append -Encoding utf8
Get-PhysicalDisk |
  Select-Object FriendlyName, MediaType, Size |
  Format-Table |
  Out-File (Join-Path $Repo "lab1_windows_environment.txt") -Append -Encoding utf8

"`n===== COMPILER =====" | Out-File (Join-Path $Repo "lab1_windows_environment.txt") -Append -Encoding utf8
g++ --version | Out-File (Join-Path $Repo "lab1_windows_environment.txt") -Append -Encoding utf8
cmake --version | Out-File (Join-Path $Repo "lab1_windows_environment.txt") -Append -Encoding utf8

"`n===== CRYPTOPP =====" | Out-File (Join-Path $Repo "lab1_windows_environment.txt") -Append -Encoding utf8
Get-ChildItem "D:\Newfolder\Crypto++" -Filter "libcryptopp.a" -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName,Length,LastWriteTime |
  Format-List |
  Out-File (Join-Path $Repo "lab1_windows_environment.txt") -Append -Encoding utf8

Write-Host "===== Help ====="
& $Tool --help > (Join-Path $LogDir "help_windows.log") 2>&1

Write-Host "===== Unit tests ====="
if ($UnitTool) {
  & $UnitTool > (Join-Path $LogDir "unit_tests_windows.log") 2>&1
} else {
  "aestool_unit_tests.exe not found" > (Join-Path $LogDir "unit_tests_windows.log")
}

Write-Host "===== CTest ====="
ctest --test-dir build --output-on-failure > (Join-Path $LogDir "ctest_windows.log") 2>&1

Write-Host "===== KAT clean scope ====="
$KatLog = Join-Path $LogDir "kat_windows_clean.log"
"===== KAT sample =====" | Out-File $KatLog -Encoding utf8
& $Tool kat --kat "vectors\aes_kat_sample.json" | Out-File $KatLog -Append -Encoding utf8

"`n===== KAT extended =====" | Out-File $KatLog -Append -Encoding utf8
& $Tool kat --kat "vectors\aes_kat_extended.json" | Out-File $KatLog -Append -Encoding utf8

Copy-Item $KatLog (Join-Path $LogDir "kat_windows.log") -Force

Write-Host "===== Negative tests ====="
powershell -ExecutionPolicy Bypass -File "scripts\negative_tests_windows.ps1" $Tool `
  > (Join-Path $LogDir "negative_tests_windows.log") 2>&1

Write-Host "===== Benchmark ====="
& $Tool bench `
  --out "artifacts\windows\bench\bench_windows_raw.csv" `
  --summary "artifacts\windows\bench\bench_windows_summary.csv" `
  --runs 30 `
  --ops 100 `
  --warmup-ms 100 `
  --sizes "1k,4k,16k,256k,1m,8m" `
  --modes "ecb,cbc,cfb,ofb,ctr,gcm,ccm,xts" `
  --platform "windows" `
  > (Join-Path $LogDir "bench_windows.log") 2>&1

Write-Host "===== Screenshot command guide ====="
@"
# Lab 1 Windows screenshot commands

## W01 - Windows artifacts tree
cd D:\Newfolder\Crypto_Labs_All
tree lab1_aes\artifacts\windows /F

## W02 - Windows aestool help
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
artifacts\windows\binaries\aestool.exe --help

## W03 - Windows CTest evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
type artifacts\windows\logs\ctest_windows.log

## W04 - Windows KAT evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
type artifacts\windows\logs\kat_windows_clean.log

## W05 - Windows negative tests evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
type artifacts\windows\logs\negative_tests_windows.log

## W06 - Windows benchmark files
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
dir artifacts\windows\bench

## W07 - Windows CBC evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\kat_windows_clean.log,artifacts\windows\logs\negative_tests_windows.log -Pattern "CBC|Cbc|cbc"

## W08 - Windows CTR/reuse evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\negative_tests_windows.log -Pattern "CTR|Ctr|ctr|reuse|nonce|IV"

## W09 - Windows GCM fail-closed evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\negative_tests_windows.log -Pattern "GCM|Gcm|gcm|AAD|aad|tag|tamper|wrong key"

## W10 - Windows CCM fail-closed evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\negative_tests_windows.log -Pattern "CCM|Ccm|ccm|tag|tamper|nonce"

## W11 - Windows XTS evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\negative_tests_windows.log -Pattern "XTS|Xts|xts|short|tamper"

## W12 - Windows ECB restriction evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\negative_tests_windows.log -Pattern "ECB|Ecb|ecb|allow|large"
"@ | Out-File (Join-Path $ReportDir "capture_commands_windows.md") -Encoding utf8

Write-Host "===== Verification summary ====="
Select-String -Path (Join-Path $LogDir "ctest_windows.log") -Pattern "100% tests passed|tests failed"
Select-String -Path (Join-Path $LogDir "kat_windows_clean.log") -Pattern "KAT summary"
Select-String -Path (Join-Path $LogDir "negative_tests_windows.log") -Pattern "summary|fail=0"
Get-ChildItem $BenchDir

Write-Host "===== Lab 1 Windows evidence run completed ====="