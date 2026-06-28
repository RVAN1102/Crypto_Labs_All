$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

Set-StrictMode -Version Latest

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Lab = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path

Set-Location $Lab

$WinArtifacts = Join-Path $Lab "artifacts\windows"
$LogDir = Join-Path $WinArtifacts "logs"
$BenchDir = Join-Path $WinArtifacts "bench"
$BinDir = Join-Path $WinArtifacts "binaries"

New-Item -ItemType Directory -Force -Path $LogDir, $BenchDir, $BinDir | Out-Null

$EnvironmentLog = Join-Path $LogDir "environment_windows_standard.log"
$ConfigureLog = Join-Path $LogDir "configure_windows_standard.log"
$BuildLog = Join-Path $LogDir "build_windows_standard.log"
$HelpLog = Join-Path $LogDir "help_windows_standard.log"
$UnitLog = Join-Path $LogDir "unit_tests_windows_standard.log"
$CTestLog = Join-Path $LogDir "ctest_windows_standard.log"
$KatLog = Join-Path $LogDir "kat_windows_standard.log"
$NegativeLog = Join-Path $LogDir "negative_tests_windows_standard.log"
$BenchLog = Join-Path $LogDir "bench_windows_standard.log"
$InventoryLog = Join-Path $LogDir "artifact_inventory_windows_standard.log"

function Copy-CompatLog($StandardName, $CompatName) {
  Copy-Item (Join-Path $LogDir $StandardName) (Join-Path $LogDir $CompatName) -Force
}

function Write-Section($Path, $Title) {
  "`n===== $Title =====" | Out-File $Path -Append -Encoding utf8
}

function Append-KatSummary($Path, $Label) {
  $Text = Get-Content -LiteralPath $Path -Raw
  $Matches = [regex]::Matches($Text, "KAT summary:\s*pass=(\d+),\s*fail=(\d+),\s*total=(\d+)")

  if ($Matches.Count -eq 0) {
    "${Label}: missing KAT summary" | Out-File $Path -Append -Encoding utf8
    return
  }

  $Last = $Matches[$Matches.Count - 1]
  "${Label}: pass=$($Last.Groups[1].Value) fail=$($Last.Groups[2].Value) total=$($Last.Groups[3].Value)" |
    Out-File $Path -Append -Encoding utf8
}

Write-Host "===== Lab 1 Windows evidence run started ====="

Write-Host "===== Environment ====="
"===== OS =====" | Out-File $EnvironmentLog -Encoding utf8
Get-ComputerInfo |
  Select-Object WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture |
  Format-List |
  Out-File $EnvironmentLog -Append -Encoding utf8

Write-Section $EnvironmentLog "CPU"
Get-CimInstance Win32_Processor |
  Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed |
  Format-List |
  Out-File $EnvironmentLog -Append -Encoding utf8

Write-Section $EnvironmentLog "RAM"
Get-CimInstance Win32_ComputerSystem |
  Select-Object TotalPhysicalMemory |
  Format-List |
  Out-File $EnvironmentLog -Append -Encoding utf8

Write-Section $EnvironmentLog "COMPILER"
g++ --version | Out-File $EnvironmentLog -Append -Encoding utf8
cmake --version | Out-File $EnvironmentLog -Append -Encoding utf8

Write-Section $EnvironmentLog "CRYPTOPP"
Get-ChildItem "D:\Newfolder\Crypto++" -Filter "libcryptopp.a" -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, LastWriteTime |
  Format-List |
  Out-File $EnvironmentLog -Append -Encoding utf8

Write-Host "===== Configure ====="
if (Test-Path (Join-Path $Lab "build")) {
  Remove-Item (Join-Path $Lab "build") -Recurse -Force
}
if (Test-Path (Join-Path $Lab "tmp_negative_tests")) {
  Remove-Item (Join-Path $Lab "tmp_negative_tests") -Recurse -Force
}

& cmake -S . -B build `
  -G "MinGW Makefiles" `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_CXX_COMPILER="C:\msys64\mingw64\bin\g++.exe" `
  *> $ConfigureLog

if ($LASTEXITCODE -ne 0) {
  throw "CMake configure failed. See artifacts\windows\logs\configure_windows_standard.log"
}

Write-Host "===== Build ====="
& cmake --build build --parallel *> $BuildLog

if ($LASTEXITCODE -ne 0) {
  throw "CMake build failed. See artifacts\windows\logs\build_windows_standard.log"
}

$ToolCandidates = @(
  (Join-Path $Lab "build\aestool.exe"),
  (Join-Path $Lab "build\Release\aestool.exe")
)
$Tool = $ToolCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $Tool) {
  throw "Cannot find aestool.exe in build output."
}
$Tool = (Resolve-Path -LiteralPath $Tool).Path

$UnitCandidates = @(
  (Join-Path $Lab "build\aestool_unit_tests.exe"),
  (Join-Path $Lab "build\Release\aestool_unit_tests.exe")
)
$UnitTool = $UnitCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $UnitTool) {
  throw "Cannot find aestool_unit_tests.exe in build output."
}
$UnitTool = (Resolve-Path -LiteralPath $UnitTool).Path

"`nBuilt binary: $Tool" | Out-File $BuildLog -Append -Encoding utf8
"Built unit test binary: $UnitTool" | Out-File $BuildLog -Append -Encoding utf8

Copy-Item $Tool (Join-Path $BinDir "aestool.exe") -Force
Copy-Item $UnitTool (Join-Path $BinDir "aestool_unit_tests.exe") -Force

Write-Host "===== Help ====="
& $Tool --help > $HelpLog 2>&1

Write-Host "===== Unit tests ====="
& $UnitTool > $UnitLog 2>&1

Write-Host "===== CTest ====="
ctest --test-dir build --output-on-failure > $CTestLog 2>&1

Write-Host "===== KAT ====="
"===== KAT sample =====" | Out-File $KatLog -Encoding utf8
& $Tool kat --kat "vectors\aes_kat_sample.json" | Out-File $KatLog -Append -Encoding utf8
Append-KatSummary $KatLog "KAT sample"

"`n===== KAT extended =====" | Out-File $KatLog -Append -Encoding utf8
& $Tool kat --kat "vectors\aes_kat_extended.json" | Out-File $KatLog -Append -Encoding utf8
Append-KatSummary $KatLog "KAT extended"

Write-Host "===== Negative tests ====="
powershell -ExecutionPolicy Bypass -File "scripts\negative_tests_windows.ps1" $Tool `
  > $NegativeLog 2>&1

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
  > $BenchLog 2>&1

Write-Host "===== Artifact inventory ====="
"===== Artifact inventory: Windows =====" | Out-File $InventoryLog -Encoding utf8
"Binaries:" | Out-File $InventoryLog -Append -Encoding utf8
Get-ChildItem $BinDir | Select-Object Name, Length, LastWriteTime | Format-Table | Out-File $InventoryLog -Append -Encoding utf8
"`nLogs:" | Out-File $InventoryLog -Append -Encoding utf8
Get-ChildItem $LogDir -Filter "*_windows_standard.log" | Select-Object Name, Length, LastWriteTime | Sort-Object Name | Format-Table | Out-File $InventoryLog -Append -Encoding utf8
"`nBenchmark CSV:" | Out-File $InventoryLog -Append -Encoding utf8
Get-ChildItem $BenchDir -Filter "*.csv" | Select-Object Name, Length, LastWriteTime | Sort-Object Name | Format-Table | Out-File $InventoryLog -Append -Encoding utf8

Copy-CompatLog "environment_windows_standard.log" "environment_windows.log"
Copy-CompatLog "configure_windows_standard.log" "configure_windows.log"
Copy-CompatLog "build_windows_standard.log" "build_windows.log"
Copy-CompatLog "help_windows_standard.log" "help_windows.log"
Copy-CompatLog "unit_tests_windows_standard.log" "unit_tests_windows.log"
Copy-CompatLog "ctest_windows_standard.log" "ctest_windows.log"
Copy-CompatLog "kat_windows_standard.log" "kat_windows.log"
Copy-CompatLog "negative_tests_windows_standard.log" "negative_tests_windows.log"
Copy-CompatLog "bench_windows_standard.log" "bench_windows.log"
Copy-CompatLog "artifact_inventory_windows_standard.log" "artifact_inventory_windows.log"

Write-Host "===== Verification summary ====="
Select-String -Path $CTestLog -Pattern "100% tests passed|tests failed"
Select-String -Path $KatLog -Pattern "KAT sample:|KAT extended:"
Select-String -Path $NegativeLog -Pattern "Windows negative test summary"
Get-ChildItem $BenchDir

Write-Host "===== Lab 1 Windows evidence run completed ====="
