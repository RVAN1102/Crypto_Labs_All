$ErrorActionPreference = "Stop"

$Repo = "D:\Newfolder\Crypto_Labs_All"
$Lab = Join-Path $Repo "lab3_rsa_hybrid"

Set-Location $Lab

$WinArtifacts = Join-Path $Lab "artifacts\windows"
$LogDir = Join-Path $WinArtifacts "logs"
$BenchDir = Join-Path $WinArtifacts "bench"
$BinDir = Join-Path $WinArtifacts "binaries"
$ReportDir = Join-Path $Lab "report"

New-Item -ItemType Directory -Force $LogDir, $BenchDir, $BinDir, $ReportDir | Out-Null

Write-Host "===== Lab 3 Windows evidence run started ====="

Remove-Item -Recurse -Force build-windows -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force tmp_negative_tests -ErrorAction SilentlyContinue

Write-Host "===== Environment ====="
$EnvFile = Join-Path $Repo "lab3_windows_environment.txt"

@"
===== OS =====
$((Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture | Format-List | Out-String).Trim())

===== Computer =====
$((Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory | Format-List | Out-String).Trim())

===== CPU =====
$((Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | Format-List | Out-String).Trim())

===== Disk =====
$((Get-CimInstance Win32_DiskDrive | Select-Object Model, Size, MediaType | Format-Table -AutoSize | Out-String).Trim())

===== PowerShell =====
$($PSVersionTable | Out-String)

===== Compiler =====
$((& "C:\msys64\mingw64\bin\g++.exe" --version) 2>&1 | Out-String)

===== CMake =====
$((cmake --version) 2>&1 | Out-String)

===== Crypto++ candidates =====
$(Get-ChildItem "D:\Newfolder\Crypto++" -ErrorAction SilentlyContinue | Select-Object Name, Length | Format-Table -AutoSize | Out-String)
"@ | Set-Content -Encoding UTF8 $EnvFile

$CryptoInclude = "D:/Newfolder/Crypto++"
$CryptoLib = "D:/Newfolder/Crypto++/libcryptopp.a"

if (!(Test-Path "D:\Newfolder\Crypto++\libcryptopp.a")) {
    throw "Cannot find Crypto++ library: D:\Newfolder\Crypto++\libcryptopp.a"
}

Write-Host "===== Configure ====="
& cmake -S . -B build-windows `
    -G "MinGW Makefiles" `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_CXX_COMPILER="C:/msys64/mingw64/bin/g++.exe" `
    -DCRYPTOPP_INCLUDE_DIR="$CryptoInclude" `
    -DCRYPTOPP_LIBRARY="$CryptoLib" `
    *> "$LogDir\configure_windows.log"

Get-Content "$LogDir\configure_windows.log"

Write-Host "===== Build ====="
& cmake --build build-windows -j $env:NUMBER_OF_PROCESSORS `
    *> "$LogDir\build_windows.log"

Get-Content "$LogDir\build_windows.log"

Write-Host "===== Locate executable ====="
$Tool = Join-Path $Lab "build-windows\rsatool.exe"
$UnitTool = Join-Path $Lab "build-windows\rsatool_unit_tests.exe"

if (!(Test-Path $Tool)) {
    Write-Host "Executable files found:"
    Get-ChildItem build-windows -Recurse -File | Where-Object { $_.Name -like "*.exe" } | Select-Object FullName
    throw "Cannot find Lab 3 executable: $Tool"
}

"Tool path: $Tool" | Tee-Object -FilePath "$LogDir\tool_path_windows.log"

Copy-Item $Tool "$BinDir\rsatool.exe" -Force
if (Test-Path $UnitTool) {
    Copy-Item $UnitTool "$BinDir\rsatool_unit_tests.exe" -Force
}

Write-Host "===== Help ====="
& $Tool --help *> "$LogDir\help_windows.log"

Write-Host "===== CTest ====="
& ctest --test-dir build-windows --output-on-failure `
    *> "$LogDir\ctest_windows.log"

Get-Content "$LogDir\ctest_windows.log"

Write-Host "===== KAT ====="
& $Tool kat --kat vectors\rsa_hybrid_kat.json `
    *> "$LogDir\kat_windows.log"

Write-Host "===== Negative tests ====="
if (Test-Path "scripts\negative_tests_windows.ps1") {
    try {
        & powershell -ExecutionPolicy Bypass -File "scripts\negative_tests_windows.ps1" $Tool `
            *> "$LogDir\negative_tests_windows.log"
    } catch {
        "First negative test invocation failed. Retrying without explicit tool argument." | Out-File "$LogDir\negative_tests_windows.log" -Append
        & powershell -ExecutionPolicy Bypass -File "scripts\negative_tests_windows.ps1" `
            *>> "$LogDir\negative_tests_windows.log"
    }
} else {
    "scripts\negative_tests_windows.ps1 not found" | Set-Content "$LogDir\negative_tests_windows.log"
}

Write-Host "===== Benchmark ====="
& $Tool bench `
    --out artifacts\windows\bench\bench_windows_raw.csv `
    --summary artifacts\windows\bench\bench_windows_summary.csv `
    *> "$LogDir\bench_windows.log"

Write-Host "===== Artifact inventory ====="
Get-ChildItem artifacts\windows -Recurse -File |
    Sort-Object FullName |
    ForEach-Object { $_.FullName.Replace($Lab + "\", "") } |
    Set-Content "$LogDir\artifact_inventory_windows.log"

Write-Host "===== Screenshot command guide ====="
@'
# Lab 3 Windows screenshot commands

## W01 - Windows artifacts tree
cd D:\Newfolder\Crypto_Labs_All
Get-ChildItem lab3_rsa_hybrid\artifacts\windows -Recurse -File | Sort-Object FullName

## W02 - Lab 3 tool help
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\help_windows.log

## W03 - CTest result
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\ctest_windows.log

## W04 - KAT result
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\kat_windows.log

## W05 - Negative tests
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\negative_tests_windows.log

## W06 - Benchmark files
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-ChildItem artifacts\windows\bench | Format-Table Name, Length, LastWriteTime -AutoSize

## W07 - RSA-OAEP direct mode evidence
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\negative_tests_windows.log,artifacts\windows\logs\kat_windows.log -Pattern "oaep|direct|small|limit|3072|4096"

## W08 - Hybrid encryption evidence
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\negative_tests_windows.log,artifacts\windows\logs\kat_windows.log -Pattern "hybrid|seal|open|aes|gcm|wrap|envelope"

## W09 - Wrong key / wrong label evidence
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Select-String -Path artifacts\windows\logs\negative_tests_windows.log -Pattern "wrong|label|private|reject|fail"

## W10 - Tamper / malformed envelope evidence
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Select-String -Path artifacts\windows\logs\negative_tests_windows.log -Pattern "tamper|malformed|ciphertext|tag|version|algorithm|envelope"
'@ | Set-Content -Encoding UTF8 "$ReportDir\capture_commands_windows.md"

Write-Host "===== Verification summary ====="
Select-String -Path "$LogDir\ctest_windows.log" -Pattern "100% tests passed|tests failed" -ErrorAction SilentlyContinue
Get-Content "$LogDir\kat_windows.log"
Get-Content "$LogDir\negative_tests_windows.log"
Get-ChildItem $BenchDir | Format-Table Name, Length, LastWriteTime -AutoSize

Write-Host "===== Lab 3 Windows evidence run completed ====="