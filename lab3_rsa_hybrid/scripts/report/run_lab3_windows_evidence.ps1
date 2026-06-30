$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
$Lab = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Repo = Split-Path -Parent $Lab

Set-Location $Lab

$WinArtifacts = Join-Path $Lab "artifacts\windows"
$LogDir = Join-Path $WinArtifacts "logs"
$BenchDir = Join-Path $WinArtifacts "bench"
$BinDir = Join-Path $WinArtifacts "binaries"
$VectorDir = Join-Path $WinArtifacts "vectors"

New-Item -ItemType Directory -Force -Path $LogDir, $BenchDir, $BinDir, $VectorDir | Out-Null

$Logs = @{
    Environment = Join-Path $LogDir "environment_windows_standard.log"
    Configure = Join-Path $LogDir "configure_windows_standard.log"
    Build = Join-Path $LogDir "build_windows_standard.log"
    Help = Join-Path $LogDir "help_windows_standard.log"
    CTest = Join-Path $LogDir "ctest_windows_standard.log"
    Unit = Join-Path $LogDir "unit_tests_windows_standard.log"
    Kat = Join-Path $LogDir "kat_windows_standard.log"
    Negative = Join-Path $LogDir "negative_tests_windows_standard.log"
    Bench = Join-Path $LogDir "bench_windows_standard.log"
    Bench100M = Join-Path $LogDir "bench_windows_hybrid_100m_standard.log"
    Inventory = Join-Path $LogDir "artifact_inventory_windows_standard.log"
    Verification = Join-Path $LogDir "verification_summary_windows_standard.log"
}

function Invoke-Text($Action) {
    try {
        return ((& $Action) 2>&1 | Out-String).Trim()
    } catch {
        return "unavailable: $($_.Exception.Message)"
    }
}

function Invoke-LoggedNative([string]$Name, [string]$LogPath, [string]$FilePath, [string[]]$Arguments) {
    Write-Host "===== $Name ====="
    & $FilePath @Arguments *> $LogPath
    $Code = $LASTEXITCODE
    if ($Code -ne 0) {
        Get-Content -LiteralPath $LogPath -ErrorAction SilentlyContinue
        throw "$Name failed with exit code $Code"
    }
    Get-Content -LiteralPath $LogPath
}

function Assert-LogContains([string]$Name, [string]$LogPath, [string]$Pattern) {
    if (!(Select-String -Path $LogPath -Pattern $Pattern -Quiet)) {
        throw "$Name missing expected pattern: $Pattern"
    }
}

function Copy-LegacyLog([string]$StandardPath, [string]$LegacyName) {
    Copy-Item -LiteralPath $StandardPath -Destination (Join-Path $LogDir $LegacyName) -Force
}

Write-Host "===== Lab 3 Windows standardized evidence run started ====="

Remove-Item -Recurse -Force (Join-Path $Lab "build-windows") -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $Lab "tmp_negative_tests") -ErrorAction SilentlyContinue

Write-Host "===== Environment ====="
$CompilerPath = "C:\msys64\mingw64\bin\g++.exe"
@"
===== OS =====
$(Invoke-Text { Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture | Format-List })

===== Architecture =====
PROCESSOR_ARCHITECTURE=$env:PROCESSOR_ARCHITECTURE

===== Machine / model =====
$(Invoke-Text { Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory | Format-List })

===== CPU / cores / threads =====
$(Invoke-Text { Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | Format-List })

===== RAM =====
$(Invoke-Text { Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory | Format-List })

===== Compiler =====
$(Invoke-Text { & $CompilerPath --version })

===== CMake =====
$(Invoke-Text { cmake --version })

===== Crypto++ =====
Include: D:\Newfolder\Crypto++
Library: D:\Newfolder\Crypto++\libcryptopp.a
$(Invoke-Text { Get-Item "D:\Newfolder\Crypto++\cryptlib.h", "D:\Newfolder\Crypto++\libcryptopp.a" | Select-Object FullName, Length | Format-Table -AutoSize })
"@ | Set-Content -Encoding UTF8 $Logs.Environment
Get-Content -LiteralPath $Logs.Environment
Copy-LegacyLog $Logs.Environment "environment_windows.log"

$CryptoInclude = "D:/Newfolder/Crypto++"
$CryptoLib = "D:/Newfolder/Crypto++/libcryptopp.a"
if (!(Test-Path -LiteralPath "D:\Newfolder\Crypto++\libcryptopp.a")) {
    throw "Cannot find Crypto++ library: D:\Newfolder\Crypto++\libcryptopp.a"
}

Invoke-LoggedNative "Configure" $Logs.Configure "cmake" @(
    "-S", ".",
    "-B", "build-windows",
    "-G", "MinGW Makefiles",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DCMAKE_CXX_COMPILER=C:/msys64/mingw64/bin/g++.exe",
    "-DCRYPTOPP_INCLUDE_DIR=$CryptoInclude",
    "-DCRYPTOPP_LIBRARY=$CryptoLib"
)
Copy-LegacyLog $Logs.Configure "configure_windows.log"

Invoke-LoggedNative "Build" $Logs.Build "cmake" @("--build", "build-windows", "-j", $env:NUMBER_OF_PROCESSORS)
Assert-LogContains "Build" $Logs.Build "Built target rsatool"
Assert-LogContains "Build" $Logs.Build "Built target rsatool_unit_tests"
Copy-LegacyLog $Logs.Build "build_windows.log"

$Tool = (Resolve-Path (Join-Path $Lab "build-windows\rsatool.exe")).Path
$UnitTool = (Resolve-Path (Join-Path $Lab "build-windows\rsatool_unit_tests.exe")).Path

Copy-Item -LiteralPath $Tool -Destination (Join-Path $BinDir "rsatool.exe") -Force
Copy-Item -LiteralPath $UnitTool -Destination (Join-Path $BinDir "rsatool_unit_tests.exe") -Force
Copy-Item -LiteralPath (Join-Path $Lab "vectors\rsa_hybrid_kat.json") -Destination (Join-Path $VectorDir "rsa_hybrid_kat.json") -Force

Invoke-LoggedNative "Help / CLI" $Logs.Help $Tool @("--help")
Copy-LegacyLog $Logs.Help "help_windows.log"

Invoke-LoggedNative "CTest" $Logs.CTest "ctest" @("--test-dir", "build-windows", "--output-on-failure")
Assert-LogContains "CTest" $Logs.CTest "100% tests passed, 0 tests failed out of 14"
Copy-LegacyLog $Logs.CTest "ctest_windows.log"

Invoke-LoggedNative "Unit tests" $Logs.Unit $UnitTool @()
Copy-LegacyLog $Logs.Unit "unit_tests_windows.log"

Invoke-LoggedNative "KAT" $Logs.Kat $Tool @("kat", "--kat", "vectors\rsa_hybrid_kat.json")
Assert-LogContains "KAT" $Logs.Kat "KAT summary: pass=5, fail=0, total=5"
Add-Content -LiteralPath $Logs.Kat -Value "KAT standard: pass=5 fail=0 total=5"
Copy-LegacyLog $Logs.Kat "kat_windows.log"

Invoke-LoggedNative "Negative tests" $Logs.Negative "powershell.exe" @(
    "-ExecutionPolicy", "Bypass",
    "-File", (Join-Path $Lab "scripts\negative_tests_windows.ps1"),
    $Tool
)
Assert-LogContains "Negative tests" $Logs.Negative "Windows negative test summary: pass=40 fail=0 total=40"
Copy-LegacyLog $Logs.Negative "negative_tests_windows.log"

Invoke-LoggedNative "Benchmark base" $Logs.Bench $Tool @(
    "bench",
    "--out", "artifacts\windows\bench\bench_windows_raw.csv",
    "--summary", "artifacts\windows\bench\bench_windows_summary.csv",
    "--runs", "10",
    "--ops", "10",
    "--sizes", "1k,16k,256k,1m",
    "--rsa-sizes", "32,190,318",
    "--rsa-bits", "3072,4096",
    "--platform", "windows-mingw64"
)
Copy-LegacyLog $Logs.Bench "bench_windows.log"

Invoke-LoggedNative "Benchmark Hybrid 100 MiB" $Logs.Bench100M $Tool @(
    "bench",
    "--out", "artifacts\windows\bench\bench_windows_hybrid_100m_raw.csv",
    "--summary", "artifacts\windows\bench\bench_windows_hybrid_100m_summary.csv",
    "--runs", "30",
    "--ops", "1",
    "--sizes", "100m",
    "--rsa-sizes", "32",
    "--rsa-bits", "3072,4096",
    "--platform", "windows-mingw64"
)
Copy-LegacyLog $Logs.Bench100M "bench_windows_hybrid_100m.log"

Write-Host "===== Artifact inventory ====="
@(
    "===== logs ====="
    Get-ChildItem -LiteralPath $LogDir -File | Sort-Object Name | ForEach-Object { "logs/$($_.Name)" }
    ""
    "===== benchmark CSVs ====="
    Get-ChildItem -LiteralPath $BenchDir -File -Filter "*.csv" | Sort-Object Name | ForEach-Object { "bench/$($_.Name)" }
    ""
    "===== generated vectors if any ====="
    Get-ChildItem -LiteralPath $VectorDir -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { "vectors/$($_.Name)" }
    ""
    "===== binaries copied by evidence runner ====="
    Get-ChildItem -LiteralPath $BinDir -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { "binaries/$($_.Name)" }
) | Set-Content -Encoding UTF8 $Logs.Inventory
Get-Content -LiteralPath $Logs.Inventory
Copy-LegacyLog $Logs.Inventory "artifact_inventory_windows.log"

Write-Host "===== Verification summary ====="
$BaseRaw = Join-Path $BenchDir "bench_windows_raw.csv"
$BaseSummary = Join-Path $BenchDir "bench_windows_summary.csv"
$Hybrid100MSummary = Join-Path $BenchDir "bench_windows_hybrid_100m_summary.csv"
$Checks = @(
    @{ Name = "CTest 14/14"; Pass = (Select-String -Path $Logs.CTest -Pattern "100% tests passed, 0 tests failed out of 14" -Quiet) },
    @{ Name = "KAT 5/5"; Pass = (Select-String -Path $Logs.Kat -Pattern "KAT standard: pass=5 fail=0 total=5" -Quiet) },
    @{ Name = "negative tests 40/40"; Pass = (Select-String -Path $Logs.Negative -Pattern "Windows negative test summary: pass=40 fail=0 total=40" -Quiet) },
    @{ Name = "base benchmark raw CSV exists"; Pass = (Test-Path -LiteralPath $BaseRaw) },
    @{ Name = "base benchmark summary CSV exists"; Pass = (Test-Path -LiteralPath $BaseSummary) },
    @{ Name = "Hybrid 100 MiB summary CSV exists"; Pass = (Test-Path -LiteralPath $Hybrid100MSummary) }
)
$VerificationLines = @("Lab 3 Windows standardized verification summary")
$AllPassed = $true
foreach ($Check in $Checks) {
    if ($Check.Pass) {
        $VerificationLines += "PASS - $($Check.Name)"
    } else {
        $VerificationLines += "FAIL - $($Check.Name)"
        $AllPassed = $false
    }
}
$VerificationLines | Set-Content -Encoding UTF8 $Logs.Verification
Get-Content -LiteralPath $Logs.Verification
if (!$AllPassed) {
    throw "Verification summary contains failures."
}

Write-Host "===== Lab 3 Windows standardized evidence run completed ====="
