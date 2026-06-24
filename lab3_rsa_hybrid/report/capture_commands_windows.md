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

## W11 - Hybrid 100 MiB benchmark
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\bench_windows_hybrid_100m.log
Import-Csv artifacts\windows\bench\bench_windows_hybrid_100m_summary.csv | Where-Object { $_.family -eq "hybrid" -and $_.payload_bytes -eq "104857600" } | Format-Table platform, rsa_bits, operation, payload_bytes, runs, ops_per_run, mean_ms_per_op, mean_mib_s -AutoSize
