# Lab 1 Windows Capture Commands

Run these commands from PowerShell.

## W01 - Environment summary
```powershell
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Get-Content artifacts\windows\logs\environment_windows_standard.log
```

## W02 - Configure and build summary
```powershell
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Get-Content artifacts\windows\logs\configure_windows_standard.log
Get-Content artifacts\windows\logs\build_windows_standard.log
```

## W03 - Help / CLI usage
```powershell
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Get-Content artifacts\windows\logs\help_windows_standard.log
```

## W04 - CTest result
```powershell
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Get-Content artifacts\windows\logs\ctest_windows_standard.log
```

## W05 - KAT sample and extended result
```powershell
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Get-Content artifacts\windows\logs\kat_windows_standard.log
```

## W06 - Negative test result
```powershell
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Get-Content artifacts\windows\logs\negative_tests_windows_standard.log
```

## W07 - Benchmark file list and benchmark summary
```powershell
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Get-ChildItem artifacts\windows\bench
Get-Content artifacts\windows\bench\bench_windows_summary.csv -TotalCount 20
```

## W08 - ECB restriction evidence
```powershell
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\negative_tests_windows_standard.log -Pattern "ECB|allow flag|large file"
```

## W09 - GCM fail-closed evidence
```powershell
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\negative_tests_windows_standard.log -Pattern "GCM|AAD|tag|tampered|wrong key|malformed|invalid"
```

## W10 - CTR/GCM nonce or IV reuse evidence
```powershell
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\negative_tests_windows_standard.log -Pattern "GCM first fixed nonce|GCM second fixed nonce|CTR first IV|CTR reused IV|nonce|IV"
```

## W11 - XTS limitation evidence
```powershell
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\negative_tests_windows_standard.log -Pattern "XTS|short input|without authentication|corrupted plaintext"
```
