# Lab 3 Windows Standardized Screenshot Commands

Run from PowerShell.

## 1. Environment summary

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\environment_windows_standard.log
```

## 2. Configure and build summary

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\configure_windows_standard.log
Get-Content artifacts\windows\logs\build_windows_standard.log
```

## 3. Help / CLI usage

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\help_windows_standard.log
```

## 4. CTest result

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\ctest_windows_standard.log
```

## 5. Unit test result

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\unit_tests_windows_standard.log
```

## 6. KAT result

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\kat_windows_standard.log
```

## 7. Negative tests full 40-case result

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\negative_tests_windows_standard.log
```

## 8. Base benchmark file list and benchmark log

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-ChildItem artifacts\windows\bench -Filter "bench_windows*.csv" | Sort-Object Name | Format-Table Name, Length, LastWriteTime -AutoSize
Get-Content artifacts\windows\logs\bench_windows_standard.log
```

## 9. Hybrid 100 MiB benchmark result

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\bench_windows_hybrid_100m_standard.log
Import-Csv artifacts\windows\bench\bench_windows_hybrid_100m_summary.csv | Where-Object { $_.family -eq "hybrid" -and $_.payload_bytes -eq "104857600" } | Format-Table platform, rsa_bits, family, operation, payload_bytes, runs, ops_per_run, mean_ms_per_op, mean_mib_s -AutoSize
```

## 10. OAEP limits and label evidence

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Select-String -Path artifacts\windows\logs\negative_tests_windows_standard.log,artifacts\windows\logs\ctest_windows_standard.log -Pattern "OAEP|oversized|wrong label|plaintext recovered|direct RSA|small"
```

## 11. PEM key and corrupted PEM evidence

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Select-String -Path artifacts\windows\logs\negative_tests_windows_standard.log -Pattern "PEM|metadata|corrupted PEM|MGF1-SHA256"
```

## 12. Hybrid AES-GCM tamper evidence

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Select-String -Path artifacts\windows\logs\negative_tests_windows_standard.log -Pattern "hybrid tampered ciphertext|hybrid tampered GCM tag|hybrid tampered encrypted AES key"
```

## 13. Envelope metadata/version/algorithm/label-indicator evidence

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Select-String -Path artifacts\windows\logs\negative_tests_windows_standard.log -Pattern "malformed envelope|unsupported version|algorithm mismatch|label indicator mismatch"
```

## 14. Auto mode small/large switching evidence

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Select-String -Path artifacts\windows\logs\negative_tests_windows_standard.log -Pattern "auto encrypt small|auto small|auto decrypt small|auto encrypt large|auto large"
```

## 15. Artifact inventory and verification summary

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab3_rsa_hybrid
Get-Content artifacts\windows\logs\artifact_inventory_windows_standard.log
Get-Content artifacts\windows\logs\verification_summary_windows_standard.log
```
