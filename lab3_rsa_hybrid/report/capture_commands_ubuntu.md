# Lab 3 Ubuntu Standardized Screenshot Commands

Run from Bash.

## 1. Environment summary

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/environment_linux_standard.log
```

## 2. Configure and build summary

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/configure_linux_standard.log
cat artifacts/linux/logs/build_linux_standard.log
```

## 3. Help / CLI usage

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/help_linux_standard.log
```

## 4. CTest result

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/ctest_linux_standard.log
```

## 5. Unit test result

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/unit_tests_linux_standard.log
```

## 6. KAT result

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/kat_linux_standard.log
```

## 7. Negative tests full 40-case result

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/negative_tests_linux_standard.log
```

## 8. Base benchmark file list and benchmark log

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
find artifacts/linux/bench -maxdepth 1 -type f -name 'bench_linux*.csv' -printf '%f %s bytes\n' | sort
cat artifacts/linux/logs/bench_linux_standard.log
```

## 9. Hybrid 100 MiB benchmark result

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/bench_linux_hybrid_100m_standard.log
python3 - <<'PY'
import csv
with open('artifacts/linux/bench/bench_linux_hybrid_100m_summary.csv', newline='') as f:
    for row in csv.DictReader(f):
        if row.get('family') == 'hybrid' and row.get('payload_bytes') == '104857600':
            print(row)
PY
```

## 10. OAEP limits and label evidence

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
grep -iE "OAEP|oversized|wrong label|plaintext recovered|direct RSA|small" artifacts/linux/logs/negative_tests_linux_standard.log artifacts/linux/logs/ctest_linux_standard.log
```

## 11. PEM key and corrupted PEM evidence

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
grep -iE "PEM|metadata|corrupted PEM|MGF1-SHA256" artifacts/linux/logs/negative_tests_linux_standard.log
```

## 12. Hybrid AES-GCM tamper evidence

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
grep -iE "hybrid tampered ciphertext|hybrid tampered GCM tag|hybrid tampered encrypted AES key" artifacts/linux/logs/negative_tests_linux_standard.log
```

## 13. Envelope metadata/version/algorithm/label-indicator evidence

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
grep -iE "malformed envelope|unsupported version|algorithm mismatch|label indicator mismatch" artifacts/linux/logs/negative_tests_linux_standard.log
```

## 14. Auto mode small/large switching evidence

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
grep -iE "auto encrypt small|auto small|auto decrypt small|auto encrypt large|auto large" artifacts/linux/logs/negative_tests_linux_standard.log
```

## 15. Artifact inventory and verification summary

```bash
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/artifact_inventory_linux_standard.log
cat artifacts/linux/logs/verification_summary_linux_standard.log
```
