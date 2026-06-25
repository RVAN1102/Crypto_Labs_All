# Lab 3 Ubuntu screenshot commands

## U01 - Ubuntu artifacts tree
cd ~/Crypto_Labs_All
find lab3_rsa_hybrid/artifacts/linux -maxdepth 4 -type f | sort

## U02 - Lab 3 tool help
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/help_linux.log

## U03 - CTest result
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/ctest_linux.log

## U04 - KAT result
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/kat_linux.log

## U05 - Negative tests
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/negative_tests_linux.log

## U06 - Benchmark files
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
find artifacts/linux/bench -maxdepth 1 -type f -print -exec ls -lh {} \;

## U07 - RSA-OAEP direct mode evidence
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
grep -iE "oaep|direct|small|limit|3072|4096" artifacts/linux/logs/ctest_linux.log artifacts/linux/logs/negative_tests_linux.log artifacts/linux/logs/kat_linux.log

## U08 - Hybrid encryption evidence
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
grep -iE "hybrid|seal|open|aes|gcm|wrap|envelope" artifacts/linux/logs/ctest_linux.log artifacts/linux/logs/negative_tests_linux.log artifacts/linux/logs/kat_linux.log

## U09 - Wrong key / wrong label evidence
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
grep -iE "wrong|label|private|reject|fail" artifacts/linux/logs/negative_tests_linux.log

## U10 - Tamper / malformed envelope evidence
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
grep -iE "tamper|malformed|ciphertext|tag|version|algorithm|envelope" artifacts/linux/logs/negative_tests_linux.log

## U11 - Hybrid 100 MiB benchmark
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/bench_linux_hybrid_100m.log
python3 - <<'PY'
import csv
p='artifacts/linux/bench/bench_linux_hybrid_100m_summary.csv'
with open(p, newline='') as f:
    for r in csv.DictReader(f):
        if r.get('family') == 'hybrid' and r.get('payload_bytes') == '104857600':
            print(r)
PY
