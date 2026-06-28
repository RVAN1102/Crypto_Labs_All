# Lab 1 Ubuntu Capture Commands

Run these commands from the repository root in Bash.

## U01 - Environment summary
```bash
cd lab1_aes
cat artifacts/linux/logs/environment_linux_standard.log
```

## U02 - Configure and build summary
```bash
cd lab1_aes
cat artifacts/linux/logs/configure_linux_standard.log
cat artifacts/linux/logs/build_linux_standard.log
```

## U03 - Help / CLI usage
```bash
cd lab1_aes
cat artifacts/linux/logs/help_linux_standard.log
```

## U04 - CTest result
```bash
cd lab1_aes
cat artifacts/linux/logs/ctest_linux_standard.log
```

## U05 - KAT sample and extended result
```bash
cd lab1_aes
cat artifacts/linux/logs/kat_linux_standard.log
```

## U06 - Negative test result
```bash
cd lab1_aes
cat artifacts/linux/logs/negative_tests_linux_standard.log
```

## U07 - Benchmark file list and benchmark summary
```bash
cd lab1_aes
ls -la artifacts/linux/bench
head -n 20 artifacts/linux/bench/bench_linux_summary.csv
```

## U08 - ECB restriction evidence
```bash
cd lab1_aes
grep -E "ECB|allow flag|large file" artifacts/linux/logs/negative_tests_linux_standard.log
```

## U09 - GCM fail-closed evidence
```bash
cd lab1_aes
grep -E "GCM|AAD|tag|tampered|wrong key|malformed|invalid" artifacts/linux/logs/negative_tests_linux_standard.log
```

## U10 - CTR/GCM nonce or IV reuse evidence
```bash
cd lab1_aes
grep -E "GCM first fixed nonce|GCM second fixed nonce|CTR first IV|CTR reused IV|nonce|IV" artifacts/linux/logs/negative_tests_linux_standard.log
```

## U11 - XTS limitation evidence
```bash
cd lab1_aes
grep -E "XTS|short input|without authentication|corrupted plaintext" artifacts/linux/logs/negative_tests_linux_standard.log
```
