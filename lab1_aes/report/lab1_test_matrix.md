# Lab 1 Cross-Platform Evidence Matrix

Windows and Ubuntu evidence runs must use the same validation targets and standardized log names.

## Standard Evidence Logs

| Evidence group | Windows log | Ubuntu log |
| --- | --- | --- |
| Environment | `artifacts/windows/logs/environment_windows_standard.log` | `artifacts/linux/logs/environment_linux_standard.log` |
| Configure | `artifacts/windows/logs/configure_windows_standard.log` | `artifacts/linux/logs/configure_linux_standard.log` |
| Build | `artifacts/windows/logs/build_windows_standard.log` | `artifacts/linux/logs/build_linux_standard.log` |
| Help / CLI | `artifacts/windows/logs/help_windows_standard.log` | `artifacts/linux/logs/help_linux_standard.log` |
| CTest | `artifacts/windows/logs/ctest_windows_standard.log` | `artifacts/linux/logs/ctest_linux_standard.log` |
| KAT | `artifacts/windows/logs/kat_windows_standard.log` | `artifacts/linux/logs/kat_linux_standard.log` |
| Negative tests | `artifacts/windows/logs/negative_tests_windows_standard.log` | `artifacts/linux/logs/negative_tests_linux_standard.log` |
| Benchmark | `artifacts/windows/logs/bench_windows_standard.log` | `artifacts/linux/logs/bench_linux_standard.log` |
| Artifact inventory | `artifacts/windows/logs/artifact_inventory_windows_standard.log` | `artifacts/linux/logs/artifact_inventory_linux_standard.log` |

## Required Summaries

- CTest: `100% tests passed, 0 tests failed out of 14`.
- KAT sample: `KAT sample: pass=8 fail=0 total=8`.
- KAT extended: `KAT extended: pass=14 fail=0 total=14`.
- Windows negative tests: `Windows negative test summary: pass=29 fail=0 total=29`.
- Ubuntu negative tests: `Linux negative test summary: pass=29 fail=0 total=29`.

## Negative Test Cases

1. Generate AES-256 key
2. Generate wrong AES-256 key
3. GCM encrypt
4. GCM decrypt
5. GCM recovered plaintext equals original
6. GCM wrong key rejected
7. GCM wrong AAD rejected
8. GCM tampered ciphertext rejected
9. GCM tampered tag rejected
10. GCM malformed metadata rejected
11. GCM invalid AES key length rejected
12. GCM invalid GCM nonce length rejected
13. GCM first fixed nonce accepted
14. GCM second fixed nonce rejected
15. CCM encrypt
16. CCM decrypt baseline
17. CCM recovered plaintext equals original
18. CCM tampered ciphertext rejected
19. CTR encrypt
20. CTR decrypt baseline
21. CTR recovered plaintext equals original
22. CTR tampering produces corrupted plaintext
23. CTR first IV accepted
24. CTR reused IV rejected
25. ECB large file blocked by default
26. ECB large file allowed with allow flag
27. XTS short input rejected
28. XTS encrypt valid data unit
29. XTS tampering produces corrupted plaintext without authentication

## Benchmark Protocol

- Modes: ecb, cbc, cfb, ofb, ctr, gcm, ccm, xts.
- Operations: encrypt and decrypt.
- Payloads: 1 KiB, 4 KiB, 16 KiB, 256 KiB, 1 MiB, 8 MiB.
- Runs: 30.
- ops_per_run: 100.
- Outputs: raw CSV and summary CSV with matching schemas on both platforms.

The evidence runners may copy standardized logs to old filenames for compatibility. Report-facing capture commands use only the standardized names.
