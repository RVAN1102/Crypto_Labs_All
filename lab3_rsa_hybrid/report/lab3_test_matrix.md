# Lab 3 Standardized Cross-Platform Test Matrix

Lab 3 evidence is standardized so Windows and Ubuntu use the same logical checks, case names, benchmark protocols, capture groups, and report-facing log names.

## Evidence logs

| Evidence group | Windows log | Ubuntu log |
| --- | --- | --- |
| Environment | `artifacts/windows/logs/environment_windows_standard.log` | `artifacts/linux/logs/environment_linux_standard.log` |
| Configure | `artifacts/windows/logs/configure_windows_standard.log` | `artifacts/linux/logs/configure_linux_standard.log` |
| Build | `artifacts/windows/logs/build_windows_standard.log` | `artifacts/linux/logs/build_linux_standard.log` |
| Help / CLI | `artifacts/windows/logs/help_windows_standard.log` | `artifacts/linux/logs/help_linux_standard.log` |
| CTest | `artifacts/windows/logs/ctest_windows_standard.log` | `artifacts/linux/logs/ctest_linux_standard.log` |
| Unit tests | `artifacts/windows/logs/unit_tests_windows_standard.log` | `artifacts/linux/logs/unit_tests_linux_standard.log` |
| KAT | `artifacts/windows/logs/kat_windows_standard.log` | `artifacts/linux/logs/kat_linux_standard.log` |
| Negative tests | `artifacts/windows/logs/negative_tests_windows_standard.log` | `artifacts/linux/logs/negative_tests_linux_standard.log` |
| Base benchmark | `artifacts/windows/logs/bench_windows_standard.log` | `artifacts/linux/logs/bench_linux_standard.log` |
| Hybrid 100 MiB benchmark | `artifacts/windows/logs/bench_windows_hybrid_100m_standard.log` | `artifacts/linux/logs/bench_linux_hybrid_100m_standard.log` |
| Artifact inventory | `artifacts/windows/logs/artifact_inventory_windows_standard.log` | `artifacts/linux/logs/artifact_inventory_linux_standard.log` |
| Verification summary | `artifacts/windows/logs/verification_summary_windows_standard.log` | `artifacts/linux/logs/verification_summary_linux_standard.log` |

## CTest

Both platforms run CTest from the platform build directory and must show:

```text
100% tests passed, 0 tests failed out of 14
```

## KAT

Both platforms run:

```text
rsatool kat --kat vectors/rsa_hybrid_kat.json
```

Required result:

```text
KAT summary: pass=5, fail=0, total=5
KAT standard: pass=5 fail=0 total=5
```

## Negative tests

Both platforms run the same 40 logical cases in this order, with `[PASS] <case name>` or `[FAIL] <case name>` output.

1. keygen RSA-3072
2. keygen wrong RSA-3072
3. keygen RSA-3072 PEM aliases with metadata
4. keygen RSA-2048 rejected
5. key metadata records MGF1-SHA256
6. OAEP encrypt baseline
7. OAEP decrypt baseline
8. OAEP plaintext recovered
9. OAEP wrong label rejected
10. OAEP wrong private key rejected
11. OAEP PEM encrypt baseline
12. OAEP PEM decrypt baseline
13. OAEP PEM plaintext recovered
14. corrupted PEM public key rejected
15. OAEP oversized plaintext rejected
16. hybrid encrypt baseline
17. hybrid decrypt baseline
18. hybrid plaintext recovered
19. hybrid PEM encrypt baseline
20. hybrid PEM decrypt baseline
21. hybrid PEM plaintext recovered
22. hybrid wrong label rejected
23. hybrid wrong private key rejected
24. hybrid tampered ciphertext rejected
25. hybrid tampered GCM tag rejected
26. hybrid tampered encrypted AES key rejected
27. hybrid malformed envelope rejected
28. hybrid unsupported version rejected
29. hybrid algorithm mismatch rejected
30. hybrid label indicator mismatch rejected
31. auto encrypt small uses OAEP
32. auto small output is direct RSA ciphertext
33. auto decrypt small OAEP
34. auto small plaintext recovered
35. auto decrypt wrong label rejected
36. auto encrypt large switches to hybrid
37. auto large envelope sidecar created
38. auto decrypt large discovers envelope
39. auto large plaintext recovered
40. auto decrypt malformed envelope rejected

Required summaries:

```text
Windows negative test summary: pass=40 fail=0 total=40
Linux negative test summary: pass=40 fail=0 total=40
```

## Base benchmark

Both platforms use the same base benchmark protocol:

| Setting | Value |
| --- | --- |
| RSA key sizes | `3072,4096` |
| RSA-OAEP payloads | `32,190,318` bytes, skipping sizes that exceed the key limit |
| Hybrid payloads | `1k,16k,256k,1m` |
| Runs | `10` |
| Ops per run | `10` |
| Operations | RSA-OAEP encrypt/decrypt and hybrid encrypt/decrypt |

Raw CSV schema:

```text
platform,rsa_bits,family,operation,payload_bytes,run_index,ops,total_ms,ms_per_op,throughput_mib_s
```

Summary CSV schema:

```text
platform,rsa_bits,family,operation,payload_bytes,runs,ops_per_run,mean_ms_per_op,median_ms_per_op,stddev_ms_per_op,ci95_ms_per_op,mean_mib_s,median_mib_s,stddev_mib_s,ci95_mib_s
```

Required output files:

| Platform | Raw CSV | Summary CSV |
| --- | --- | --- |
| Windows | `artifacts/windows/bench/bench_windows_raw.csv` | `artifacts/windows/bench/bench_windows_summary.csv` |
| Ubuntu | `artifacts/linux/bench/bench_linux_raw.csv` | `artifacts/linux/bench/bench_linux_summary.csv` |

## Hybrid 100 MiB benchmark

Both platforms use:

| Setting | Value |
| --- | --- |
| Hybrid payload | `104857600` bytes |
| Runs | `30` |
| Ops per run | `1` |
| RSA key sizes | `3072,4096` |
| Required operations | Hybrid encrypt/decrypt for RSA-3072 and RSA-4096 |

The benchmark command uses `--sizes 100m --rsa-sizes 32 --rsa-bits 3072,4096` so the tool emits the required hybrid rows while preserving its existing benchmark CSV schema.

Required summary CSVs:

| Platform | Summary CSV |
| --- | --- |
| Windows | `artifacts/windows/bench/bench_windows_hybrid_100m_summary.csv` |
| Ubuntu | `artifacts/linux/bench/bench_linux_hybrid_100m_summary.csv` |

## Screenshot groups

Windows and Ubuntu capture command files use the same 15 logical screenshot groups:

1. Environment summary
2. Configure and build summary
3. Help / CLI usage
4. CTest result
5. Unit test result
6. KAT result
7. Negative tests full 40-case result
8. Base benchmark file list and benchmark log
9. Hybrid 100 MiB benchmark result
10. OAEP limits and label evidence
11. PEM key and corrupted PEM evidence
12. Hybrid AES-GCM tamper evidence
13. Envelope metadata/version/algorithm/label-indicator evidence
14. Auto mode small/large switching evidence
15. Artifact inventory and verification summary
