# Lab 1 â€” Symmetric Encryption with Crypto++

## 1. Overview

This project implements `aestool`, a command-line AES encryption tool for Lab 1 of Cryptography & Applications. The tool uses Crypto++ for all cryptographic primitives and supports the AES modes required by the lab: ECB, CBC, CFB, OFB, CTR, XTS, CCM, and GCM.

The implementation focuses on secure engineering practices, including binary-safe file I/O, UTF-8 text input, sidecar metadata for IV, nonce, tweak, and authentication tag storage, AEAD authentication checks, misuse prevention, Known Answer Tests, negative tests, CTest integration, and performance benchmarking.

## 2. Supported Features

The current implementation supports AES-ECB, AES-CBC, AES-CFB, AES-OFB, AES-CTR, AES-GCM, AES-CCM, and AES-XTS. GCM and CCM support AAD and authentication tag verification. XTS supports 256-bit or 512-bit XTS key material and a 16-byte tweak. The tool also supports raw binary file input/output, console encoding as hex or base64, sidecar JSON metadata, nonce/IV reuse detection for CTR, GCM, and CCM, ECB warning and large-file restriction, JSON Known Answer Tests, Windows negative tests, CTest integration, and benchmark CSV output.

## 3. Environment

### Windows Test Environment

| Item | Value |
|---|---|
| Operating system | Windows 11 25H2 |
| Compiler | MinGW64 g++ 16.0.1 |
| CMake | 4.3.3 |
| Crypto++ | 8.9.0 |
| Crypto++ root | `D:/Newfolder/Crypto++` |
| CPU | AMD Ryzen 5 7535HS with Radeon Graphics |
| Cores / threads | 6 cores / 12 threads |
| RAM | 8 GB |
| Storage | Samsung MZVL8512HELU-00BTW SSD |
| Power mode | performance |

## 4. Build Instructions on Windows

Configure the project:

```bat
cmake -S . -B build -G "MinGW Makefiles" ^
  -DCRYPTOPP_ROOT="D:/Newfolder/Crypto++" ^
  -DCMAKE_BUILD_TYPE=Release
```

Build the executable:

```bat
cmake --build build -j12
```

Run help:

```bat
build\aestool.exe --help
```

## 5. Basic Usage

Generate an AES-256 key:

```bat
build\aestool.exe keygen --bits 256 --out key.bin
```

Encrypt with AES-GCM:

```bat
build\aestool.exe encrypt --mode gcm --key key.bin --text "Hello Lab 1" --out ct_gcm.bin --aad-text "lab1"
```

Decrypt with AES-GCM:

```bat
build\aestool.exe decrypt --mode gcm --key key.bin --in ct_gcm.bin --out pt_gcm.txt --aad-text "lab1"
```

Encrypt with AES-CBC:

```bat
build\aestool.exe encrypt --mode cbc --key key.bin --text "Hello CBC" --out ct_cbc.bin
```

Decrypt with AES-CBC:

```bat
build\aestool.exe decrypt --mode cbc --key key.bin --in ct_cbc.bin --out pt_cbc.txt
```

Generate 512-bit XTS key material:

```bat
build\aestool.exe keygen --bits 512 --out xts_key.bin
```

Encrypt with AES-XTS:

```bat
build\aestool.exe encrypt --mode xts --key xts_key.bin --text "This is a valid AES-XTS data unit." --out ct_xts.bin
```

Decrypt with AES-XTS:

```bat
build\aestool.exe decrypt --mode xts --key xts_key.bin --in ct_xts.bin --out pt_xts.txt
```

## 6. Metadata Format

Encryption writes raw ciphertext to the selected output file and creates a sidecar JSON metadata file using the default name:

```text
<output-file>.meta.json
```

For GCM and CCM, the metadata contains the nonce and authentication tag. For CBC, CFB, OFB, and CTR, the metadata contains the IV. For XTS, the metadata contains the 16-byte tweak. ECB does not use IV metadata.

## 7. Known Answer Tests

Run KAT:

```bat
build\aestool.exe kat --kat vectors\aes_kat_sample.json
```

Expected result:

```text
KAT summary: pass=8, fail=0, total=8
```

The current KAT sample covers AES-128 ECB single-block FIPS-197, AES-128 CBC/CFB/OFB/CTR from NIST SP 800-38A, AES-128 GCM vectors, and an AES-CCM packet vector.

## 8. Negative Testing

Run Windows negative tests:

```bat
powershell -ExecutionPolicy Bypass -File scripts\negative_tests_windows.ps1 -Exe ".\build\aestool.exe"
```

The negative test script checks wrong key handling, wrong AAD handling, tampered GCM ciphertext, tampered GCM tag, malformed metadata, invalid key length, invalid IV/nonce length, nonce reuse rejection for GCM and CTR, tampered CCM ciphertext, CTR tampering behavior without authentication, ECB large-file blocking, ECB override using `--allow-ecb`, XTS short input rejection, and XTS tampering behavior without authentication.

## 9. CTest

Run all configured tests:

```bat
ctest --test-dir build --output-on-failure
```

Expected result:

```text
100% tests passed, 0 tests failed
```

The current CTest configuration runs the KAT sample and the Windows negative test script.

## 10. Benchmarking

Run benchmark on Windows:

```bat
build\aestool.exe bench ^
  --out bench_windows_raw.csv ^
  --summary bench_windows_summary.csv ^
  --runs 30 ^
  --ops 100 ^
  --warmup-ms 1000 ^
  --sizes 1k,4k,16k,256k,1m,8m ^
  --modes ecb,cbc,cfb,ofb,ctr,gcm,ccm,xts ^
  --platform windows11-mingw64
```

The raw CSV contains per-run measurements. The summary CSV contains mean, median, standard deviation, and 95% confidence interval for latency and throughput.

## 11. Artifacts

Windows artifacts are stored under:

```text
artifacts/windows/
```

Recommended structure:

```text
artifacts/windows/
â”œâ”€â”€ binaries/
â”‚   â””â”€â”€ aestool.exe
â”œâ”€â”€ bench/
â”‚   â”œâ”€â”€ bench_windows_raw.csv
â”‚   â””â”€â”€ bench_windows_summary.csv
â””â”€â”€ logs/
    â”œâ”€â”€ build_windows_mingw64.log
    â”œâ”€â”€ kat_windows.log
    â”œâ”€â”€ negative_tests_windows.log
    â””â”€â”€ ctest_windows.log
```

## 12. Security Notes

ECB mode is implemented only because it is required by the lab. The tool prints a warning when ECB is selected and blocks files larger than 16 KiB unless `--allow-ecb` is explicitly used.

CTR, GCM, and CCM require unique nonce/IV values under the same key. The tool implements a local registry based on `mode + SHA256(key) + nonce/IV` and rejects reuse.

GCM and CCM are AEAD modes. Decryption fails closed when the ciphertext, AAD, or authentication tag is modified.

CBC, CFB, OFB, CTR, ECB, and XTS do not provide integrity protection. Tampering may produce corrupted plaintext without reliable detection. XTS is intended for storage-like data units and is not an authenticated encryption mode.

## 13. Current Limitations

Linux build and benchmark results are not included yet. MSVC build verification is not included yet. KAT coverage is currently representative and can be extended with more vectors. The nonce reuse registry is a local misuse-prevention mechanism and is not a tamper-resistant security database.
