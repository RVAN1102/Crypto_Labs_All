# Lab 5 - Classical Digital Signatures

This lab implements the full main Lab 5 requirements in `sigtool`, a C++17 command-line tool for detached digital signatures using OpenSSL.

## Features

- ECDSA over NIST P-256 / secp256r1 with SHA-256.
- Deterministic ECDSA nonces using RFC 6979 HMAC-SHA256.
- RSA-PSS with RSA-3072, SHA-256, MGF1-SHA256, 32-byte randomized salt, and public exponent 65537.
- Detached signatures over binary-safe file input.
- PEM keys by default, with DER key output selected by `--format der` or `.der` paths.
- Signature encodings:
  - ECDSA: `der`, `raw` as `r || s`, and `base64` over DER.
  - RSA-PSS: `raw` and `base64`; `der` is accepted as the same detached RSA signature bytes.
- CTest integration, unit tests, CLI negative tests, KAT/correctness runner, and CSV benchmarks.
- Batch verification using a CSV manifest.

## Dependencies

Windows MinGW64:

- CMake 3.20 or newer
- MinGW64 C++ compiler
- OpenSSL development package
- GoogleTest when available

Ubuntu/Linux:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev libgtest-dev
```

## Build on Windows

```powershell
cmake -S lab5_signatures -B lab5_signatures/build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build lab5_signatures/build
ctest --test-dir lab5_signatures/build --output-on-failure
```

If OpenSSL is not found automatically:

```powershell
cmake -S lab5_signatures -B lab5_signatures/build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=C:/msys64/mingw64
```

Helper scripts save logs under `artifacts/windows/logs`:

```powershell
powershell -ExecutionPolicy Bypass -File lab5_signatures/scripts/build_windows.ps1
powershell -ExecutionPolicy Bypass -File lab5_signatures/scripts/test_windows.ps1
```

## Build on Ubuntu

```bash
cmake -S lab5_signatures -B lab5_signatures/build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build lab5_signatures/build-linux -j"$(nproc)"
ctest --test-dir lab5_signatures/build-linux --output-on-failure
```

Helper scripts:

```bash
bash lab5_signatures/scripts/build_linux.sh
bash lab5_signatures/scripts/test_linux.sh
bash lab5_signatures/scripts/run_lab5_ubuntu_evidence.sh
```

The evidence script configures, builds, runs CTest, exercises PEM and DER keys,
checks deterministic ECDSA and randomized RSA-PSS behavior, runs negative and
batch tests, and executes the final 30-run benchmark.

## CLI Usage

ECDSA-P256:

```powershell
lab5_signatures\build\sigtool.exe keygen --algo ecdsa-p256 --pub pub.pem --priv priv.pem --meta key.json
lab5_signatures\build\sigtool.exe sign --algo ecdsa-p256 --priv priv.pem --in msg.bin --out sig.der --hash sha256 --encode der
lab5_signatures\build\sigtool.exe verify --algo ecdsa-p256 --pub pub.pem --in msg.bin --sig sig.der --hash sha256 --encode der
```

RSA-PSS-3072:

```powershell
lab5_signatures\build\sigtool.exe keygen --algo rsa-pss-3072 --pub rsa_pub.pem --priv rsa_priv.pem
lab5_signatures\build\sigtool.exe sign --algo rsa-pss-3072 --priv rsa_priv.pem --in msg.bin --out rsa.sig --hash sha256 --encode raw
lab5_signatures\build\sigtool.exe verify --algo rsa-pss-3072 --pub rsa_pub.pem --in msg.bin --sig rsa.sig --hash sha256 --encode raw
```

DER keys:

```powershell
lab5_signatures\build\sigtool.exe keygen --algo ecdsa-p256 --pub pub.der --priv priv.der --format der
```

Batch verification manifest format:

```text
message1.bin,signature1.bin
message2.bin,signature2.bin
```

```powershell
lab5_signatures\build\sigtool.exe batch-verify --algo ecdsa-p256 --pub pub.pem --manifest manifest.csv --hash sha256 --encode der
```

## Tests

CTest includes:

- `sigtool_help`
- `sigtool_kat`
- GoogleTest unit tests when GoogleTest is available
- Windows or Linux negative CLI tests
- smoke benchmark test

Negative tests cover modified messages, modified signatures, wrong public keys,
wrong algorithm identifiers, wrong hash names, malformed keys, malformed
signatures, unsupported encodings, unsupported key formats, unsupported
parameters, base64 signatures, and batch verification. The
`sigtool_cli_requirements` CTest performs DER keygen/sign/verify end to end for
both required algorithms.

## Benchmarks

Smoke benchmark:

```powershell
lab5_signatures\build\sigtool.exe bench --out lab5_signatures\artifacts\windows\bench\bench_windows_smoke_raw.csv --summary lab5_signatures\artifacts\windows\bench\bench_windows_smoke_summary.csv --runs 1 --ops 1 --sizes 1k --algos ecdsa-p256,rsa-pss-3072 --platform windows-mingw64
```

Full benchmark target:

```powershell
lab5_signatures\build\sigtool.exe bench --out lab5_signatures\artifacts\windows\bench\bench_windows_raw.csv --summary lab5_signatures\artifacts\windows\bench\bench_windows_summary.csv --runs 30 --ops 1 --sizes 1k,16k,1m,8m --algos ecdsa-p256,rsa-pss-3072 --platform windows-mingw64
```

The final protocol runs both algorithms and all three operations (`keygen`,
`sign`, and `verify`) with at least 30 runs. Sign and verify use 1 KiB, 16 KiB,
1 MiB, and 8 MiB messages. The raw CSV contains every timing sample. The summary
CSV reports mean, median, sample standard deviation, approximate 95% confidence
interval, and throughput in operations per second.

## File Formats and Metadata

`keygen --meta key.json` writes key metadata with the algorithm, hash, key parameters, format, and output paths. Signatures are detached files and do not embed message data.

## Self-Grade Checklist

- [x] ECDSA-P256 with SHA-256 implemented.
- [x] RFC 6979 deterministic ECDSA nonce implemented and tested.
- [x] RSA-PSS-3072 with SHA-256, MGF1-SHA256, 32-byte salt, and exponent 65537 implemented.
- [x] PEM keys supported.
- [x] DER keys supported.
- [x] Detached signatures supported.
- [x] Raw, DER, and base64 signature encodings supported where applicable.
- [x] Binary-safe file I/O.
- [x] CLI keygen/sign/verify/batch-verify implemented.
- [x] Fail-closed malformed input behavior covered by tests.
- [x] GoogleTest unit tests included.
- [x] CTest integration included.
- [x] Negative tests included for Windows and Linux.
- [x] Benchmark runner writes raw and summary CSV.
- [x] Artifact/log directories included.
- [x] No Lab 2 work and no Lab 1/3/4 implementation changes.
- [x] Ubuntu evidence script covers the complete main-requirement workflow.

## Academic Integrity and AI Assistance

This implementation was prepared with AI coding assistance. The algorithms, parameters, command behavior, tests, and limitations are documented so the work can be reviewed and reproduced. OpenSSL provides the cryptographic primitives and key serialization. The ECDSA RFC 6979 nonce derivation is implemented in this lab code and is covered by deterministic repeatability tests.

## Current Limitations

- ECDSA-P384 is not included; the required ECDSA-P256 and RSA-PSS-3072 paths are prioritized.
- Advanced formula-level bonus work is not included or claimed.
- The `kat` command is a local correctness runner rather than a third-party published vector parser.
- Windows evidence scripts are provided, but Windows commands are not run from Ubuntu.
