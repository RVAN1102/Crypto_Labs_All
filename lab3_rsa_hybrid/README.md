# Lab 3 - RSA-OAEP(SHA-256) and Hybrid Encryption

This lab implements `rsatool`, a C++17 command-line tool using Crypto++ for RSA-OAEP with SHA-256 and hybrid file encryption with AES-256-GCM.

## Features

- RSA key generation for RSA-3072 and RSA-4096 in DER format.
- Direct RSA-OAEP encryption/decryption with SHA-256 explicitly selected.
- Optional OAEP label via text, file, or hex input.
- Direct RSA-OAEP plaintext limits are enforced:
  - RSA-3072: 318 bytes
  - RSA-4096: 446 bytes
- Hybrid encryption for files:
  1. Generate a fresh AES-256 key using Crypto++ `AutoSeededRandomPool`.
  2. Encrypt data with AES-256-GCM.
  3. Encrypt the AES key with RSA-OAEP(SHA-256).
  4. Store envelope metadata in JSON.
- GoogleTest unit tests, CTest integration, correctness KAT runner, negative tests, and CSV benchmarks.

## Build

Windows MinGW64:

```bat
cmake -S . -B build -G "MinGW Makefiles" -DCRYPTOPP_ROOT="D:/Newfolder/Crypto++" -DCMAKE_BUILD_TYPE=Release
cmake --build build -j12
```

Ubuntu/Linux:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

## Commands

Generate RSA-3072 keys:

```bat
build\rsatool.exe keygen --bits 3072 --private private.der --public public.der
```

Direct RSA-OAEP for small messages:

```bat
build\rsatool.exe oaep-encrypt --pub public.der --text "small message" --out msg.rsa --label-text "lab3"
build\rsatool.exe oaep-decrypt --priv private.der --in msg.rsa --out msg.txt --label-text "lab3"
```

Hybrid encryption for files:

```bat
build\rsatool.exe seal --pub public.der --in plain.bin --out cipher.bin --envelope cipher.bin.envelope.json --label-text "lab3"
build\rsatool.exe open --priv private.der --in cipher.bin --envelope cipher.bin.envelope.json --out recovered.bin --label-text "lab3"
```

Aliases:

```bat
build\rsatool.exe hybrid-encrypt --pub public.der --in plain.bin --out cipher.bin --envelope env.json
build\rsatool.exe hybrid-decrypt --priv private.der --in cipher.bin --envelope env.json --out recovered.bin
```

Run KAT/correctness tests:

```bat
build\rsatool.exe kat --kat vectors\rsa_hybrid_kat.json
```

Run benchmarks:

```bat
build\rsatool.exe bench --out artifacts\windows\bench\bench_windows_raw.csv --summary artifacts\windows\bench\bench_windows_summary.csv --runs 3 --ops 3 --sizes 1k,16k --rsa-sizes 32,190 --rsa-bits 3072,4096 --platform windows-mingw64
```

Run all tests:

```bat
ctest --test-dir build --output-on-failure
```

## Envelope Format

Hybrid mode writes raw AES-GCM ciphertext to the selected output file and stores metadata in a JSON envelope. The envelope includes:

- `version`
- `envelope_alg`
- `key_alg`
- `content_alg`
- `rsa_bits`
- `oaep_hash`
- `oaep_label_present`
- `oaep_label_sha256_hex`
- `encrypted_key_hex`
- `nonce_hex`
- `tag_hex`
- `ciphertext_mode`
- `ciphertext_file`

Decryption validates the envelope version, algorithm identifiers, RSA size, OAEP label hash, encrypted AES key, nonce, and tag. Wrong keys, wrong labels, tampered ciphertext, tampered GCM tags, tampered encrypted AES keys, malformed envelopes, unsupported versions, and algorithm mismatches fail closed.

## Artifacts

Windows artifacts are stored under:

```text
artifacts/windows/
  bench/
  binaries/
  logs/
  vectors/
```

Linux artifacts use the same structure under `artifacts/linux/`.

## Self-Grade Checklist

- [x] RSA-OAEP uses SHA-256 explicitly.
- [x] RSA-3072 minimum enforced.
- [x] RSA-3072 and RSA-4096 supported.
- [x] Optional OAEP label supported.
- [x] Direct RSA plaintext limits enforced.
- [x] Hybrid AES-256-GCM envelope implemented.
- [x] Binary-safe file I/O.
- [x] GoogleTest and CTest integrated.
- [x] KAT/correctness runner included.
- [x] Negative tests for Windows and Linux included.
- [x] Benchmark raw and summary CSV output included.
- [x] No GUI, DOCX, or PDF report.

## Academic Integrity and AI Assistance

This implementation was prepared with AI coding assistance. The cryptographic design choices, parameters, tests, and limitations are documented here so the work can be reviewed and reproduced. Crypto++ is used for all cryptographic primitives; no custom RSA, OAEP, AES, GCM, or random-number generation is implemented.

## Current Limitations

- DER key format is implemented. PEM support is intentionally not included in this version.
- Envelope JSON parsing is strict and intentionally minimal for this lab format.
- Linux build and artifact logs should be generated separately after the Windows acceptance path passes.
