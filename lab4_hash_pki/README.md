# Lab 4 - Hash and PKI

Windows-only first sprint for hashing and message authentication.

Implemented milestones:

- Project skeleton with CMake, CLI, tests, vectors, scripts, demos, and artifact folders.
- `hashtool --help`
- `hash` for SHA-2, SHA-3, SHAKE128, and SHAKE256 using OpenSSL.
- KAT runner for hash and SHAKE vectors.
- HMAC and intentionally vulnerable naive MAC demonstration.
- X.509 certificate parsing, signature verification, and policy checks.
- Windows negative tests registered with CTest.

Later milestone placeholders only:

- TLS
- MD5 collision demonstration
- Benchmarks
- Length-extension forging

## Build on Windows

```powershell
cmake -S lab4_hash_pki -B lab4_hash_pki/build
cmake --build lab4_hash_pki/build
ctest --test-dir lab4_hash_pki/build --output-on-failure
```

## Examples

```powershell
lab4_hash_pki\build\hashtool.exe --help
lab4_hash_pki\build\hashtool.exe hash --algo sha256 --text abc
lab4_hash_pki\build\hashtool.exe hash --algo sha512 --in file.bin --stream
lab4_hash_pki\build\hashtool.exe hash --algo sha3-512 --text abc
lab4_hash_pki\build\hashtool.exe hash --algo shake256 --outlen 64 --text abc
lab4_hash_pki\build\hashtool.exe kat --kat lab4_hash_pki\vectors\hash_kat.json
lab4_hash_pki\build\hashtool.exe kat --kat lab4_hash_pki\vectors\shake_kat.json
lab4_hash_pki\build\hashtool.exe naive-mac --algo sha256 --key-hex 001122 --text "comment=10&uid=1"
lab4_hash_pki\build\hashtool.exe hmac --algo sha256 --key-hex 001122 --text hello
lab4_hash_pki\build\hashtool.exe cert-info --cert lab4_hash_pki\tests\certs\leaf_valid.pem
lab4_hash_pki\build\hashtool.exe cert-info --cert lab4_hash_pki\tests\certs\leaf_valid.der --format der
lab4_hash_pki\build\hashtool.exe cert-info --cert lab4_hash_pki\tests\certs\leaf_valid.pem --json lab4_hash_pki\artifacts\windows\logs\cert_info.json
lab4_hash_pki\build\hashtool.exe cert-verify --cert lab4_hash_pki\tests\certs\leaf_valid.pem --issuer lab4_hash_pki\tests\certs\test_ca.pem
lab4_hash_pki\build\hashtool.exe cert-verify --cert lab4_hash_pki\tests\certs\leaf_valid.pem
lab4_hash_pki\build\hashtool.exe cert-policy --cert lab4_hash_pki\tests\certs\leaf_valid.pem
lab4_hash_pki\build\hashtool.exe bench --out lab4_hash_pki\artifacts\windows\bench\bench_windows_smoke_raw.csv --summary lab4_hash_pki\artifacts\windows\bench\bench_windows_smoke_summary.csv --runs 3 --ops 5 --warmup-ms 100 --sizes 1m --algos sha256,sha512,sha3-256,sha3-512 --platform windows11-mingw64
lab4_hash_pki\build\hashtool.exe length-extension-demo --out-dir lab4_hash_pki\demos\length_extension
```

## Certificate Commands

`cert-info` extracts the subject, issuer, subject public key algorithm and parameters, signature algorithm, validity window, key usage, extended key usage, subject alternative names, serial number, SHA-256 fingerprint, and a legacy SHA-1 fingerprint display.

`cert-verify` with `--issuer` verifies the certificate signature using the issuer public key and fails closed on malformed certificates, wrong issuers, or failed signatures. Without `--issuer`, it performs only structural parsing and prints:

```text
issuer key unavailable; full signature verification not performed
```

`cert-policy` prints machine-testable checks:

```text
CHECK <name> PASS|WARN|FAIL detail=<detail>
Policy summary: pass=N warn=M fail=K total=T
```

Current policy checks flag MD5 and SHA-1 signatures, RSA keys below 2048 bits, expired or not-yet-valid certificates, and missing SAN for TLS server use.

## Benchmarks

`bench` measures streaming file hashing with deterministic non-secret synthetic input generated in a temporary benchmark directory. The measured path uses the same streaming hash core as `hashtool hash --in FILE --stream`; large files are not loaded fully into memory during measurement.

Smoke benchmark for quick validation:

```powershell
lab4_hash_pki\build\hashtool.exe bench ^
  --out lab4_hash_pki\artifacts\windows\bench\bench_windows_smoke_raw.csv ^
  --summary lab4_hash_pki\artifacts\windows\bench\bench_windows_smoke_summary.csv ^
  --runs 3 ^
  --ops 5 ^
  --warmup-ms 100 ^
  --sizes 1m ^
  --algos sha256,sha512,sha3-256,sha3-512 ^
  --platform windows11-mingw64
```

Full benchmark for manual runs:

```powershell
lab4_hash_pki\build\hashtool.exe bench ^
  --out lab4_hash_pki\artifacts\windows\bench\bench_windows_raw.csv ^
  --summary lab4_hash_pki\artifacts\windows\bench\bench_windows_summary.csv ^
  --runs 30 ^
  --ops 100 ^
  --warmup-ms 1000 ^
  --sizes 1m,100m ^
  --algos sha256,sha512,sha3-256,sha3-512 ^
  --platform windows11-mingw64
```

Supported benchmark sizes are `1k`, `4k`, `1m`, `100m`, and `1g`. Automated tests run only the 1 MiB smoke benchmark; 100 MiB and 1 GiB inputs are intended for manual benchmark runs.

## Length-Extension Demo

`length-extension-demo` creates an offline defensive demonstration against the intentionally insecure construction `MAC = SHA256(key || message)`. It writes the original message/MAC, forged message/MAC, glue padding diagram, verification results, and a detailed README under `demos/length_extension/`.

The demo does not target a live service or network endpoint. It also shows that the forged message is accepted by the naive MAC check but rejected when checked as HMAC-SHA256.

Supported algorithms exactly:

- `sha224`
- `sha256`
- `sha384`
- `sha512`
- `sha3-224`
- `sha3-256`
- `sha3-384`
- `sha3-512`
- `shake128`
- `shake256`

Output encodings:

- `hex` default
- `base64`
- `raw`, only with `--out`
