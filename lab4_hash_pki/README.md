# Lab 4 - Hash and PKI

Windows-only first sprint for hashing and message authentication.

Implemented milestones:

- Project skeleton with CMake, CLI, tests, vectors, scripts, demos, and artifact folders.
- `hashtool --help`
- `hash` for SHA-2, SHA-3, SHAKE128, and SHAKE256 using OpenSSL.
- KAT runner for hash and SHAKE vectors.
- HMAC and intentionally vulnerable naive MAC demonstration.
- Windows negative tests registered with CTest.

Later milestone placeholders only:

- X.509
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
```

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

