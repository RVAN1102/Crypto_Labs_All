# Lab 6: OpenSSL Post-Quantum Signatures and KEMs

`pqtool` is a cross-platform C++17 CLI using only OpenSSL provider APIs for
ML-DSA and ML-KEM. Ubuntu validation uses OpenSSL 4.0.1 installed separately
at `/opt/openssl-4.0`. OpenSSL 3.5+ is required; OpenSSL 3.0.x does not provide
the native ML-DSA/ML-KEM implementations required here.

Supported algorithms:

- ML-DSA-44 and ML-DSA-65: key generation, detached sign/verify, batch verify
- ML-KEM-512 and ML-KEM-768: key generation, encapsulation/decapsulation,
  batch decapsulation timing
- Educational canonical-JSON PQ certificates signed by ML-DSA
- Raw and summary CSV benchmarks plus valid/invalid timing-variance sampling

The JSON certificate is not X.509 and this project is not production PKI.
Official NIST/ACVP KAT files are not included; tests are OpenSSL roundtrips and
negative tests, not official KAT claims.

## Ubuntu

```bash
cd /home/rvan1102/Crypto_Labs_All/lab6_pqc
source ~/.openssl-4.0-env
bash scripts/build_linux.sh
bash scripts/test_linux.sh
bash scripts/demo_linux.sh
bash scripts/negative_tests_linux.sh
bash scripts/benchmark_linux.sh --quick
bash scripts/collect_evidence_linux.sh
```

## CLI examples

```bash
build-linux/pqtool keygen --algo mldsa-44 --pub pub.pem --priv priv.pem
build-linux/pqtool sign --algo mldsa-44 --priv priv.pem --in msg.bin --out sig.bin
build-linux/pqtool verify --algo mldsa-44 --pub pub.pem --in msg.bin --sig sig.bin
build-linux/pqtool keygen --algo mlkem-512 --pub kem-pub.pem --priv kem-priv.pem
build-linux/pqtool encaps --algo mlkem-512 --pub kem-pub.pem --ct ct.bin --ss sender.ss
build-linux/pqtool decaps --algo mlkem-512 --priv kem-priv.pem --ct ct.bin --ss recipient.ss
build-linux/pqtool cert-create --subject "Student Lab 6" --subject-pub pub.pem \
  --issuer "PQ-CA" --ca-priv ca-priv.pem --out cert.json
build-linux/pqtool cert-verify --cert cert.json --ca-pub ca-pub.pem
```

## Windows MinGW

After pulling the current Git branch (currently `master`):

```powershell
cd D:\Newfolder\Crypto_Labs_All\lab6_pqc
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows_mingw.ps1 -OpenSSLRoot "C:\OpenSSL-4.0"
powershell -ExecutionPolicy Bypass -File .\scripts\test_windows.ps1 -BuildDir "build-windows-mingw"
powershell -ExecutionPolicy Bypass -File .\scripts\demo_windows.ps1 -BuildDir "build-windows-mingw"
powershell -ExecutionPolicy Bypass -File .\scripts\negative_tests_windows.ps1 -BuildDir "build-windows-mingw"
powershell -ExecutionPolicy Bypass -File .\scripts\benchmark_windows.ps1 -BuildDir "build-windows-mingw" -Quick
powershell -ExecutionPolicy Bypass -File .\scripts\collect_evidence_windows.ps1 -BuildDir "build-windows-mingw"
```

For MSVC, run `build_windows_msvc.ps1` and pass `-BuildDir
"build-windows-msvc"` to the remaining scripts. Windows results must be
collected on Windows; Ubuntu validation does not claim a Windows pass.

