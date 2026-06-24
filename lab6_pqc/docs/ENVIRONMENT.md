# Environment

Ubuntu validation targets the isolated installation `/opt/openssl-4.0` and
uses `~/.openssl-4.0-env` to set `PATH`, `LD_LIBRARY_PATH`,
`PKG_CONFIG_PATH`, and `OPENSSL_ROOT_DIR`. The system OpenSSL is unchanged.

The gate requires OpenSSL 3.5+ and provider discovery of `ML-DSA-44`,
`ML-DSA-65`, `ML-KEM-512`, and `ML-KEM-768`. The validated Ubuntu version is
OpenSSL 4.0.1.

CMake must be configured with:

```bash
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=/opt/openssl-4.0
```

