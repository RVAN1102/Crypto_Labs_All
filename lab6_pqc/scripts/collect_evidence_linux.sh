#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "${ROOT}/.." && pwd)"
OPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR:-/opt/openssl-4.0}"
LOG="${ROOT}/artifacts/linux/logs/evidence_linux.log"
export PATH="${OPENSSL_ROOT_DIR}/bin:${PATH}"
export LD_LIBRARY_PATH="${OPENSSL_ROOT_DIR}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export PKG_CONFIG_PATH="${OPENSSL_ROOT_DIR}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
mkdir -p "$(dirname "${LOG}")"

{
    echo "=== OpenSSL ==="; openssl version -a
    echo "=== pkg-config OpenSSL ==="; pkg-config --modversion openssl
    echo "=== CMake ==="; cmake --version
    echo "=== C++ compiler ==="; c++ --version
    echo "=== Git branch ==="; git -C "${REPO}" branch --show-current
    echo "=== Git status ==="; git -C "${REPO}" status --short
    echo "=== pqtool SHA-256 ==="; sha256sum "${ROOT}/build-linux/pqtool"
    echo "=== Quality logs ==="
    for name in build_linux.log ctest_linux.log demo_linux.log negative_tests_linux.log benchmark_linux.log; do
        test -f "${ROOT}/artifacts/linux/logs/${name}"
        echo "${ROOT}/artifacts/linux/logs/${name}"
    done
    echo "=== Benchmark CSVs ==="
    find "${ROOT}/artifacts/linux/benchmarks" -maxdepth 1 -type f -name '*.csv' -print | sort
    echo "=== Non-secret summary ==="
    echo "OpenSSL provider algorithms, build, 20 CTest cases, functional demo,"
    echo "negative tests, and quick/full benchmark artifacts were collected."
    echo "No private key or shared-secret bytes are included in this log."
} 2>&1 | tee "${LOG}"

