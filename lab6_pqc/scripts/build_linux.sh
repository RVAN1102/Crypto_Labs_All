#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR:-/opt/openssl-4.0}"
LOG_DIR="${ROOT}/artifacts/linux/logs"
mkdir -p "${LOG_DIR}"

export LD_LIBRARY_PATH="${OPENSSL_ROOT_DIR}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export PKG_CONFIG_PATH="${OPENSSL_ROOT_DIR}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"

{
    echo "OpenSSL root: ${OPENSSL_ROOT_DIR}"
    "${OPENSSL_ROOT_DIR}/bin/openssl" version -a
    cmake -S "${ROOT}" -B "${ROOT}/build-linux" \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR}"
    cmake --build "${ROOT}/build-linux" -j"$(nproc)"
} 2>&1 | tee "${LOG_DIR}/build_linux.log"

