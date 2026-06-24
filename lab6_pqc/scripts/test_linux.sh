#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR:-/opt/openssl-4.0}"
mkdir -p "${ROOT}/artifacts/linux/logs"
export LD_LIBRARY_PATH="${OPENSSL_ROOT_DIR}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

ctest --test-dir "${ROOT}/build-linux" --output-on-failure 2>&1 |
    tee "${ROOT}/artifacts/linux/logs/ctest_linux.log"

