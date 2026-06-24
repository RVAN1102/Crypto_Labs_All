#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB="$ROOT/lab5_signatures"
BUILD_DIR="${1:-$LAB/build-linux}"
LOG_DIR="$LAB/artifacts/linux/logs"
mkdir -p "$LOG_DIR"

cmake -S "$LAB" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release 2>&1 | tee "$LOG_DIR/configure_linux.log"
cmake --build "$BUILD_DIR" -j"$(nproc)" 2>&1 | tee "$LOG_DIR/build_linux.log"
