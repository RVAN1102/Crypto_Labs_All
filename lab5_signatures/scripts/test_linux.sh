#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB="$ROOT/lab5_signatures"
BUILD_DIR="${1:-$LAB/build-linux}"
LOG_DIR="$LAB/artifacts/linux/logs"
mkdir -p "$LOG_DIR"

ctest --test-dir "$BUILD_DIR" --output-on-failure 2>&1 | tee "$LOG_DIR/ctest_linux.log"
