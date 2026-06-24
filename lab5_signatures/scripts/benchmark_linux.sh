#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB="$ROOT/lab5_signatures"
EXE="${1:-$LAB/build-linux/sigtool}"
RUNS="${RUNS:-30}"
OPS="${OPS:-1}"
SIZES="${SIZES:-1k,16k,1m,8m}"
LOG_DIR="$LAB/artifacts/linux/logs"
BENCH_DIR="$LAB/artifacts/linux/bench"
mkdir -p "$LOG_DIR" "$BENCH_DIR"

"$EXE" bench \
  --out "$BENCH_DIR/bench_linux_raw.csv" \
  --summary "$BENCH_DIR/bench_linux_summary.csv" \
  --runs "$RUNS" \
  --ops "$OPS" \
  --sizes "$SIZES" \
  --algos ecdsa-p256,rsa-pss-3072 \
  --platform ubuntu-linux 2>&1 | tee "$LOG_DIR/bench_linux.log"
