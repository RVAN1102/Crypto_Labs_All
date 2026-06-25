#!/usr/bin/env bash
set -euo pipefail

REPO="$HOME/Crypto_Labs_All"
LAB="$REPO/lab3_rsa_hybrid"

cd "$LAB"

LOG_DIR="$LAB/artifacts/linux/logs"
BENCH_DIR="$LAB/artifacts/linux/bench"
TOOL="$LAB/build-linux/rsatool"

mkdir -p "$LOG_DIR" "$BENCH_DIR"

if [ ! -x "$TOOL" ]; then
  rm -rf build-linux
  cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release > "$LOG_DIR/configure_linux_large_bench.log" 2>&1
  cmake --build build-linux -j"$(nproc)" > "$LOG_DIR/build_linux_large_bench.log" 2>&1
fi

if [ ! -x "$TOOL" ]; then
  echo "Cannot find Lab 3 executable: $TOOL" >&2
  exit 1
fi

echo "===== Lab 3 Ubuntu large Hybrid benchmark ====="
echo "Tool: $TOOL"
echo "Protocol: runs=30, ops=1, Hybrid payload=100 MiB"

"$TOOL" bench \
  --out artifacts/linux/bench/bench_linux_hybrid_100m_raw.csv \
  --summary artifacts/linux/bench/bench_linux_hybrid_100m_summary.csv \
  --runs 30 \
  --ops 1 \
  --sizes 100m \
  --rsa-sizes 32 \
  --rsa-bits 3072,4096 \
  > "$LOG_DIR/bench_linux_hybrid_100m.log" 2>&1

cat "$LOG_DIR/bench_linux_hybrid_100m.log"

echo "===== Lab 3 Ubuntu large Hybrid benchmark completed ====="
