#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO="$(cd "$LAB/.." && pwd)"

cd "$LAB"

LINUX_ARTIFACTS="$LAB/artifacts/linux"
LOG_DIR="$LINUX_ARTIFACTS/logs"
BENCH_DIR="$LINUX_ARTIFACTS/bench"
BIN_DIR="$LINUX_ARTIFACTS/binaries"
VECTOR_DIR="$LINUX_ARTIFACTS/vectors"

mkdir -p "$LOG_DIR" "$BENCH_DIR" "$BIN_DIR" "$VECTOR_DIR"

ENV_LOG="$LOG_DIR/environment_linux_standard.log"
CONFIGURE_LOG="$LOG_DIR/configure_linux_standard.log"
BUILD_LOG="$LOG_DIR/build_linux_standard.log"
HELP_LOG="$LOG_DIR/help_linux_standard.log"
CTEST_LOG="$LOG_DIR/ctest_linux_standard.log"
UNIT_LOG="$LOG_DIR/unit_tests_linux_standard.log"
KAT_LOG="$LOG_DIR/kat_linux_standard.log"
NEGATIVE_LOG="$LOG_DIR/negative_tests_linux_standard.log"
BENCH_LOG="$LOG_DIR/bench_linux_standard.log"
BENCH_100M_LOG="$LOG_DIR/bench_linux_hybrid_100m_standard.log"
INVENTORY_LOG="$LOG_DIR/artifact_inventory_linux_standard.log"
VERIFY_LOG="$LOG_DIR/verification_summary_linux_standard.log"

run_logged() {
  local name="$1"
  local log="$2"
  shift 2

  echo "===== $name ====="
  set +e
  "$@" > "$log" 2>&1
  local code=$?
  set -e
  cat "$log"
  if [ "$code" -ne 0 ]; then
    echo "$name failed with exit code $code" >&2
    exit "$code"
  fi
}

assert_log_contains() {
  local name="$1"
  local log="$2"
  local pattern="$3"
  if ! grep -qE "$pattern" "$log"; then
    echo "$name missing expected pattern: $pattern" >&2
    exit 1
  fi
}

copy_legacy_log() {
  local standard_path="$1"
  local legacy_name="$2"
  cp "$standard_path" "$LOG_DIR/$legacy_name"
}

echo "===== Lab 3 Ubuntu standardized evidence run started ====="

rm -rf build-linux tmp_negative_tests

echo "===== Environment ====="
{
  echo "===== OS ====="
  lsb_release -a 2>/dev/null || cat /etc/os-release
  echo

  echo "===== Architecture ====="
  uname -m
  uname -a
  echo

  echo "===== Machine / model ====="
  cat /sys/devices/virtual/dmi/id/sys_vendor 2>/dev/null || true
  cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null || true
  echo

  echo "===== CPU / cores / threads ====="
  lscpu
  echo

  echo "===== RAM ====="
  free -h
  echo

  echo "===== Compiler ====="
  g++ --version
  echo

  echo "===== CMake ====="
  cmake --version
  echo

  echo "===== Crypto++ ====="
  dpkg -l | grep -E 'libcrypto\+\+|libcryptopp' || true
  ls -l /usr/include/cryptopp/cryptlib.h 2>/dev/null || true
  ls -l /usr/include/crypto++/cryptlib.h 2>/dev/null || true
  ls -l /usr/lib/x86_64-linux-gnu/libcryptopp.* 2>/dev/null || true
} > "$ENV_LOG"
cat "$ENV_LOG"
copy_legacy_log "$ENV_LOG" "environment_linux.log"

run_logged "Configure" "$CONFIGURE_LOG" cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release
copy_legacy_log "$CONFIGURE_LOG" "configure_linux.log"

run_logged "Build" "$BUILD_LOG" cmake --build build-linux -j"$(nproc)"
assert_log_contains "Build" "$BUILD_LOG" "Built target rsatool"
assert_log_contains "Build" "$BUILD_LOG" "Built target rsatool_unit_tests"
copy_legacy_log "$BUILD_LOG" "build_linux.log"

TOOL="$LAB/build-linux/rsatool"
UNIT_TOOL="$LAB/build-linux/rsatool_unit_tests"
if [ ! -x "$TOOL" ]; then
  echo "Cannot find Lab 3 executable: $TOOL" >&2
  find build-linux -maxdepth 3 -type f -executable | sort >&2 || true
  exit 1
fi
if [ ! -x "$UNIT_TOOL" ]; then
  echo "Cannot find Lab 3 unit-test executable: $UNIT_TOOL" >&2
  find build-linux -maxdepth 3 -type f -executable | sort >&2 || true
  exit 1
fi

cp "$TOOL" "$BIN_DIR/rsatool"
cp "$UNIT_TOOL" "$BIN_DIR/rsatool_unit_tests"
cp "$LAB/vectors/rsa_hybrid_kat.json" "$VECTOR_DIR/rsa_hybrid_kat.json"

run_logged "Help / CLI" "$HELP_LOG" "$TOOL" --help
copy_legacy_log "$HELP_LOG" "help_linux.log"

run_logged "CTest" "$CTEST_LOG" ctest --test-dir build-linux --output-on-failure
assert_log_contains "CTest" "$CTEST_LOG" "100% tests passed, 0 tests failed out of 14"
copy_legacy_log "$CTEST_LOG" "ctest_linux.log"

run_logged "Unit tests" "$UNIT_LOG" "$UNIT_TOOL"
copy_legacy_log "$UNIT_LOG" "unit_tests_linux.log"

run_logged "KAT" "$KAT_LOG" "$TOOL" kat --kat vectors/rsa_hybrid_kat.json
assert_log_contains "KAT" "$KAT_LOG" "KAT summary: pass=5, fail=0, total=5"
printf '%s\n' "KAT standard: pass=5 fail=0 total=5" >> "$KAT_LOG"
copy_legacy_log "$KAT_LOG" "kat_linux.log"

run_logged "Negative tests" "$NEGATIVE_LOG" bash scripts/negative_tests_linux.sh "$TOOL"
assert_log_contains "Negative tests" "$NEGATIVE_LOG" "Linux negative test summary: pass=40 fail=0 total=40"
copy_legacy_log "$NEGATIVE_LOG" "negative_tests_linux.log"

run_logged "Benchmark base" "$BENCH_LOG" "$TOOL" bench \
  --out artifacts/linux/bench/bench_linux_raw.csv \
  --summary artifacts/linux/bench/bench_linux_summary.csv \
  --runs 10 \
  --ops 10 \
  --sizes 1k,16k,256k,1m \
  --rsa-sizes 32,190,318 \
  --rsa-bits 3072,4096 \
  --platform linux
copy_legacy_log "$BENCH_LOG" "bench_linux.log"

run_logged "Benchmark Hybrid 100 MiB" "$BENCH_100M_LOG" "$TOOL" bench \
  --out artifacts/linux/bench/bench_linux_hybrid_100m_raw.csv \
  --summary artifacts/linux/bench/bench_linux_hybrid_100m_summary.csv \
  --runs 30 \
  --ops 1 \
  --sizes 100m \
  --rsa-sizes 32 \
  --rsa-bits 3072,4096 \
  --platform linux
copy_legacy_log "$BENCH_100M_LOG" "bench_linux_hybrid_100m.log"

echo "===== Artifact inventory ====="
{
  echo "===== logs ====="
  find "$LOG_DIR" -maxdepth 1 -type f -printf 'logs/%f\n' | sort
  echo
  echo "===== benchmark CSVs ====="
  find "$BENCH_DIR" -maxdepth 1 -type f -name '*.csv' -printf 'bench/%f\n' | sort
  echo
  echo "===== generated vectors if any ====="
  find "$VECTOR_DIR" -maxdepth 1 -type f -printf 'vectors/%f\n' | sort
  echo
  echo "===== binaries copied by evidence runner ====="
  find "$BIN_DIR" -maxdepth 1 -type f -printf 'binaries/%f\n' | sort
} > "$INVENTORY_LOG"
cat "$INVENTORY_LOG"
copy_legacy_log "$INVENTORY_LOG" "artifact_inventory_linux.log"

echo "===== Verification summary ====="
BASE_RAW="$BENCH_DIR/bench_linux_raw.csv"
BASE_SUMMARY="$BENCH_DIR/bench_linux_summary.csv"
HYBRID_100M_SUMMARY="$BENCH_DIR/bench_linux_hybrid_100m_summary.csv"
verify_failed=0
{
  echo "Lab 3 Linux standardized verification summary"

  if grep -q "100% tests passed, 0 tests failed out of 14" "$CTEST_LOG"; then
    echo "PASS - CTest 14/14"
  else
    echo "FAIL - CTest 14/14"
    verify_failed=1
  fi

  if grep -q "KAT standard: pass=5 fail=0 total=5" "$KAT_LOG"; then
    echo "PASS - KAT 5/5"
  else
    echo "FAIL - KAT 5/5"
    verify_failed=1
  fi

  if grep -q "Linux negative test summary: pass=40 fail=0 total=40" "$NEGATIVE_LOG"; then
    echo "PASS - negative tests 40/40"
  else
    echo "FAIL - negative tests 40/40"
    verify_failed=1
  fi

  if [ -f "$BASE_RAW" ]; then
    echo "PASS - base benchmark raw CSV exists"
  else
    echo "FAIL - base benchmark raw CSV exists"
    verify_failed=1
  fi

  if [ -f "$BASE_SUMMARY" ]; then
    echo "PASS - base benchmark summary CSV exists"
  else
    echo "FAIL - base benchmark summary CSV exists"
    verify_failed=1
  fi

  if [ -f "$HYBRID_100M_SUMMARY" ]; then
    echo "PASS - Hybrid 100 MiB summary CSV exists"
  else
    echo "FAIL - Hybrid 100 MiB summary CSV exists"
    verify_failed=1
  fi
} > "$VERIFY_LOG"
cat "$VERIFY_LOG"

if [ "$verify_failed" -ne 0 ]; then
  echo "Verification summary contains failures." >&2
  exit 1
fi

echo "===== Lab 3 Ubuntu standardized evidence run completed ====="
