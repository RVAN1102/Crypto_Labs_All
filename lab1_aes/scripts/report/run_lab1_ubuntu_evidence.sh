#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
LAB_DIR="$(cd "$SCRIPT_DIR/../.." && pwd -P)"

cd "$LAB_DIR"

ARTIFACT_DIR="$LAB_DIR/artifacts/linux"
LOG_DIR="$ARTIFACT_DIR/logs"
BENCH_DIR="$ARTIFACT_DIR/bench"
BIN_DIR="$ARTIFACT_DIR/binaries"

mkdir -p "$LOG_DIR" "$BENCH_DIR" "$BIN_DIR"

ENVIRONMENT_LOG="$LOG_DIR/environment_linux_standard.log"
CONFIGURE_LOG="$LOG_DIR/configure_linux_standard.log"
BUILD_LOG="$LOG_DIR/build_linux_standard.log"
HELP_LOG="$LOG_DIR/help_linux_standard.log"
UNIT_LOG="$LOG_DIR/unit_tests_linux_standard.log"
CTEST_LOG="$LOG_DIR/ctest_linux_standard.log"
KAT_LOG="$LOG_DIR/kat_linux_standard.log"
NEGATIVE_LOG="$LOG_DIR/negative_tests_linux_standard.log"
BENCH_LOG="$LOG_DIR/bench_linux_standard.log"
INVENTORY_LOG="$LOG_DIR/artifact_inventory_linux_standard.log"

copy_compat_log() {
    cp "$LOG_DIR/$1" "$LOG_DIR/$2"
}

append_kat_summary() {
    local source_log="$1"
    local label="$2"
    local raw
    local summary

    raw="$(grep -E 'KAT summary:' "$source_log" | tail -n 1 || true)"
    summary="$(printf '%s\n' "$raw" | sed -E "s/KAT summary: pass=([0-9]+), fail=([0-9]+), total=([0-9]+)/${label}: pass=\\1 fail=\\2 total=\\3/")"

    if [ -n "$raw" ]; then
        printf '%s\n' "$summary" >>"$KAT_LOG"
    else
        printf '%s: missing KAT summary\n' "$label" >>"$KAT_LOG"
    fi
}

run_kat_group() {
    local label="$1"
    local vector="$2"
    local tmp_log="$LOG_DIR/.kat_${label// /_}.tmp"

    printf '===== %s =====\n' "$label" >>"$KAT_LOG"
    "$TOOL" kat --kat "$vector" >"$tmp_log" 2>&1
    cat "$tmp_log" >>"$KAT_LOG"
    append_kat_summary "$tmp_log" "$label"
    printf '\n' >>"$KAT_LOG"
    rm -f "$tmp_log"
}

echo "===== Lab 1 Ubuntu evidence run started ====="

echo "===== Environment ====="
{
    echo "===== OS ====="
    if [ -r /etc/os-release ]; then
        cat /etc/os-release
    fi
    uname -a
    echo ""
    echo "===== CPU ====="
    grep -m 1 'model name' /proc/cpuinfo || true
    printf 'cores_threads: '
    nproc
    echo ""
    echo "===== RAM ====="
    free -h || true
    echo ""
    echo "===== COMPILER ====="
    g++ --version
    cmake --version
    echo ""
    echo "===== CRYPTOPP ====="
    ldconfig -p 2>/dev/null | grep -i cryptopp || true
    find /usr /usr/local -name 'libcryptopp*' -o -name 'cryptopp' 2>/dev/null | head -n 25 || true
} >"$ENVIRONMENT_LOG" 2>&1

echo "===== Configure ====="
cmake -S "$LAB_DIR" -B "$LAB_DIR/build-linux" \
    -DCMAKE_BUILD_TYPE=Release \
    >"$CONFIGURE_LOG" 2>&1

echo "===== Build ====="
cmake --build "$LAB_DIR/build-linux" --parallel \
    >"$BUILD_LOG" 2>&1

TOOL="$LAB_DIR/build-linux/aestool"
UNIT_TOOL="$LAB_DIR/build-linux/aestool_unit_tests"

if [ ! -x "$TOOL" ]; then
    echo "Cannot find executable: $TOOL" >&2
    exit 1
fi

if [ ! -x "$UNIT_TOOL" ]; then
    echo "Cannot find executable: $UNIT_TOOL" >&2
    exit 1
fi

{
    echo ""
    echo "Built binary: $TOOL"
    echo "Built unit test binary: $UNIT_TOOL"
} >>"$BUILD_LOG"

cp "$TOOL" "$BIN_DIR/aestool"
cp "$UNIT_TOOL" "$BIN_DIR/aestool_unit_tests"

echo "===== Help ====="
"$TOOL" --help >"$HELP_LOG" 2>&1

echo "===== Unit tests ====="
"$UNIT_TOOL" >"$UNIT_LOG" 2>&1

echo "===== CTest ====="
ctest --test-dir "$LAB_DIR/build-linux" --output-on-failure \
    >"$CTEST_LOG" 2>&1

echo "===== KAT ====="
: >"$KAT_LOG"
run_kat_group "KAT sample" "$LAB_DIR/vectors/aes_kat_sample.json"
run_kat_group "KAT extended" "$LAB_DIR/vectors/aes_kat_extended.json"

echo "===== Negative tests ====="
bash "$LAB_DIR/scripts/negative_tests_linux.sh" "$TOOL" \
    >"$NEGATIVE_LOG" 2>&1

echo "===== Benchmark ====="
"$TOOL" bench \
    --out "$BENCH_DIR/bench_linux_raw.csv" \
    --summary "$BENCH_DIR/bench_linux_summary.csv" \
    --runs 30 \
    --ops 100 \
    --warmup-ms 100 \
    --sizes "1k,4k,16k,256k,1m,8m" \
    --modes "ecb,cbc,cfb,ofb,ctr,gcm,ccm,xts" \
    --platform "linux" \
    >"$BENCH_LOG" 2>&1

echo "===== Artifact inventory ====="
{
    echo "===== Artifact inventory: Linux ====="
    echo "Binaries:"
    find "$BIN_DIR" -maxdepth 1 -type f -printf '%f %s bytes\n' | sort
    echo ""
    echo "Logs:"
    find "$LOG_DIR" -maxdepth 1 -type f -name '*_linux_standard.log' -printf '%f %s bytes\n' | sort
    echo ""
    echo "Benchmark CSV:"
    find "$BENCH_DIR" -maxdepth 1 -type f -name '*.csv' -printf '%f %s bytes\n' | sort
} >"$INVENTORY_LOG" 2>&1

copy_compat_log "environment_linux_standard.log" "environment_linux.log"
copy_compat_log "configure_linux_standard.log" "configure_linux.log"
copy_compat_log "build_linux_standard.log" "build_linux.log"
copy_compat_log "help_linux_standard.log" "help_linux.log"
copy_compat_log "unit_tests_linux_standard.log" "unit_tests_linux.log"
copy_compat_log "ctest_linux_standard.log" "ctest_linux.log"
copy_compat_log "kat_linux_standard.log" "kat_linux.log"
copy_compat_log "negative_tests_linux_standard.log" "negative_tests_linux.log"
copy_compat_log "bench_linux_standard.log" "bench_linux.log"
copy_compat_log "artifact_inventory_linux_standard.log" "artifact_inventory_linux.log"

echo "===== Verification summary ====="
grep -E "100% tests passed|tests failed" "$CTEST_LOG" || true
grep -E "KAT sample:|KAT extended:" "$KAT_LOG" || true
grep -E "Linux negative test summary" "$NEGATIVE_LOG" || true
ls -la "$BENCH_DIR"

echo "===== Lab 1 Ubuntu evidence run completed ====="
