#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB="$ROOT/lab5_signatures"
BUILD="$LAB/build-linux"
EXE="$BUILD/sigtool"
LOG_DIR="$LAB/artifacts/linux/logs"
BENCH_DIR="$LAB/artifacts/linux/bench"
MANUAL_DIR="$LAB/artifacts/linux/manual"
DER_DIR="$LAB/artifacts/linux/der"

mkdir -p "$LOG_DIR" "$BENCH_DIR" "$MANUAL_DIR" "$DER_DIR"

{
    echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "repository_root=$ROOT"
    echo "platform=ubuntu-linux"
    uname -a
    if command -v lsb_release >/dev/null 2>&1; then
        lsb_release -a 2>/dev/null
    fi
    cmake --version
    c++ --version
    openssl version -a
} > "$LOG_DIR/environment_linux.log"

cmake -S "$LAB" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release \
    2>&1 | tee "$LOG_DIR/configure_linux.log"
cmake --build "$BUILD" -j"$(nproc)" \
    2>&1 | tee "$LOG_DIR/build_linux.log"
ctest --test-dir "$BUILD" --output-on-failure \
    2>&1 | tee "$LOG_DIR/ctest_linux.log"

printf 'Lab 5 binary-safe smoke\000message\n' > "$MANUAL_DIR/msg.bin"

{
    echo "Lab 5 manual smoke: PEM keys and all signature encodings"
    for algo in ecdsa-p256 rsa-pss-3072; do
        prefix="${algo%%-*}"
        if [[ "$algo" == "rsa-pss-3072" ]]; then
            prefix="rsa"
        fi
        "$EXE" keygen --algo "$algo" \
            --priv "$MANUAL_DIR/${prefix}_priv.pem" \
            --pub "$MANUAL_DIR/${prefix}_pub.pem" \
            --format pem
        for encoding in raw der base64; do
            "$EXE" sign --algo "$algo" \
                --priv "$MANUAL_DIR/${prefix}_priv.pem" \
                --in "$MANUAL_DIR/msg.bin" \
                --out "$MANUAL_DIR/${prefix}_${encoding}.sig" \
                --hash sha256 --encode "$encoding"
            "$EXE" verify --algo "$algo" \
                --pub "$MANUAL_DIR/${prefix}_pub.pem" \
                --in "$MANUAL_DIR/msg.bin" \
                --sig "$MANUAL_DIR/${prefix}_${encoding}.sig" \
                --hash sha256 --encode "$encoding"
        done
    done
    echo "manual smoke passed"
} 2>&1 | tee "$LOG_DIR/manual_smoke_linux.log"

{
    echo "Lab 5 DER key end-to-end checks"
    for algo in ecdsa-p256 rsa-pss-3072; do
        if [[ "$algo" == "ecdsa-p256" ]]; then
            prefix="ecdsa"
            encoding="der"
        else
            prefix="rsa"
            encoding="raw"
        fi
        "$EXE" keygen --algo "$algo" \
            --priv "$DER_DIR/${prefix}_priv.der" \
            --pub "$DER_DIR/${prefix}_pub.der" \
            --format der
        "$EXE" sign --algo "$algo" \
            --priv "$DER_DIR/${prefix}_priv.der" \
            --in "$MANUAL_DIR/msg.bin" \
            --out "$DER_DIR/${prefix}.sig" \
            --hash sha256 --encode "$encoding"
        "$EXE" verify --algo "$algo" \
            --pub "$DER_DIR/${prefix}_pub.der" \
            --in "$MANUAL_DIR/msg.bin" \
            --sig "$DER_DIR/${prefix}.sig" \
            --hash sha256 --encode "$encoding"
    done
    echo "DER key checks passed"
} 2>&1 | tee "$LOG_DIR/der_key_check_linux.log"

{
    echo "Lab 5 deterministic/randomized behavior checks"
    "$EXE" sign --algo ecdsa-p256 \
        --priv "$MANUAL_DIR/ecdsa_priv.pem" --in "$MANUAL_DIR/msg.bin" \
        --out "$MANUAL_DIR/ecdsa_det_a.sig" --hash sha256 --encode der
    "$EXE" sign --algo ecdsa-p256 \
        --priv "$MANUAL_DIR/ecdsa_priv.pem" --in "$MANUAL_DIR/msg.bin" \
        --out "$MANUAL_DIR/ecdsa_det_b.sig" --hash sha256 --encode der
    cmp "$MANUAL_DIR/ecdsa_det_a.sig" "$MANUAL_DIR/ecdsa_det_b.sig"
    echo "[PASS] ECDSA-P256 signatures are identical for the same key and message"

    "$EXE" sign --algo rsa-pss-3072 \
        --priv "$MANUAL_DIR/rsa_priv.pem" --in "$MANUAL_DIR/msg.bin" \
        --out "$MANUAL_DIR/rsa_rand_a.sig" --hash sha256 --encode raw
    "$EXE" sign --algo rsa-pss-3072 \
        --priv "$MANUAL_DIR/rsa_priv.pem" --in "$MANUAL_DIR/msg.bin" \
        --out "$MANUAL_DIR/rsa_rand_b.sig" --hash sha256 --encode raw
    if cmp -s "$MANUAL_DIR/rsa_rand_a.sig" "$MANUAL_DIR/rsa_rand_b.sig"; then
        echo "[FAIL] RSA-PSS signatures unexpectedly matched"
        exit 1
    fi
    "$EXE" verify --algo rsa-pss-3072 \
        --pub "$MANUAL_DIR/rsa_pub.pem" --in "$MANUAL_DIR/msg.bin" \
        --sig "$MANUAL_DIR/rsa_rand_a.sig" --hash sha256 --encode raw
    "$EXE" verify --algo rsa-pss-3072 \
        --pub "$MANUAL_DIR/rsa_pub.pem" --in "$MANUAL_DIR/msg.bin" \
        --sig "$MANUAL_DIR/rsa_rand_b.sig" --hash sha256 --encode raw
    echo "[PASS] RSA-PSS signatures differ and both verify"
} 2>&1 | tee "$LOG_DIR/deterministic_randomized_linux.log"

bash "$LAB/scripts/negative_tests_linux.sh" "$EXE" \
    2>&1 | tee "$LOG_DIR/negative_tests_linux.log"

"$EXE" bench \
    --out "$BENCH_DIR/bench_linux_raw.csv" \
    --summary "$BENCH_DIR/bench_linux_summary.csv" \
    --runs 30 \
    --ops 1 \
    --sizes 1k,16k,1m,8m \
    --algos ecdsa-p256,rsa-pss-3072 \
    --platform ubuntu-linux \
    2>&1 | tee "$LOG_DIR/bench_linux.log"

echo "Lab 5 Ubuntu evidence run completed successfully."
