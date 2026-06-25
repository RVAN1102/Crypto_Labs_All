#!/usr/bin/env bash
set -euo pipefail

EXE="${1:?usage: negative_tests_linux.sh /path/to/sigtool}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/artifacts/linux/negative"
mkdir -p "$WORK"

run_ok() {
    echo "[RUN] $EXE $*"
    "$EXE" "$@"
}

run_fail() {
    echo "[EXPECT FAIL] $EXE $*"
    if "$EXE" "$@"; then
        echo "expected failure: $EXE $*" >&2
        exit 1
    fi
    echo "[PASS] command failed as expected"
}

printf 'lab5\000msg' > "$WORK/msg.bin"
printf 'lab5\001msg' > "$WORK/msg_tampered.bin"
printf 'not a key\n' > "$WORK/malformed.pem"
printf 'not a signature\n' > "$WORK/malformed.sig"

MSG="$WORK/msg.bin"
BAD_MSG="$WORK/msg_tampered.bin"
BAD_KEY="$WORK/malformed.pem"
BAD_SIG="$WORK/malformed.sig"

for algo in ecdsa-p256 rsa-pss-3072; do
    if [[ "$algo" == "ecdsa-p256" ]]; then
        prefix="ecdsa"
        enc="der"
        wrong_algo="rsa-pss-3072"
    else
        prefix="rsa"
        enc="raw"
        wrong_algo="ecdsa-p256"
    fi

    priv="$WORK/$prefix.priv.pem"
    pub="$WORK/$prefix.pub.pem"
    wrong_priv="$WORK/$prefix.wrong.priv.pem"
    wrong_pub="$WORK/$prefix.wrong.pub.pem"
    sig="$WORK/$prefix.sig"
    sig_bad="$WORK/$prefix.sig.bad"

    run_ok keygen --algo "$algo" --priv "$priv" --pub "$pub" --meta "$WORK/$prefix.meta.json"
    run_ok keygen --algo "$algo" --priv "$wrong_priv" --pub "$wrong_pub"
    run_ok sign --algo "$algo" --priv "$priv" --in "$MSG" --out "$sig" --hash sha256 --encode "$enc"
    run_ok verify --algo "$algo" --pub "$pub" --in "$MSG" --sig "$sig" --hash sha256 --encode "$enc"

    cp "$sig" "$sig_bad"
    printf '\001' | dd of="$sig_bad" bs=1 seek=5 count=1 conv=notrunc status=none

    run_fail verify --algo "$algo" --pub "$pub" --in "$BAD_MSG" --sig "$sig" --hash sha256 --encode "$enc"
    run_fail verify --algo "$algo" --pub "$pub" --in "$MSG" --sig "$sig_bad" --hash sha256 --encode "$enc"
    run_fail verify --algo "$algo" --pub "$wrong_pub" --in "$MSG" --sig "$sig" --hash sha256 --encode "$enc"
    run_fail verify --algo "$wrong_algo" --pub "$pub" --in "$MSG" --sig "$sig" --hash sha256 --encode "$enc"
    run_fail verify --algo "$algo" --pub "$pub" --in "$MSG" --sig "$sig" --hash sha512 --encode "$enc"
    run_fail sign --algo "$algo" --priv "$BAD_KEY" --in "$MSG" --out "$WORK/$prefix.badkey.sig" --hash sha256 --encode "$enc"
    run_fail verify --algo "$algo" --pub "$pub" --in "$MSG" --sig "$BAD_SIG" --hash sha256 --encode "$enc"
done

B64="$WORK/ecdsa.b64"
run_ok sign --algo ecdsa-p256 --priv "$WORK/ecdsa.priv.pem" --in "$MSG" --out "$B64" --hash sha256 --encode base64
run_ok verify --algo ecdsa-p256 --pub "$WORK/ecdsa.pub.pem" --in "$MSG" --sig "$B64" --hash sha256 --encode base64
run_fail sign --algo ecdsa-p256 --priv "$WORK/ecdsa.priv.pem" --in "$MSG" --out "$WORK/unsupported.sig" --hash sha256 --encode hex
run_fail keygen --algo ecdsa-p256 --priv "$WORK/unsupported.priv" --pub "$WORK/unsupported.pub" --format pkcs8
run_fail sign --algo rsa-pss-3072 --priv "$WORK/rsa.priv.pem" --in "$MSG" --out "$WORK/unsupported-parameter.sig" --hash sha256 --encode raw --salt-len 20

MANIFEST="$WORK/batch_manifest.csv"
SIG2="$WORK/ecdsa2.sig"
run_ok sign --algo ecdsa-p256 --priv "$WORK/ecdsa.priv.pem" --in "$MSG" --out "$SIG2" --hash sha256 --encode der
printf '%s,%s\n' "$MSG" "$SIG2" > "$MANIFEST"
run_ok batch-verify --algo ecdsa-p256 --pub "$WORK/ecdsa.pub.pem" --manifest "$MANIFEST" --hash sha256 --encode der

echo "negative tests passed"
