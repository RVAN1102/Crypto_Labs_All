#!/usr/bin/env bash

set +e

EXE="$1"

if [ -z "$EXE" ]; then
    echo "Usage: negative_tests_linux.sh /path/to/aestool"
    exit 1
fi

TMP_DIR="$(mktemp -d)"
PASS=0
FAIL=0

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cd "$TMP_DIR" || exit 1

run_ok() {
    NAME="$1"
    shift

    "$@" >out.log 2>err.log
    RC=$?

    if [ "$RC" -eq 0 ]; then
        echo "[PASS] $NAME"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $NAME"
        cat out.log
        cat err.log
        FAIL=$((FAIL + 1))
    fi
}

run_fail() {
    NAME="$1"
    shift

    "$@" >out.log 2>err.log
    RC=$?

    if [ "$RC" -ne 0 ]; then
        echo "[PASS] $NAME"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $NAME"
        echo "Command unexpectedly succeeded."
        cat out.log
        cat err.log
        FAIL=$((FAIL + 1))
    fi
}

tamper_file() {
    python3 - "$1" <<'PY'
import sys
from pathlib import Path

p = Path(sys.argv[1])
data = bytearray(p.read_bytes())

if not data:
    raise SystemExit("empty file")

data[0] ^= 0x01
p.write_bytes(data)
PY
}

run_ok "Generate AES-256 key" \
    "$EXE" keygen --bits 256 --out key.bin

run_ok "Generate wrong AES-256 key" \
    "$EXE" keygen --bits 256 --out wrong_key.bin

run_ok "GCM encrypt" \
    "$EXE" encrypt --mode gcm --key key.bin --text "Linux GCM message" --out gcm.bin --aad-text "aad-linux"

run_ok "GCM decrypt" \
    "$EXE" decrypt --mode gcm --key key.bin --in gcm.bin --out gcm.txt --aad-text "aad-linux"

run_fail "GCM wrong key rejected" \
    "$EXE" decrypt --mode gcm --key wrong_key.bin --in gcm.bin --out wrong.txt --aad-text "aad-linux"

run_fail "GCM wrong AAD rejected" \
    "$EXE" decrypt --mode gcm --key key.bin --in gcm.bin --out wrong_aad.txt --aad-text "wrong-aad"

cp gcm.bin gcm_tampered.bin
tamper_file gcm_tampered.bin

run_fail "GCM tampered ciphertext rejected" \
    "$EXE" decrypt --mode gcm --key key.bin --in gcm_tampered.bin --meta gcm.bin.meta.json --out tampered.txt --aad-text "aad-linux"

run_ok "CCM encrypt" \
    "$EXE" encrypt --mode ccm --key key.bin --text "Linux CCM message" --out ccm.bin --aad-text "ccm-aad"

run_ok "CCM decrypt" \
    "$EXE" decrypt --mode ccm --key key.bin --in ccm.bin --out ccm.txt --aad-text "ccm-aad"

cp ccm.bin ccm_tampered.bin
tamper_file ccm_tampered.bin

run_fail "CCM tampered ciphertext rejected" \
    "$EXE" decrypt --mode ccm --key key.bin --in ccm_tampered.bin --meta ccm.bin.meta.json --out ccm_tampered.txt --aad-text "ccm-aad"

run_ok "CTR encrypt" \
    "$EXE" encrypt --mode ctr --key key.bin --text "Linux CTR message" --out ctr.bin

run_ok "CTR decrypt" \
    "$EXE" decrypt --mode ctr --key key.bin --in ctr.bin --out ctr.txt

head -c 20000 /dev/zero > big.bin

run_fail "ECB large file blocked by default" \
    "$EXE" encrypt --mode ecb --key key.bin --in big.bin --out ecb_blocked.bin

run_ok "ECB large file allowed with allow flag" \
    "$EXE" encrypt --mode ecb --key key.bin --in big.bin --out ecb_allowed.bin --allow-ecb

run_ok "Generate XTS key material" \
    "$EXE" keygen --bits 512 --out xts_key.bin

run_fail "XTS short input rejected" \
    "$EXE" encrypt --mode xts --key xts_key.bin --text "short" --out xts_short.bin

run_ok "XTS encrypt valid data unit" \
    "$EXE" encrypt --mode xts --key xts_key.bin --text "This is a valid AES-XTS data unit for Linux testing." --out xts.bin

run_ok "XTS decrypt valid data unit" \
    "$EXE" decrypt --mode xts --key xts_key.bin --in xts.bin --out xts.txt

echo "Linux negative test summary: pass=$PASS fail=$FAIL"

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

exit 0