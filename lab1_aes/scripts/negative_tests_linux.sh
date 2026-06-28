#!/usr/bin/env bash

set +e
set -u

if [ "$#" -ne 1 ]; then
    echo "Usage: negative_tests_linux.sh /absolute/path/to/aestool"
    exit 1
fi

resolve_path() {
    case "$1" in
        /*)
            printf '%s\n' "$1"
            ;;
        */*)
            local dir
            dir="$(dirname "$1")" || return 1
            local base
            base="$(basename "$1")" || return 1
            dir="$(cd "$dir" 2>/dev/null && pwd -P)" || return 1
            printf '%s/%s\n' "$dir" "$base"
            ;;
        *)
            printf '%s/%s\n' "$(pwd -P)" "$1"
            ;;
    esac
}

if ! EXE="$(resolve_path "$1")"; then
    echo "Executable not found or not executable: $1"
    exit 1
fi

if [ ! -x "$EXE" ]; then
    echo "Executable not found or not executable: $EXE"
    exit 1
fi

TMP_PARENT="${TMPDIR:-/tmp}"
TMP_PARENT="${TMP_PARENT%/}"
WORK="$(mktemp -d "$TMP_PARENT/lab1_negative_tests.XXXXXX")"
PASS=0
FAIL=0

cleanup() {
    if [ -n "${WORK:-}" ] && [ -d "$WORK" ]; then
        case "$WORK" in
            "$TMP_PARENT"/lab1_negative_tests.*)
                rm -rf -- "$WORK"
                ;;
        esac
    fi
}
trap cleanup EXIT

cd "$WORK" || exit 1

echo "Running negative tests with: $EXE"
echo "Working directory: $WORK"
echo ""

write_pass() {
    echo "[PASS] $1"
    PASS=$((PASS + 1))
}

write_fail() {
    echo "[FAIL] $1 :: $2"
    FAIL=$((FAIL + 1))
}

run_cmd() {
    "$@" >"$WORK/out.log" 2>"$WORK/err.log"
    return $?
}

expect_success() {
    local name="$1"
    shift

    run_cmd "$@"
    local rc=$?

    if [ "$rc" -eq 0 ]; then
        write_pass "$name"
    else
        write_fail "$name" "expected success, exit=$rc, output=$(cat "$WORK/out.log" "$WORK/err.log")"
    fi
}

expect_fail() {
    local name="$1"
    shift

    run_cmd "$@"
    local rc=$?

    if [ "$rc" -ne 0 ]; then
        write_pass "$name"
    else
        write_fail "$name" "expected failure, but command succeeded. output=$(cat "$WORK/out.log" "$WORK/err.log")"
    fi
}

assert_text_equals() {
    local name="$1"
    local path="$2"
    local expected="$3"
    local expected_file="$WORK/expected_text.txt"

    printf '%s' "$expected" >"$expected_file"

    if [ -f "$path" ] && cmp -s "$path" "$expected_file"; then
        write_pass "$name"
    else
        write_fail "$name" "plaintext mismatch"
    fi
}

assert_text_not_equals() {
    local name="$1"
    local path="$2"
    local expected="$3"
    local expected_file="$WORK/expected_text.txt"

    printf '%s' "$expected" >"$expected_file"

    if [ ! -f "$path" ]; then
        write_fail "$name" "plaintext file was not produced"
    elif cmp -s "$path" "$expected_file"; then
        write_fail "$name" "expected corrupted plaintext, but plaintext is unchanged"
    else
        write_pass "$name"
    fi
}

expect_success_and_text_not_equals() {
    local name="$1"
    local path="$2"
    local expected="$3"
    shift 3
    local expected_file="$WORK/expected_text.txt"

    printf '%s' "$expected" >"$expected_file"
    run_cmd "$@"
    local rc=$?

    if [ "$rc" -ne 0 ]; then
        write_fail "$name" "expected unauthenticated decrypt success, exit=$rc, output=$(cat "$WORK/out.log" "$WORK/err.log")"
    elif [ ! -f "$path" ]; then
        write_fail "$name" "plaintext file was not produced"
    elif cmp -s "$path" "$expected_file"; then
        write_fail "$name" "expected corrupted plaintext, but plaintext is unchanged"
    else
        write_pass "$name"
    fi
}

setup_or_die() {
    "$@" >"$WORK/setup.out.log" 2>"$WORK/setup.err.log"
    local rc=$?

    if [ "$rc" -ne 0 ]; then
        echo "Setup failed: $*"
        cat "$WORK/setup.out.log" "$WORK/setup.err.log"
        exit 1
    fi
}

tamper_first_byte() {
    python3 - "$1" "$2" <<'PY'
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
data = bytearray(src.read_bytes())
if not data:
    raise SystemExit(f"Cannot tamper empty file: {src}")
data[0] ^= 0x01
dst.write_bytes(data)
PY
}

tamper_tag_in_meta() {
    python3 - "$1" "$2" <<'PY'
import re
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
text = src.read_text(encoding="ascii")
match = re.search(r'"tag_hex"\s*:\s*"([0-9a-fA-F]+)"', text)
if not match:
    raise SystemExit("tag_hex not found in metadata")
old = match.group(1)
new = ("1" if old[0] == "0" else "0") + old[1:]
dst.write_text(text[:match.start(1)] + new + text[match.end(1):], encoding="ascii")
PY
}

remove_nonce_from_meta() {
    python3 - "$1" "$2" <<'PY'
import re
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
text = src.read_text(encoding="ascii")
text = re.sub(r'\s*"nonce_hex"\s*:\s*"[0-9a-fA-F]+",?\n', "\n", text, count=1)
dst.write_text(text, encoding="ascii")
PY
}

printf '\001\002\003\004\005' >bad_key.bin
setup_or_die "$EXE" keygen --bits 512 --out xts_key.bin --encode raw

expect_success "Generate AES-256 key" \
    "$EXE" keygen --bits 256 --out key.bin --encode raw

expect_success "Generate wrong AES-256 key" \
    "$EXE" keygen --bits 256 --out wrong_key.bin --encode raw

gcm_text="GCM negative testing message"

expect_success "GCM encrypt" \
    "$EXE" encrypt --mode gcm \
    --key key.bin \
    --text "$gcm_text" \
    --out gcm_ct.bin \
    --aad-text aad-ok \
    --nonce-registry gcm_registry.jsonl

expect_success "GCM decrypt" \
    "$EXE" decrypt --mode gcm \
    --key key.bin \
    --in gcm_ct.bin \
    --out gcm_pt.txt \
    --aad-text aad-ok

assert_text_equals "GCM recovered plaintext equals original" gcm_pt.txt "$gcm_text"

expect_fail "GCM wrong key rejected" \
    "$EXE" decrypt --mode gcm \
    --key wrong_key.bin \
    --in gcm_ct.bin \
    --out gcm_wrongkey.txt \
    --aad-text aad-ok

expect_fail "GCM wrong AAD rejected" \
    "$EXE" decrypt --mode gcm \
    --key key.bin \
    --in gcm_ct.bin \
    --out gcm_wrongaad.txt \
    --aad-text aad-wrong

tamper_first_byte gcm_ct.bin gcm_ct_tampered.bin
cp gcm_ct.bin.meta.json gcm_ct_tampered.bin.meta.json

expect_fail "GCM tampered ciphertext rejected" \
    "$EXE" decrypt --mode gcm \
    --key key.bin \
    --in gcm_ct_tampered.bin \
    --out gcm_tampered.txt \
    --aad-text aad-ok

tamper_tag_in_meta gcm_ct.bin.meta.json gcm_badtag.meta.json

expect_fail "GCM tampered tag rejected" \
    "$EXE" decrypt --mode gcm \
    --key key.bin \
    --in gcm_ct.bin \
    --out gcm_badtag.txt \
    --aad-text aad-ok \
    --meta gcm_badtag.meta.json

remove_nonce_from_meta gcm_ct.bin.meta.json gcm_malformed.meta.json

expect_fail "GCM malformed metadata rejected" \
    "$EXE" decrypt --mode gcm \
    --key key.bin \
    --in gcm_ct.bin \
    --out gcm_malformed.txt \
    --aad-text aad-ok \
    --meta gcm_malformed.meta.json

expect_fail "GCM invalid AES key length rejected" \
    "$EXE" encrypt --mode gcm \
    --key bad_key.bin \
    --text "bad key" \
    --out badkey_ct.bin

expect_fail "GCM invalid GCM nonce length rejected" \
    "$EXE" encrypt --mode gcm \
    --key key.bin \
    --nonce-hex 001122 \
    --text "bad nonce" \
    --out badnonce_ct.bin

expect_success "GCM first fixed nonce accepted" \
    "$EXE" encrypt --mode gcm \
    --key key.bin \
    --nonce-hex 00112233445566778899aabb \
    --text first \
    --out reuse1.bin \
    --nonce-registry reuse_registry.jsonl

expect_fail "GCM second fixed nonce rejected" \
    "$EXE" encrypt --mode gcm \
    --key key.bin \
    --nonce-hex 00112233445566778899aabb \
    --text second \
    --out reuse2.bin \
    --nonce-registry reuse_registry.jsonl

ccm_text="CCM negative testing message"

expect_success "CCM encrypt" \
    "$EXE" encrypt --mode ccm \
    --key key.bin \
    --text "$ccm_text" \
    --out ccm_ct.bin \
    --aad-text ccm-aad \
    --nonce-registry ccm_registry.jsonl

expect_success "CCM decrypt baseline" \
    "$EXE" decrypt --mode ccm \
    --key key.bin \
    --in ccm_ct.bin \
    --out ccm_pt.txt \
    --aad-text ccm-aad

assert_text_equals "CCM recovered plaintext equals original" ccm_pt.txt "$ccm_text"

tamper_first_byte ccm_ct.bin ccm_ct_tampered.bin
cp ccm_ct.bin.meta.json ccm_ct_tampered.bin.meta.json

expect_fail "CCM tampered ciphertext rejected" \
    "$EXE" decrypt --mode ccm \
    --key key.bin \
    --in ccm_ct_tampered.bin \
    --out ccm_tampered.txt \
    --aad-text ccm-aad

ctr_text="CTR mode has no authentication, so tampering corrupts plaintext."

expect_success "CTR encrypt" \
    "$EXE" encrypt --mode ctr \
    --key key.bin \
    --iv-hex 00112233445566778899aabbccddeeff \
    --text "$ctr_text" \
    --out ctr_ct.bin \
    --nonce-registry ctr_registry_a.jsonl

expect_success "CTR decrypt baseline" \
    "$EXE" decrypt --mode ctr \
    --key key.bin \
    --in ctr_ct.bin \
    --out ctr_pt.txt

assert_text_equals "CTR recovered plaintext equals original" ctr_pt.txt "$ctr_text"

tamper_first_byte ctr_ct.bin ctr_ct_tampered.bin
cp ctr_ct.bin.meta.json ctr_ct_tampered.bin.meta.json
setup_or_die "$EXE" decrypt --mode ctr --key key.bin --in ctr_ct_tampered.bin --out ctr_tampered.txt

assert_text_not_equals "CTR tampering produces corrupted plaintext" ctr_tampered.txt "$ctr_text"

expect_success "CTR first IV accepted" \
    "$EXE" encrypt --mode ctr \
    --key key.bin \
    --iv-hex 11112222333344445555666677778888 \
    --text "first ctr" \
    --out ctr_reuse1.bin \
    --nonce-registry ctr_reuse_registry.jsonl

expect_fail "CTR reused IV rejected" \
    "$EXE" encrypt --mode ctr \
    --key key.bin \
    --iv-hex 11112222333344445555666677778888 \
    --text "second ctr" \
    --out ctr_reuse2.bin \
    --nonce-registry ctr_reuse_registry.jsonl

dd if=/dev/zero of=big_plain.bin bs=20000 count=1 >/dev/null 2>&1

expect_fail "ECB large file blocked by default" \
    "$EXE" encrypt --mode ecb \
    --key key.bin \
    --in big_plain.bin \
    --out big_ecb.bin

expect_success "ECB large file allowed with allow flag" \
    "$EXE" encrypt --mode ecb \
    --key key.bin \
    --in big_plain.bin \
    --out big_ecb_allowed.bin \
    --allow-ecb

expect_fail "XTS short input rejected" \
    "$EXE" encrypt --mode xts \
    --key xts_key.bin \
    --text short \
    --out short_xts.bin

xts_text="This is a valid AES-XTS data unit for negative testing."

expect_success "XTS encrypt valid data unit" \
    "$EXE" encrypt --mode xts \
    --key xts_key.bin \
    --text "$xts_text" \
    --out xts_ct.bin

tamper_first_byte xts_ct.bin xts_ct_tampered.bin
cp xts_ct.bin.meta.json xts_ct_tampered.bin.meta.json

expect_success_and_text_not_equals "XTS tampering produces corrupted plaintext without authentication" xts_tampered.txt "$xts_text" \
    "$EXE" decrypt --mode xts \
    --key xts_key.bin \
    --in xts_ct_tampered.bin \
    --out xts_tampered.txt

echo ""
echo "Linux negative test summary: pass=$PASS fail=$FAIL total=$((PASS + FAIL))"

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

exit 0
