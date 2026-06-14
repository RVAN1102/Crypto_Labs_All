#!/usr/bin/env bash
set -u

EXE="${1:-./build/rsatool}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/tmp_negative_tests/$(date +%Y%m%d_%H%M%S)_$$"
mkdir -p "$WORK"

PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1 :: $2"; FAIL=$((FAIL + 1)); }

expect_success() {
  local name="$1"; shift
  local output
  if output="$("$EXE" "$@" 2>&1)"; then
    pass "$name"
  else
    fail "$name" "expected success, output=$output"
  fi
}

expect_fail() {
  local name="$1"; shift
  if "$EXE" "$@" >/dev/null 2>&1; then
    fail "$name" "expected failure, command succeeded"
  else
    pass "$name"
  fi
}

tamper_first_byte() {
  cp "$1" "$2"
  printf '\x01' | dd of="$2" bs=1 count=1 conv=notrunc status=none
}

if [ ! -x "$EXE" ]; then
  echo "Executable not found: $EXE"
  exit 1
fi

PRIV="$WORK/private.der"
PUB="$WORK/public.der"
WRONG_PRIV="$WORK/wrong_private.der"
WRONG_PUB="$WORK/wrong_public.der"
PT="$WORK/plain.bin"
RSA_CT="$WORK/direct.rsa"
RSA_OUT="$WORK/direct.out"
CT="$WORK/hybrid.ct"
ENV="$WORK/hybrid.env.json"
OUT="$WORK/hybrid.out"

printf 'Lab 3 negative tests plaintext' > "$PT"

expect_success "keygen RSA-3072" keygen --bits 3072 --private "$PRIV" --public "$PUB"
expect_success "keygen wrong RSA-3072" keygen --bits 3072 --private "$WRONG_PRIV" --public "$WRONG_PUB"
expect_fail "keygen RSA-2048 rejected" keygen --bits 2048 --private "$WORK/bad.der" --public "$WORK/badpub.der"

expect_success "OAEP encrypt baseline" oaep-encrypt --pub "$PUB" --in "$PT" --out "$RSA_CT" --label-text right
expect_success "OAEP decrypt baseline" oaep-decrypt --priv "$PRIV" --in "$RSA_CT" --out "$RSA_OUT" --label-text right
cmp -s "$PT" "$RSA_OUT" && pass "OAEP plaintext recovered" || fail "OAEP plaintext recovered" "mismatch"
expect_fail "OAEP wrong label rejected" oaep-decrypt --priv "$PRIV" --in "$RSA_CT" --out "$WORK/wrong_label.out" --label-text wrong
expect_fail "OAEP wrong private key rejected" oaep-decrypt --priv "$WRONG_PRIV" --in "$RSA_CT" --out "$WORK/wrong_key.out" --label-text right

python3 - "$WORK/too_large.bin" <<'PY'
import sys
open(sys.argv[1], "wb").write(bytes([x % 256 for x in range(319)]))
PY
expect_fail "OAEP oversized plaintext rejected" oaep-encrypt --pub "$PUB" --in "$WORK/too_large.bin" --out "$WORK/too_large.rsa"

expect_success "hybrid encrypt baseline" seal --pub "$PUB" --in "$PT" --out "$CT" --envelope "$ENV" --label-text right
expect_success "hybrid decrypt baseline" open --priv "$PRIV" --in "$CT" --envelope "$ENV" --out "$OUT" --label-text right
cmp -s "$PT" "$OUT" && pass "hybrid plaintext recovered" || fail "hybrid plaintext recovered" "mismatch"

expect_fail "hybrid wrong label rejected" open --priv "$PRIV" --in "$CT" --envelope "$ENV" --out "$WORK/wrong_label.out" --label-text wrong
expect_fail "hybrid wrong private key rejected" open --priv "$WRONG_PRIV" --in "$CT" --envelope "$ENV" --out "$WORK/wrong_key.out" --label-text right

tamper_first_byte "$CT" "$WORK/tampered.ct"
expect_fail "hybrid tampered ciphertext rejected" open --priv "$PRIV" --in "$WORK/tampered.ct" --envelope "$ENV" --out "$WORK/tampered.out" --label-text right

sed -E 's/"version"[[:space:]]*:[[:space:]]*1/"version": 99/' "$ENV" > "$WORK/bad_version.env.json"
expect_fail "hybrid unsupported version rejected" open --priv "$PRIV" --in "$CT" --envelope "$WORK/bad_version.env.json" --out "$WORK/bad_version.out" --label-text right

sed -E 's/AES-256-GCM/AES-128-GCM/g' "$ENV" > "$WORK/bad_alg.env.json"
expect_fail "hybrid algorithm mismatch rejected" open --priv "$PRIV" --in "$CT" --envelope "$WORK/bad_alg.env.json" --out "$WORK/bad_alg.out" --label-text right

sed -E 's/"oaep_label_present"[[:space:]]*:[[:space:]]*true/"oaep_label_present": false/' "$ENV" > "$WORK/bad_label_indicator.env.json"
expect_fail "hybrid label indicator mismatch rejected" open --priv "$PRIV" --in "$CT" --envelope "$WORK/bad_label_indicator.env.json" --out "$WORK/bad_label_indicator.out" --label-text right

echo "Negative test summary: pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
