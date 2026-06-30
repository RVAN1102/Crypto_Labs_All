#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INPUT_EXE="${1:-./build/rsatool}"
if [[ "$INPUT_EXE" = /* ]]; then
  EXE="$INPUT_EXE"
elif [ -e "$INPUT_EXE" ]; then
  EXE="$(cd "$(dirname "$INPUT_EXE")" && pwd)/$(basename "$INPUT_EXE")"
elif [ -e "$ROOT/$INPUT_EXE" ]; then
  EXE="$(cd "$(dirname "$ROOT/$INPUT_EXE")" && pwd)/$(basename "$INPUT_EXE")"
else
  EXE="$(pwd)/$INPUT_EXE"
fi

TMP_ROOT="$ROOT/tmp_negative_tests"
WORK="$TMP_ROOT/$(date +%Y%m%d_%H%M%S)_$$"
mkdir -p "$WORK"

cleanup() {
  case "$WORK" in
    "$TMP_ROOT"/*)
      rm -rf "$WORK"
      ;;
  esac
}
trap cleanup EXIT

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

tamper_envelope_hex_field() {
  python3 - "$1" "$2" "$3" <<'PY'
import re
import sys

inp, out, field = sys.argv[1:]
with open(inp, "r", encoding="ascii") as f:
    text = f.read()

pattern = rf'"{re.escape(field)}"\s*:\s*"([0-9a-fA-F]+)"'
match = re.search(pattern, text)
if not match:
    raise SystemExit(f"Field not found: {field}")

old = match.group(1)
new = ("1" if old[0] == "0" else "0") + old[1:]
text = text[:match.start(1)] + new + text[match.end(1):]

with open(out, "w", encoding="ascii") as f:
    f.write(text)
PY
}

if [ ! -x "$EXE" ]; then
  echo "Executable not found: $EXE"
  exit 1
fi

PRIV="$WORK/private.der"
PUB="$WORK/public.der"
WRONG_PRIV="$WORK/wrong_private.der"
WRONG_PUB="$WORK/wrong_public.der"
PEM_PRIV="$WORK/private.pem"
PEM_PUB="$WORK/public.pem"
PEM_META="$WORK/key_metadata.json"
BAD_PEM_PUB="$WORK/bad_public.pem"
PT="$WORK/plain.bin"
RSA_CT="$WORK/direct.rsa"
RSA_OUT="$WORK/direct.out"
PEM_RSA_CT="$WORK/direct_pem.rsa"
PEM_RSA_OUT="$WORK/direct_pem.out"
CT="$WORK/hybrid.ct"
ENV="$WORK/hybrid.env.json"
OUT="$WORK/hybrid.out"
PEM_CT="$WORK/hybrid_pem.ct"
PEM_ENV="$WORK/hybrid_pem.env.json"
PEM_OUT="$WORK/hybrid_pem.out"
AUTO_SMALL_CT="$WORK/auto_small.ct"
AUTO_SMALL_OUT="$WORK/auto_small.out"
AUTO_LARGE_CT="$WORK/auto_large.ct"
AUTO_LARGE_OUT="$WORK/auto_large.out"
AUTO_LARGE_MALFORMED_ENV="$WORK/auto_large_malformed.env.json"

printf 'Lab 3 negative tests plaintext' > "$PT"

expect_success "keygen RSA-3072" keygen --bits 3072 --private "$PRIV" --public "$PUB"
expect_success "keygen wrong RSA-3072" keygen --bits 3072 --private "$WRONG_PRIV" --public "$WRONG_PUB"
expect_success "keygen RSA-3072 PEM aliases with metadata" keygen --bits 3072 --priv "$PEM_PRIV" --pub "$PEM_PUB" --meta "$PEM_META"
expect_fail "keygen RSA-2048 rejected" keygen --bits 2048 --private "$WORK/bad.der" --public "$WORK/badpub.der"

if [ -f "$PEM_META" ] && grep -q '"mgf"[[:space:]]*:[[:space:]]*"MGF1-SHA256"' "$PEM_META"; then
  pass "key metadata records MGF1-SHA256"
else
  fail "key metadata records MGF1-SHA256" "metadata missing or malformed"
fi

expect_success "OAEP encrypt baseline" oaep-encrypt --pub "$PUB" --in "$PT" --out "$RSA_CT" --label-text right
expect_success "OAEP decrypt baseline" oaep-decrypt --priv "$PRIV" --in "$RSA_CT" --out "$RSA_OUT" --label-text right
cmp -s "$PT" "$RSA_OUT" && pass "OAEP plaintext recovered" || fail "OAEP plaintext recovered" "mismatch"
expect_fail "OAEP wrong label rejected" oaep-decrypt --priv "$PRIV" --in "$RSA_CT" --out "$WORK/wrong_label.out" --label-text wrong
expect_fail "OAEP wrong private key rejected" oaep-decrypt --priv "$WRONG_PRIV" --in "$RSA_CT" --out "$WORK/wrong_key.out" --label-text right

expect_success "OAEP PEM encrypt baseline" oaep-encrypt --pub "$PEM_PUB" --in "$PT" --out "$PEM_RSA_CT" --label-text pem
expect_success "OAEP PEM decrypt baseline" oaep-decrypt --priv "$PEM_PRIV" --in "$PEM_RSA_CT" --out "$PEM_RSA_OUT" --label-text pem
cmp -s "$PT" "$PEM_RSA_OUT" && pass "OAEP PEM plaintext recovered" || fail "OAEP PEM plaintext recovered" "mismatch"

printf '%s\n' '-----BEGIN RSA PUBLIC KEY-----' 'not-valid-base64' '-----END RSA PUBLIC KEY-----' > "$BAD_PEM_PUB"
expect_fail "corrupted PEM public key rejected" oaep-encrypt --pub "$BAD_PEM_PUB" --in "$PT" --out "$WORK/bad_pem.rsa"

python3 - "$WORK/too_large.bin" <<'PY'
import sys
open(sys.argv[1], "wb").write(bytes([x % 256 for x in range(319)]))
PY
expect_fail "OAEP oversized plaintext rejected" oaep-encrypt --pub "$PUB" --in "$WORK/too_large.bin" --out "$WORK/too_large.rsa"

expect_success "hybrid encrypt baseline" seal --pub "$PUB" --in "$PT" --out "$CT" --envelope "$ENV" --label-text right
expect_success "hybrid decrypt baseline" open --priv "$PRIV" --in "$CT" --envelope "$ENV" --out "$OUT" --label-text right
cmp -s "$PT" "$OUT" && pass "hybrid plaintext recovered" || fail "hybrid plaintext recovered" "mismatch"

expect_success "hybrid PEM encrypt baseline" hybrid-encrypt --pub "$PEM_PUB" --in "$PT" --out "$PEM_CT" --envelope "$PEM_ENV" --label-text pem
expect_success "hybrid PEM decrypt baseline" hybrid-decrypt --priv "$PEM_PRIV" --in "$PEM_CT" --envelope "$PEM_ENV" --out "$PEM_OUT" --label-text pem
cmp -s "$PT" "$PEM_OUT" && pass "hybrid PEM plaintext recovered" || fail "hybrid PEM plaintext recovered" "mismatch"

expect_fail "hybrid wrong label rejected" open --priv "$PRIV" --in "$CT" --envelope "$ENV" --out "$WORK/wrong_label.out" --label-text wrong
expect_fail "hybrid wrong private key rejected" open --priv "$WRONG_PRIV" --in "$CT" --envelope "$ENV" --out "$WORK/wrong_key.out" --label-text right

tamper_first_byte "$CT" "$WORK/tampered.ct"
expect_fail "hybrid tampered ciphertext rejected" open --priv "$PRIV" --in "$WORK/tampered.ct" --envelope "$ENV" --out "$WORK/tampered.out" --label-text right

tamper_envelope_hex_field "$ENV" "$WORK/bad_tag.env.json" "tag_hex"
expect_fail "hybrid tampered GCM tag rejected" open --priv "$PRIV" --in "$CT" --envelope "$WORK/bad_tag.env.json" --out "$WORK/bad_tag.out" --label-text right

tamper_envelope_hex_field "$ENV" "$WORK/bad_key.env.json" "encrypted_key_hex"
expect_fail "hybrid tampered encrypted AES key rejected" open --priv "$PRIV" --in "$CT" --envelope "$WORK/bad_key.env.json" --out "$WORK/bad_key.out" --label-text right

sed -E 's/"nonce_hex"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]+",[[:space:]]*//' "$ENV" > "$WORK/malformed.env.json"
expect_fail "hybrid malformed envelope rejected" open --priv "$PRIV" --in "$CT" --envelope "$WORK/malformed.env.json" --out "$WORK/malformed.out" --label-text right

sed -E 's/"version"[[:space:]]*:[[:space:]]*1/"version": 99/' "$ENV" > "$WORK/bad_version.env.json"
expect_fail "hybrid unsupported version rejected" open --priv "$PRIV" --in "$CT" --envelope "$WORK/bad_version.env.json" --out "$WORK/bad_version.out" --label-text right

sed -E 's/AES-256-GCM/AES-128-GCM/g' "$ENV" > "$WORK/bad_alg.env.json"
expect_fail "hybrid algorithm mismatch rejected" open --priv "$PRIV" --in "$CT" --envelope "$WORK/bad_alg.env.json" --out "$WORK/bad_alg.out" --label-text right

sed -E 's/"oaep_label_present"[[:space:]]*:[[:space:]]*true/"oaep_label_present": false/' "$ENV" > "$WORK/bad_label_indicator.env.json"
expect_fail "hybrid label indicator mismatch rejected" open --priv "$PRIV" --in "$CT" --envelope "$WORK/bad_label_indicator.env.json" --out "$WORK/bad_label_indicator.out" --label-text right

SMALL_PLAIN="$WORK/auto_small_plain.bin"
printf 'small assignment-compatible message' > "$SMALL_PLAIN"
expect_success "auto encrypt small uses OAEP" encrypt --pub "$PUB" --in "$SMALL_PLAIN" --out "$AUTO_SMALL_CT" --label-text auto
if [ "$(wc -c < "$AUTO_SMALL_CT")" -eq 384 ] && [ ! -f "$AUTO_SMALL_CT.envelope.json" ]; then
  pass "auto small output is direct RSA ciphertext"
else
  fail "auto small output is direct RSA ciphertext" "unexpected length or envelope sidecar"
fi
expect_success "auto decrypt small OAEP" decrypt --priv "$PRIV" --in "$AUTO_SMALL_CT" --out "$AUTO_SMALL_OUT" --label-text auto
cmp -s "$SMALL_PLAIN" "$AUTO_SMALL_OUT" && pass "auto small plaintext recovered" || fail "auto small plaintext recovered" "mismatch"
expect_fail "auto decrypt wrong label rejected" decrypt --priv "$PRIV" --in "$AUTO_SMALL_CT" --out "$WORK/auto_wrong_label.out" --label-text wrong

expect_success "auto encrypt large switches to hybrid" encrypt --pub "$PUB" --in "$WORK/too_large.bin" --out "$AUTO_LARGE_CT" --label-text auto
if [ -f "$AUTO_LARGE_CT.envelope.json" ]; then
  pass "auto large envelope sidecar created"
else
  fail "auto large envelope sidecar created" "missing default envelope"
fi
expect_success "auto decrypt large discovers envelope" decrypt --priv "$PRIV" --in "$AUTO_LARGE_CT" --out "$AUTO_LARGE_OUT" --label-text auto
cmp -s "$WORK/too_large.bin" "$AUTO_LARGE_OUT" && pass "auto large plaintext recovered" || fail "auto large plaintext recovered" "mismatch"
sed -E 's/"tag_hex"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]+"/"tag_hex": "00"/' "$AUTO_LARGE_CT.envelope.json" > "$AUTO_LARGE_MALFORMED_ENV"
expect_fail "auto decrypt malformed envelope rejected" decrypt --priv "$PRIV" --in "$AUTO_LARGE_CT" --envelope "$AUTO_LARGE_MALFORMED_ENV" --out "$WORK/auto_malformed.out" --label-text auto

TOTAL=$((PASS + FAIL))
echo "Linux negative test summary: pass=$PASS fail=$FAIL total=$TOTAL"
[ "$FAIL" -eq 0 ] && [ "$TOTAL" -eq 40 ]
