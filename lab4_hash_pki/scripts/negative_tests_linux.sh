#!/usr/bin/env bash
set -euo pipefail

exe="${1:-./build/hashtool}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

stamp="$(date +%Y%m%d_%H%M%S_%N)"
work="$root/tmp_negative_tests/$stamp"
mkdir -p "$work"

pass=0
fail=0

write_pass() {
    printf '[PASS] %s\n' "$1"
    pass=$((pass + 1))
}

write_fail() {
    printf '[FAIL] %s :: %s\n' "$1" "$2"
    fail=$((fail + 1))
}

run_cmd() {
    local output
    set +e
    output="$("$exe" "$@" 2>&1)"
    local code=$?
    set -e
    RUN_CODE="$code"
    RUN_OUTPUT="$output"
}

expect_success() {
    local name="$1"
    shift
    run_cmd "$@"
    if [[ "$RUN_CODE" -eq 0 ]]; then
        write_pass "$name"
    else
        write_fail "$name" "expected success, exit=$RUN_CODE, output=$RUN_OUTPUT"
    fi
}

expect_fail() {
    local name="$1"
    shift
    run_cmd "$@"
    if [[ "$RUN_CODE" -ne 0 ]]; then
        write_pass "$name"
    else
        write_fail "$name" "expected failure, command succeeded"
    fi
}

printf 'Running Lab 4 negative tests with: %s\n' "$exe"
printf 'Working directory: %s\n\n' "$work"

if [[ ! -x "$exe" ]]; then
    echo "executable not found or not executable: $exe" >&2
    exit 1
fi

input_file="$work/input.bin"
printf 'abc' > "$input_file"

expect_fail "unsupported algorithm rejected" hash --algo md5 --text abc
expect_fail "SHAKE without outlen rejected" hash --algo shake256 --text abc
expect_fail "fixed hash with outlen rejected" hash --algo sha256 --outlen 64 --text abc
expect_fail "missing input rejected" hash --algo sha256
expect_fail "both in and text rejected" hash --algo sha256 --in "$input_file" --text abc
expect_fail "invalid encoding rejected" hash --algo sha256 --text abc --encode base32
expect_fail "file not found rejected" hash --algo sha256 --in "$work/missing.bin"
expect_fail "wrong HMAC fails verification" hmac-verify --algo sha256 --key-hex 001122 --text hello --mac-hex 00
expect_fail "malformed key hex rejected" hmac --algo sha256 --key-hex 00112 --text hello

expect_success "valid hash still works" hash --algo sha256 --text abc

cert_dir="$root/tests/certs"
leaf_valid="$cert_dir/leaf_valid.pem"
test_ca="$cert_dir/test_ca.pem"
wrong_ca="$cert_dir/wrong_ca.pem"
malformed_cert="$cert_dir/malformed_cert.pem"
leaf_no_san="$cert_dir/leaf_no_san.pem"
expired_leaf="$cert_dir/expired_leaf.pem"

expect_fail "malformed certificate rejected" cert-info --cert "$malformed_cert"
expect_fail "wrong issuer fails certificate verification" cert-verify --cert "$leaf_valid" --issuer "$wrong_ca"
expect_success "correct issuer verifies certificate" cert-verify --cert "$leaf_valid" --issuer "$test_ca"

run_cmd cert-policy --cert "$leaf_no_san"
if [[ "$RUN_CODE" -eq 0 && "$RUN_OUTPUT" == *"CHECK tls_server_san FAIL"* ]]; then
    write_pass "missing SAN flagged"
else
    write_fail "missing SAN flagged" "exit=$RUN_CODE, output=$RUN_OUTPUT"
fi

if [[ -f "$expired_leaf" ]]; then
    run_cmd cert-policy --cert "$expired_leaf"
    if [[ "$RUN_CODE" -eq 0 && "$RUN_OUTPUT" == *"CHECK validity_not_after FAIL"* ]]; then
        write_pass "expired certificate flagged"
    else
        write_fail "expired certificate flagged" "exit=$RUN_CODE, output=$RUN_OUTPUT"
    fi
fi

bench_raw="$work/bench_raw.csv"
bench_summary="$work/bench_summary.csv"
expect_fail "unsupported benchmark algorithm rejected" bench --out "$bench_raw" --summary "$bench_summary" --runs 1 --ops 1 --warmup-ms 0 --sizes 1m --algos sha256,md5 --platform ubuntu
expect_fail "invalid benchmark size rejected" bench --out "$bench_raw" --summary "$bench_summary" --runs 1 --ops 1 --warmup-ms 0 --sizes 2m --algos sha256 --platform ubuntu
expect_fail "missing benchmark output rejected" bench --summary "$bench_summary" --runs 1 --ops 1 --warmup-ms 0 --sizes 1m --algos sha256 --platform ubuntu

length_extension_dir="$work/length_extension"
expect_success "length-extension demo runs" length-extension-demo --out-dir "$length_extension_dir"
verification_file="$length_extension_dir/verification_result.txt"
if [[ -f "$verification_file" && "$(cat "$verification_file")" == *"naive_forged_verify=PASS"* ]]; then
    write_pass "forged naive MAC accepted"
else
    write_fail "forged naive MAC accepted" "verification_result.txt missing or did not contain naive_forged_verify=PASS"
fi

if [[ -f "$verification_file" && "$(cat "$verification_file")" == *"hmac_forged_verify=FAIL"* ]]; then
    write_pass "forged message rejected under HMAC"
else
    write_fail "forged message rejected under HMAC" "verification_result.txt missing or did not contain hmac_forged_verify=FAIL"
fi

printf '\nNegative test summary: pass=%d fail=%d\n' "$pass" "$fail"

if [[ "$fail" -ne 0 ]]; then
    exit 1
fi

