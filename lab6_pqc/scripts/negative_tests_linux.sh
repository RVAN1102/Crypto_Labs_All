#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXE="${ROOT}/build-linux/pqtool"
OPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR:-/opt/openssl-4.0}"
WORK="${ROOT}/artifacts/linux/demos/negative"
LOG="${ROOT}/artifacts/linux/logs/negative_tests_linux.log"
export LD_LIBRARY_PATH="${OPENSSL_ROOT_DIR}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
mkdir -p "${WORK}" "$(dirname "${LOG}")"
rm -rf "${WORK:?}"/*

failures=0
expect_fail() {
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "FAIL: ${name}"; failures=$((failures + 1))
    else
        echo "PASS: ${name}"
    fi
}
expect_mismatch() {
    local name="$1" left="$2" right="$3"
    if cmp -s "${left}" "${right}"; then
        echo "FAIL: ${name}"; failures=$((failures + 1))
    else
        echo "PASS: ${name}"
    fi
}
tamper_b64_field() {
    local field="$1" input="$2" output="$3"
    FIELD="${field}" perl -0777 -pe \
        '$f=$ENV{FIELD}; s/("\Q$f\E"\s*:\s*")([A-Za-z0-9+\/])/$1 . ($2 eq "A" ? "B" : "A")/e' \
        "${input}" > "${output}"
}
tamper_binary() {
    local input="$1" output="$2"
    perl -0777 -pe 'substr($_, 0, 1) = chr(ord(substr($_, 0, 1)) ^ 1)' \
        "${input}" > "${output}"
}

{
    printf 'negative tests\n' > "${WORK}/message.bin"
    "${EXE}" keygen --algo mldsa-44 --pub "${WORK}/dsa.pub" --priv "${WORK}/dsa.priv"
    "${EXE}" keygen --algo mldsa-44 --pub "${WORK}/wrong-dsa.pub" --priv "${WORK}/wrong-dsa.priv"
    "${EXE}" sign --algo mldsa-44 --priv "${WORK}/dsa.priv" --in "${WORK}/message.bin" --out "${WORK}/message.sig"
    cp "${WORK}/message.bin" "${WORK}/modified-message.bin"; printf X >> "${WORK}/modified-message.bin"
    tamper_binary "${WORK}/message.sig" "${WORK}/modified.sig"
    expect_fail "modified ML-DSA message" "${EXE}" verify --algo mldsa-44 --pub "${WORK}/dsa.pub" --in "${WORK}/modified-message.bin" --sig "${WORK}/message.sig"
    expect_fail "modified ML-DSA signature" "${EXE}" verify --algo mldsa-44 --pub "${WORK}/dsa.pub" --in "${WORK}/message.bin" --sig "${WORK}/modified.sig"
    expect_fail "wrong ML-DSA public key" "${EXE}" verify --algo mldsa-44 --pub "${WORK}/wrong-dsa.pub" --in "${WORK}/message.bin" --sig "${WORK}/message.sig"
    expect_fail "unsupported algorithm" "${EXE}" keygen --algo unsupported --pub x --priv y
    expect_fail "missing input file" "${EXE}" sign --algo mldsa-44 --priv "${WORK}/dsa.priv" --in "${WORK}/missing" --out "${WORK}/x"
    printf 'bad key' > "${WORK}/bad.priv"; printf 'bad key' > "${WORK}/bad.pub"
    expect_fail "malformed private key" "${EXE}" sign --algo mldsa-44 --priv "${WORK}/bad.priv" --in "${WORK}/message.bin" --out "${WORK}/x"
    expect_fail "malformed public key" "${EXE}" verify --algo mldsa-44 --pub "${WORK}/bad.pub" --in "${WORK}/message.bin" --sig "${WORK}/message.sig"

    "${EXE}" keygen --algo mlkem-512 --pub "${WORK}/kem.pub" --priv "${WORK}/kem.priv"
    "${EXE}" keygen --algo mlkem-512 --pub "${WORK}/wrong-kem.pub" --priv "${WORK}/wrong-kem.priv"
    "${EXE}" encaps --algo mlkem-512 --pub "${WORK}/kem.pub" --ct "${WORK}/kem.ct" --ss "${WORK}/expected.ss"
    tamper_binary "${WORK}/kem.ct" "${WORK}/modified.ct"
    "${EXE}" decaps --algo mlkem-512 --priv "${WORK}/kem.priv" --ct "${WORK}/modified.ct" --ss "${WORK}/modified.ss"
    expect_mismatch "modified ML-KEM ciphertext" "${WORK}/expected.ss" "${WORK}/modified.ss"
    "${EXE}" decaps --algo mlkem-512 --priv "${WORK}/wrong-kem.priv" --ct "${WORK}/kem.ct" --ss "${WORK}/wrong.ss"
    expect_mismatch "wrong ML-KEM private key" "${WORK}/expected.ss" "${WORK}/wrong.ss"

    "${EXE}" cert-create --subject "Student Lab 6" --subject-pub "${WORK}/dsa.pub" \
        --issuer "PQ-CA" --ca-priv "${WORK}/dsa.priv" --out "${WORK}/cert.json"
    sed 's/Student Lab 6/Mallory/' "${WORK}/cert.json" > "${WORK}/cert-subject.json"
    expect_fail "tampered certificate subject" "${EXE}" cert-verify --cert "${WORK}/cert-subject.json" --ca-pub "${WORK}/dsa.pub"
    tamper_b64_field public_key_pem_b64 "${WORK}/cert.json" "${WORK}/cert-public.json"
    expect_fail "tampered certificate public key" "${EXE}" cert-verify --cert "${WORK}/cert-public.json" --ca-pub "${WORK}/dsa.pub"
    tamper_b64_field signature_b64 "${WORK}/cert.json" "${WORK}/cert-signature.json"
    expect_fail "tampered certificate signature" "${EXE}" cert-verify --cert "${WORK}/cert-signature.json" --ca-pub "${WORK}/dsa.pub"

    if (( failures != 0 )); then
        echo "NEGATIVE TESTS FAIL: ${failures} case(s)"; exit 1
    fi
    echo "NEGATIVE TESTS PASS"
} 2>&1 | tee "${LOG}"
