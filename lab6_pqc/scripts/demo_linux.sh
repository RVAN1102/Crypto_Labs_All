#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXE="${ROOT}/build-linux/pqtool"
OPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR:-/opt/openssl-4.0}"
DEMO="${ROOT}/artifacts/linux/demos"
KEYS="${ROOT}/artifacts/linux/keys"
CERTS="${ROOT}/artifacts/linux/certs"
LOG="${ROOT}/artifacts/linux/logs/demo_linux.log"
export LD_LIBRARY_PATH="${OPENSSL_ROOT_DIR}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
mkdir -p "${DEMO}" "${KEYS}" "${CERTS}" "$(dirname "${LOG}")"
find "${DEMO}" -mindepth 1 -maxdepth 1 ! -name .gitkeep -exec rm -rf -- {} +
find "${KEYS}" -mindepth 1 -maxdepth 1 ! -name .gitkeep -exec rm -rf -- {} +
find "${CERTS}" -mindepth 1 -maxdepth 1 ! -name .gitkeep -exec rm -rf -- {} +

{
    printf 'Lab 6 binary-safe demo\n\0payload\n' > "${DEMO}/message.bin"
    "${EXE}" keygen --algo mldsa-44 --pub "${KEYS}/ca_mldsa44_pub.pem" --priv "${KEYS}/ca_mldsa44_priv.pem"
    "${EXE}" keygen --algo mldsa-44 --pub "${KEYS}/subject_mldsa44_pub.pem" --priv "${KEYS}/subject_mldsa44_priv.pem"
    "${EXE}" sign --algo mldsa-44 --priv "${KEYS}/subject_mldsa44_priv.pem" \
        --in "${DEMO}/message.bin" --out "${DEMO}/message.sig"
    "${EXE}" verify --algo mldsa-44 --pub "${KEYS}/subject_mldsa44_pub.pem" \
        --in "${DEMO}/message.bin" --sig "${DEMO}/message.sig"
    cp "${DEMO}/message.bin" "${DEMO}/tampered-message.bin"
    printf X >> "${DEMO}/tampered-message.bin"
    if "${EXE}" verify --algo mldsa-44 --pub "${KEYS}/subject_mldsa44_pub.pem" \
        --in "${DEMO}/tampered-message.bin" --sig "${DEMO}/message.sig"; then
        echo "ERROR: tampered message verified"; exit 1
    fi
    echo "PASS: tampered message rejected"

    "${EXE}" keygen --algo mlkem-512 --pub "${KEYS}/mlkem512_pub.pem" --priv "${KEYS}/mlkem512_priv.pem"
    "${EXE}" encaps --algo mlkem-512 --pub "${KEYS}/mlkem512_pub.pem" \
        --ct "${DEMO}/kem.ct" --ss "${DEMO}/sender.ss"
    "${EXE}" decaps --algo mlkem-512 --priv "${KEYS}/mlkem512_priv.pem" \
        --ct "${DEMO}/kem.ct" --ss "${DEMO}/recipient.ss"
    cmp -s "${DEMO}/sender.ss" "${DEMO}/recipient.ss"
    echo "PASS: ML-KEM shared secrets match (bytes not printed)"

    "${EXE}" cert-create --subject "Student Lab 6" \
        --subject-pub "${KEYS}/subject_mldsa44_pub.pem" --issuer "PQ-CA" \
        --ca-priv "${KEYS}/ca_mldsa44_priv.pem" --out "${CERTS}/student-cert.json"
    "${EXE}" cert-verify --cert "${CERTS}/student-cert.json" --ca-pub "${KEYS}/ca_mldsa44_pub.pem"
    sed 's/Student Lab 6/Tampered Student/' "${CERTS}/student-cert.json" > "${CERTS}/tampered-cert.json"
    if "${EXE}" cert-verify --cert "${CERTS}/tampered-cert.json" --ca-pub "${KEYS}/ca_mldsa44_pub.pem"; then
        echo "ERROR: tampered certificate verified"; exit 1
    fi
    echo "PASS: tampered certificate rejected"
    "${EXE}" selftest
    echo "DEMO PASS"
} 2>&1 | tee "${LOG}"
