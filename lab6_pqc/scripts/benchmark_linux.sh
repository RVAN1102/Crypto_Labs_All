#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXE="${ROOT}/build-linux/pqtool"
OPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR:-/opt/openssl-4.0}"
OUT="${ROOT}/artifacts/linux/benchmarks"
LOG="${ROOT}/artifacts/linux/logs/benchmark_linux.log"
export LD_LIBRARY_PATH="${OPENSSL_ROOT_DIR}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
runs=30
if [[ "${1:-}" == "--quick" ]]; then runs=3
elif [[ $# -ne 0 ]]; then echo "Usage: $0 [--quick]" >&2; exit 2
fi
mkdir -p "${OUT}" "$(dirname "${LOG}")"
rm -f "${OUT}"/*.csv

{
    for alg in mldsa-44 mldsa-65; do
        "${EXE}" bench --algo "${alg}" --ops keygen,sign,verify \
            --sizes 1024,16384,1048576,8388608 --runs "${runs}" \
            --out "${OUT}/${alg}.csv"
    done
    for alg in mlkem-512 mlkem-768; do
        "${EXE}" bench --algo "${alg}" --ops keygen,encaps,decaps \
            --runs "${runs}" --out "${OUT}/${alg}.csv"
    done
    "${EXE}" timing-variance --algo mldsa-44 --case verify-valid-vs-invalid \
        --runs "${runs}" --out "${OUT}/timing_variance_mldsa44.csv"
    "${EXE}" timing-variance --algo mlkem-512 --case decaps-valid-vs-invalid \
        --runs "${runs}" --out "${OUT}/timing_variance_mlkem512.csv"
    echo "BENCHMARK PASS (${runs} runs)"
} 2>&1 | tee "${LOG}"

