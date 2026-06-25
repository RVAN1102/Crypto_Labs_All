#!/usr/bin/env bash
set -Eeuo pipefail

RUN_1G=0
if [[ "${1:-}" == "--run-1g" ]]; then
  RUN_1G=1
fi

REPO="$HOME/Crypto_Labs_All"
LAB="$REPO/lab4_hash_pki"
BUILD="$LAB/build-linux"
LOGS="$LAB/artifacts/linux/logs"
BENCH="$LAB/artifacts/linux/bench"
BIN="$LAB/artifacts/linux/binaries"
REPORT="$LAB/report"
EXE="$BUILD/hashtool"
MULTIARCH="$(gcc -print-multiarch)"
OPENSSL_INCLUDE="/usr/include"
OPENSSL_CRYPTO="/usr/lib/${MULTIARCH}/libcrypto.so"
OPENSSL_SSL="/usr/lib/${MULTIARCH}/libssl.so"

mkdir -p "$LOGS" "$BENCH" "$BIN" "$REPORT"

run_step() {
  local name="$1"
  local log="$2"
  shift 2

  echo "==== $name ===="
  set +e
  "$@" > "$log" 2>&1
  local code=$?
  set -e

  if [[ $code -ne 0 ]]; then
    echo "[FAIL] $name"
    echo "Log: $log"
    cat "$log"
    exit $code
  fi

  echo "[PASS] $name"
}

require_text() {
  local file="$1"
  local pattern="$2"
  local message="$3"

  if ! grep -Eq "$pattern" "$file"; then
    echo "[FAIL] $message"
    echo "File: $file"
    cat "$file"
    exit 1
  fi
}

cd "$REPO"

branch="$(git branch --show-current)"
if [[ "$branch" != "master" ]]; then
  echo "Wrong branch: $branch. Expected master."
  exit 1
fi

git status -sb > "$LOGS/git_status_before_ubuntu_final.log"

rm -rf "$BUILD"

run_step "configure_ubuntu" "$LOGS/configure_ubuntu_final.log" \
  cmake -S "$LAB" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_ROOT_DIR=/usr \
    -DOPENSSL_INCLUDE_DIR="$OPENSSL_INCLUDE" \
    -DOPENSSL_CRYPTO_LIBRARY="$OPENSSL_CRYPTO" \
    -DOPENSSL_SSL_LIBRARY="$OPENSSL_SSL"

run_step "build_ubuntu" "$LOGS/build_ubuntu_final.log" \
  cmake --build "$BUILD" -j"$(nproc)"

chmod +x "$EXE"
chmod +x "$LAB/scripts/negative_tests_linux.sh" || true
chmod +x "$LAB/scripts/verify_md5_collision.sh" || true
chmod +x "$LAB/scripts/tls_local_self_signed_demo_linux.sh" || true

sed -i 's/\r$//' "$LAB/scripts/negative_tests_linux.sh" || true
sed -i 's/\r$//' "$LAB/scripts/verify_md5_collision.sh" || true
sed -i 's/\r$//' "$LAB/scripts/tls_local_self_signed_demo_linux.sh" || true

run_step "help_ubuntu" "$LOGS/help_ubuntu_final.log" \
  "$EXE" --help

run_step "ctest_ubuntu" "$LOGS/ctest_ubuntu_final.log" \
  ctest --test-dir "$BUILD" --output-on-failure

require_text "$LOGS/ctest_ubuntu_final.log" "100% tests passed, 0 tests failed out of 17" "CTest did not pass 17/17"

run_step "negative_tests_ubuntu" "$LOGS/negative_tests_ubuntu_final.log" \
  "$LAB/scripts/negative_tests_linux.sh" "$EXE"

require_text "$LOGS/negative_tests_ubuntu_final.log" "fail=0" "Negative tests did not report fail=0"

run_step "kat_hash_ubuntu" "$LOGS/kat_hash_ubuntu_final.log" \
  "$EXE" kat --kat "$LAB/vectors/hash_kat.json"

require_text "$LOGS/kat_hash_ubuntu_final.log" "KAT summary: pass=16 fail=0 total=16" "Hash KAT did not pass 16/16"

run_step "kat_shake_ubuntu" "$LOGS/kat_shake_ubuntu_final.log" \
  "$EXE" kat --kat "$LAB/vectors/shake_kat.json"

require_text "$LOGS/kat_shake_ubuntu_final.log" "KAT summary: pass=4 fail=0 total=4" "SHAKE KAT did not pass 4/4"

run_step "hash_suite_ubuntu" "$LOGS/hash_suite_ubuntu_final.log" bash -c "
  '$EXE' hash --algo sha224 --text abc
  '$EXE' hash --algo sha256 --text abc
  '$EXE' hash --algo sha384 --text abc
  '$EXE' hash --algo sha512 --text abc
  '$EXE' hash --algo sha3-224 --text abc
  '$EXE' hash --algo sha3-256 --text abc
  '$EXE' hash --algo sha3-384 --text abc
  '$EXE' hash --algo sha3-512 --text abc
  '$EXE' hash --algo shake128 --outlen 64 --text abc
  '$EXE' hash --algo shake256 --outlen 64 --text abc
"

run_step "pki_x509_ubuntu" "$LOGS/pki_x509_ubuntu_final.log" bash -c "
  '$EXE' cert-info --cert '$LAB/tests/certs/leaf_valid.pem'
  '$EXE' cert-info --cert '$LAB/tests/certs/leaf_valid.der' --format der
  '$EXE' cert-verify --cert '$LAB/tests/certs/leaf_valid.pem' --issuer '$LAB/tests/certs/test_ca.pem'
  '$EXE' cert-policy --cert '$LAB/tests/certs/leaf_no_san.pem'
  '$EXE' cert-policy --cert '$LAB/tests/certs/leaf_weak.pem'
  '$EXE' cert-policy --cert '$LAB/tests/certs/expired_leaf.pem'
"

echo "==== pki_wrong_issuer_ubuntu_expected_fail ===="
set +e
"$EXE" cert-verify --cert "$LAB/tests/certs/leaf_valid.pem" --issuer "$LAB/tests/certs/wrong_ca.pem" > "$LOGS/pki_wrong_issuer_ubuntu_final.log" 2>&1
wrong_code=$?
set -e
{
  echo "exit_code=$wrong_code"
  if [[ $wrong_code -ne 0 ]]; then
    echo "Wrong issuer rejected as expected with exit code $wrong_code"
  fi
} >> "$LOGS/pki_wrong_issuer_ubuntu_final.log"

if [[ $wrong_code -eq 0 ]]; then
  echo "[FAIL] pki_wrong_issuer_ubuntu_expected_fail"
  cat "$LOGS/pki_wrong_issuer_ubuntu_final.log"
  exit 1
fi
echo "[PASS] pki_wrong_issuer_ubuntu_expected_fail"

run_step "length_extension_ubuntu" "$LOGS/length_extension_ubuntu_final.log" bash -c "
  '$EXE' length-extension-demo --out-dir '$LAB/demos/length_extension'
  cat '$LAB/demos/length_extension/verification_result.txt'
"

require_text "$LAB/demos/length_extension/verification_result.txt" "naive_original_verify=PASS" "Original naive MAC verification did not pass"
require_text "$LAB/demos/length_extension/verification_result.txt" "naive_forged_verify=PASS" "Forged naive MAC did not pass"
require_text "$LAB/demos/length_extension/verification_result.txt" "hmac_forged_verify=FAIL" "Forged HMAC was not rejected"

run_step "md5_collision_verify_ubuntu" "$LOGS/md5_collision_verify_ubuntu_final.log" bash -c "
  '$LAB/scripts/verify_md5_collision.sh' '$LAB/demos/md5_collision'
  md5sum '$LAB/demos/md5_collision/collision_a.bin' '$LAB/demos/md5_collision/collision_b.bin'
  sha256sum '$LAB/demos/md5_collision/collision_a.bin' '$LAB/demos/md5_collision/collision_b.bin'
"

require_text "$LOGS/md5_collision_verify_ubuntu_final.log" "PASS" "MD5 collision verification did not pass"

run_step "tls_local_self_signed_ubuntu" "$LOGS/tls_local_self_signed_ubuntu_final.log" bash -c "
  '$LAB/scripts/tls_local_self_signed_demo_linux.sh'
  cat '$LAB/demos/tls/tls_test_log.txt'
  cat '$LAB/demos/tls/cert_chain_info.txt'
"

run_step "bench_ubuntu_1m" "$LOGS/bench_ubuntu_1m_final.log" \
  "$EXE" bench --out "$BENCH/bench_ubuntu_1m_raw.csv" --summary "$BENCH/bench_ubuntu_1m_summary.csv" --runs 30 --ops 100 --warmup-ms 1000 --sizes 1m --algos sha256,sha512,sha3-256,sha3-512 --platform ubuntu24.04-gcc

run_step "bench_ubuntu_100m" "$LOGS/bench_ubuntu_100m_final.log" \
  "$EXE" bench --out "$BENCH/bench_ubuntu_100m_raw.csv" --summary "$BENCH/bench_ubuntu_100m_summary.csv" --runs 30 --ops 1 --warmup-ms 1000 --sizes 100m --algos sha256,sha512,sha3-256,sha3-512 --platform ubuntu24.04-gcc

if [[ "$RUN_1G" -eq 1 ]]; then
  run_step "bench_ubuntu_1g" "$LOGS/bench_ubuntu_1g_final.log" \
    "$EXE" bench --out "$BENCH/bench_ubuntu_1g_raw.csv" --summary "$BENCH/bench_ubuntu_1g_summary.csv" --runs 3 --ops 1 --warmup-ms 500 --sizes 1g --algos sha256,sha512,sha3-256,sha3-512 --platform ubuntu24.04-gcc
fi

cp -f "$EXE" "$BIN/hashtool"
cp -f "$BUILD/libhashtool_core.a" "$BIN/libhashtool_core.a"

{
  echo "Lab 4 Ubuntu Environment"
  echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "OS: $(. /etc/os-release && echo "$PRETTY_NAME")"
  echo "Kernel: $(uname -a)"
  echo "Compiler: $(g++ --version | head -1)"
  echo "CMake: $(cmake --version | head -1)"
  echo "OpenSSL: $(openssl version)"
  echo "g++ path: $(command -v g++)"
  echo "cmake path: $(command -v cmake)"
  echo "openssl path: $(command -v openssl)"
  echo "Build type: Release"
  echo "Generator: default Unix Makefiles"
  echo "Tool: lab4_hash_pki/build-linux/hashtool"
  echo "Core library bonus artifact: lab4_hash_pki/artifacts/linux/binaries/libhashtool_core.a"
  echo ""
  lscpu | grep -E 'Model name|CPU\(s\)|Thread|Core|Socket' || true
} > "$REPO/lab4_ubuntu_environment.txt"

cat > "$REPORT/capture_commands_ubuntu.md" <<CAPTURE
# Lab 4 Ubuntu capture commands

Run final CTest screenshot:
ctest --test-dir lab4_hash_pki/build-linux --output-on-failure

Run final negative tests screenshot:
./lab4_hash_pki/scripts/negative_tests_linux.sh "\$(realpath lab4_hash_pki/build-linux/hashtool)"

Run MD5 collision verification screenshot:
./lab4_hash_pki/scripts/verify_md5_collision.sh lab4_hash_pki/demos/md5_collision
md5sum lab4_hash_pki/demos/md5_collision/collision_a.bin lab4_hash_pki/demos/md5_collision/collision_b.bin
sha256sum lab4_hash_pki/demos/md5_collision/collision_a.bin lab4_hash_pki/demos/md5_collision/collision_b.bin

Run length-extension screenshot:
./lab4_hash_pki/build-linux/hashtool length-extension-demo --out-dir lab4_hash_pki/demos/length_extension
cat lab4_hash_pki/demos/length_extension/verification_result.txt

Run TLS local evidence screenshot:
./lab4_hash_pki/scripts/tls_local_self_signed_demo_linux.sh
cat lab4_hash_pki/demos/tls/tls_test_log.txt
CAPTURE

ZIP="$REPO/lab4_ubuntu_report_input_standardized.zip"
STAGE="/tmp/lab4_ubuntu_report_input_standardized"

rm -rf "$STAGE"
mkdir -p "$STAGE"/{logs,bench,demos,binaries,certs,vectors}

cp -f "$LAB/README.md" "$STAGE/README.md"
cp -f "$LAB/CMakeLists.txt" "$STAGE/CMakeLists.txt"
cp -f "$LAB/scripts/report/run_lab4_ubuntu_evidence.sh" "$STAGE/run_lab4_ubuntu_evidence.sh"
cp -f "$REPORT/capture_commands_ubuntu.md" "$STAGE/capture_commands_ubuntu.md"
cp -f "$REPO/lab4_ubuntu_environment.txt" "$STAGE/lab4_ubuntu_environment.txt"

cp -f "$LOGS"/*_final.log "$STAGE/logs/"
cp -f "$BENCH"/bench_ubuntu_*.csv "$STAGE/bench/"

cp -f "$BIN/hashtool" "$STAGE/binaries/"
cp -f "$BIN/libhashtool_core.a" "$STAGE/binaries/"

cp -f "$LAB"/vectors/*.json "$STAGE/vectors/"
cp -f "$LAB"/tests/certs/*.pem "$STAGE/certs/"
cp -f "$LAB"/tests/certs/*.der "$STAGE/certs/"

cp -a "$LAB/demos/length_extension" "$STAGE/demos/length_extension"
cp -a "$LAB/demos/md5_collision" "$STAGE/demos/md5_collision"
cp -a "$LAB/demos/tls" "$STAGE/demos/tls"

rm -f "$ZIP"
python3 - <<PYZIP
import os
import zipfile

stage = "$STAGE"
zip_path = "$ZIP"

with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk(stage):
        dirs[:] = [d for d in dirs if d not in {"build", "build-linux", "build-windows", "ca_db"}]
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, stage).replace(os.sep, "/")
            zf.write(full, rel)
PYZIP

echo ""
echo "==== UBUNTU LAB 4 EVIDENCE COMPLETE ===="
echo "Zip: $ZIP"
echo "CTest: 17/17 PASS"
echo "KAT: hash 16/16 PASS, SHAKE 4/4 PASS"
echo "Length extension: naive forged PASS, HMAC forged FAIL"
echo "Bonus core library: libhashtool_core.a copied"
echo ""
git status -sb
