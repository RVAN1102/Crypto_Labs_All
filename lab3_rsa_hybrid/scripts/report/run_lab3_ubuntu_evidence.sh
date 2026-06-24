#!/usr/bin/env bash
set -euo pipefail

REPO="$HOME/Crypto_Labs_All"
LAB="$REPO/lab3_rsa_hybrid"

cd "$LAB"

LINUX_ARTIFACTS="$LAB/artifacts/linux"
LOG_DIR="$LINUX_ARTIFACTS/logs"
BENCH_DIR="$LINUX_ARTIFACTS/bench"
BIN_DIR="$LINUX_ARTIFACTS/binaries"
REPORT_DIR="$LAB/report"

mkdir -p "$LOG_DIR" "$BENCH_DIR" "$BIN_DIR" "$REPORT_DIR"

echo "===== Lab 3 Ubuntu evidence run started ====="

rm -rf build-linux tmp_negative_tests

echo "===== Environment ====="
{
  echo "===== OS ====="
  lsb_release -a 2>/dev/null || cat /etc/os-release
  echo

  echo "===== Kernel ====="
  uname -a
  echo

  echo "===== CPU ====="
  lscpu
  echo

  echo "===== RAM ====="
  free -h
  echo

  echo "===== Disk ====="
  lsblk -o NAME,MODEL,SIZE,TYPE,MOUNTPOINT
  echo

  echo "===== Compiler ====="
  g++ --version
  echo
  cmake --version
  echo

  echo "===== Crypto++ ====="
  dpkg -l | grep -E 'libcrypto\+\+|libcryptopp' || true
  ls -l /usr/include/cryptopp/cryptlib.h 2>/dev/null || true
  ls -l /usr/include/crypto++/cryptlib.h 2>/dev/null || true
  ls -l /usr/lib/x86_64-linux-gnu/libcryptopp.* 2>/dev/null || true
} > "$REPO/lab3_ubuntu_environment.txt"

echo "===== Configure ====="
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release \
  > "$LOG_DIR/configure_linux.log" 2>&1
cat "$LOG_DIR/configure_linux.log"

echo "===== Build ====="
cmake --build build-linux -j"$(nproc)" \
  > "$LOG_DIR/build_linux.log" 2>&1
cat "$LOG_DIR/build_linux.log"

echo "===== Locate executable ====="
TOOL="$LAB/build-linux/rsatool"
UNIT_TOOL="$LAB/build-linux/rsatool_unit_tests"

if [ ! -x "$TOOL" ]; then
  echo "Cannot find Lab 3 executable: $TOOL" >&2
  find build-linux -maxdepth 3 -type f -executable | sort
  exit 1
fi

echo "Tool path: $TOOL" | tee "$LOG_DIR/tool_path_linux.log"

cp "$TOOL" "$BIN_DIR/rsatool"
if [ -x "$UNIT_TOOL" ]; then
  cp "$UNIT_TOOL" "$BIN_DIR/rsatool_unit_tests"
fi

echo "===== Help ====="
"$TOOL" --help > "$LOG_DIR/help_linux.log" 2>&1 || true

echo "===== CTest ====="
ctest --test-dir build-linux --output-on-failure \
  > "$LOG_DIR/ctest_linux.log" 2>&1
cat "$LOG_DIR/ctest_linux.log"

echo "===== KAT ====="
{
  echo "===== KAT: vectors/rsa_hybrid_kat.json ====="
  "$TOOL" kat --kat vectors/rsa_hybrid_kat.json
} > "$LOG_DIR/kat_linux.log" 2>&1

echo "===== Negative tests ====="
if [ -f scripts/negative_tests_linux.sh ]; then
  chmod +x scripts/negative_tests_linux.sh
  bash scripts/negative_tests_linux.sh "$TOOL" \
    > "$LOG_DIR/negative_tests_linux.log" 2>&1
else
  echo "scripts/negative_tests_linux.sh not found" > "$LOG_DIR/negative_tests_linux.log"
fi

echo "===== Benchmark ====="
"$TOOL" bench \
  --out artifacts/linux/bench/bench_linux_raw.csv \
  --summary artifacts/linux/bench/bench_linux_summary.csv \
  > "$LOG_DIR/bench_linux.log" 2>&1 || true

echo "===== Artifact inventory ====="
find artifacts/linux -maxdepth 4 -type f | sort \
  > "$LOG_DIR/artifact_inventory_linux.log"

echo "===== Screenshot command guide ====="
cat > "$REPORT_DIR/capture_commands_ubuntu.md" <<'CMDS'
# Lab 3 Ubuntu screenshot commands

## U01 - Ubuntu artifacts tree
cd ~/Crypto_Labs_All
find lab3_rsa_hybrid/artifacts/linux -maxdepth 4 -type f | sort

## U02 - Lab 3 tool help
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/help_linux.log

## U03 - CTest result
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/ctest_linux.log

## U04 - KAT result
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/kat_linux.log

## U05 - Negative tests
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
cat artifacts/linux/logs/negative_tests_linux.log

## U06 - Benchmark files
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
find artifacts/linux/bench -maxdepth 1 -type f -print -exec ls -lh {} \;

## U07 - RSA-OAEP direct mode evidence
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
grep -iE "oaep|direct|small|limit|3072|4096" artifacts/linux/logs/ctest_linux.log artifacts/linux/logs/negative_tests_linux.log artifacts/linux/logs/kat_linux.log

## U08 - Hybrid encryption evidence
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
grep -iE "hybrid|seal|open|aes|gcm|wrap|envelope" artifacts/linux/logs/ctest_linux.log artifacts/linux/logs/negative_tests_linux.log artifacts/linux/logs/kat_linux.log

## U09 - Wrong key / wrong label evidence
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
grep -iE "wrong|label|private|reject|fail" artifacts/linux/logs/negative_tests_linux.log

## U10 - Tamper / malformed envelope evidence
cd ~/Crypto_Labs_All/lab3_rsa_hybrid
grep -iE "tamper|malformed|ciphertext|tag|version|algorithm|envelope" artifacts/linux/logs/negative_tests_linux.log
CMDS

echo "===== Verification summary ====="
grep -E "100% tests passed|tests failed" "$LOG_DIR/ctest_linux.log" || true
grep -Ei "pass|fail|summary|kat" "$LOG_DIR/kat_linux.log" || true
grep -Ei "pass|fail|summary|reject" "$LOG_DIR/negative_tests_linux.log" || true
ls -lah "$BENCH_DIR"

echo "===== Lab 3 Ubuntu evidence run completed ====="
