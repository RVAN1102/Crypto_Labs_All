#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_lab4="$(cd "$script_dir/.." && pwd)"
demo_dir="$repo_lab4/demos/md5_collision"
mkdir -p "$demo_dir"

tool=""
if command -v md5_fastcoll >/dev/null 2>&1; then
    tool="$(command -v md5_fastcoll)"
elif command -v fastcoll >/dev/null 2>&1; then
    tool="$(command -v fastcoll)"
else
    cat >&2 <<'MSG'
hashclash fast MD5 collision tool not found.
Expected one of these commands on PATH:
  md5_fastcoll
  fastcoll

No collision files were generated. Install/build hashclash on Ubuntu using
the steps in demos/md5_collision/README.md, then rerun this script.
MSG
    exit 1
fi

prefix_file="$demo_dir/benign_prefix.txt"
file_a="$demo_dir/collision_a.bin"
file_b="$demo_dir/collision_b.bin"
md5_result="$demo_dir/md5_collision_result.txt"
sha256_result="$demo_dir/sha256_difference_result.txt"

cat > "$prefix_file" <<'EOF'
Lab 4 benign offline MD5 collision demo file.
This file is generated only for local defensive cryptography coursework.
No live targets, real certificates, public websites, or third-party files are involved.
EOF

rm -f "$file_a" "$file_b" "$md5_result" "$sha256_result"

set +e
"$tool" -p "$prefix_file" -o "$file_a" "$file_b"
code=$?
set -e

if [[ "$code" -ne 0 ]]; then
    echo "hashclash tool failed with exit code $code" >&2
    exit "$code"
fi

verification_output="$(bash "$script_dir/verify_md5_collision.sh" "$demo_dir")"
printf '%s\n' "$verification_output"

md5_line="$(printf '%s\n' "$verification_output" | grep '^collision_a_md5=' || true)"
sha_a_line="$(printf '%s\n' "$verification_output" | grep '^collision_a_sha256=' || true)"
sha_b_line="$(printf '%s\n' "$verification_output" | grep '^collision_b_sha256=' || true)"

if [[ -z "$md5_line" || -z "$sha_a_line" || -z "$sha_b_line" ]]; then
    echo "verification output did not include expected digest lines" >&2
    exit 1
fi

{
    echo "MD5 collision verification: PASS"
    echo "$md5_line"
    echo "collision_b_md5=${md5_line#collision_a_md5=}"
} > "$md5_result"

{
    echo "SHA-256 difference verification: PASS"
    echo "$sha_a_line"
    echo "$sha_b_line"
} > "$sha256_result"

echo "MD5 collision demo complete: $demo_dir"
