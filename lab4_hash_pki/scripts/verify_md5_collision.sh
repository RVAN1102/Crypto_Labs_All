#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_lab4="$(cd "$script_dir/.." && pwd)"
demo_dir="${1:-$repo_lab4/demos/md5_collision}"

file_a="$demo_dir/collision_a.bin"
file_b="$demo_dir/collision_b.bin"

if [[ ! -f "$file_a" || ! -f "$file_b" ]]; then
    echo "missing collision files: $file_a and/or $file_b" >&2
    exit 1
fi

md5_a="$(md5sum "$file_a" | awk '{print $1}')"
md5_b="$(md5sum "$file_b" | awk '{print $1}')"
sha256_a="$(sha256sum "$file_a" | awk '{print $1}')"
sha256_b="$(sha256sum "$file_b" | awk '{print $1}')"

if [[ "$md5_a" != "$md5_b" ]]; then
    echo "MD5 collision verification: FAIL" >&2
    echo "collision_a.bin MD5: $md5_a" >&2
    echo "collision_b.bin MD5: $md5_b" >&2
    exit 1
fi

if [[ "$sha256_a" == "$sha256_b" ]]; then
    echo "SHA-256 difference verification: FAIL" >&2
    echo "both files have SHA-256: $sha256_a" >&2
    exit 1
fi

echo "MD5 collision verification: PASS"
echo "SHA-256 difference verification: PASS"
echo "collision_a_md5=$md5_a"
echo "collision_b_md5=$md5_b"
echo "collision_a_sha256=$sha256_a"
echo "collision_b_sha256=$sha256_b"

