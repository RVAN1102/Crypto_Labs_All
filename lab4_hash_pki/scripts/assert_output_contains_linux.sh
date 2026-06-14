#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "usage: $0 EXE NEEDLE ARGS..." >&2
    exit 2
fi

exe="$1"
needle="$2"
shift 2

if [[ ! -x "$exe" ]]; then
    echo "executable not found or not executable: $exe" >&2
    exit 1
fi

output="$("$exe" "$@" 2>&1)"
printf '%s\n' "$output"

if [[ "$output" != *"$needle"* ]]; then
    echo "expected output to contain: $needle" >&2
    exit 1
fi

