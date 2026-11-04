#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <cargo-msrv-output>" >&2
  exit 2
fi

output=$(sed -E $'s/\033\\[[0-9;]*[[:alpha:]]//g' "$1")

if [[ "$output" =~ (Minimum\ Supported\ Rust\ Version\ \(MSRV\):|MSRV:)[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+) ]]; then
  printf '%s\n' "${BASH_REMATCH[2]}"
  exit 0
fi

echo "cargo msrv did not report a minimum supported Rust version" >&2
exit 1
