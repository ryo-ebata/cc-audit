#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
parser="$script_dir/parse-msrv-output.sh"
fixture_dir=$(mktemp -d)
trap 'rm -rf "$fixture_dir"' EXIT

assert_version() {
  local name=$1
  local expected=$2
  local actual
  actual=$(bash "$parser" "$fixture_dir/$name")
  [[ "$actual" == "$expected" ]]
}

printf '%s\n' 'Minimum Supported Rust Version (MSRV): 1.75.0' > "$fixture_dir/legacy.txt"
assert_version legacy.txt 1.75.0

printf 'Result:\n   MSRV:                     \033[4m\033[1m\033[32m1.88.0\033[39m\033[0m\033[0m\n' > "$fixture_dir/ansi.txt"
assert_version ansi.txt 1.88.0

printf '%s\n' 'Result: MSRV: 1.88.0' > "$fixture_dir/plain.txt"
assert_version plain.txt 1.88.0

: > "$fixture_dir/empty.txt"
if bash "$parser" "$fixture_dir/empty.txt"; then
  echo "empty output unexpectedly succeeded" >&2
  exit 1
fi

printf '%s\n' 'MSRV: not-a-version' > "$fixture_dir/invalid.txt"
if bash "$parser" "$fixture_dir/invalid.txt"; then
  echo "invalid output unexpectedly succeeded" >&2
  exit 1
fi

echo "MSRV output parser fixtures passed"
