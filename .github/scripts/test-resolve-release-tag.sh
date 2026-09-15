#!/usr/bin/env bash
set -euo pipefail

resolve() {
  awk -v sha="$1" '
    $1 == sha && $2 ~ /^refs\/tags\/v/ {
      tag = $2
      sub(/^refs\/tags\//, "", tag)
      sub(/\^\{\}$/, "", tag)
      print tag
      exit
    }
  '
}

lightweight=$(printf '%s\n' \
  'abc123 refs/tags/v1.2.3' \
  'def456 refs/tags/v1.2.4' |
  resolve abc123)
test "$lightweight" = v1.2.3

annotated=$(printf '%s\n' \
  'tag789 refs/tags/v1.2.5' \
  'abc123 refs/tags/v1.2.5^{}' |
  resolve abc123)
test "$annotated" = v1.2.5

non_tag=$(printf '%s\n' 'abc123 refs/heads/main' | resolve abc123)
test -z "$non_tag"
