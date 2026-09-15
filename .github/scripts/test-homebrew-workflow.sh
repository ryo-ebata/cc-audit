#!/usr/bin/env bash

set -euo pipefail

workflow=".github/workflows/homebrew-update.yml"
checkout_line=$(grep -n -m1 'name: Checkout cc-audit at release commit' "${workflow}" | cut -d: -f1)
resolve_line=$(grep -n -m1 'bash .github/scripts/resolve-release-tag.sh' "${workflow}" | cut -d: -f1)

test -n "${checkout_line}"
test -n "${resolve_line}"
test "${checkout_line}" -lt "${resolve_line}"

sed -n "${checkout_line},${resolve_line}p" "${workflow}" | grep -Fq 'ref: ${{ github.event.workflow_run.head_sha }}'
sed -n "${checkout_line},${resolve_line}p" "${workflow}" | grep -Fq 'fetch-depth: 1'
echo "homebrew workflow checkout regression test passed"
