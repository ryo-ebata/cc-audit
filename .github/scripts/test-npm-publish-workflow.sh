#!/usr/bin/env bash

set -euo pipefail

workflow=".github/workflows/npm-publish.yml"
identity_line=$(grep -n -m1 'name: Verify npm publisher identity before publish' "${workflow}" | cut -d: -f1)
publish_line=$(grep -n -m1 'npm publish --access public' "${workflow}" | cut -d: -f1)

test -n "${identity_line}"
test -n "${publish_line}"
test "${identity_line}" -lt "${publish_line}"

sed -n "${identity_line},${publish_line}p" "${workflow}" | grep -Fq 'bash .github/scripts/npm-publish-preflight.sh'
sed -n "${identity_line},${publish_line}p" "${workflow}" | grep -Fq 'NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}'
echo "npm publish workflow diagnostics regression test passed"
