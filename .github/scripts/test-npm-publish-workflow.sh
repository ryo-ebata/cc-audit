#!/usr/bin/env bash

set -euo pipefail

workflow=".github/workflows/npm-publish.yml"
identity_count=$(grep -c 'name: Verify npm publisher identity before publish' "${workflow}")
publish_count=$(grep -c 'npm publish --access public' "${workflow}")
test "${identity_count}" -eq 2
test "${publish_count}" -eq 2

identity_line=$(grep -n -m1 'name: Verify npm publisher identity before publish' "${workflow}" | cut -d: -f1)
second_identity_line=$(grep -n 'name: Verify npm publisher identity before publish' "${workflow}" | tail -n1 | cut -d: -f1)
publish_line=$(grep -n -m1 'npm publish --access public' "${workflow}" | cut -d: -f1)
second_publish_line=$(grep -n 'npm publish --access public' "${workflow}" | tail -n1 | cut -d: -f1)

test -n "${identity_line}"
test -n "${publish_line}"
test "${identity_line}" -lt "${publish_line}"
test "${publish_line}" -lt "${second_identity_line}"
test "${second_identity_line}" -lt "${second_publish_line}"

sed -n "${identity_line},${publish_line}p" "${workflow}" | grep -Fq 'bash .github/scripts/npm-publish-preflight.sh'
sed -n "${identity_line},${publish_line}p" "${workflow}" | grep -Fq 'NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}'
sed -n "${second_identity_line},${second_publish_line}p" "${workflow}" | grep -Fq 'bash .github/scripts/npm-publish-preflight.sh'
sed -n "${second_identity_line},${second_publish_line}p" "${workflow}" | grep -Fq 'NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}'
echo "npm publish workflow diagnostics regression test passed"
