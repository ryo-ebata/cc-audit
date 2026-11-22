#!/usr/bin/env bash

set -euo pipefail

workflow=".github/workflows/npm-publish.yml"
publish_count=$(grep -c 'npm publish --access public' "${workflow}")
test "${publish_count}" -eq 2

# Publishing must be triggered by the completed Release workflow and use OIDC.
grep -Fq 'workflow_run:' "${workflow}"
grep -Fq 'workflows: ["Release"]' "${workflow}"
grep -Fq 'types: [completed]' "${workflow}"
grep -Fq 'id-token: write' "${workflow}"

# Trusted Publishing must not regress to a long-lived npm token.
if grep -Fq 'NPM_TOKEN' "${workflow}"; then
  echo "npm publish workflow must not use NPM_TOKEN" >&2
  exit 1
fi
if grep -Fq 'NODE_AUTH_TOKEN' "${workflow}"; then
  echo "npm publish workflow must not inject NODE_AUTH_TOKEN" >&2
  exit 1
fi

# npm's OIDC implementation requires the documented runtime/tool versions.
test "$(grep -c "node-version: '22.14.0'" "${workflow}")" -eq 2
test "$(grep -c 'npm install --global npm@11.5.1' "${workflow}")" -eq 2

# Every published package must identify this repository for npm Trusted Publishing.
for package_json in npm/*/package.json; do
  test "$(jq -r '.repository.url // empty' "${package_json}")" = "https://github.com/ryo-ebata/cc-audit.git"
done

echo "npm publish workflow Trusted Publishing regression test passed"
