#!/usr/bin/env bash

set -euo pipefail

TEST_ROOT=$(mktemp -d)
trap 'rm -rf "${TEST_ROOT}"' EXIT
mkdir -p "${TEST_ROOT}/bin"
cat > "${TEST_ROOT}/bin/npm" <<'MOCK_NPM'
#!/usr/bin/env bash
if [[ "$*" == *whoami* ]]; then
  if [ "${MOCK_NPM_AUTH:-fail}" = fail ]; then exit 1; fi
  echo test-publisher
  exit 0
fi
echo publish-called > "${MOCK_ROOT}/publish-called"
exit 0
MOCK_NPM
chmod +x "${TEST_ROOT}/bin/npm"

set +e
NODE_AUTH_TOKEN=token MOCK_ROOT="${TEST_ROOT}" MOCK_NPM_AUTH=fail PATH="${TEST_ROOT}/bin:${PATH}" \
  bash .github/scripts/npm-publish-preflight.sh
status=$?
set -e
test "${status}" -ne 0
test ! -e "${TEST_ROOT}/publish-called"

NODE_AUTH_TOKEN=token MOCK_ROOT="${TEST_ROOT}" MOCK_NPM_AUTH=success PATH="${TEST_ROOT}/bin:${PATH}" \
  bash .github/scripts/npm-publish-preflight.sh | grep -Fq 'test-publisher'
echo "npm publish preflight regression test passed"
