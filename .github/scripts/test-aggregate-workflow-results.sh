#!/usr/bin/env bash
set -euo pipefail

run_case() {
  local expected="$1"
  shift
  if .github/scripts/check-aggregate-workflow-results.sh "$@"; then
    actual=0
  else
    actual=1
  fi
  [[ "$actual" == "$expected" ]] || { echo "case failed: $*"; exit 1; }
}

run_case 0 conditional success true success success
run_case 1 conditional success true cancelled success
run_case 1 conditional success true skipped success
run_case 0 conditional success false failure
run_case 1 conditional success empty success
run_case 1 conditional failure false success

run_case 0 ci success success success true success success success success success
run_case 1 ci failure success success false success success success success success
run_case 1 ci success cancelled success true success success success success success

run_case 0 security schedule success true false success success success success success
run_case 0 security pull_request success false false cancelled cancelled cancelled cancelled cancelled
run_case 1 security schedule success true invalid success success success success success
run_case 1 security pull_request failure false false success success success success success

run_case 0 semver push success true false success skipped
run_case 0 semver pull_request success true true success success
run_case 0 semver pull_request success false false success skipped
run_case 1 semver push success true false success success
run_case 1 semver pull_request success true true success skipped
run_case 1 semver pull_request success empty true success success
run_case 1 semver pull_request failure false false success skipped

run_case 0 unconditional success
run_case 1 unconditional cancelled
run_case 1 unconditional skipped

output_file="$(mktemp)"
GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh filter true false
grep -Fq 'rust=true' "$output_file"
if GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh filter empty false; then
  echo "empty filter output must fail"
  exit 1
fi
GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh filter empty true
grep -Fq 'rust=false' "$output_file"

grep -Fq 'check-aggregate-workflow-results.sh ci' .github/workflows/ci.yml
grep -Fq 'check-aggregate-workflow-results.sh conditional' .github/workflows/msrv.yml
grep -Fq 'check-aggregate-workflow-results.sh security' .github/workflows/security.yml
grep -Fq 'check-aggregate-workflow-results.sh conditional' .github/workflows/performance.yml
grep -Fq 'check-aggregate-workflow-results.sh semver' .github/workflows/semver.yml
grep -Fq 'check-aggregate-workflow-results.sh unconditional' .github/workflows/npm-install-test.yml
grep -Fq 'check-aggregate-workflow-results.sh unconditional' .github/workflows/cargo-install-test.yml
grep -Fq 'check-aggregate-workflow-results.sh unconditional' .github/workflows/self-audit.yml

echo "aggregate workflow result checks passed"
