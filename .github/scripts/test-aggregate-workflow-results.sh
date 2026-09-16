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
run_case 1 security schedule success false "" success success success success success
run_case 0 security pull_request success false false cancelled cancelled cancelled cancelled cancelled
run_case 1 security schedule success true invalid success success success success success
run_case 1 security pull_request failure false false success success success success success
run_case 1 security pull_request success false empty success success success success success

run_case 0 semver push success true false success skipped
run_case 1 semver push success true "" success skipped
run_case 0 semver pull_request success true true success success
run_case 0 semver pull_request success false false success skipped
run_case 1 semver push success true false success success
run_case 1 semver pull_request success true true success skipped
run_case 1 semver pull_request success empty true success success
run_case 1 semver pull_request failure false false success skipped
run_case 1 semver pull_request success false empty success skipped

run_case 0 terraform success false '[]' skipped skipped skipped skipped
run_case 1 terraform success false '[]' cancelled skipped skipped skipped
run_case 0 terraform success true '[]' skipped skipped skipped skipped
run_case 1 terraform success true '[]' skipped success skipped skipped
run_case 0 terraform success true '["infra/a"]' success success success success
run_case 1 terraform success true '["infra/a"]' success cancelled success success
run_case 1 terraform success true '' success success success success
run_case 1 terraform success true '{}' success success success success
run_case 1 terraform failure false '[]' success success success success
run_case 1 terraform success false '["infra/a"]' success success success success
run_case 1 terraform success false '' success success success success
run_case 1 terraform success true ' ' success success success success
run_case 1 terraform success true '[] []' success success success success
run_case 1 terraform success true '[1]' success success success success

run_case 0 unconditional success
run_case 1 unconditional cancelled
run_case 1 unconditional skipped

check_result_job_wiring() {
  local workflow="$1"
  local mode="$2"
  local expected_needs="$3"
  local arg_marker="$4"
  awk -v mode="$mode" -v expected_needs="$expected_needs" -v arg_marker="$arg_marker" '
    BEGIN { bad_order=0 }
    /^  [a-z0-9-]+-result:/ { in_result=1; next }
    in_result && /^  [a-z0-9-]+:/ { exit !(found && checked_out && has_needs && !bad_order) }
    in_result && /^    needs:/ { has_needs=index($0, expected_needs) > 0 }
    in_result && /actions\/checkout@v7/ { checked_out=1 }
    in_result && index($0, "check-aggregate-workflow-results.sh " mode) { found=1; bad_order=!checked_out }
    in_result && found && index($0, arg_marker) { arg_seen=1 }
    END { if (in_result) exit !(found && checked_out && has_needs && !bad_order && arg_seen) }
  ' ".github/workflows/$workflow.yml"
  grep -Fq "$arg_marker" ".github/workflows/$workflow.yml"
}

check_result_job_wiring ci ci 'needs: [workflow-action-references, release-tag-resolution, changes, fmt, clippy, test, coverage, doc]' 'needs.workflow-action-references.result'
check_result_job_wiring msrv conditional 'needs: [changes, msrv-check, msrv-verify]' 'needs.changes.result'
check_result_job_wiring security security 'needs: [changes, audit, deny, supply-chain, advisory-db, outdated]' 'needs.changes.outputs.should_run'
check_result_job_wiring performance conditional 'needs: [changes, benchmark, binary-size, build-time]' 'needs.changes.result'
check_result_job_wiring semver semver 'needs: [changes, semver-check, changelog-check]' 'needs.changes.outputs.should_run'
check_result_job_wiring npm-install-test unconditional 'needs: [npm-install-test]' 'needs.npm-install-test.result'
check_result_job_wiring cargo-install-test unconditional 'needs: [cargo-install-test]' 'needs.cargo-install-test.result'
check_result_job_wiring self-audit unconditional 'needs: [self-audit]' 'needs.self-audit.result'
check_result_job_wiring terraform terraform 'needs: [changes, fmt, validate, tflint, tfsec]' 'needs.changes.outputs.directories'
grep -Fq 'needs.release-tag-resolution.result' .github/workflows/ci.yml

output_file="$(mktemp)"
trap 'rm -f "$output_file"' EXIT
reset_output() { : > "$output_file"; }
reset_output
GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh filter true false
grep -Fq 'rust=true' "$output_file"
reset_output
if GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh filter "" false; then
  echo "empty filter output must fail"
  exit 1
fi
reset_output
GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh filter empty true
grep -Fq 'rust=false' "$output_file"

reset_output
GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh terraform-filter false ""
grep -Fq 'infra=false' "$output_file"
grep -Fq 'directories=[]' "$output_file"
reset_output
if GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh terraform-filter true ""; then
  echo "missing Terraform directories must fail"
  exit 1
fi
reset_output
GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh terraform-filter true '[]'
grep -Fq 'infra=true' "$output_file"
grep -Fq 'directories=[]' "$output_file"
reset_output
GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh terraform-filter true '["infra/a"]'
grep -Fq 'directories=["infra/a"]' "$output_file"
reset_output
if GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh terraform-filter true '[] []'; then
  echo "multiple Terraform JSON documents must fail"
  exit 1
fi
reset_output
if GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh terraform-filter true '[1]'; then
  echo "non-string Terraform directory must fail"
  exit 1
fi

fixture_dir="$(mktemp -d)"
trap 'rm -f "$output_file"; rm -rf "$fixture_dir"' EXIT
mkdir "$fixture_dir/empty"
mkdir "$fixture_dir/with-tf"
touch "$fixture_dir/with-tf/main.tf"
reset_output
GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh terraform-discover "$fixture_dir/empty"
grep -Fq 'directories=[]' "$output_file"
reset_output
GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh terraform-discover "$fixture_dir/missing"
grep -Fq 'directories=[]' "$output_file"
reset_output
GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh terraform-discover "$fixture_dir"
grep -Fq "directories=[\"$fixture_dir/with-tf\"]" "$output_file"
if GITHUB_OUTPUT="$output_file" .github/scripts/check-aggregate-workflow-results.sh terraform-filter invalid ""; then
  echo "invalid Terraform infra output must fail"
  exit 1
fi

grep -Fq 'check-aggregate-workflow-results.sh ci' .github/workflows/ci.yml
grep -Fq 'check-aggregate-workflow-results.sh conditional' .github/workflows/msrv.yml
grep -Fq 'check-aggregate-workflow-results.sh security' .github/workflows/security.yml
grep -Fq 'check-aggregate-workflow-results.sh conditional' .github/workflows/performance.yml
grep -Fq 'check-aggregate-workflow-results.sh semver' .github/workflows/semver.yml
grep -Fq 'check-aggregate-workflow-results.sh unconditional' .github/workflows/npm-install-test.yml
grep -Fq 'check-aggregate-workflow-results.sh unconditional' .github/workflows/cargo-install-test.yml
grep -Fq 'check-aggregate-workflow-results.sh unconditional' .github/workflows/self-audit.yml
grep -Fq 'check-aggregate-workflow-results.sh terraform' .github/workflows/terraform.yml
grep -Fq 'check-aggregate-workflow-results.sh terraform-filter' .github/workflows/terraform.yml

echo "aggregate workflow result checks passed"
