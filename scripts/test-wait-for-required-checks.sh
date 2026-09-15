#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "${TEST_ROOT}"' EXIT
mkdir -p "${TEST_ROOT}/bin"

cat > "${TEST_ROOT}/bin/gh" <<'MOCK_GH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *headRefOid* ]]; then
  count_file="${MOCK_ROOT}/head-count"
  count=0
  if [ -f "${count_file}" ]; then count=$(cat "${count_file}"); fi
  count=$((count + 1))
  echo "${count}" > "${count_file}"
  if [ "${MOCK_HEAD_MODE:-stable}" = changed ] && [ "${count}" -ge 2 ]; then
    echo def
  elif [ "${MOCK_HEAD_MODE:-stable}" = final-changed ] && [ "${count}" -ge 3 ]; then
    echo def
  else
    echo abc
  fi
  exit 0
fi
if [[ "$*" == *statusCheckRollup* ]]; then
  count_file="${MOCK_ROOT}/rollup-count"
  count=0
  if [ -f "${count_file}" ]; then count=$(cat "${count_file}"); fi
  count=$((count + 1))
  echo "${count}" > "${count_file}"
  if [ "${MOCK_STATUS_FAIL_ONCE:-0}" = 1 ] && [ "${count}" -eq 1 ]; then exit 1; fi
  cat "${MOCK_ROOT}/rollup-${MOCK_ROLLUP:-default}-${count}" 2>/dev/null || cat "${MOCK_ROOT}/rollup-${MOCK_ROLLUP:-default}"
  exit 0
fi
if [[ "$*" == *pr\ merge* ]]; then
  echo "$*" > "${MOCK_ROOT}/merged"
  exit 0
fi
exit 1
MOCK_GH
chmod +x "${TEST_ROOT}/bin/gh"
cat > "${TEST_ROOT}/bin/sleep" <<'MOCK_SLEEP'
#!/usr/bin/env bash
exit 0
MOCK_SLEEP
chmod +x "${TEST_ROOT}/bin/sleep"
cat > "${TEST_ROOT}/bin/date" <<'MOCK_DATE'
#!/usr/bin/env bash
count_file="${MOCK_ROOT}/date-count"
count=0
if [ -f "${count_file}" ]; then count=$(cat "${count_file}"); fi
count=$((count + 1))
echo "${count}" > "${count_file}"
  case "${MOCK_DATE_MODE:-stable}:${count}" in
    delayed:1) echo 0 ;;
    delayed:2) echo 301 ;;
    delayed:*) echo 302 ;;
    pending:1) echo 0 ;;
    pending:2) echo 301 ;;
    pending:*) echo 302 ;;
    timeout:1) echo 0 ;;
  timeout:2) echo 5 ;;
  timeout:*) echo 7 ;;
  *) echo 0 ;;
esac
MOCK_DATE
chmod +x "${TEST_ROOT}/bin/date"

write_rollup() {
  local name="$1"
  shift
  printf '%s\n' "$@" > "${TEST_ROOT}/rollup-${name}"
}

run_case() {
  local name="$1"
  local expected_status="$2"
  local deadline=20
  shift 2
  case "${name}" in
    missing) deadline=7 ;;
    delayed | pending) deadline=1500 ;;
  esac
  rm -f "${TEST_ROOT}/head-count" "${TEST_ROOT}/rollup-count" "${TEST_ROOT}/date-count" "${TEST_ROOT}/merged"
  set +e
  WAIT_DEADLINE_SECONDS="${deadline}" WAIT_SLEEP_SECONDS=0 GH_RETRY_DELAY_SECONDS=0 \
    PATH="${TEST_ROOT}/bin:${PATH}" MOCK_ROOT="${TEST_ROOT}" MOCK_ROLLUP="${name}" "$@" \
    > "${TEST_ROOT}/${name}.out" 2>&1
  status=$?
  set -e
  if [ "${status}" -ne "${expected_status}" ]; then
    echo "${name}: expected exit ${expected_status}, got ${status}" >&2
    cat "${TEST_ROOT}/${name}.out" >&2
    exit 1
  fi
  if [ "${expected_status}" -ne 0 ] && [ -f "${TEST_ROOT}/merged" ]; then
    echo "${name}: unexpectedly invoked merge" >&2
    exit 1
  fi
  if [ "${expected_status}" -eq 0 ]; then
    if [ ! -f "${TEST_ROOT}/merged" ]; then
      echo "${name}: expected merge was not invoked" >&2
      exit 1
    fi
    grep -q -- '--match-head-commit abc' "${TEST_ROOT}/merged"
  fi
}

write_rollup delayed-1 "dependency"$'\tStatusContext\t\t\tSUCCESS'
write_rollup delayed-2 "dependency"$'\tStatusContext\t\t\tSUCCESS' "Result"$'\tCheckRun\tCOMPLETED\tSUCCESS\t'
run_case delayed 0 bash "${SCRIPT_DIR}/wait-for-required-checks.sh" 383 Result

write_rollup pending-1 "Result"$'\tCheckRun\tQUEUED\tSUCCESS\t'
write_rollup pending-2 "Result"$'\tCheckRun\tIN_PROGRESS\tSUCCESS\t'
write_rollup pending-3 "Result"$'\tCheckRun\tCOMPLETED\tSUCCESS\t'
run_case pending 0 env MOCK_DATE_MODE=pending bash "${SCRIPT_DIR}/wait-for-required-checks.sh" 383 Result

write_rollup context-pending-1 "Result"$'\tStatusContext\t\t\tPENDING'
write_rollup context-pending-2 "Result"$'\tStatusContext\t\t\tSUCCESS'
run_case context-pending 0 bash "${SCRIPT_DIR}/wait-for-required-checks.sh" 383 Result

write_rollup missing
run_case missing 1 env MOCK_DATE_MODE=timeout bash "${SCRIPT_DIR}/wait-for-required-checks.sh" 383 Result

write_rollup failure "Result"$'\tCheckRun\tCOMPLETED\tFAILURE\t'
run_case failure 1 bash "${SCRIPT_DIR}/wait-for-required-checks.sh" 383 Result

write_rollup changed "Result"$'\tCheckRun\tCOMPLETED\tSUCCESS\t'
run_case changed 1 env MOCK_HEAD_MODE=changed bash "${SCRIPT_DIR}/wait-for-required-checks.sh" 383 Result

write_rollup final-changed "Result"$'\tCheckRun\tCOMPLETED\tSUCCESS\t'
run_case final-changed 1 env MOCK_HEAD_MODE=final-changed bash "${SCRIPT_DIR}/wait-for-required-checks.sh" 383 Result

write_rollup success "CI Result"$'\tStatusContext\t\t\tSUCCESS' "Result"$'\tCheckRun\tCOMPLETED\tSUCCESS\t'
run_case success 0 bash "${SCRIPT_DIR}/wait-for-required-checks.sh" 383 "CI Result
Result"

write_rollup retry "Result"$'\tCheckRun\tCOMPLETED\tSUCCESS\t'
run_case retry 0 env MOCK_STATUS_FAIL_ONCE=1 bash "${SCRIPT_DIR}/wait-for-required-checks.sh" 383 Result

echo "wait-for-required-checks regression tests passed"
