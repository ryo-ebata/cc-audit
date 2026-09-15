#!/usr/bin/env bash

set -euo pipefail

PR="${1:?pull request number is required}"
REQUIRED_CHECKS="${2:?required checks are required}"
WAIT_DEADLINE_SECONDS="${WAIT_DEADLINE_SECONDS:-1500}"
WAIT_SLEEP_SECONDS="${WAIT_SLEEP_SECONDS:-15}"
GH_RETRY_ATTEMPTS="${GH_RETRY_ATTEMPTS:-3}"
GH_RETRY_DELAY_SECONDS="${GH_RETRY_DELAY_SECONDS:-5}"

if [ -z "${REQUIRED_CHECKS//[[:space:]]/}" ]; then
  echo "::error::No required checks were supplied; refusing to merge."
  exit 1
fi
mapfile -t REQUIRED <<< "${REQUIRED_CHECKS}"

get_head() {
  local attempt=1
  local head
  while [ "${attempt}" -le "${GH_RETRY_ATTEMPTS}" ]; do
    if head=$(gh pr view "${PR}" --json headRefOid --jq '.headRefOid'); then
      printf '%s' "${head}"
      return 0
    fi
    echo "  [retry] unable to read PR head (attempt ${attempt}/${GH_RETRY_ATTEMPTS})" >&2
    attempt=$((attempt + 1))
    sleep "${GH_RETRY_DELAY_SECONDS}"
  done
  return 1
}

get_rollup() {
  local attempt=1
  local rollup
  while [ "${attempt}" -le "${GH_RETRY_ATTEMPTS}" ]; do
    if rollup=$(gh pr view "${PR}" --json statusCheckRollup \
      -q '.statusCheckRollup[]? | [(.name // .context), (.__typename // ""), (.status // ""), (.conclusion // ""), (.state // "")] | @tsv'); then
      printf '%s' "${rollup}"
      return 0
    fi
    echo "  [retry] unable to read status checks (attempt ${attempt}/${GH_RETRY_ATTEMPTS})" >&2
    attempt=$((attempt + 1))
    sleep "${GH_RETRY_DELAY_SECONDS}"
  done
  return 1
}

classify_outcome() {
  local kind="$1"
  local status="$2"
  local conclusion="$3"
  local state="$4"

  if [ "${kind}" = "CheckRun" ]; then
    if [ "${status}" != "COMPLETED" ]; then
      printf 'PENDING:%s' "${status:-pending}"
    else
      printf '%s' "${conclusion}"
    fi
  else
    printf '%s' "${state}"
  fi
}

started_at=$(date +%s)
deadline=$((started_at + WAIT_DEADLINE_SECONDS))
expected_head=$(get_head) || {
  echo "::error::Could not determine the initial head SHA for PR #${PR}; refusing to merge."
  exit 1
}
if [ -z "${expected_head}" ]; then
  echo "::error::Could not determine the initial head SHA for PR #${PR}; refusing to merge."
  exit 1
fi

while true; do
  current_head=$(get_head) || {
    echo "::error::Unable to read PR #${PR} head after bounded retries; refusing to merge."
    exit 1
  }
  if [ "${current_head}" != "${expected_head}" ]; then
    echo "::error::PR #${PR} head changed from ${expected_head} to ${current_head}; refusing to merge stale checks."
    exit 1
  fi

  rollup=$(get_rollup) || {
    echo "::error::Unable to read PR #${PR} status checks after bounded retries; refusing to merge."
    exit 1
  }
  all_done=true
  failed=false
  missing=""
  pending=""

  for name in "${REQUIRED[@]}"; do
    row=$(printf '%s\n' "${rollup}" | awk -F '\t' -v n="${name}" '$1 == n { print; exit }')
    if [ -z "${row}" ]; then
      all_done=false
      missing="${missing}${name}\n"
      echo "  [missing] ${name}"
      continue
    fi
    kind=$(printf '%s\n' "${row}" | awk -F '\t' '{ print $2 }')
    status=$(printf '%s\n' "${row}" | awk -F '\t' '{ print $3 }')
    conclusion=$(printf '%s\n' "${row}" | awk -F '\t' '{ print $4 }')
    state=$(printf '%s\n' "${row}" | awk -F '\t' '{ print $5 }')
    outcome=$(classify_outcome "${kind}" "${status}" "${conclusion}" "${state}")
    case "${outcome}" in
      SUCCESS | NEUTRAL | SKIPPED)
        ;;
      PENDING:*)
        all_done=false
        pending="${pending}${name} (${outcome#PENDING:})\n"
        echo "  [pending] ${name} -> ${outcome#PENDING:}"
        ;;
      *)
        failed=true
        echo "  [FAILED ] ${name} -> ${outcome}"
        ;;
    esac
  done

  if [ "${failed}" = true ]; then
    echo "::error::Required check(s) failed; not merging PR #${PR}."
    exit 1
  fi
  if [ "${all_done}" = true ]; then
    final_head=$(get_head) || {
      echo "::error::Unable to recheck PR #${PR} head before merge; refusing to merge."
      exit 1
    }
    if [ "${final_head}" != "${expected_head}" ]; then
      echo "::error::PR #${PR} head changed before merge; refusing to merge."
      exit 1
    fi
    echo "All required checks passed."
    break
  fi

  if [ "$(date +%s)" -ge "${deadline}" ]; then
    echo "::error::Timed out waiting for required checks on PR #${PR}."
    echo "Missing required checks:"
    printf '%b' "${missing}"
    echo "Pending required checks:"
    printf '%b' "${pending}"
    exit 1
  fi
  sleep "${WAIT_SLEEP_SECONDS}"
done

gh pr merge "${PR}" --squash --delete-branch --match-head-commit "${expected_head}"
