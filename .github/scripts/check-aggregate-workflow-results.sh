#!/usr/bin/env bash
set -euo pipefail

require_boolean() {
  [[ "$1" == "true" || "$1" == "false" ]]
}

check_conditional() {
  local changes_result="$1"
  local rust_output="$2"
  shift 2
  [[ "$changes_result" == "success" ]] || return 1
  require_boolean "$rust_output" || return 1
  [[ "$rust_output" == "false" ]] && return 0
  local child_result
  for child_result in "$@"; do
    [[ "$child_result" == "success" ]] || return 1
  done
}

check_security() {
  local event="$1"
  local changes_result="$2"
  local should_run="$3"
  local rust_output="$4"
  shift 4
  [[ "$event" == "pull_request" || "$event" == "push" || "$event" == "schedule" ]] || return 1
  [[ "$changes_result" == "success" ]] || return 1
  require_boolean "$should_run" || return 1
  require_boolean "$rust_output" || return 1
  [[ "$should_run" == "false" ]] && return 0
  local child_result
  for child_result in "$@"; do
    [[ "$child_result" == "success" ]] || return 1
  done
}

check_semver() {
  local event="$1"
  local changes_result="$2"
  local should_run="$3"
  local rust_output="$4"
  local semver_result="$5"
  local changelog_result="$6"
  [[ "$event" == "pull_request" || "$event" == "push" ]] || return 1
  [[ "$changes_result" == "success" ]] || return 1
  require_boolean "$should_run" || return 1
  require_boolean "$rust_output" || return 1
  [[ "$should_run" == "false" ]] && return 0
  [[ "$semver_result" == "success" ]] || return 1
  if [[ "$event" == "pull_request" ]]; then
    if [[ "$rust_output" == "true" ]]; then
      [[ "$changelog_result" == "success" ]] || return 1
    fi
  else
    [[ "$changelog_result" == "skipped" ]] || return 1
  fi
}

check_terraform() {
  local changes_result="$1"
  local infra_output="$2"
  local directories="$3"
  shift 3
  [[ "$changes_result" == "success" ]] || return 1
  require_boolean "$infra_output" || return 1
  jq -e 'type == "array" and all(.[]; type == "string")' <<<"$directories" >/dev/null || return 1
  [[ "$infra_output" == "false" && "$directories" == "[]" ]] && return 0
  [[ "$infra_output" == "true" ]] || return 1
  [[ "$directories" != "[]" ]] || return 0
  local child_result
  for child_result in "$@"; do
    [[ "$child_result" == "success" ]] || return 1
  done
}

case "${1:-}" in
  ci)
    shift
    [[ "$1" == "success" && "$2" == "success" ]] || exit 1
    shift 2
    check_conditional "$@"
    ;;
  conditional)
    shift
    check_conditional "$@"
    ;;
  security)
    shift
    check_security "$@"
    ;;
  semver)
    shift
    check_semver "$@"
    ;;
  terraform)
    shift
    check_terraform "$@"
    ;;
  unconditional)
    [[ "${2:-}" == "success" ]]
    ;;
  filter)
    [[ "${3:-}" == "true" ]] && { echo "rust=false" >> "$GITHUB_OUTPUT"; exit 0; }
    require_boolean "${2:-}" || exit 1
    echo "rust=${2}" >> "$GITHUB_OUTPUT"
    ;;
  terraform-filter)
    infra_output="${2:-}"
    directories="${3:-}"
    require_boolean "$infra_output" || exit 1
    if [[ "$infra_output" == "false" ]]; then
      [[ -z "$directories" ]] || exit 1
      echo "infra=false" >> "$GITHUB_OUTPUT"
      echo "directories=[]" >> "$GITHUB_OUTPUT"
      exit 0
    fi
    jq -e 'type == "array" and all(.[]; type == "string")' <<<"$directories" >/dev/null || exit 1
    echo "infra=true" >> "$GITHUB_OUTPUT"
    echo "directories=$(jq -c . <<<"$directories")" >> "$GITHUB_OUTPUT"
    ;;
  *)
    echo "usage: $0 {ci|conditional|security|semver|terraform|unconditional|filter|terraform-filter} ..." >&2
    exit 2
    ;;
esac
