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
  [[ "$should_run" == "false" ]] && return 0
  require_boolean "$rust_output" || return 1
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
  [[ "$should_run" == "false" ]] && return 0
  [[ "$semver_result" == "success" ]] || return 1
  if [[ "$event" == "pull_request" ]]; then
    require_boolean "$rust_output" || return 1
    if [[ "$rust_output" == "true" ]]; then
      [[ "$changelog_result" == "success" ]] || return 1
    fi
  else
    require_boolean "$rust_output"
    [[ "$changelog_result" == "skipped" ]] || return 1
  fi
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
  unconditional)
    [[ "${2:-}" == "success" ]]
    ;;
  filter)
    [[ "${3:-}" == "true" ]] && { echo "rust=false" >> "$GITHUB_OUTPUT"; exit 0; }
    require_boolean "${2:-}" || exit 1
    echo "rust=${2}" >> "$GITHUB_OUTPUT"
    ;;
  *)
    echo "usage: $0 {ci|conditional|security|semver|unconditional} ..." >&2
    exit 2
    ;;
esac
