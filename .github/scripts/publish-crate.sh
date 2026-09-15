#!/usr/bin/env bash
set -euo pipefail

crate_name=${1:?crate name is required}
crate_version=${2:?crate version is required}

max_attempts=${PUBLISH_MAX_ATTEMPTS:-4}
initial_backoff=${PUBLISH_INITIAL_BACKOFF:-30}
crates_io_api=${CRATES_IO_API:-https://crates.io/api/v1}
crates_io_user_agent=${CRATES_IO_USER_AGENT:-cc-audit-release/$crate_version (+https://github.com/ryo-ebata/cc-audit)}

if ! [[ "$max_attempts" =~ ^[1-9][0-9]*$ && "$initial_backoff" =~ ^[0-9]+$ ]]; then
  echo "PUBLISH_MAX_ATTEMPTS and PUBLISH_INITIAL_BACKOFF must be non-negative integers" >&2
  exit 2
fi

version_url="$crates_io_api/crates/$crate_name/$crate_version"
version_status=$(curl -sS -A "$crates_io_user_agent" -H 'Accept: application/json' -o /dev/null -w '%{http_code}' "$version_url" || echo 000)
if [[ "$version_status" == 200 ]]; then
  echo "$crate_name $crate_version is already published; treating as success"
  exit 0
fi
if [[ "$version_status" != 404 && "$version_status" != 429 && "$version_status" != 500 && "$version_status" != 502 && "$version_status" != 503 && "$version_status" != 504 ]]; then
  echo "Unable to determine whether $crate_name $crate_version is published (HTTP $version_status)" >&2
  exit 1
fi

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  log_file=$(mktemp)
  if cargo publish --token "$CARGO_REGISTRY_TOKEN" >"$log_file" 2>&1; then
    cat "$log_file"
    rm -f "$log_file"
    exit 0
  fi

  cat "$log_file" >&2
  if grep -Eiq 'too many versions.*last 24 hours|last 24 hours.*too many versions' "$log_file"; then
    echo "crates.io daily publish quota reached; stopping without retry. Wait for the rolling 24-hour window to recover, then rerun this release once." >&2
    rm -f "$log_file"
    exit 1
  fi
  post_status=$(curl -sS -A "$crates_io_user_agent" -H 'Accept: application/json' -o /dev/null -w '%{http_code}' "$version_url" || echo 000)
  if [[ "$post_status" == 200 ]]; then
    echo "$crate_name $crate_version became available after publish; treating as success"
    rm -f "$log_file"
    exit 0
  fi
  if ! grep -Eiq '429|too many requests|502|503|504|timed out|timeout|could not download|failed to fetch' "$log_file"; then
    rm -f "$log_file"
    exit 1
  fi
  rm -f "$log_file"

  if (( attempt == max_attempts )); then
    echo "cargo publish failed after $max_attempts attempts" >&2
    exit 1
  fi

  backoff=$((initial_backoff * (2 ** (attempt - 1))))
  echo "Transient crates.io failure; retrying in ${backoff}s (attempt $((attempt + 1))/$max_attempts)" >&2
  if [[ -n "${PUBLISH_SLEEP_COMMAND:-}" ]]; then
    "$PUBLISH_SLEEP_COMMAND" "$backoff"
  else
    sleep "$backoff"
  fi
done
