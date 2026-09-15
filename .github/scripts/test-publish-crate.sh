#!/usr/bin/env bash
set -euo pipefail

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT

cat >"$test_dir/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s' "${FAKE_CURL_STATUS:-404}"
EOF
cat >"$test_dir/cargo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${FAKE_CARGO_OUTPUT:-published}"
if [[ -n "${FAKE_CARGO_FAILURES:-}" ]]; then
  count_file=${FAKE_CARGO_COUNT_FILE:?}
  count=$(cat "$count_file")
  printf '%s' "$((count + 1))" >"$count_file"
  if (( count < FAKE_CARGO_FAILURES )); then
    echo 'error: 429 Too Many Requests' >&2
    exit 1
  fi
fi
EOF
cat >"$test_dir/noop-sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$test_dir/curl" "$test_dir/cargo" "$test_dir/noop-sleep"

PATH="$test_dir:$PATH" CARGO_REGISTRY_TOKEN=test-token \
  FAKE_CURL_STATUS=200 PUBLISH_SLEEP_COMMAND=noop-sleep \
  .github/scripts/publish-crate.sh cc-audit 1.2.3 >"$test_dir/idempotent.out"
grep -Fq 'already published' "$test_dir/idempotent.out"

count_file="$test_dir/count"
printf '0' >"$count_file"
PATH="$test_dir:$PATH" CARGO_REGISTRY_TOKEN=test-token \
  FAKE_CURL_STATUS=404 FAKE_CARGO_FAILURES=2 FAKE_CARGO_COUNT_FILE="$count_file" \
  PUBLISH_MAX_ATTEMPTS=3 PUBLISH_INITIAL_BACKOFF=0 PUBLISH_SLEEP_COMMAND=noop-sleep \
  .github/scripts/publish-crate.sh cc-audit 1.2.4 >"$test_dir/retry.out" 2>"$test_dir/retry.err"
test "$(cat "$count_file")" = 3
grep -Fq 'retrying' "$test_dir/retry.err"

echo 'publish-crate tests passed'
