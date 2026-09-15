#!/usr/bin/env bash
set -euo pipefail

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT

cat >"$test_dir/curl" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" != *"-A cc-audit-test"* ]]; then
  printf '%s' 403
  exit 0
fi
printf '%s' "${FAKE_CURL_STATUS:-404}"
EOF
cat >"$test_dir/cargo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${FAKE_CARGO_OUTPUT:-published}"
if [[ -n "${FAKE_CARGO_QUOTA:-}" ]]; then
  echo 'error: 429 Too Many Requests: You have published too many versions of this crate in the last 24 hours' >&2
  exit 1
fi
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
  FAKE_CURL_STATUS=200 CRATES_IO_USER_AGENT=cc-audit-test PUBLISH_SLEEP_COMMAND=noop-sleep \
  .github/scripts/publish-crate.sh cc-audit 1.2.3 >"$test_dir/idempotent.out"
grep -Fq 'already published' "$test_dir/idempotent.out"

count_file="$test_dir/count"
printf '0' >"$count_file"
PATH="$test_dir:$PATH" CARGO_REGISTRY_TOKEN=test-token \
  FAKE_CURL_STATUS=404 FAKE_CARGO_FAILURES=2 FAKE_CARGO_COUNT_FILE="$count_file" \
  CRATES_IO_USER_AGENT=cc-audit-test PUBLISH_MAX_ATTEMPTS=3 PUBLISH_INITIAL_BACKOFF=0 PUBLISH_SLEEP_COMMAND=noop-sleep \
  .github/scripts/publish-crate.sh cc-audit 1.2.4 >"$test_dir/retry.out" 2>"$test_dir/retry.err"
test "$(cat "$count_file")" = 3
grep -Fq 'retrying' "$test_dir/retry.err"

set +e
PATH="$test_dir:$PATH" CARGO_REGISTRY_TOKEN=test-token \
  FAKE_CURL_STATUS=404 FAKE_CARGO_QUOTA=1 CRATES_IO_USER_AGENT=cc-audit-test \
  PUBLISH_SLEEP_COMMAND=noop-sleep .github/scripts/publish-crate.sh cc-audit 1.2.5 \
  >"$test_dir/quota.out" 2>"$test_dir/quota.err"
quota_status=$?
set -e
test "$quota_status" -ne 0
grep -Fq 'daily publish quota reached' "$test_dir/quota.err"
if grep -Fq 'retrying' "$test_dir/quota.err"; then
  echo 'quota failure must not be retried' >&2
  exit 1
fi

echo 'publish-crate tests passed'
