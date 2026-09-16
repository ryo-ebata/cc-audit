#!/usr/bin/env bash
set -euo pipefail

resolve() {
  awk -v sha="$1" '
    $1 == sha && $2 ~ /^refs\/tags\/v/ {
      tag = $2
      sub(/^refs\/tags\//, "", tag)
      sub(/\^\{\}$/, "", tag)
      print tag
      exit
    }
  '
}

lightweight=$(printf '%s\n' \
  'abc123 refs/tags/v1.2.3' \
  'def456 refs/tags/v1.2.4' |
  resolve abc123)
test "$lightweight" = v1.2.3

annotated=$(printf '%s\n' \
  'tag789 refs/tags/v1.2.5' \
  'abc123 refs/tags/v1.2.5^{}' |
  resolve abc123)
test "$annotated" = v1.2.5

non_tag=$(printf '%s\n' 'abc123 refs/heads/main' | resolve abc123)
test -z "$non_tag"

# Exercise the real resolver with enough output to trigger SIGPIPE if awk exits
# before git has finished writing. The resolver must consume all refs while
# still returning only the first matching tag.
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT
cat > "$test_root/git" <<'MOCK_GIT'
#!/usr/bin/env bash
if [[ "${FAKE_GIT_FAIL:-}" == "1" ]]; then
  exit 23
fi

test "$1" = ls-remote
printf '%s\n' 'abc123 refs/tags/v9.9.9'
for i in $(seq 1 100000); do
  printf 'noise-%s refs/tags/v0.0.%s\n' "$i" "$i"
done
MOCK_GIT
chmod +x "$test_root/git"

resolved=$(PATH="$test_root:$PATH" bash .github/scripts/resolve-release-tag.sh \
  abc123 https://example.invalid/repository.git)
test "$resolved" = v9.9.9

if PATH="$test_root:$PATH" FAKE_GIT_FAIL=1 \
  bash .github/scripts/resolve-release-tag.sh abc123 https://example.invalid/repository.git
then
  echo "resolver unexpectedly succeeded when git failed" >&2
  exit 1
else
  test "$?" -eq 23
fi
