#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

target_branch="${TARGET_BRANCH:-main}"
api_root="repos/${GITHUB_REPOSITORY}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# The rulesets endpoint requires the GitHub App installation to have
# Administration: Read. Fail with an actionable message instead of exposing
# only gh's generic 403/422 response when the installation is misconfigured.
if ! gh api "$api_root/rulesets" --silent >/dev/null 2>"$tmp_dir/rulesets-error"; then
  echo "::error::Unable to read repository rulesets. Grant the GitHub App installation Administration: Read for ${GITHUB_REPOSITORY}, then update the installation and rerun this workflow." >&2
  cat "$tmp_dir/rulesets-error" >&2
  exit 1
fi

mapfile -t ruleset_ids < <(
  gh api --paginate "$api_root/rulesets" \
    --jq '.[] | select(.target == "branch" and .enforcement == "active") | .id'
)

if [ "${#ruleset_ids[@]}" -eq 0 ]; then
  echo "No active branch rulesets were returned for ${target_branch}." >&2
  exit 1
fi

for ruleset_id in "${ruleset_ids[@]}"; do
  if ! gh api "$api_root/rulesets/$ruleset_id" > "$tmp_dir/$ruleset_id.json" 2>"$tmp_dir/ruleset-$ruleset_id-error"; then
    echo "::error::Unable to read active ruleset ${ruleset_id}. Confirm the GitHub App installation has Administration: Read, then update the installation and rerun this workflow." >&2
    cat "$tmp_dir/ruleset-$ruleset_id-error" >&2
    exit 1
  fi
done

required_checks=$(
  jq -s -r --arg ref "refs/heads/${target_branch}" '
    [ .[]
      | select(.enforcement == "active")
      | select((.conditions.ref_name.include // []) | index($ref))
      | .rules[]?
      | select(.type == "required_status_checks")
      | .parameters.required_status_checks[]?.context
    ] | unique | .[]
  ' "$tmp_dir"/*.json
)

if [ -z "$required_checks" ]; then
  echo "No required status checks were found for ${target_branch}." >&2
  exit 1
fi

printf '%s\n' "$required_checks"
