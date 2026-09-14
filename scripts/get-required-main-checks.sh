#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

target_branch="${TARGET_BRANCH:-main}"
api_root="repos/${GITHUB_REPOSITORY}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mapfile -t ruleset_ids < <(
  gh api --paginate "$api_root/rulesets" \
    --jq '.[] | select(.target == "branch" and .enforcement == "active") | .id'
)

if [ "${#ruleset_ids[@]}" -eq 0 ]; then
  echo "No active branch rulesets were returned for ${target_branch}." >&2
  exit 1
fi

for ruleset_id in "${ruleset_ids[@]}"; do
  gh api "$api_root/rulesets/$ruleset_id" > "$tmp_dir/$ruleset_id.json"
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
