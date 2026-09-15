#!/usr/bin/env bash
set -euo pipefail

head_sha=${1:?head SHA is required}
repository_url=${2:?repository URL is required}

# git ls-remote emits a peeled commit line for annotated tags (`^{}`), while
# lightweight tags emit the commit line directly. Accept both forms.
git ls-remote --tags "$repository_url" |
  awk -v sha="$head_sha" '
    $1 == sha && $2 ~ /^refs\/tags\/v/ {
      tag = $2
      sub(/^refs\/tags\//, "", tag)
      sub(/\^\{\}$/, "", tag)
      print tag
      exit
    }
  '
