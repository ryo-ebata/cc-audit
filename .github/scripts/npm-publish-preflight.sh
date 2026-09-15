#!/usr/bin/env bash

set -euo pipefail

if [ -z "${NODE_AUTH_TOKEN:-}" ]; then
  echo "::error::NPM_TOKEN is not configured; refusing to publish."
  exit 1
fi

if ! NPM_USER=$(npm whoami --registry=https://registry.npmjs.org); then
  echo "::error::NPM_TOKEN authentication failed; refusing to publish."
  exit 1
fi
if [ -z "${NPM_USER}" ]; then
  echo "::error::npm whoami returned no identity; refusing to publish."
  exit 1
fi
echo "npm authentication succeeded for user ${NPM_USER}"
