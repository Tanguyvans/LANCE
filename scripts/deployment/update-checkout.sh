#!/usr/bin/env bash
# Caller holds the shared lab lock and has stopped this instance's service.
set -euo pipefail
slot=${1:?}
sha=${2:?}
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || exit 1
git fetch "${DEPLOY_REMOTE:?}" "$sha"
if [[ "$slot" == main ]]; then
  git merge --ff-only "$sha"
else
  git diff --quiet
  git diff --cached --quiet
  git checkout --detach "$sha"
fi
[[ "$(git rev-parse HEAD)" == "$sha" ]] || { echo 'Checkout is ahead of tested commit' >&2; exit 1; }
