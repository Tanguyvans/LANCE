#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BENCH_USER="lancebench"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Refusing blind run: launcher must start as root and drop privileges itself" >&2
  exit 1
fi

blind=false
managed=true
for arg in "$@"; do
  [[ "$arg" == "--blind" ]] && blind=true
  [[ "$arg" == "--no-manage-scenario" ]] && managed=false
done
if [[ "$blind" != true || "$managed" != false ]]; then
  echo "Refusing worker run without --blind and --no-manage-scenario" >&2
  exit 1
fi

if ! id "$BENCH_USER" >/dev/null 2>&1; then
  echo "Refusing blind run: user '$BENCH_USER' is not prepared" >&2
  exit 1
fi
if [[ ! -x "$REPO_DIR/.venv/bin/python" ]]; then
  echo "Refusing blind run: $REPO_DIR/.venv/bin/python is unavailable" >&2
  exit 1
fi
if runuser -u "$BENCH_USER" -- test -r "$REPO_DIR/benchmarks/ground_truth/scenario_1.yaml"; then
  echo "Refusing blind run: ground truth is readable before privilege drop" >&2
  echo "Run prepare_blind_worker.sh first" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source "$REPO_DIR/.env"
set +a
: "${MINIMAX_API_KEY:?MINIMAX_API_KEY is required}"
GIT_COMMIT="$(git -C "$REPO_DIR" rev-parse HEAD)"

cd "$REPO_DIR"
exec runuser -u "$BENCH_USER" -- env -i \
  HOME="/var/lib/$BENCH_USER" \
  LANG="C.UTF-8" \
  PATH="$REPO_DIR/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  MINIMAX_API_KEY="$MINIMAX_API_KEY" \
  LANCE_GIT_COMMIT="$GIT_COMMIT" \
  "$REPO_DIR/.venv/bin/python" -m src.agent "$@"
