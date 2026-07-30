#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BENCH_USER="lancebench"
REQUIRED_TOOLS_FILE="$SCRIPT_DIR/blind_worker_required_tools.txt"
WORKER_PATH="$REPO_DIR/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Refusing blind run: launcher must start as root and drop privileges itself" >&2
  exit 1
fi

preflight_tools() {
  local missing=()
  local tool
  if [[ ! -f "$REQUIRED_TOOLS_FILE" ]]; then
    echo "Refusing blind run: missing tool contract $REQUIRED_TOOLS_FILE" >&2
    return 1
  fi
  while IFS= read -r tool; do
    [[ -z "$tool" || "$tool" == \#* ]] && continue
    if ! runuser -u "$BENCH_USER" -- env PATH="$WORKER_PATH" sh -c \
      'command -v "$1" >/dev/null 2>&1' sh "$tool"; then
      missing+=("$tool")
    fi
  done < "$REQUIRED_TOOLS_FILE"
  if ((${#missing[@]})); then
    echo "Blind worker preflight failed; missing commands: ${missing[*]}" >&2
    return 1
  fi
}

blind=false
managed=true
preflight_only=false
[[ "${1:-}" == "--preflight" ]] && preflight_only=true
for arg in "$@"; do
  [[ "$arg" == "--blind" ]] && blind=true
  [[ "$arg" == "--no-manage-scenario" ]] && managed=false
done
if [[ "$preflight_only" != true && ("$blind" != true || "$managed" != false) ]]; then
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

preflight_tools
if [[ "${1:-}" == "--preflight" ]]; then
  echo "Blind worker preflight passed"
  exit 0
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
  PATH="$WORKER_PATH" \
  MINIMAX_API_KEY="$MINIMAX_API_KEY" \
  LANCE_GIT_COMMIT="$GIT_COMMIT" \
  LANCE_BLIND="1" \
  "$REPO_DIR/.venv/bin/python" -m src.agent "$@"
