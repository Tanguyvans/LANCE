#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${1:-/opt/nato-smartcity-iot-v3.4}"
BENCH_USER="lancebench"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This preparation script must run as root" >&2
  exit 1
fi
if [[ ! -d "$REPO_DIR/src" || ! -f "$REPO_DIR/benchmarks/catalog.yaml" ]]; then
  echo "Invalid LANCE repository: $REPO_DIR" >&2
  exit 1
fi

if ! id "$BENCH_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "/var/lib/$BENCH_USER" --create-home --shell /usr/sbin/nologin "$BENCH_USER"
fi

chmod 0755 "$REPO_DIR"
chmod 0711 "$REPO_DIR/benchmarks"
chmod 0644 "$REPO_DIR/benchmarks/catalog.yaml"
chmod 0600 "$REPO_DIR/.env"

for path in \
  "$REPO_DIR/.git" \
  "$REPO_DIR/paper" \
  "$REPO_DIR/tests" \
  "$REPO_DIR/tmp" \
  "$REPO_DIR/benchmarks/ansible" \
  "$REPO_DIR/benchmarks/baselines" \
  "$REPO_DIR/benchmarks/campaigns" \
  "$REPO_DIR/benchmarks/docs" \
  "$REPO_DIR/benchmarks/eval_profiles" \
  "$REPO_DIR/benchmarks/external" \
  "$REPO_DIR/benchmarks/ground_truth" \
  "$REPO_DIR/benchmarks/packs" \
  "$REPO_DIR/benchmarks/results" \
  "$REPO_DIR/benchmarks/scenarios" \
  "$REPO_DIR/benchmarks/templates" \
  "$REPO_DIR/benchmarks/tools" \
  "$REPO_DIR/benchmarks/topologies"
do
  [[ ! -e "$path" ]] || chmod 0700 "$path"
done

for path in /opt/nato-smartcity-iot /opt/baseline-tools; do
  [[ ! -e "$path" ]] || chmod 0700 "$path"
done

install -d -m 0750 -o "$BENCH_USER" -g "$BENCH_USER" "$REPO_DIR/output/campaigns"

if runuser -u "$BENCH_USER" -- test -r "$REPO_DIR/benchmarks/ground_truth/scenario_1.yaml"; then
  echo "Blind worker isolation failed: ground truth remains readable" >&2
  exit 1
fi
if ! runuser -u "$BENCH_USER" -- test -r "$REPO_DIR/benchmarks/catalog.yaml"; then
  echo "Blind worker isolation failed: public catalog is unreadable" >&2
  exit 1
fi

echo "Blind worker prepared: $BENCH_USER can execute LANCE but cannot read benchmark oracles"
