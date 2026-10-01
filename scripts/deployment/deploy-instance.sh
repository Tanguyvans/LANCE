#!/usr/bin/env bash
# Run only on the existing nato-master Actions runner, after CI validation.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
slot=${1:?instance required}
sha=${2:?tested commit required}
branch=${3:?branch required}
case "$slot" in
  main) port=8501; root=/opt/nato-smartcity-iot; service=nato-fastapi ;;
  dev-1) port=8502; root=/opt/lance-dev-1; service=lance-dev-1 ;;
  dev-2) port=8503; root=/opt/lance-dev-2; service=lance-dev-2 ;;
  *) echo 'Unknown instance' >&2; exit 1 ;;
esac
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || exit 1
[[ "$branch" =~ ^[a-zA-Z0-9._/-]+$ ]] || exit 1
[[ "${RUNNER_NAME:-}" == nato-master ]] || { echo 'Requires nato-master runner' >&2; exit 1; }
ip -o -4 addr show | grep -q '100\.103\.253\.86/' || { echo 'Not the nato-master host' >&2; exit 1; }
[[ $(id -u) == 0 ]] || { echo 'Root runner required' >&2; exit 1; }
stable=/opt/nato-smartcity-iot
shared=/var/lib/lance
install -d -m 0700 "$shared"
# Same persistent file as every API/CLI process. Never unlink this file.
exec 9>>"$shared/lab.lock"
flock -x 9
if [[ "$slot" != main ]]; then
  # A legacy stable process cannot participate in mutual exclusion.
  curl -fsS --max-time 10 http://127.0.0.1:8501/api/environment |
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["instance"] == "main" and d["lab_lock_enabled"], "Update main before enabling development"'
elif systemctl is-active --quiet "$service"; then
  # Bootstrap check also protects an old service which predates the lock.
  curl -fsS --max-time 10 http://127.0.0.1:8501/api/pipeline/status |
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert not (d["running"] or d.get("teardown_running")), "Stable instance is busy; retry after completion"'
fi
if systemctl is-active --quiet "$service"; then
  curl -fsS --max-time 10 "http://127.0.0.1:$port/api/pipeline/status" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert not (d["running"] or d.get("teardown_running")), "Instance has active or queued work; retry after completion"'
fi
# No application code or dependencies are changed under a running service.
if systemctl is-active --quiet "$service"; then
  systemctl stop "$service"
fi
failed() {
  systemctl stop "$service" || true
  echo "Deployment failed. $service remains stopped; inspect checkout/dependencies before restarting." >&2
}
trap failed ERR
if [[ ! -d "$root/.git" ]]; then
  [[ "$slot" != main && ! -e "$root" ]] || { echo 'Unexpected checkout state' >&2; exit 1; }
  git init -q "$root"
fi
cd "$root"
bash "$script_dir/update-checkout.sh" "$slot" "$sha"
# Refuse old branches without the laboratory protocol.
test -f src/benchmark/lab_lock.py
if [[ "$slot" != main ]]; then
  for relative in benchmarks/ansible/inventory.yml benchmarks/ansible/group_vars/all/main.yml benchmarks/ansible/group_vars/all/vault_master.yml; do
    test -f "$stable/$relative"
    install -m 0600 "$stable/$relative" "$root/$relative"
    git update-index --skip-worktree -- "$relative"
  done
  if [[ ! -f .env ]]; then install -m 0600 "$stable/.env" .env; fi
fi
# Each checkout owns its dependencies, database and run artifacts.
if [[ ! -x venv/bin/python ]]; then python3 -m venv venv; fi
venv/bin/pip install -r requirements.txt --quiet
if [[ ! -x /root/.local/bin/codex ]]; then
  curl -fsSL https://chatgpt.com/codex/install.sh | sh
fi
export LANCE_DB_PATH="$root/data/lance.db"
venv/bin/python scripts/deployment/seed-registry.py "$stable/data/lance.db"
venv/bin/python -m src.db.inject_moe
install -d -m 0755 "/etc/systemd/system/$service.service.d"
# EnvironmentFile entries take precedence over Environment and the copied .env.
umask 077
cat > "$shared/$slot.env" <<ENV
LANCE_INSTANCE=$slot
LANCE_BRANCH=$branch
LANCE_COMMIT=$sha
LANCE_DB_PATH=$root/data/lance.db
LANCE_LAB_LOCK=$shared/lab.lock
LANCE_DEPLOYMENT_ROOT=$stable/output/scenario_deployments
ENV
cat > "/etc/systemd/system/$service.service.d/instance.conf" <<UNIT
[Service]
EnvironmentFile=$shared/$slot.env
UNIT
if [[ "$slot" != main ]]; then
  cat > "/etc/systemd/system/$service.service" <<UNIT
[Unit]
Description=LANCE development $slot
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=$root
Environment=LANG=C.UTF-8
Environment=LC_ALL=C.UTF-8
Environment=LANCE_CODEX_CLI_PATH=/root/.local/bin/codex
EnvironmentFile=$root/.env
ExecStart=$root/venv/bin/uvicorn src.api.main:app --host 0.0.0.0 --port $port --workers 1
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
fi
systemctl daemon-reload
systemctl enable "$service"
systemctl start "$service"
curl -fsS --retry 20 --retry-connrefused --retry-delay 1 --max-time 10 "http://127.0.0.1:$port/api/environment" |
  EXPECTED_SHA="$sha" EXPECTED_SLOT="$slot" venv/bin/python -c 'import json,os,sys; d=json.load(sys.stdin); assert d["commit"] == os.environ["EXPECTED_SHA"] and d["instance"] == os.environ["EXPECTED_SLOT"] and d["lab_lock_enabled"]; print(d)'
trap - ERR
