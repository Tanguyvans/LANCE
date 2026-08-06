#!/bin/bash
set -euo pipefail

MODE="${1:?mode required}"
PROFILE="${2:?profile required}"
NAME="${3:?name required}"
ALLOWED_FETCH_HOSTS="${4:-}"
ALLOWED_METADATA_SOURCE="${ALLOWED_FETCH_HOSTS%%,*}"
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq python3 ca-certificates curl
install -d -m 0755 /opt/nato-benchmark
install -d -m 0755 /etc/nato-benchmark
install -m 0755 /tmp/benchmark_simulator.py /opt/nato-benchmark/simulator.py

python3 - "${MODE}" "${PROFILE}" "${NAME}" "${ALLOWED_FETCH_HOSTS}" <<'PY'
import json
import sys
from pathlib import Path

mode, profile, name, raw_hosts = sys.argv[1:]
config = {
    "mode": mode,
    "profile": profile,
    "name": name,
    "allowed_fetch_hosts": [host for host in raw_hosts.split(",") if host],
}
Path("/etc/nato-benchmark/simulator.json").write_text(
    json.dumps(config, sort_keys=True), encoding="utf-8"
)
PY
chmod 0644 /etc/nato-benchmark/simulator.json

cat > /etc/systemd/system/nato-benchmark-simulator.service <<'EOF'
[Unit]
Description=NATO Smart City deterministic benchmark simulator
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=BENCHMARK_SIM_CONFIG=/etc/nato-benchmark/simulator.json
ExecStart=/usr/bin/python3 /opt/nato-benchmark/simulator.py
Restart=on-failure
RestartSec=1
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
EOF

if [ "${MODE}" = "cloud_metadata" ]; then
  apt-get install -y -qq iptables
  cat > /usr/local/sbin/nato-benchmark-metadata-firewall <<'EOF'
#!/bin/sh
set -eu
iptables -C INPUT -p tcp --dport 8080 -s __ALLOWED_METADATA_SOURCE__ -j ACCEPT 2>/dev/null || \
  iptables -I INPUT 1 -p tcp --dport 8080 -s __ALLOWED_METADATA_SOURCE__ -j ACCEPT
iptables -C INPUT -p tcp --dport 8080 -j REJECT 2>/dev/null || \
  iptables -I INPUT 2 -p tcp --dport 8080 -j REJECT
EOF
  sed -i "s/__ALLOWED_METADATA_SOURCE__/${ALLOWED_METADATA_SOURCE}/g" /usr/local/sbin/nato-benchmark-metadata-firewall
  chmod 0755 /usr/local/sbin/nato-benchmark-metadata-firewall
  cat > /etc/systemd/system/nato-benchmark-metadata-firewall.service <<'EOF'
[Unit]
Description=Restrict simulated metadata service to the cloud-web fixture
Before=nato-benchmark-simulator.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/nato-benchmark-metadata-firewall
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
if [ "${MODE}" = "cloud_metadata" ]; then
  systemctl enable nato-benchmark-metadata-firewall.service
  systemctl restart nato-benchmark-metadata-firewall.service
fi
systemctl enable nato-benchmark-simulator.service
systemctl restart nato-benchmark-simulator.service
sleep 1
systemctl is-active --quiet nato-benchmark-simulator.service
echo "SIMULATOR_OK mode=${MODE} profile=${PROFILE}"
