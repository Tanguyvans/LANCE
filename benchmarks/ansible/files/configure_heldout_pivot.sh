#!/bin/bash
set -euo pipefail

ROLE="${1:?role required}"
PROFILE="${2:?profile required}"
SCENARIO_ID="${3:?scenario id required}"
NEXT_IP="${4:-}"
export DEBIAN_FRONTEND=noninteractive

case "${ROLE}" in
  heldout_entry|heldout_relay_l1|heldout_relay_l2) ;;
  *)
    echo "unsupported public held-out pivot role: ${ROLE}" >&2
    exit 2
    ;;
esac

apt-get update -qq
apt-get install -y -qq openssh-server sshpass curl
install -d -m 0755 /etc/ssh/sshd_config.d /etc/iot
useradd -m -s /bin/bash pivot 2>/dev/null || true

if [ "${PROFILE}" = "vulnerable" ]; then
  echo "pivot:Pivot-S${SCENARIO_ID}!" | chpasswd
  cat > /etc/ssh/sshd_config.d/99-benchmark-heldout-pivot.conf <<'EOF'
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers pivot
EOF
else
  passwd -l pivot >/dev/null 2>&1 || true
  cat > /etc/ssh/sshd_config.d/99-benchmark-heldout-pivot.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
AllowUsers pivot
EOF
fi

if [ -n "${NEXT_IP}" ]; then
  cat > /etc/iot/next-hop.conf <<EOF
host=${NEXT_IP}
user=pivot
credential_scope=public-benchmark-S${SCENARIO_ID}
purpose=${ROLE}
probe_ports=22,8080
http_export_path=/export
EOF
  chown root:pivot /etc/iot/next-hop.conf
  chmod 0640 /etc/iot/next-hop.conf
fi

sshd -t
systemctl enable ssh
systemctl restart ssh
echo "HELDOUT_PIVOT_OK role=${ROLE} profile=${PROFILE}"
