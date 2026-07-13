#!/bin/bash
set -euo pipefail

ROLE="${1:?role required}"
PROFILE="${2:?profile required}"
export DEBIAN_FRONTEND=noninteractive

case "${ROLE}" in
  mqtt_broker)
    apt-get update -qq
    apt-get install -y -qq mosquitto mosquitto-clients
    install -d -m 0750 -o mosquitto -g mosquitto /etc/mosquitto/passwd.d
    mosquitto_passwd -b -c /etc/mosquitto/passwd.d/benchmark benchmark 'Benchmark-MQTT-2026!'
    chown mosquitto:mosquitto /etc/mosquitto/passwd.d/benchmark
    chmod 0600 /etc/mosquitto/passwd.d/benchmark
    cat > /etc/mosquitto/conf.d/benchmark.conf <<'EOF'
listener 1883 0.0.0.0
allow_anonymous false
password_file /etc/mosquitto/passwd.d/benchmark
EOF
    systemctl enable mosquitto
    systemctl restart mosquitto
    ;;

  web_server)
    apt-get update -qq
    apt-get install -y -qq nginx
    rm -f /etc/nginx/sites-enabled/default
    install -d -m 0755 /var/www/html
    cat > /var/www/html/index.html <<EOF
<!doctype html><title>Smart City Operations</title>
<h1>Smart City Operations</h1><p>Profile: ${PROFILE}</p><a href="/admin">Administration</a>
EOF
    cat > /etc/nginx/conf.d/default.conf <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
    autoindex off;
    location / { try_files $uri $uri/ =404; }
    location ^~ /backup/ { return 404; }
    location = /admin {
        add_header WWW-Authenticate 'Basic realm="Smart City"' always;
        return 401;
    }
}
EOF
    nginx -t
    systemctl enable nginx
    systemctl restart nginx
    ;;

  ssh_server)
    apt-get update -qq
    apt-get install -y -qq openssh-server
    install -d -m 0755 /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/99-benchmark-hardened.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
EOF
    sshd -t
    systemctl enable ssh
    systemctl restart ssh
    ;;

  db_server_v2)
    apt-get update -qq
    apt-get install -y -qq redis-server
    sed -i 's/^bind .*/bind 0.0.0.0/' /etc/redis/redis.conf
    sed -i 's/^protected-mode .*/protected-mode yes/' /etc/redis/redis.conf
    if grep -qE '^requirepass ' /etc/redis/redis.conf; then
      sed -i 's/^requirepass .*/requirepass Benchmark-Redis-2026!/' /etc/redis/redis.conf
    else
      printf '\nrequirepass Benchmark-Redis-2026!\n' >> /etc/redis/redis.conf
    fi
    systemctl enable redis-server
    systemctl restart redis-server
    ;;

  *)
    echo "Unsupported S14 control role: ${ROLE}" >&2
    exit 2
    ;;
esac

echo "CONTROL_OK role=${ROLE} profile=${PROFILE}"
