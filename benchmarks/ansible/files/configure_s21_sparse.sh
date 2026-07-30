#!/bin/bash
set -euo pipefail

ROLE="${1:?role required}"
export DEBIAN_FRONTEND=noninteractive

case "${ROLE}" in
  mqtt_broker)
    apt-get update -qq
    apt-get install -y -qq mosquitto mosquitto-clients
    cat > /etc/mosquitto/conf.d/benchmark.conf <<'EOF'
listener 1883 0.0.0.0
allow_anonymous true
EOF
    systemctl enable mosquitto
    systemctl restart mosquitto
    sleep 1
    # Keep the sole flaw authentication-related: no credentials or sensitive
    # values are published by this low-prevalence fixture.
    mosquitto_pub -h localhost -t benchmark/retained -m 'SPARSE-MQTT-S21' -r
    ;;

  web_server)
    apt-get update -qq
    apt-get install -y -qq nginx
    rm -f /etc/nginx/sites-enabled/default
    install -d -m 0755 /var/www/html/backup
    cat > /var/www/html/backup/db_backup_2024-01-15.sql <<'EOF'
-- Bounded S21 fixture
INSERT INTO benchmark_users VALUES (1,'fixture-admin','S21-only-fixture-password');
EOF
    cat > /etc/nginx/conf.d/default.conf <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
    autoindex on;
    location / { try_files $uri $uri/ =404; }
}
EOF
    nginx -t
    systemctl enable nginx
    systemctl restart nginx
    ;;

  *)
    echo "unsupported S21 sparse role: ${ROLE}" >&2
    exit 2
    ;;
esac

echo "SPARSE_OK role=${ROLE}"
