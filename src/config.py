"""Shared configuration for the NATO Smart City IoT pipeline.

All magic numbers that could reasonably change between environments
(physical lab vs benchmark scenarios) are centralized here.
"""

from __future__ import annotations

# ── Network subnets ──────────────────────────────────────────────────────────

PHYSICAL_SUBNET  = "192.168.88.0/24"   # Physical lab (MikroTik, Netgear, sensors…)
BENCHMARK_SUBNET = "192.168.100.0/24"  # Benchmark scenario VMs (Ansible-provisioned)

# ── Default port ranges per device role ──────────────────────────────────────

DEVICE_DEFAULT_PORTS: dict[str, str] = {
    "router":          "22,23,80,443,8080,8291",
    "modbus_server":   "22,80,502,102,44818",
    "mqtt_broker":     "22,80,1883,8883",
    "mqtt_broker_v2":  "22,80,1883,8883",
    "camera_server":   "22,80,443,554,8080,8554",
    "nvr_server":      "22,80,443,554,8080,8554",
    "iot_gateway":     "22,80,443,502,8080,8086",
    "web_server":      "22,80,443,8080,8443",
    "web_server_v2":   "22,80,443,8080,8443",
    "web_upload":      "22,80,443,8080",
    "hmi_server":      "22,80,443,8080,8443",
    "nodered_server":  "22,80,1880,8080",
    "db_server":       "22,80,3306,5432,27017",
    "db_server_v2":    "22,80,6379",
    "historian_server":"22,80,3306,8086",
    "scada_server":    "22,80,443,5000,8080",
    "ftp_server":      "21,22,80",
    "snmp_server":     "22,80,161",
    "coap_server":     "22,80,5683",
    "ssh_server":      "22,80,443",
    "ssh_server_v2":   "22,80,443",
}

# Fallback port list when no role-specific entry exists
DEFAULT_PORTS = "22,23,80,443,502,554,1883,3306,8080,8443"

# ── LLM call limits ──────────────────────────────────────────────────────────

EXPLOIT_MAX_TURNS   = 10   # Phase 4 per-vuln exploit agents
EXPLOIT_MAX_TOKENS  = 4096

INTRUSION_MAX_TURNS  = 10
INTRUSION_MAX_TOKENS = 2048

# ── API rate limiting ────────────────────────────────────────────────────────

NVD_MAX_REQUESTS_WITH_KEY  = 50
NVD_MAX_REQUESTS_NO_KEY    = 5
NVD_RATE_WINDOW_SECONDS    = 30.0
NVD_REQUEST_TIMEOUT        = 30.0

# ── API call timeout ─────────────────────────────────────────────────────────

API_TIMEOUT = 120.0

# ── Truncation limits ────────────────────────────────────────────────────────

EVIDENCE_TRUNCATE       = 200
RECON_TEXT_TRUNCATE     = 3000
OUTPUT_TRUNCATE         = 2000
TITLE_TRUNCATE          = 80