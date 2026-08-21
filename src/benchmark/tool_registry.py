"""Shared service/tool compatibility metadata for benchmark scenarios.

The agent historically kept several copies of the role -> service -> tool
mapping.  Scenario composition needs the same information as the scanner and
the evaluator, so this module is deliberately dependency-light and safe to
import from both sides of the benchmark.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


ROLE_SERVICES: dict[str, tuple[dict[str, Any], ...]] = {
    "router": (
        {"name": "ssh", "port": 22, "protocol": "tcp"},
        {"name": "http", "port": 80, "protocol": "tcp"},
    ),
    "gateway": ({"name": "ssh", "port": 22, "protocol": "tcp"},),
    "iot_gateway": (
        {"name": "ssh", "port": 22, "protocol": "tcp"},
        {"name": "http", "port": 80, "protocol": "tcp"},
    ),
    "pivot_entry": ({"name": "ssh", "port": 22, "protocol": "tcp"},),
    "pivot_relay": ({"name": "ssh", "port": 22, "protocol": "tcp"},),
    "pivot_vault": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "pivot_decoy": ({"name": "ssh", "port": 22, "protocol": "tcp"},),
    "mqtt_broker": ({"name": "mqtt", "port": 1883, "protocol": "tcp"},),
    "mqtt_broker_v2": ({"name": "mqtt", "port": 1883, "protocol": "tcp"},),
    "web_server": ({"name": "http", "port": 80, "protocol": "tcp"},),
    "web_server_v2": ({"name": "http", "port": 80, "protocol": "tcp"},),
    "web_upload": ({"name": "http", "port": 80, "protocol": "tcp"},),
    "camera_server": ({"name": "http", "port": 80, "protocol": "tcp"},),
    "ssh_server": ({"name": "ssh", "port": 22, "protocol": "tcp"},),
    "ssh_server_v2": ({"name": "ssh", "port": 22, "protocol": "tcp"},),
    "ldap_server": ({"name": "ldap", "port": 389, "protocol": "tcp"},),
    "nfs_server": ({"name": "nfs", "port": 2049, "protocol": "tcp"},),
    "nvr_server": ({"name": "ssh", "port": 22, "protocol": "tcp"},),
    "ftp_server": ({"name": "ftp", "port": 21, "protocol": "tcp"},),
    "db_server": ({"name": "mysql", "port": 3306, "protocol": "tcp"},),
    "db_server_v2": ({"name": "redis", "port": 6379, "protocol": "tcp"},),
    "nodered_server": ({"name": "http", "port": 1880, "protocol": "tcp"},),
    "modbus_server": ({"name": "modbus", "port": 502, "protocol": "tcp"},),
    "coap_server": ({"name": "coap", "port": 5683, "protocol": "udp"},),
    "snmp_server": ({"name": "snmp", "port": 161, "protocol": "udp"},),
    "api_identity_server": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "api_tenant_server": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "api_data_store": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "api_event_broker": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "api_admin_portal": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "pki_ca_server": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "pki_enrollment_server": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "pki_mtls_server": ({"name": "https", "port": 8443, "protocol": "tcp"},),
    "pki_registry": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "pki_device": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "ota_repository": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "ota_server": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "ota_device": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "ota_signer": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "ota_monitor": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "cloud_web_server": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "cloud_metadata_server": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "cloud_control_plane": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "cloud_worker": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "cloud_audit": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "ot_hmi": ({"name": "http", "port": 8080, "protocol": "tcp"},),
    "ot_opcua_server": (
        {"name": "opcua", "port": 4840, "protocol": "tcp"},
        {"name": "http", "port": 8080, "protocol": "tcp"},
    ),
    "ot_bacnet_server": (
        {"name": "bacnet", "port": 47808, "protocol": "udp"},
        {"name": "http", "port": 8080, "protocol": "tcp"},
    ),
    "ot_historian": ({"name": "http", "port": 8080, "protocol": "tcp"},),
}


SERVICE_TOOLS: dict[str, dict[str, tuple[str, ...]]] = {
    "ssh": {
        "recon": ("ssh_audit", "nmap_scan"),
        "verification": ("ssh_login", "try_credential", "ssh_audit", "nmap_scan"),
        "intrusion": ("ssh_login", "try_credential", "ssh_exec"),
    },
    "http": {
        "recon": ("curl_headers", "http_get", "nmap_scan"),
        "verification": ("curl_headers", "http_get", "http_request"),
        "intrusion": ("curl_headers", "http_get", "http_request", "python_exec"),
    },
    "https": {
        "recon": ("tls_inspect", "curl_headers", "nmap_scan"),
        "verification": ("tls_inspect", "http_get", "http_request", "mtls_request"),
        "intrusion": ("http_get", "http_request", "mtls_request"),
    },
    "mqtt": {
        "recon": ("mqtt_listen", "nmap_scan"),
        "verification": ("mqtt_listen", "try_credential", "nmap_scan"),
        "intrusion": ("mqtt_listen", "try_credential"),
    },
    "ftp": {
        "recon": ("ftp_list", "nmap_scan"),
        "verification": ("ftp_list", "try_credential", "nmap_scan"),
        "intrusion": ("ftp_list", "try_credential"),
    },
    "mysql": {
        "recon": ("nmap_scan",),
        "verification": ("mysql_query", "nmap_scan"),
        "intrusion": ("mysql_query",),
    },
    "redis": {
        "recon": ("nmap_scan",),
        "verification": ("redis_cmd", "nmap_scan"),
        "intrusion": ("redis_cmd",),
    },
    "modbus": {
        "recon": ("modbus_scan", "nmap_scan"),
        "verification": ("modbus_scan", "nmap_scan"),
        "intrusion": ("modbus_scan", "tcp_send"),
    },
    "coap": {
        "recon": ("nmap_scan",),
        "verification": ("nmap_scan", "udp_send"),
        "intrusion": ("udp_send",),
    },
    "snmp": {
        "recon": ("nmap_scan",),
        "verification": ("nmap_scan",),
        "intrusion": ("nmap_scan",),
    },
    "opcua": {
        "recon": ("tcp_send", "nmap_scan"),
        "verification": ("tcp_send", "nmap_scan"),
        "intrusion": ("tcp_send",),
    },
    "bacnet": {
        "recon": ("udp_send", "nmap_scan"),
        "verification": ("udp_send", "nmap_scan"),
        "intrusion": ("udp_send",),
    },
    "telnet": {
        "recon": ("nmap_scan",),
        "verification": ("telnet_connect", "try_credential", "nmap_scan"),
        "intrusion": ("telnet_connect", "try_credential"),
    },
}


SERVICE_ALIASES: dict[str, str] = {
    "ssh": "ssh",
    "http": "http",
    "https": "https",
    "http-alt": "http",
    "http-proxy": "http",
    "ssl/http": "https",
    "mqtt": "mqtt",
    "mosquitto": "mqtt",
    "mosquitto?": "mqtt",
    "port-9001": "mqtt",
    "telnet": "telnet",
    "mysql": "mysql",
    "mysql?": "mysql",
    "mariadb": "mysql",
    "mariadb?": "mysql",
    "modbus": "modbus",
    "redis": "redis",
    "ftp": "ftp",
    "snmp": "snmp",
    "coap": "coap",
    "ldap": "ldap",
    "opcua": "opcua",
    "bacnet": "bacnet",
}


PHASES = ("recon", "verification", "intrusion")
INTERNAL_TOOLS = frozenset({"save_deliverable", "read_deliverable", "complete_intrusion_campaign"})


def service_descriptors(role: str, explicit: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Return normalized service descriptors for a topology node."""
    if explicit:
        return [dict(item) for item in explicit]
    return [dict(item) for item in ROLE_SERVICES.get(str(role), ())]


def available_tool_names(repo_root: Path | None = None) -> set[str]:
    """Read tool names without importing the agent runtime."""
    root = repo_root or Path(__file__).resolve().parents[2]
    directory = root / "src" / "agent" / "tools" / "definitions"
    names = set(INTERNAL_TOOLS)
    for path in directory.glob("*.yaml"):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, UnicodeError, yaml.YAMLError):
            continue
        if isinstance(data, dict) and data.get("name"):
            names.add(str(data["name"]))
    return names


def tools_for_services(services: list[str], phase: str) -> set[str]:
    """Return tools compatible with at least one declared service."""
    result: set[str] = set()
    for service in services:
        service_key = SERVICE_ALIASES.get(
            str(service).casefold(), str(service).casefold()
        )
        result.update(SERVICE_TOOLS.get(service_key, {}).get(phase, ()))
    return result


def tools_for_role(role: str, phase: str, explicit_services: list[dict[str, Any]] | None = None) -> set[str]:
    descriptors = service_descriptors(role, explicit_services)
    return tools_for_services([str(item.get("name", "")) for item in descriptors], phase)


def tool_policy_for_phase(policy: dict[str, Any], phase: str) -> set[str] | None:
    """Return an allowlist for a phase, or None when the phase is unrestricted."""
    if not policy:
        return None
    value = policy.get(phase)
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get("tools", [])
    if not isinstance(value, list):
        return set()
    return {str(item) for item in value}
