"""Network reconnaissance tools (safe, read-only).

Each tool wraps a subprocess call with timeout protection.
All tools return {stdout, stderr, return_code} as JSON.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess

from src.cve_lookup import query_nvd


def _run(cmd: list[str], timeout: int = 30) -> dict:
    """Run a command and return structured output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s: {shlex.join(cmd)}",
            "return_code": -1,
        }
    except FileNotFoundError:
        return {
            "stdout": "",
            "stderr": f"Command not found: {cmd[0]}",
            "return_code": -1,
        }


def nmap_scan(target: str, ports: str | None = None) -> str:
    """Run nmap service version scan on a target."""
    cmd = ["nmap", "-sV", target]
    if ports:
        cmd.extend(["-p", ports])
    return json.dumps(_run(cmd, timeout=120))


def ssh_audit(host: str, port: int = 22) -> str:
    """Run ssh-audit on a host to check SSH configuration."""
    cmd = ["ssh-audit", f"{host}:{port}"]
    return json.dumps(_run(cmd, timeout=30))


def curl_headers(url: str) -> str:
    """Fetch HTTP response headers from a URL."""
    cmd = ["curl", "-sI", "--max-time", "10", url]
    return json.dumps(_run(cmd, timeout=15))


def mqtt_listen(broker: str, topic: str = "#", count: int = 10, timeout: int = 5) -> str:
    """Listen for MQTT messages on a broker."""
    cmd = [
        "mosquitto_sub",
        "-h", broker,
        "-t", topic,
        "-C", str(count),
        "-W", str(timeout),
    ]
    return json.dumps(_run(cmd, timeout=timeout + 5))


def nvd_lookup(query: str) -> str:
    """Search NIST NVD for known CVEs by CPE string or keyword."""
    api_key = os.environ.get("NVD_API_KEY")
    try:
        results = query_nvd(query, api_key)
        return json.dumps(
            [
                {
                    "cve_id": r.cve_id,
                    "description": r.description,
                    "cvss_score": r.cvss_score,
                    "severity": r.severity,
                    "attack_vector": r.attack_vector,
                }
                for r in results
            ]
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ── Tool definitions (for the provider) ──────────────────────────

RECON_TOOLS = [
    {
        "name": "nmap_scan",
        "description": "Run an nmap service version scan (-sV) on a target IP or subnet. Returns open ports, services, and versions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP, hostname, or subnet (e.g. '192.168.88.0/24' or '192.168.88.1')",
                },
                "ports": {
                    "type": "string",
                    "description": "Optional port range (e.g. '22,80,443' or '1-1000'). If omitted, nmap uses default ports.",
                },
            },
            "required": ["target"],
        },
        "function": nmap_scan,
    },
    {
        "name": "ssh_audit",
        "description": "Run ssh-audit on a host to analyze SSH configuration: key exchange, ciphers, MACs, host keys, and known vulnerabilities like Terrapin.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Target IP or hostname",
                },
                "port": {
                    "type": "integer",
                    "description": "SSH port (default: 22)",
                    "default": 22,
                },
            },
            "required": ["host"],
        },
        "function": ssh_audit,
    },
    {
        "name": "curl_headers",
        "description": "Fetch HTTP response headers from a URL to check for security headers (X-Frame-Options, CSP, HSTS, etc.) and server version.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL to fetch headers from (e.g. 'http://192.168.88.1')",
                }
            },
            "required": ["url"],
        },
        "function": curl_headers,
    },
    {
        "name": "mqtt_listen",
        "description": "Listen for MQTT messages on a broker to check if anonymous access is allowed and what topics are exposed.",
        "input_schema": {
            "type": "object",
            "properties": {
                "broker": {
                    "type": "string",
                    "description": "MQTT broker IP or hostname",
                },
                "topic": {
                    "type": "string",
                    "description": "MQTT topic filter (default: '#' for all topics)",
                    "default": "#",
                },
                "count": {
                    "type": "integer",
                    "description": "Number of messages to capture before stopping (default: 10)",
                    "default": 10,
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max seconds to wait for messages (default: 5)",
                    "default": 5,
                },
            },
            "required": ["broker"],
        },
        "function": mqtt_listen,
    },
    {
        "name": "nvd_lookup",
        "description": "Search NIST NVD for known CVEs by CPE string or keyword. Use for versions discovered by nmap. Example: nvd_lookup('cpe:2.3:a:eclipse:mosquitto:2.0.11:*:*:*:*:*:*:*') or nvd_lookup('Dropbear SSH 2020.81').",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "CPE 2.3 string or keyword search (e.g. 'cpe:2.3:a:eclipse:mosquitto:2.0.11:*:*:*:*:*:*:*' or 'MikroTik RouterOS 7.18')",
                },
            },
            "required": ["query"],
        },
        "function": nvd_lookup,
    },
]
