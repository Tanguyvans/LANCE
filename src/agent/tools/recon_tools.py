"""Network reconnaissance tools — YAML-defined with Python handlers.

Subprocess tools (nmap, ssh-audit, curl, mosquitto_sub) are loaded from
YAML definitions in definitions/. Python-only tools (nvd_lookup) are
defined here and registered as handlers.

All subprocess tools return {stdout, stderr, return_code} as JSON.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess

from src.cve_lookup import query_nvd

_ANSI_ESC = re.compile(r'\x1b\[[0-9;]*[mK]')


def _run(cmd: list[str], timeout: int = 30) -> dict:
    """Run a command and return structured output (ANSI codes stripped)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": _ANSI_ESC.sub('', result.stdout),
            "stderr": _ANSI_ESC.sub('', result.stderr),
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


# MAC OUI prefix → manufacturer mapping for common IoT vendors
_OUI_DB: dict[str, str] = {
    "cc:50:e3": "Espressif (ESP32/ESP8266)",
    "80:7d:3a": "Espressif (ESP32)",
    "24:6f:28": "Espressif (ESP32)",
    "88:a2:9e": "Raspberry Pi",
    "d8:3a:dd": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "2c:cf:67": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "ac:1f:09": "RAK Wireless (WisGate)",
    "e4:fa:c4": "TP-Link",
    "6c:63:f8": "Ubiquiti",
    "f4:c8:8a": "Maxglo / Unknown",
    "04:f4:1c": "MikroTik",
    "3c:6d:66": "NVIDIA (Jetson)",
    "48:8f:4b": "Unknown (IoT)",
    "1e:63:c5": "Unknown (random MAC)",
    "ae:8b:dd": "Unknown (random MAC)",
    "58:02:05": "NVIDIA (Jetson)",
    "00:e0:4c": "Realtek",
}


def _identify_vendor(mac: str) -> str:
    """Look up manufacturer from MAC OUI prefix."""
    mac_clean = mac.lower().replace("-", ":")
    parts = mac_clean.split(":")
    prefix = ":".join(parts[:3])
    # Check if locally administered (bit 1 of first octet = 1)
    # These are randomized MACs from phones/modern devices
    first_byte = int(parts[0], 16)
    if first_byte & 0x02:
        return "Randomized MAC (phone/tablet)"
    return _OUI_DB.get(prefix, "Unknown")


def _parse_arp_line(line: str) -> dict | None:
    """Parse a single arp -a output line into structured data."""
    # Format: ? (192.168.88.202) at cc:50:e3:9c:13:14 on en0 ifscope [ethernet]
    # Or: router.lan (192.168.88.1) at 4:f4:1c:51:c1:3b on en0 ifscope [ethernet]
    m = re.search(r"(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)(?:\s+\[\w+\])?\s+on\s+(\S+)", line)
    if not m:
        return None
    hostname, ip, mac, interface = m.groups()
    # Normalize MAC to 2-digit octets (macOS uses single-digit e.g. 4:f4:1c)
    mac_parts = mac.split(":")
    mac_norm = ":".join(p.zfill(2) for p in mac_parts)
    return {
        "ip": ip,
        "mac": mac_norm,
        "hostname": hostname if hostname != "?" else "",
        "vendor": _identify_vendor(mac_norm),
        "interface": interface,
    }


def arp_scan(**kwargs) -> str:
    """Double ping-sweep then dump ARP table for full Layer 2 discovery."""
    import concurrent.futures
    import time
    import logging

    log = logging.getLogger(__name__)
    try:
        from src.agent.tools.graph_tools import _scenario_topology
        # Ensure we have a string here
        subnet = str(_scenario_topology.get("subnet", "192.168.88.0")).rsplit(".", 1)[0] if _scenario_topology else "192.168.88"
    except Exception:
        subnet = "192.168.88"

    def ping_host(ip: str) -> None:
        try:
            # Force text=True to avoid byte errors
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True, text=True, timeout=5,
            )
        except Exception:
            pass  # Ignore all errors — we just want to populate ARP cache

    # Two passes to catch slow/intermittent devices
    for pass_num in range(2):
        ips = [f"{subnet}.{i}" for i in range(1, 255)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
            list(pool.map(ping_host, ips))  # list() forces completion
        if pass_num == 0:
            time.sleep(1)  # Wait for ARP cache to settle before pass 2

    # Dump ARP table directly via subprocess (not _run, to avoid interference)
    arp_output = ""
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5,
        )
        arp_output = result.stdout
    except subprocess.TimeoutExpired as e:
        log.warning("arp -a timed out, using partial output")
        raw = e.stdout or b""
        arp_output = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else (raw or "")
    except Exception as e:
        log.error("arp -a failed: %s", e)
        return json.dumps({"hosts": [], "count": 0, "error": str(e)})

    # Parse and deduplicate by IP (keep first interface seen)
    seen_ips: set[str] = set()
    hosts = []
    for line in arp_output.splitlines():
        if subnet not in line or "incomplete" in line:
            continue
        parsed = _parse_arp_line(line)
        if parsed and parsed["ip"] not in seen_ips:
            # Skip broadcast addresses
            last_octet = parsed["ip"].split(".")[-1]
            if last_octet in ("0", "255"):
                continue
            seen_ips.add(parsed["ip"])
            hosts.append(parsed)

    # Sort by IP
    hosts.sort(key=lambda h: tuple(int(x) for x in h["ip"].split(".")))

    return json.dumps({
        "hosts": hosts,
        "count": len(hosts),
    })


def nvd_lookup(query: str, top_k: int = 10) -> str:
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
                for r in results[:top_k]
            ]
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ── Tool definitions (generated from YAML) ───────────────────────

def _load_recon_tools() -> list[dict]:
    """Load recon tools from YAML definitions, attach Python handlers."""
    from src.agent.tools.tool_loader import load_all_tools, register_python_handler

    tools = load_all_tools()
    register_python_handler(tools, "nvd_lookup", nvd_lookup)
    register_python_handler(tools, "arp_scan", arp_scan)
    return tools


RECON_TOOLS = _load_recon_tools()
