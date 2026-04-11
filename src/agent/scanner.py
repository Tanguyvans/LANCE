"""Phase 3a: Deterministic scanner — runs all recon tools per device, extracts trivial findings.

Replaces the LLM-driven tool-calling in Phase 3 device agents.
Python decides which tools to run (guaranteed coverage), then saves raw results
and extracts obvious findings via regex/pattern matching.
"""
from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scan matrix: service name → list of (tool_name, kwargs_template)
# Placeholders {ip} and {port} are resolved at scan time.
# ---------------------------------------------------------------------------

SCAN_MATRIX: dict[str, list[tuple[str, dict[str, Any]]]] = {
    "ssh": [
        ("ssh_audit", {"host": "{ip}"}),
        ("nmap_scan", {
            "target": "{ip}", "ports": "{port}",
            "scripts": "ssh-auth-methods", "skip_discovery": True,
        }),
    ],
    "http": [
        ("curl_headers", {"url": f"http://{{host}}{path}"})
        for path in [
            "/", "/backup/", "/config/", "/admin", "/logs/",
            "/firmware/", "/api/devices", "/api/status", "/update",
            "/.env", "/robots.txt",
        ]
    ],
    "mqtt": [
        ("mqtt_listen", {"broker": "{ip}", "topic": "#", "count": 5, "timeout": 5}),
        ("mqtt_listen", {"broker": "{ip}", "topic": "$SYS/#", "count": 3, "timeout": 5}),
        ("nmap_scan", {"target": "{ip}", "ports": "9001", "skip_discovery": True}),
    ],
    "telnet": [
        ("nmap_scan", {"target": "{ip}", "ports": "23", "skip_discovery": True}),
    ],
    "mysql": [
        ("nmap_scan", {
            "target": "{ip}", "ports": "3306",
            "scripts": "mysql-empty-password", "skip_discovery": True,
        }),
    ],
    "modbus": [
        ("nmap_scan", {
            "target": "{ip}", "ports": "502,102,44818", "skip_discovery": True,
        }),
    ],
}

# Role-based extra scans (run regardless of declared services)
ROLE_EXTRA_SCANS: dict[str, list[tuple[str, dict[str, Any]]]] = {
    "router": [
        ("nmap_scan", {"target": "{ip}", "ports": "23", "skip_discovery": True}),
        ("curl_headers", {"url": "http://{ip}/cgi-bin/luci"}),
    ],
    "gateway": [
        ("nmap_scan", {"target": "{ip}", "ports": "23", "skip_discovery": True}),
    ],
    "iot_gateway": [
        ("nmap_scan", {"target": "{ip}", "ports": "23", "skip_discovery": True}),
    ],
}

# Service name aliases → SCAN_MATRIX key
SERVICE_ALIASES: dict[str, str] = {
    "ssh": "ssh",
    "http": "http", "https": "http", "http-alt": "http",
    "mqtt": "mqtt",
    "telnet": "telnet",
    "mysql": "mysql", "mariadb": "mysql",
    "modbus": "modbus",
    "port-9001": "mqtt",  # MQTT WebSocket
}


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def _resolve_kwargs(template: dict[str, Any], ip: str, port: int) -> dict[str, Any]:
    """Replace {ip}, {port}, {host} placeholders in kwargs template."""
    host = ip if port == 80 else f"{ip}:{port}"
    resolved = {}
    for k, v in template.items():
        if isinstance(v, str):
            resolved[k] = v.replace("{ip}", ip).replace("{port}", str(port)).replace("{host}", host)
        else:
            resolved[k] = v
    return resolved


def scan_device(device: dict, tools_map: dict[str, Any]) -> dict[str, list[dict]]:
    """Run all applicable tools for a device. Returns {service: [{tool, kwargs, result}]}."""
    ip = device.get("ip", "")
    device_id = device.get("id", "unknown")
    results: dict[str, list[dict]] = {}
    seen_calls: set[str] = set()  # avoid duplicate calls

    def _call(tool_name: str, kwargs: dict, svc_key: str):
        call_key = f"{tool_name}|{json.dumps(kwargs, sort_keys=True)}"
        if call_key in seen_calls:
            return
        seen_calls.add(call_key)

        fn = tools_map.get(tool_name)
        if fn is None:
            log.warning("Tool %s not found, skipping", tool_name)
            return

        try:
            result_str = fn(**kwargs)
        except Exception as e:
            log.warning("Tool %s failed for %s: %s", tool_name, device_id, e)
            result_str = json.dumps({"stdout": "", "stderr": str(e), "return_code": -1})

        results.setdefault(svc_key, []).append({
            "tool": tool_name,
            "kwargs": kwargs,
            "result": result_str,
        })

    # Scan each declared service
    for svc in device.get("services", []):
        svc_name = svc.get("name", "").lower()
        port = svc.get("port", 0)
        matrix_key = SERVICE_ALIASES.get(svc_name)
        if not matrix_key or matrix_key not in SCAN_MATRIX:
            continue

        for tool_name, kwargs_tmpl in SCAN_MATRIX[matrix_key]:
            kwargs = _resolve_kwargs(kwargs_tmpl, ip, port)
            _call(tool_name, kwargs, svc_name)

    # Role-based extra scans
    role = device.get("role", "")
    for tool_name, kwargs_tmpl in ROLE_EXTRA_SCANS.get(role, []):
        kwargs = _resolve_kwargs(kwargs_tmpl, ip, 80)
        _call(tool_name, kwargs, f"role_{role}")

    return results


# ---------------------------------------------------------------------------
# Finding extractors — each returns a list of vulnerability dicts
# ---------------------------------------------------------------------------

def _make_finding(device: dict, vuln_type: str, severity: str, service: str,
                  port: int, details: str, evidence: str,
                  status: str = "confirmed", technique: str = "",
                  tools: list[str] | None = None) -> dict:
    """Build a finding dict in the standard schema."""
    return {
        "id": "",  # renumbered during aggregation
        "device_id": device.get("id", ""),
        "device_ip": device.get("ip", ""),
        "type": vuln_type,
        "severity": severity,
        "service": service,
        "port": port,
        "details": details,
        "evidence": evidence,
        "cve_ids": [],
        "exploitation_status": status,
        "suggested_technique": technique,
        "suggested_tools": tools or [],
    }


def _parse_result(entry: dict) -> dict:
    """Parse a scan entry's result JSON string to dict."""
    r = entry.get("result", "{}")
    if isinstance(r, str):
        try:
            return json.loads(r)
        except json.JSONDecodeError:
            return {"stdout": r, "stderr": "", "return_code": -1}
    return r


def _extract_server_version(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Server: nginx or Server: Apache/X.Y in HTTP headers → info_disclosure LOW."""
    findings = []
    for entry in entries:
        if entry["tool"] != "curl_headers":
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        match = re.search(r"(?i)^Server:\s*(.+)$", stdout, re.MULTILINE)
        if match:
            server = match.group(1).strip()
            findings.append(_make_finding(
                device, "info_disclosure", "LOW", svc_name, 80,
                f"Server version disclosure ({server})",
                f"Server: {server}",
            ))
            break  # one finding per device
    return findings


def _extract_missing_headers(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Missing security headers → missing_header LOW."""
    for entry in entries:
        if entry["tool"] != "curl_headers":
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        rc = result.get("return_code", -1)
        if rc != 0 or not stdout:
            continue
        # Only check on root path
        url = entry.get("kwargs", {}).get("url", "")
        if not url.endswith("/") or "/backup" in url or "/config" in url:
            continue
        headers_lower = stdout.lower()
        missing = []
        for h in ["x-frame-options", "strict-transport-security", "content-security-policy"]:
            if h not in headers_lower:
                missing.append(h)
        if missing:
            return [_make_finding(
                device, "missing_header", "LOW", svc_name, 80,
                f"Missing HTTP security headers: {', '.join(missing)}",
                f"Headers checked on {url} — missing: {', '.join(missing)}",
            )]
    return []


def _extract_directory_listing(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """'Index of' in curl body → directory_listing HIGH."""
    findings = []
    paths_found = []
    for entry in entries:
        if entry["tool"] != "curl_headers":
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        if "Index of" in stdout:
            url = entry.get("kwargs", {}).get("url", "")
            paths_found.append(url)
    if paths_found:
        findings.append(_make_finding(
            device, "directory_listing", "HIGH", svc_name, 80,
            f"Directory listing enabled on: {', '.join(paths_found)}",
            f"'Index of' found at: {', '.join(paths_found)}",
        ))
    return findings


def _extract_http_data_exposure(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Sensitive content (passwords, keys) in HTTP responses → data_exposure CRITICAL."""
    sensitive_patterns = re.compile(
        r"(password|passwd|secret|api[_-]?key|token|credential|INSERT INTO|db_pass|smtp_pass)",
        re.IGNORECASE,
    )
    findings = []
    exposed_urls = []
    evidence_parts = []
    for entry in entries:
        if entry["tool"] != "curl_headers":
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        rc = result.get("return_code", 0)
        if rc != 0 or not stdout:
            continue
        url = entry.get("kwargs", {}).get("url", "")
        # Skip root path and 404s
        if "404 Not Found" in stdout:
            continue
        if sensitive_patterns.search(stdout):
            exposed_urls.append(url)
            # Extract a snippet around the match
            for m in sensitive_patterns.finditer(stdout):
                start = max(0, m.start() - 30)
                end = min(len(stdout), m.end() + 50)
                evidence_parts.append(f"{url}: ...{stdout[start:end]}...")
    if exposed_urls:
        findings.append(_make_finding(
            device, "data_exposure", "CRITICAL", svc_name, 80,
            f"Sensitive data exposed via HTTP at: {', '.join(exposed_urls)}",
            "\n".join(evidence_parts[:5]),
            status="confirmed",
            technique="Download files via http_get to extract credentials",
            tools=["http_get"],
        ))
    return findings


def _extract_mqtt_no_auth(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """mqtt_listen return_code 0 or 27 → no_auth HIGH confirmed."""
    for entry in entries:
        if entry["tool"] != "mqtt_listen":
            continue
        kwargs = entry.get("kwargs", {})
        if kwargs.get("topic") != "#":
            continue
        result = _parse_result(entry)
        rc = result.get("return_code", -1)
        if rc in (0, 27):
            stdout = result.get("stdout", "")
            return [_make_finding(
                device, "no_auth", "HIGH", "mqtt", 1883,
                "MQTT broker allows anonymous connections",
                f"mqtt_listen(topic=#) — return_code={rc}, messages received:\n{stdout[:300]}",
            )]
    return []


def _extract_mqtt_data_exposure(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Credentials/keys in MQTT messages → data_exposure MEDIUM confirmed."""
    sensitive_re = re.compile(r"(password|passwd|pass|secret|api[_-]?key|token|credential)", re.IGNORECASE)
    for entry in entries:
        if entry["tool"] != "mqtt_listen":
            continue
        kwargs = entry.get("kwargs", {})
        if kwargs.get("topic") != "#":
            continue
        result = _parse_result(entry)
        rc = result.get("return_code", -1)
        stdout = result.get("stdout", "")
        if rc in (0, 27) and sensitive_re.search(stdout):
            return [_make_finding(
                device, "data_exposure", "MEDIUM", "mqtt", 1883,
                "Credentials exposed in MQTT messages",
                f"mqtt_listen(topic=#) captured:\n{stdout[:400]}",
            )]
    return []


def _extract_mqtt_sys(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """$SYS topics accessible → info_disclosure LOW confirmed."""
    for entry in entries:
        if entry["tool"] != "mqtt_listen":
            continue
        kwargs = entry.get("kwargs", {})
        if "$SYS" not in kwargs.get("topic", ""):
            continue
        result = _parse_result(entry)
        rc = result.get("return_code", -1)
        stdout = result.get("stdout", "")
        if rc in (0, 27) and stdout.strip():
            return [_make_finding(
                device, "info_disclosure", "LOW", "mqtt", 1883,
                "MQTT $SYS topics accessible (broker metadata exposed)",
                f"mqtt_listen(topic=$SYS/#) returned:\n{stdout[:300]}",
            )]
    return []


def _extract_mqtt_websocket(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Port 9001 open on mqtt_broker → no_auth HIGH confirmed."""
    role = device.get("role", "")
    if "mqtt" not in role and "mqtt" not in svc_name:
        return []
    for entry in entries:
        if entry["tool"] != "nmap_scan":
            continue
        kwargs = entry.get("kwargs", {})
        if "9001" not in kwargs.get("ports", ""):
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        if "9001/tcp" in stdout and "open" in stdout:
            return [_make_finding(
                device, "no_auth", "HIGH", "mqtt-ws", 9001,
                "MQTT WebSocket exposed without authentication (port 9001)",
                f"nmap port 9001: {stdout.strip()[:200]}",
            )]
    return []


def _extract_telnet_open(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """23/tcp open → insecure_protocol MEDIUM confirmed."""
    for entry in entries:
        if entry["tool"] != "nmap_scan":
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        if "23/tcp" in stdout and "open" in stdout:
            return [_make_finding(
                device, "insecure_protocol", "MEDIUM", "telnet", 23,
                "Telnet service enabled (cleartext protocol)",
                f"nmap: 23/tcp open",
            )]
    return []


def _extract_ssh_weak_ciphers(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """[fail] lines in ssh_audit → weak_cipher MEDIUM confirmed."""
    for entry in entries:
        if entry["tool"] != "ssh_audit":
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        fail_lines = [l.strip() for l in stdout.splitlines() if "[fail]" in l]
        if fail_lines:
            return [_make_finding(
                device, "weak_cipher", "MEDIUM", "ssh", 22,
                "SSH uses weak cryptographic algorithms",
                "\n".join(fail_lines[:5]),
            )]
    return []


def _extract_ssh_banner(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """SSH banner with OS/version → info_disclosure LOW confirmed."""
    for entry in entries:
        if entry["tool"] != "ssh_audit":
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        # Look for banner line like "(gen) banner: SSH-2.0-OpenSSH_9.2p1 Debian-2"
        match = re.search(r"banner:\s*(SSH-\S+\s+\S+)", stdout)
        if not match:
            # Also check nmap output for SSH version
            match = re.search(r"SSH-2\.0-(\S+)", stdout)
        if match:
            banner = match.group(0)
            return [_make_finding(
                device, "info_disclosure", "LOW", "ssh", 22,
                f"SSH banner discloses software version",
                banner,
            )]
    return []


def _extract_ssh_default_creds(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """role=ssh_server → ALWAYS add default_credentials suspected."""
    role = device.get("role", "")
    if role != "ssh_server":
        return []
    # Find evidence from ssh-auth-methods if available
    evidence = "SSH service detected on ssh_server device — credential testing deferred to Phase 4"
    for entry in entries:
        if entry["tool"] != "nmap_scan":
            continue
        kwargs = entry.get("kwargs", {})
        if "ssh-auth-methods" not in kwargs.get("scripts", ""):
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        if "password" in stdout.lower():
            evidence = f"ssh-auth-methods confirms password authentication:\n{stdout[:200]}"
        elif "ERROR" in stdout:
            evidence = f"ssh-auth-methods failed — credential testing deferred to Phase 4:\n{stdout[:200]}"
    return [_make_finding(
        device, "default_credentials", "HIGH", "ssh", 22,
        "SSH default credentials must be tested (admin:admin, root:root)",
        evidence,
        status="suspected",
        technique="Test SSH login with default IoT credentials: admin:admin, root:root, ubnt:ubnt, pi:raspberry",
        tools=["ssh_login"],
    )]


def _extract_ot_no_auth(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Port 502/102/44818 open → no_auth CRITICAL confirmed."""
    findings = []
    for entry in entries:
        if entry["tool"] != "nmap_scan":
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        for port_str, proto in [("502/tcp", "Modbus"), ("102/tcp", "S7comm"), ("44818/tcp", "EtherNet/IP")]:
            if port_str in stdout and "open" in stdout:
                port = int(port_str.split("/")[0])
                findings.append(_make_finding(
                    device, "no_auth", "CRITICAL", proto.lower(), port,
                    f"{proto} accessible without authentication",
                    f"nmap: {port_str} open",
                ))
    return findings


def _extract_http_no_auth_admin(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """LuCI/admin accessible on router → no_auth CRITICAL confirmed."""
    role = device.get("role", "")
    if role not in ("router", "gateway", "iot_gateway"):
        return []
    for entry in entries:
        if entry["tool"] != "curl_headers":
            continue
        url = entry.get("kwargs", {}).get("url", "")
        if "/cgi-bin/luci" not in url and "/admin" not in url:
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        rc = result.get("return_code", -1)
        if rc == 0 and ("200" in stdout[:50] or "403" in stdout[:50] or "302" in stdout[:50]):
            return [_make_finding(
                device, "no_auth", "CRITICAL", "http", 80,
                "Router admin interface accessible from network",
                f"curl {url} returned HTTP response (admin exposed)",
            )]
    return []


# All extractors in order
FINDING_EXTRACTORS = [
    _extract_server_version,
    _extract_missing_headers,
    _extract_directory_listing,
    _extract_http_data_exposure,
    _extract_mqtt_no_auth,
    _extract_mqtt_data_exposure,
    _extract_mqtt_sys,
    _extract_mqtt_websocket,
    _extract_telnet_open,
    _extract_ssh_weak_ciphers,
    _extract_ssh_banner,
    _extract_ssh_default_creds,
    _extract_ot_no_auth,
    _extract_http_no_auth_admin,
]


def extract_findings(scan_results: dict[str, list[dict]], device: dict) -> list[dict]:
    """Apply all extractors on scan results, return deduplicated findings."""
    findings: list[dict] = []
    all_entries: list[dict] = []
    for svc_entries in scan_results.values():
        all_entries.extend(svc_entries)

    for extractor in FINDING_EXTRACTORS:
        try:
            new = extractor(all_entries, device, "")
            findings.extend(new)
        except Exception as e:
            log.warning("Extractor %s failed for %s: %s", extractor.__name__, device.get("id"), e)

    # Dedup by (type, port)
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for f in findings:
        key = (f["type"], f.get("port"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)

    # Number findings
    for i, f in enumerate(deduped, 1):
        f["id"] = f"VULN-{i:03d}"

    return deduped


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_scanner(
    run_dir: Path,
    devices: list[dict],
    stream_callback=None,
) -> dict[str, dict]:
    """Run Phase 3a: scan all devices, save raw results, extract trivial findings.

    Returns: {device_id: {"scan_results": {...}, "findings": [...]}}
    """
    from src.agent.tools.recon_tools import RECON_TOOLS

    tools_map = {t["name"]: t["function"] for t in RECON_TOOLS}
    scans_dir = run_dir / "03_scans"
    scans_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, dict] = {}

    def _scan_one(device: dict):
        device_id = device["id"]
        device_ip = device.get("ip", "unknown")

        print(f"  [scan] {device_id} ({device_ip})...")
        if stream_callback:
            stream_callback({
                "type": "scan_start", "device_id": device_id,
                "device_ip": device_ip, "phase": 3,
            })

        # Run all tools
        scan_results = scan_device(device, tools_map)

        # Save raw results
        scan_path = scans_dir / f"{device_id}.json"
        scan_path.write_text(
            json.dumps(scan_results, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        # Extract trivial findings
        findings = extract_findings(scan_results, device)

        # Save findings as fallback 03_device_*.json (LLM will overwrite if it succeeds)
        fallback_path = run_dir / f"03_device_{device_id}.json"
        fallback = {
            "device_id": device_id,
            "device_ip": device_ip,
            "vulnerabilities": findings,
            "summary": _compute_summary(findings),
        }
        fallback_path.write_text(
            json.dumps(fallback, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        print(f"  [scan] {device_id}: {len(scan_results)} services scanned, {len(findings)} findings extracted")
        if stream_callback:
            stream_callback({
                "type": "scan_done", "device_id": device_id,
                "device_ip": device_ip, "phase": 3,
                "findings_count": len(findings),
            })

        return device_id, {"scan_results": scan_results, "findings": findings}

    print(f"\n{'=' * 60}")
    print(f"PHASE 3a: DETERMINISTIC SCANNING ({len(devices)} devices)")
    print(f"{'=' * 60}\n")

    with ThreadPoolExecutor(max_workers=min(len(devices), 6)) as pool:
        for device_id, data in pool.map(_scan_one, devices):
            results[device_id] = data

    total_findings = sum(len(d["findings"]) for d in results.values())
    print(f"\n  Scanning complete: {total_findings} total findings extracted")
    return results


def _compute_summary(findings: list[dict]) -> dict:
    """Compute severity summary from findings list."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
    return {"total": len(findings), **counts}
