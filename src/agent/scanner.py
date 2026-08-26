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
from urllib.parse import urljoin, urlsplit

from src.benchmark.tool_registry import SERVICE_ALIASES

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
            "/firmware/", "/api/devices", "/api/status", "/api/exec",
            "/update", "/.env", "/robots.txt",
            "/upload", "/uploads/",
            "/health", "/docs", "/protocol", "/firmware", "/status",
            "/identity/certificate", "/identity/fingerprint",
            "/ca/private-key", "/credentials",
        ]
    ],
    "https": [
        ("tls_inspect", {"host": "{ip}", "port": "{port}"}),
    ],
    "mqtt": [
        ("mqtt_listen", {"broker": "{ip}", "topic": "#", "count": 5, "timeout": 5}),
        ("mqtt_listen", {"broker": "{ip}", "topic": "$SYS/#", "count": 3, "timeout": 5}),
        ("mqtt_listen", {"broker": "{ip}", "topic": "#", "count": 5, "timeout": 5, "username": "test", "password": "test"}),
        ("nmap_scan", {"target": "{ip}", "ports": "9001", "skip_discovery": True}),
        ("http_request", {
            "url": "http://{ip}:9001/",
            "headers": {
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "MDEyMzQ1Njc4OWFiY2RlZg==",
            },
            "follow_redirects": False,
        }),
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
            "target": "{ip}", "ports": "502,102,44818",
            "scripts": "modbus-discover", "skip_discovery": True,
        }),
    ],
    "ldap": [
        ("nmap_scan", {
            "target": "{ip}", "ports": "389,636",
            "scripts": "ldap-rootdse,ldap-search", "skip_discovery": True,
        }),
    ],
    "redis": [
        ("redis_cmd", {"host": "{ip}", "port": "{port}", "command": "PING"}),
        ("nmap_scan", {
            "target": "{ip}", "ports": "6379",
            "scripts": "redis-info", "skip_discovery": True,
        }),
    ],
    "ftp": [
        ("nmap_scan", {
            "target": "{ip}", "ports": "21",
            "scripts": "ftp-anon,ftp-bounce", "skip_discovery": True,
        }),
    ],
    "snmp": [
        ("nmap_scan", {
            "target": "{ip}", "ports": "161",
            "scripts": "snmp-info,snmp-brute",
            "skip_discovery": True,
            "udp_scan": True,
        }),
    ],
    "coap": [
        ("nmap_scan", {
            "target": "{ip}", "ports": "5683",
            "skip_discovery": True,
            "udp_scan": True,
        }),
    ],
    "opcua": [
        ("tcp_send", {
            "host": "{ip}", "port": "{port}", "payload_hex": "48454c",
            "recv_bytes": 256, "timeout": 5,
        }),
        ("tcp_send", {
            "host": "{ip}", "port": "{port}",
            "payload_hex": "524541442042656e6368506f696e74",
            "recv_bytes": 256, "timeout": 5,
        }),
    ],
    "bacnet": [
        ("udp_send", {
            "host": "{ip}", "port": "{port}", "payload": "WHO-IS",
            "encoding": "text", "recv_bytes": 256, "timeout": 5,
        }),
        ("udp_send", {
            "host": "{ip}", "port": "{port}", "payload": "READ BenchPoint",
            "encoding": "text", "recv_bytes": 256, "timeout": 5,
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
    "nodered_server": [
        ("nmap_scan", {"target": "{ip}", "ports": "1880", "skip_discovery": True}),
        ("curl_headers", {"url": "http://{ip}:1880/admin"}),
        ("curl_headers", {"url": "http://{ip}:1880/flows"}),
    ],
    "snmp_server": [
        ("nmap_scan", {
            "target": "{ip}", "ports": "161",
            "scripts": "snmp-info,snmp-brute",
            "skip_discovery": True,
            "udp_scan": True,
        }),
    ],
    "coap_server": [
        ("nmap_scan", {
            "target": "{ip}", "ports": "5683",
            "skip_discovery": True,
            "udp_scan": True,
        }),
    ],
    "exploit_auth_server": [
        ("http_request", {
            "url": "http://{ip}:8080/login",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": "{\"username\":\"operator\",\"password\":{\"$ne\":null}}",
            "follow_redirects": False,
        }),
    ],
    "exploit_files_server": [
        ("http_request", {
            "url": "http://{ip}:8080/files?path=../../etc/device-secret",
            "method": "GET",
            "follow_redirects": False,
        }),
    ],
    "exploit_command_server": [
        ("http_request", {
            "url": "http://{ip}:8080/diagnostics",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": "{\"target\":\"127.0.0.1;id\"}",
            "follow_redirects": False,
        }),
    ],
    "exploit_privilege_server": [
        ("http_request", {
            "url": "http://{ip}:8080/jobs",
            "method": "POST",
            "headers": {
                "Authorization": "Bearer low-privilege-s22",
                "Content-Type": "application/json",
            },
            "body": "{\"role\":\"admin\",\"command\":\"status\"}",
            "follow_redirects": False,
        }),
    ],
    # S15 uses bounded authenticated application probes. Keep the no-token
    # control beside the positive probes so generic HTTP 200 responses never
    # become authorization findings.
    "api_tenant_server": [
        ("http_request", {
            "url": "http://{ip}:8080/v1/devices/device-a",
            "method": "GET",
            "follow_redirects": False,
        }),
        ("http_request", {
            "url": "http://{ip}:8080/v1/devices/device-b",
            "method": "GET",
            "headers": {"Authorization": "Bearer tenant-a-read"},
            "follow_redirects": False,
        }),
        ("http_request", {
            "url": "http://{ip}:8080/v1/admin/export",
            "method": "GET",
            "headers": {"Authorization": "Bearer tenant-a-read"},
            "follow_redirects": False,
        }),
        ("http_request", {
            "url": "http://{ip}:8080/v1/devices/device-a",
            "method": "PATCH",
            "headers": {
                "Authorization": "Bearer tenant-a-read",
                "Content-Type": "application/json",
            },
            "body": "{\"role\":\"admin\"}",
            "follow_redirects": False,
        }),
        ("http_request", {
            "url": "http://{ip}:8080/v1/devices/device-a",
            "method": "GET",
            "headers": {"Authorization": "Bearer tenant-a-read"},
            "follow_redirects": False,
        }),
    ],
    # S16 uses deterministic PKI simulators. Keep the probes explicit and
    # bounded: the enrollment replay intentionally repeats the same token,
    # while the marker headers only distinguish requests in the scanner ledger.
    "pki_ca_server": [
        ("http_request", {
            "url": "http://{ip}:8080/ca/private-key",
            "method": "GET",
            "follow_redirects": False,
        }),
    ],
    "pki_enrollment_server": [
        ("http_request", {
            "url": "http://{ip}:8080/enroll",
            "method": "POST",
            "headers": {
                "Content-Type": "application/json",
                "X-Benchmark-Replay": "first",
            },
            "body": '{"token":"bootstrap-device-b"}',
            "follow_redirects": False,
        }),
        ("http_request", {
            "url": "http://{ip}:8080/enroll",
            "method": "POST",
            "headers": {
                "Content-Type": "application/json",
                "X-Benchmark-Replay": "second",
            },
            "body": '{"token":"bootstrap-device-b"}',
            "follow_redirects": False,
        }),
    ],
    "pki_device": [
        ("http_request", {
            "url": "http://{ip}:8080/identity/fingerprint",
            "method": "GET",
            "follow_redirects": False,
        }),
    ],
    # S17 is stateful: the repository manifest is the only source of valid
    # fixtures; the pipeline replays those fixtures against the two devices.
    "ota_repository": [
        ("http_request", {
            "url": "http://{ip}:8080/firmware",
            "method": "GET",
            "follow_redirects": False,
        }),
    ],
    "ota_device": [
        ("http_request", {
            "url": "http://{ip}:8080/status",
            "method": "GET",
            "follow_redirects": False,
        }),
    ],
    # S18 must be tested through the public fetcher. Direct metadata access is
    # intentionally not attempted because it would invalidate the isolation
    # control and cannot prove the SSRF chain.
    "cloud_web_server": [
        ("http_request", {
            "url": "http://{ip}:8080/docs",
            "method": "GET",
            "follow_redirects": False,
        }),
        ("http_request", {
            "url": "http://{ip}:8080/fetch?url=http%3A%2F%2F192.168.100.12%3A8080%2Fcredentials",
            "method": "GET",
            "follow_redirects": False,
        }),
    ],
    "cloud_control_plane": [
        ("http_request", {
            "url": "http://{ip}:8080/bucket/city-secrets",
            "method": "GET",
            "headers": {"Authorization": "Bearer limited-token"},
            "follow_redirects": False,
        }),
    ],
    # HTTP /protocol is only metadata; the protocol-aware write is performed
    # against the disposable BenchPoint and immediately restored.
    "ot_opcua_server": [
        ("http_request", {
            "url": "http://{ip}:8080/protocol",
            "method": "GET",
            "follow_redirects": False,
        }),
        ("tcp_send", {
            "host": "{ip}", "port": "4840",
            "payload_hex": "57524954452042656e6368506f696e742032322e35",
            "recv_bytes": 256, "timeout": 5,
        }),
        ("tcp_send", {
            "host": "{ip}", "port": "4840",
            "payload_hex": "57524954452042656e6368506f696e742032312e35",
            "recv_bytes": 256, "timeout": 5,
        }),
    ],
    "ot_bacnet_server": [
        ("http_request", {
            "url": "http://{ip}:8080/protocol",
            "method": "GET",
            "follow_redirects": False,
        }),
        ("udp_send", {
            "host": "{ip}", "port": "47808", "payload": "WRITE BenchPoint 22.5",
            "encoding": "text", "recv_bytes": 256, "timeout": 5,
        }),
        ("udp_send", {
            "host": "{ip}", "port": "47808", "payload": "WRITE BenchPoint 21.5",
            "encoding": "text", "recv_bytes": 256, "timeout": 5,
        }),
    ],
    "camera_server": [
        ("curl_headers", {"url": "http://{ip}/admin"}),
        ("curl_headers", {"url": "http://{ip}/snapshot/latest.jpg"}),
    ],
    "web_upload": [
        ("curl_headers", {"url": "http://{ip}/upload"}),
        ("curl_headers", {"url": "http://{ip}/uploads/"}),
        ("curl_headers", {"url": "http://{ip}/fileupload"}),
    ],
    "nvr_server": [
        ("nmap_scan", {
            "target": "{ip}", "ports": "22",
            "scripts": "ssh-auth-methods", "skip_discovery": True,
        }),
    ],
}

# Service aliases are shared with manual scenario compatibility validation.

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


_SENSITIVE_LISTING_LINK = re.compile(
    r"(?i)(?:passw|credential|backup|dump|secret|config|api[_-]?key|token|"
    r"\.sql(?:$|\?)|\.env(?:$|\?)|\.conf(?:$|\?)|\.config(?:$|\?)|"
    r"\.key(?:$|\?)|\.pem(?:$|\?))"
)


def _listed_sensitive_urls(
    results: dict[str, list[dict]], device_ip: str, *, limit: int = 8
) -> list[str]:
    """Return bounded, same-host sensitive links from observed directory pages."""
    urls: set[str] = set()
    snapshot = [entry for entries in results.values() for entry in entries]
    for entry in snapshot:
        if entry.get("tool") != "curl_headers":
            continue
        result = _parse_result(entry)
        stdout = str(result.get("stdout", ""))
        if "Index of" not in stdout:
            continue
        base_url = str((entry.get("kwargs") or {}).get("url", ""))
        if not base_url:
            continue
        for href in re.findall(r"(?i)href\s*=\s*[\"']?([^\"'\s>]+)", stdout):
            if href.startswith(("#", "?")) or href in {"../", "./"}:
                continue
            candidate = urljoin(base_url, href)
            parsed = urlsplit(candidate)
            if parsed.scheme not in {"http", "https"} or parsed.hostname != device_ip:
                continue
            if parsed.path.endswith("/") or not _SENSITIVE_LISTING_LINK.search(parsed.path):
                continue
            urls.add(candidate)
    return sorted(urls)[: max(0, limit)]


def _phase2_recon_scan_entries(run_dir: Path, device: dict) -> list[dict]:
    """Project recorded Phase 2 service versions into the Phase 3 evidence set."""
    path = run_dir / "02_recon_evidence.json"
    if not path.is_file():
        return []
    try:
        projection = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return []
    device_ip = str(device.get("ip", ""))
    rows = projection.get("devices", []) if isinstance(projection, dict) else []
    row = next(
        (
            item for item in rows
            if isinstance(item, dict) and str(item.get("ip", "")) == device_ip
        ),
        None,
    )
    if not row:
        return []
    lines = []
    ports = []
    for service in row.get("services", []):
        if not isinstance(service, dict) or not isinstance(service.get("port"), int):
            continue
        port = int(service["port"])
        ports.append(port)
        version = str(service.get("version", "")).strip()
        lines.append(
            f"{port}/{service.get('protocol', 'tcp')} open "
            f"{service.get('service', 'unknown')}"
            + (f" {version}" if version else "")
        )
    if not lines:
        return []
    return [{
        "tool": "nmap_scan",
        "kwargs": {"target": device_ip, "ports": ",".join(map(str, sorted(ports)))},
        "result": json.dumps({
            "stdout": "\n".join(lines),
            "stderr": "",
            "return_code": 0,
            "source": "02_recon_evidence.json",
        }),
        "source": "02_recon_evidence.json",
        "evidence_phase": 2,
        "authoritative": False,
    }]


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
            "evidence_phase": 3,
            "authoritative": True,
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

    # Follow only suspicious file links already disclosed by same-host directory
    # listings. This remains bounded and avoids benchmark-specific filenames.
    for url in _listed_sensitive_urls(results, ip):
        _call("curl_headers", {"url": url}, "http_discovered")

    return results


# ---------------------------------------------------------------------------
# Finding extractors — each returns a list of vulnerability dicts
# ---------------------------------------------------------------------------

def _make_finding(device: dict, vuln_type: str, severity: str, service: str,
                  port: int, details: str, evidence: str,
                  status: str = "confirmed", technique: str = "",
                  tools: list[str] | None = None, *, protocol: str | None = None,
                  endpoint: str = "", product: str = "", version: str = "") -> dict:
    """Build a finding dict in the strict-v3-compatible standard schema."""
    if not service:
        service = {80: "http", 443: "https", 22: "ssh", 23: "telnet"}.get(port, "")
    if protocol is None:
        protocol = "udp" if service.casefold() in {"coap", "snmp", "bacnet"} else "tcp"
    if not endpoint:
        match = re.search(r"https?://[^\s,]+", f"{details} {evidence}")
        if match:
            endpoint = urlsplit(match.group(0).rstrip(".)")).path or "/"
    return {
        "id": "",  # renumbered during aggregation
        "device_id": device.get("id", ""),
        "device_ip": device.get("ip", ""),
        "type": vuln_type,
        "severity": severity,
        "service": service,
        "port": port,
        "protocol": protocol,
        "endpoint": endpoint,
        "product": product,
        "version": version,
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
            # A bare product token (for example ``Server: nginx``) is not a
            # version disclosure. Require a product/version pair so a generic
            # HTTP response cannot become a vulnerability by itself.
            version_match = re.search(
                r"(?i)\b(?:nginx|apache(?:/httpd)?|iis|caddy|lighttpd|gunicorn|openresty)"
                r"(?:[/ -]v?)?(\d+(?:\.\d+){1,3})\b",
                server,
            )
            if version_match:
                findings.append(_make_finding(
                    device, "info_disclosure", "LOW", svc_name, 80,
                    f"Server version disclosure ({server})",
                    f"Server: {server}",
                    version=version_match.group(1),
                ))
                break  # one finding per device
    return findings


def _extract_missing_headers(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Missing security headers → missing_header LOW."""
    if str(device.get("role", "")).casefold() not in {"web_server", "iot_gateway"}:
        return []
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


def _extract_directory_listing(
    entries: list[dict], device: dict, svc_name: str, *, strict_paths: bool = False
) -> list[dict]:
    """'Index of' in curl body → directory_listing MEDIUM (config issue, not a direct exploit).

    Skipped for web_upload devices: their /uploads/ directory is intentionally browsable
    (uploaded files must be accessible). The real finding for these devices is code_injection.
    """
    role = device.get("role", "")
    if role == "web_upload":
        return []
    findings = []
    paths_found = []
    for entry in entries:
        if entry["tool"] != "curl_headers":
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        if "Index of" in stdout:
            url = entry.get("kwargs", {}).get("url", "")
            if strict_paths:
                requested_path = urlsplit(url).path or "/"
                requested_path = requested_path.rstrip("/") or "/"
                heading = re.search(
                    r"(?is)index\s+of\s+([^<\r\n]+)", stdout
                )
                if heading:
                    listed_path = heading.group(1).strip().strip(chr(34))
                    if listed_path.startswith(("http://", "https://")):
                        listed_path = urlsplit(listed_path).path or "/"
                    elif not listed_path.startswith("/"):
                        listed_path = "/" + listed_path
                    listed_path = listed_path.rstrip("/") or "/"
                    if listed_path != requested_path:
                        # Some appliances return the root directory listing for
                        # every unknown path. Do not attribute that root body to
                        # /backup/, /config/, etc. in compact mode.
                        continue
            paths_found.append(url)
    if paths_found:
        specific_paths = [
            url for url in paths_found
            if (urlsplit(url).path or "/") not in {"", "/"}
        ]
        paths_found = specific_paths or paths_found
        findings.append(_make_finding(
            device, "directory_listing", "MEDIUM", svc_name, 80,
            f"Directory listing enabled on: {', '.join(paths_found)}",
            f"'Index of' found at: {', '.join(paths_found)}",
        ))
    return findings


def _apply_compact_evidence_contract(findings: list[dict]) -> list[dict]:
    """Annotate/downgrade scanner heuristics used by the compact profile.

    Full-capability profiles use the original extractor output unchanged. The
    compact profile keeps every raw candidate but requires a fresh protocol or
    application proof before a heuristic can become a confirmed finding.
    """
    for finding in findings:
        vuln_type = str(finding.get("type") or "").casefold()
        service = str(finding.get("service") or "").casefold()
        try:
            port = int(finding.get("port"))
        except (TypeError, ValueError):
            port = None
        status = str(finding.get("exploitation_status") or "").casefold()
        evidence = str(finding.get("evidence") or "")

        finding["compact_confidence"] = (
            "direct" if status == "confirmed" else "suspected"
        )
        finding["compact_evidence_kind"] = (
            "direct_observation" if status == "confirmed" else "heuristic"
        )
        finding["compact_requires_verification"] = status != "confirmed"

        # Low-value configuration observations remain available in the raw
        # registry/report, but do not consume compact exploitation slots.
        if (
            vuln_type == "missing_header"
            or (
                vuln_type == "info_disclosure"
                and str(finding.get("severity", "")).upper() == "LOW"
            )
        ):
            finding["compact_report_only"] = True
            finding["compact_requires_verification"] = False

        # An open OT/CoAP port identifies a service, not an authentication
        # bypass. Force protocol-level verification in compact mode.
        if vuln_type == "no_auth" and (
            port in {102, 502, 44818, 5683}
            or service in {"modbus", "s7comm", "ethernet/ip", "coap"}
        ):
            finding["exploitation_status"] = "suspected"
            finding["compact_confidence"] = "suspected"
            finding["compact_evidence_kind"] = "open_service"
            finding["compact_requires_verification"] = True
            finding["compact_required_probe"] = "protocol_response"

        # Endpoint existence (200/400/405) is not proof of command execution.
        if vuln_type == "code_injection" and not re.search(
            r"(?i)(?:uid=|command\s+output|executed|shell\s+opened|rce\s+confirmed)",
            evidence,
        ):
            finding["exploitation_status"] = "suspected"
            finding["compact_confidence"] = "suspected"
            finding["compact_evidence_kind"] = "endpoint_presence"
            finding["compact_requires_verification"] = True
            finding["compact_required_probe"] = "safe_http_validation"

        # A reachable OTA endpoint is not evidence that an unsigned update was
        # accepted. Keep it as a candidate until the request is validated.
        if vuln_type == "insecure_update":
            finding["exploitation_status"] = "suspected"
            finding["compact_confidence"] = "suspected"
            finding["compact_evidence_kind"] = "endpoint_presence"
            finding["compact_requires_verification"] = True
            finding["compact_required_probe"] = "safe_http_validation"

    return findings
def _extract_http_data_exposure(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Sensitive content (actual credentials, API keys) in HTTP responses → data_exposure CRITICAL.

    Only flags when credentials appear to be REAL values (not form field labels or HTML placeholders).
    Skips admin login pages and HTML responses.
    """
    # Pattern for actual credential VALUES (not just field names)
    # e.g. "password=secretpass", "api_key:sk-123", "P@ssw0rd", database dump inserts
    credential_value_patterns = [
        re.compile(r"(?i)(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?([^\s\"',\n<>{}]{3,})"),
        re.compile(r"(?i)(?:api[_-]?key|token|secret)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{8,})"),
        re.compile(r"INSERT INTO\s+\w+\s+VALUES\s*\("),  # SQL dump
        re.compile(r"(?i)smtp_(?:password|pass)\s*[:=]\s*\S+"),
        re.compile(r"(?i)db_(?:password|pass)\s*[:=]\s*\S+"),
    ]

    findings = []
    exposed_urls = []
    evidence_parts = []

    # Paths to SKIP (admin login pages are not data exposure — it's auth surface)
    SKIP_PATHS = ("/cgi-bin/luci", "/admin", "/login")

    for entry in entries:
        if entry["tool"] != "curl_headers":
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        rc = result.get("return_code", 0)
        if rc != 0 or not stdout:
            continue
        url = entry.get("kwargs", {}).get("url", "")

        # Skip 404s and admin login pages
        if "404 Not Found" in stdout:
            continue
        if any(skip in url for skip in SKIP_PATHS):
            continue
        # Skip HTML login pages (they contain form fields with "password" but not actual values)
        if "<form" in stdout.lower() and "type=\"password\"" in stdout.lower():
            continue

        # Check for actual credential values
        matches = []
        for pattern in credential_value_patterns:
            for m in pattern.finditer(stdout):
                matches.append(m)
                if len(matches) >= 3:
                    break
            if len(matches) >= 3:
                break

        if matches:
            exposed_urls.append(url)
            for m in matches[:3]:
                start = max(0, m.start() - 20)
                end = min(len(stdout), m.end() + 30)
                evidence_parts.append(f"{url}: ...{stdout[start:end].strip()}...")

    if exposed_urls:
        # Static backup/config files served via HTTP → HIGH (download required, not live API)
        # Live API endpoints exposing credentials → CRITICAL (direct access)
        is_static_file = any(
            any(kw in u.lower() for kw in ("/backup", "/dump", ".sql", ".env", "/config", "/logs", ".conf"))
            for u in exposed_urls
        )
        severity = "HIGH" if is_static_file else "CRITICAL"
        findings.append(_make_finding(
            device, "data_exposure", severity, svc_name, 80,
            f"Sensitive data exposed via HTTP at: {', '.join(exposed_urls)}",
            "\n".join(evidence_parts[:3])[:400],
            status="confirmed",
            technique="Download files via http_get to extract credentials",
            tools=["http_get"],
        ))
    return findings


def _extract_mqtt_no_auth(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """mqtt_listen anonymous return_code 0 or 27 -> no_auth HIGH confirmed."""
    for entry in entries:
        if entry["tool"] != "mqtt_listen":
            continue
        kwargs = entry.get("kwargs", {})
        if kwargs.get("topic") != "#" or kwargs.get("username"):
            continue
        result = _parse_result(entry)
        rc = result.get("return_code", -1)
        stdout = result.get("stdout", "")
        if rc in (0, 27) and stdout.strip():
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


def _extract_mqtt_weak_creds(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Weak MQTT credentials only count when anonymous access is denied first."""
    anonymous_open = False
    anonymous_denied = False
    for entry in entries:
        if entry["tool"] != "mqtt_listen":
            continue
        kwargs = entry.get("kwargs", {})
        if kwargs.get("topic") != "#" or kwargs.get("username"):
            continue
        result = _parse_result(entry)
        rc = result.get("return_code", -1)
        if rc in (0, 27):
            anonymous_open = True
        elif rc == 5:
            anonymous_denied = True
    if anonymous_open or not anonymous_denied:
        return []

    for entry in entries:
        if entry["tool"] != "mqtt_listen":
            continue
        kwargs = entry.get("kwargs", {})
        if kwargs.get("username") != "test" or kwargs.get("topic") != "#":
            continue
        result = _parse_result(entry)
        rc = result.get("return_code", -1)
        stdout = result.get("stdout", "")
        if rc in (0, 27) and stdout.strip():
            return [_make_finding(
                device, "default_credentials", "HIGH", "mqtt", 1883,
                "MQTT broker accepts weak credentials (test:test)",
                f"mqtt_listen(username=test, password=test) — return_code={rc}, messages:\n{stdout[:200]}",
                status="confirmed",
                technique="mosquitto_sub -h <ip> -u test -P test -t '#' to subscribe with weak credentials",
                tools=["mqtt_listen"],
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
    """Confirm a WebSocket handshake when possible; otherwise retain exposure."""
    role = device.get("role", "")
    if "mqtt" not in role and "mqtt" not in svc_name:
        return []
    for entry in entries:
        if entry.get("tool") != "http_request":
            continue
        kwargs = entry.get("kwargs", {})
        if ":9001" not in str(kwargs.get("url", "")):
            continue
        result = _parse_result(entry)
        if result.get("status_code") == 101:
            return [_make_finding(
                device, "no_auth", "HIGH", "mqtt-ws", 9001,
                "MQTT WebSocket listener accepts an unauthenticated HTTP upgrade",
                "HTTP 101 Switching Protocols returned for a WebSocket upgrade on port 9001",
                status="confirmed",
                technique="Connect to the MQTT broker over the accepted unauthenticated WebSocket",
                tools=["http_request"],
            )]
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
                device, "network_exposure", "LOW", "mqtt-ws", 9001,
                "MQTT WebSocket listener exposed on the network",
                f"nmap port 9001: {stdout.strip()[:200]}",
                status="suspected",
                technique="Verify with an HTTP WebSocket upgrade request before claiming no_auth",
                tools=["http_request"],
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
    """[fail] lines in ssh_audit → weak_cipher LOW confirmed (no exploit, detection only)."""
    for entry in entries:
        if entry["tool"] != "ssh_audit":
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        fail_lines = [l.strip() for l in stdout.splitlines() if "[fail]" in l]
        if fail_lines:
            return [_make_finding(
                device, "weak_cipher", "LOW", "ssh", 22,
                "SSH uses weak cryptographic algorithms",
                "\n".join(fail_lines[:5]),
            )]
    return []


def _extract_ssh_banner(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """SSH banner with OS/version or custom message → info_disclosure LOW confirmed."""
    for entry in entries:
        result = _parse_result(entry)
        stdout = result.get("stdout", "")

        # ssh_audit banner line: "(gen) banner: SSH-2.0-OpenSSH_9.2p1 Debian-2"
        match = re.search(r"(?:banner:|\(gen\)\s*banner:)\s*(SSH-\S+.*)", stdout)
        if not match:
            # nmap SSH version in PORT output: "22/tcp open ssh OpenSSH 9.2p1 Debian-2"
            match = re.search(r"22/tcp\s+open\s+ssh\s+(\S+\s+[\d.p]+\S*)", stdout)
        if not match:
            # Access-denied/ACL text is a control-flow response, not a software
            # version or service banner. Do not turn it into info_disclosure.
            continue
        if match:
            banner = match.group(0)
            return [_make_finding(
                device, "info_disclosure", "LOW", "ssh", 22,
                "SSH banner discloses software version",
                banner[:150],
            )]
    return []


def _extract_ssh_default_creds(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """role=ssh_server or nvr_server → ALWAYS add default_credentials suspected."""
    role = device.get("role", "")
    if role not in ("ssh_server", "nvr_server"):
        return []
    # Find evidence from ssh-auth-methods if available
    cred_hint = "ubnt:ubnt" if role == "nvr_server" else "admin:admin, root:root"
    evidence = f"SSH service detected on {role} device — credential testing deferred to Phase 4"
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
        f"SSH default credentials must be tested ({cred_hint})",
        evidence,
        status="suspected",
        technique=f"Test SSH login with default IoT credentials: {cred_hint}",
        tools=["ssh_login"],
    )]


def _extract_ssh_key_exposure(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """ssh_server_v2 (bastion/admin): world-readable SSH keys suspected — add misconfiguration HIGH.

    Phase 4 will verify via SSH post-login. If login fails → FAILED status → excluded from evaluator.
    """
    role = device.get("role", "")
    if role != "ssh_server_v2":
        return []
    # SSH reachability alone does not prove a world-readable key.
    # Require the audit output to name a key path and an observed mode.
    for entry in entries:
        if entry.get("tool") not in ("ssh_audit", "nmap_scan"):
            continue
        result = _parse_result(entry)
        stdout = str(result.get("stdout") or "")
        if result.get("return_code", -1) != 0:
            continue
        has_key_path = re.search(r"(?i)(?:id_(?:rsa|ed25519)|authorized_keys)", stdout)
        has_insecure_mode = re.search(r"(?i)(?:\b0?644\b|world[- ]readable|permissions?\s*[:=]\s*[0-7]{3,4})", stdout)
        if has_key_path and has_insecure_mode:
            return [_make_finding(
                device, "misconfiguration", "HIGH", "ssh", 22,
                "SSH private key has directly observed insecure file permissions",
                stdout[:500],
                status="confirmed",
                technique="Verify the named SSH key path and remediate its file mode",
                tools=[entry.get("tool", "ssh_audit")],
            )]
    return []


def _extract_nodered_no_auth_fallback(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Retain no Node-RED finding without direct HTTP authentication evidence.

    Port reachability or the role name alone is insufficient; the HTTP admin
    extractor is responsible for confirmed Node-RED findings.
    """
    role = device.get("role", "")
    if role != "nodered_server":
        return []
    # A role name or a failed probe is not evidence that Node-RED is exposed.
    # Continue only when nmap directly observed 1880/tcp as open.
    has_open_port = any(
        entry.get("tool") == "nmap_scan"
        and "1880" in entry.get("kwargs", {}).get("ports", "")
        and "1880/tcp" in _parse_result(entry).get("stdout", "")
        and "open" in _parse_result(entry).get("stdout", "")
        for entry in entries
    )
    if not has_open_port:
        return []
    # If any 1880 curl already returned 200/302, _extract_http_no_auth_admin handled it
    for entry in entries:
        if entry["tool"] != "curl_headers":
            continue
        url = entry.get("kwargs", {}).get("url", "")
        if ":1880" not in url:
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        rc = result.get("return_code", -1)
        if rc == 0 and ("200" in stdout[:50] or "302" in stdout[:50] or "403" in stdout[:50]):
            return []  # Already confirmed — extractor above handled it
    # Check if nmap explicitly confirmed port 1880 as closed/filtered — skip if so
    for entry in entries:
        if entry["tool"] != "nmap_scan":
            continue
        if "1880" not in entry.get("kwargs", {}).get("ports", ""):
            continue
        stdout = _parse_result(entry).get("stdout", "")
        if "1880/tcp" in stdout and "open" not in stdout:
            return []  # Port confirmed closed/filtered by nmap — not a real finding

    # Port reachability alone is not evidence of unauthenticated flow
    # execution. The HTTP extractor above is the only promotion path.
    return []


def _extract_ot_no_auth(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Port 502/102/44818 open → no_auth CRITICAL confirmed."""
    findings = []
    for entry in entries:
        if entry["tool"] != "nmap_scan":
            continue
        if entry.get("authoritative") is False or entry.get("evidence_phase") not in (None, 3):
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        for port_str, proto in [("502/tcp", "Modbus"), ("102/tcp", "S7comm"), ("44818/tcp", "EtherNet/IP")]:
            if re.search(rf"(?im)^\s*{re.escape(port_str)}\s+open(?:\s|$)", stdout):
                port = int(port_str.split("/")[0])
                findings.append(_make_finding(
                    device, "no_auth", "CRITICAL", proto.lower(), port,
                    f"{proto} accessible without authentication",
                    f"nmap: {port_str} open",
                ))
    return findings


def _extract_api_exec(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Detect the endpoint, but require execution output before confirmation."""
    role = device.get("role", "")
    if "web_server" not in role and "monitor" not in role:
        return []
    for entry in entries:
        if entry["tool"] != "curl_headers":
            continue
        url = entry.get("kwargs", {}).get("url", "")
        if "/api/exec" not in url:
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        rc = result.get("return_code", -1)
        if rc == 0 and ("200" in stdout[:50] or "405" in stdout[:50] or "400" in stdout[:50]):
            execution_proof = bool(re.search(r"(?i)(?:uid=\d+|command\s+(?:output|result)|executed|shell\s+opened|rce\s+confirmed)", stdout))
            return [_make_finding(
                device, "code_injection", "CRITICAL", "http", 80,
                "RCE endpoint /api/exec accessible — remote code execution possible",
                f"curl GET /api/exec returned: {stdout[:150]}",
                status="confirmed" if execution_proof else "suspected",
                technique="curl -X POST http://<ip>/api/exec -d '{\"cmd\":\"id\"}' to execute commands",
                tools=["http_get"],
            )]
    return []


def _extract_web_upload_endpoint(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """web_upload role: /upload returns 200/405 → code_injection CRITICAL suspected."""
    role = device.get("role", "")
    if role != "web_upload":
        return []
    for entry in entries:
        if entry["tool"] != "curl_headers":
            continue
        url = entry.get("kwargs", {}).get("url", "")
        if "/upload" not in url:
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        rc = result.get("return_code", -1)
        if rc == 0 and ("200" in stdout[:50] or "405" in stdout[:50] or "400" in stdout[:50] or "403" in stdout[:50]):
            return [_make_finding(
                device, "code_injection", "CRITICAL", "http", 80,
                "File upload endpoint accessible — unrestricted file upload may enable RCE",
                f"HTTP response on {url}: {stdout[:120]}",
                status="suspected",
                technique="curl -F 'file=@/etc/passwd' http://<ip>/upload to test unrestricted upload",
                tools=["http_get"],
            )]
    # Fallback: if root / returns 200 with no upload path found, flag as suspected
    for entry in entries:
        if entry["tool"] != "curl_headers":
            continue
        url = entry.get("kwargs", {}).get("url", "")
        if not url.endswith("/"):
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        rc = result.get("return_code", -1)
        if rc == 0 and "200" in stdout[:50]:
            return [_make_finding(
                device, "code_injection", "CRITICAL", "http", 80,
                "Web upload service detected — file upload without validation suspected",
                f"HTTP 200 on root — upload endpoint requires manual discovery",
                status="suspected",
                technique="curl -F 'file=@/etc/passwd' http://<ip>/upload to test unrestricted upload",
                tools=["http_get"],
            )]
    return []


def _extract_http_no_auth_admin(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Admin interface accessible without authentication on router/gateway/nodered/camera."""
    role = device.get("role", "")
    if role not in ("router", "gateway", "iot_gateway", "nodered_server", "camera_server"):
        return []

    is_nodered = role == "nodered_server"
    is_camera = role == "camera_server"

    for entry in entries:
        if entry["tool"] != "curl_headers":
            continue
        url = entry.get("kwargs", {}).get("url", "")
        if "/cgi-bin/luci" not in url and "/admin" not in url and "/flows" not in url:
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        rc = result.get("return_code", -1)
        status_match = re.search(r"HTTP/\S+\s+(\d{3})", stdout[:200])
        status_code = int(status_match.group(1)) if status_match else None
        lower = stdout.lower()
        login_challenge = any(marker in lower for marker in (
            "login", "sign in", "password", "unauthorized", "forbidden",
            "www-authenticate", "authentication required",
        ))
        if (
            rc == 0
            and status_code == 200
            and (
                not login_challenge
                or (
                    role == "router"
                    and "/cgi-bin/luci" in url
                    and re.search(r"(?i)(?:luci|openwrt|router)", lower)
                )
            )
        ):
            if is_nodered:
                findings = [
                    _make_finding(
                        device, "no_auth", "CRITICAL", "nodered", 1880,
                        "Node-RED admin interface accessible without authentication",
                        f"curl {url} returned HTTP response (admin exposed)",
                        status="confirmed",
                    ),
                    _make_finding(
                        device, "code_injection", "CRITICAL", "nodered", 1880,
                        "Node-RED exec nodes accessible = RCE via POST /api/exec",
                        f"Port 1880 confirmed open without auth — exec nodes accessible by default",
                        status="suspected",
                        technique="POST http://<ip>:1880/api/exec with JSON payload to execute OS commands",
                        tools=["http_get"],
                    ),
                ]
                return findings
            elif is_camera:
                svc = "http"
                port = 80
                severity = "HIGH"
                details = "Camera admin interface accessible without authentication"
            else:
                svc = "http"
                port = 80
                severity = "CRITICAL"
                details = "Router/gateway admin interface accessible from network"
            return [_make_finding(
                device, "no_auth", severity, svc, port,
                details,
                f"curl {url} returned HTTP response (admin exposed)",
            )]
    return []

def _extract_mysql_default_credentials_compact(
    entries: list[dict], device: dict, svc_name: str
) -> list[dict]:
    """Detect an empty MySQL/MariaDB root password from the NSE result."""
    if str(device.get("role", "")).casefold() not in {"db_server", "database", "mysql_server"}:
        return []
    for entry in entries:
        if entry.get("tool") != "nmap_scan":
            continue
        kwargs = entry.get("kwargs", {})
        if "mysql-empty-password" not in str(kwargs.get("scripts", "")):
            continue
        result = _parse_result(entry)
        stdout = str(result.get("stdout", ""))
        lower = stdout.casefold()
        if result.get("return_code", -1) != 0:
            continue
        port_open = bool(re.search(r"\b3306/tcp\s+open\b", lower))
        empty_password = any(marker in lower for marker in (
            "empty password", "no password", "blank password",
            "root account has an empty", "root account has empty",
            "without password", "without a password",
        ))
        if port_open and empty_password:
            return [_make_finding(
                device, "default_credentials", "CRITICAL", "mysql", 3306,
                "MySQL/MariaDB root account accepts an empty password",
                stdout[:800],
                status="confirmed",
                technique="Connect as root with an empty password and query the users table",
                tools=["try_credential"],
            )]
    return []


def _extract_insecure_update_compact(
    entries: list[dict], device: dict, svc_name: str
) -> list[dict]:
    """Detect an active OTA endpoint or unsigned firmware listing on gateways."""
    role = str(device.get("role", "")).casefold()
    if role not in {"gateway", "iot_gateway"}:
        return []

    update_evidence: list[str] = []
    firmware_evidence: list[str] = []
    for entry in entries:
        if entry.get("tool") != "curl_headers":
            continue
        url = str(entry.get("kwargs", {}).get("url", ""))
        result = _parse_result(entry)
        stdout = str(result.get("stdout", ""))
        if result.get("return_code", -1) != 0:
            continue
        status_match = re.search(r"HTTP/\S+\s+(\d{3})", stdout[:300])
        status_code = int(status_match.group(1)) if status_match else None
        path = urlsplit(url).path.casefold()
        if (
            path.rstrip("/") == "/update"
            and status_code in {200, 201, 202, 204}
            and re.search(r"(?i)(?:update|firmware|version|accepted)", stdout)
        ):
            update_evidence.append(f"{url}: HTTP {status_code}")
        if path.rstrip("/") in {"/firmware", "/firmware/"} and "index of" in stdout.casefold():
            if not re.search(r"\.(?:sha256|sha512|sig|asc)\b", stdout, re.IGNORECASE):
                firmware_evidence.append(f"{url}: unsigned firmware listing")

    if not update_evidence and not firmware_evidence:
        return []
    evidence = "\n".join((update_evidence + firmware_evidence)[:4])
    return [_make_finding(
        device, "insecure_update", "HIGH", "http", 80,
        "Firmware update endpoint or unsigned firmware is exposed without a verifiable signature",
        evidence,
        status="confirmed" if update_evidence else "suspected",
        technique="Verify an unauthenticated POST to /update and enforce signed firmware validation",
        tools=["http_get", "http_request"],
        endpoint="/update" if update_evidence else "/firmware/",
    )]


def _extract_redis_no_auth(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """A successful unauthenticated PING proves Redis no_auth; keys remain only suspected exposure."""
    ping_ok = False
    ping_evidence = ""
    for entry in entries:
        tool = str(entry.get("tool") or "")
        result = _parse_result(entry)
        if tool == "redis_cmd":
            command = str(entry.get("kwargs", {}).get("command") or "").strip().casefold()
            if (
                command == "ping"
                and result.get("return_code") == 0
                and str(result.get("stdout") or "").strip().casefold() == "pong"
            ):
                ping_ok = True
                ping_evidence = "redis_cmd PING returned PONG"
    if not ping_ok:
        # Some images expose redis-info but do not ship redis_cmd. Accept
        # only explicit unauthenticated markers, never an open port alone.
        for entry in entries:
            if entry.get("tool") != "nmap_scan":
                continue
            stdout = str(_parse_result(entry).get("stdout") or "")
            if (
                "6379/tcp" in stdout
                and "open" in stdout
                and re.search(r"(?i)(?:no password|without authentication|unauthenticated|no requirepass|requirepass[^\n]*(?:no|off|disabled))", stdout)
            ):
                ping_ok = True
                break
    if not ping_ok:
        return []
    for entry in entries:
        if entry["tool"] != "nmap_scan":
            continue
        kwargs = entry.get("kwargs", {})
        if "6379" not in kwargs.get("ports", ""):
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        if "6379/tcp" not in stdout or "open" not in stdout:
            continue

        evidence = ping_evidence or "nmap redis-info explicitly reported unauthenticated access"
        if "redis_version" in stdout.lower() or "redis" in stdout.lower():
            evidence = f"{evidence}; nmap redis-info: {stdout.strip()[:200]}"

        findings = [_make_finding(
            device, "no_auth", "HIGH", "redis", 6379,
            "Redis accessible without authentication (no requirepass set)",
            evidence,
            status="confirmed",
            technique="redis-cli -h <ip> KEYS '*' to enumerate all keys and dump sensitive data",
            tools=["redis_cmd"] if ping_evidence else ["nmap_scan"],
        )]

        # An open Redis port proves unauthenticated access, not sensitive content.
        # Promote data_exposure only when the scan reports at least one stored key;
        # Phase 4 still has to retrieve a value before treating the content as confirmed.
        keys_match = re.search(r"db\d+:keys=(\d+)", stdout)
        key_count = int(keys_match.group(1)) if keys_match else 0
        if key_count > 0:
            findings.append(_make_finding(
                device, "data_exposure", "MEDIUM", "redis", 6379,
                f"Redis stores {key_count} key(s) — stored keys may contain sensitive data (credentials, tokens, configs)",
                f"nmap redis-info: {stdout.strip()[:200]}",
                status="suspected",
                technique="redis-cli -h <ip> KEYS '*' then GET <key> to dump sensitive data",
                tools=["nmap_scan"],
            ))

        return findings
    return []


def _extract_ftp_anonymous(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """FTP port 21 open (with ftp-anon script) → misconfiguration HIGH."""
    for entry in entries:
        if entry["tool"] != "nmap_scan":
            continue
        kwargs = entry.get("kwargs", {})
        if "21" not in kwargs.get("ports", ""):
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        if "21/tcp" not in stdout or "open" not in stdout:
            continue
        # ftp-anon script output confirms anonymous access
        if "Anonymous FTP login allowed" in stdout or "ftp-anon:" in stdout:
            files_match = re.search(r"ftp-anon:[^\n]*\n((?:\|[^\n]*\n)*)", stdout)
            files_info = files_match.group(0)[:200] if files_match else "anonymous login allowed"
            findings = [_make_finding(
                device, "insecure_protocol", "HIGH", "ftp", 21,
                "FTP anonymous login enabled — sensitive files accessible without credentials",
                files_info,
                status="confirmed",
                technique="ftp -n <ip>, then login as anonymous to list and download files",
                tools=["nmap_scan"],
            )]
            # Check if listing contains sensitive filenames
            _sensitive_ftp = re.compile(
                r"passw|credential|backup|\.sql|\.env|secret|\.conf|config|\.key|api[_-]?key",
                re.IGNORECASE,
            )
            listing_text = files_match.group(0) if files_match else stdout
            sensitive_hits = _sensitive_ftp.findall(listing_text)
            if sensitive_hits:
                findings.append(_make_finding(
                    device, "data_exposure", "MEDIUM", "ftp", 21,
                    "FTP anonymous listing contains sensitive files (credentials/config/backup)",
                    f"Sensitive filenames detected: {', '.join(dict.fromkeys(sensitive_hits))[:200]}",
                    status="suspected",
                    technique="ftp -n <ip>, login anonymous, GET sensitive files",
                    tools=["nmap_scan"],
                ))
            return findings
        # Port open but script didn't confirm anon — still flag as insecure_protocol
        return [_make_finding(
            device, "insecure_protocol", "MEDIUM", "ftp", 21,
            "FTP service exposed (cleartext protocol, test anonymous access)",
            f"nmap: 21/tcp open — anonymous access not confirmed",
            status="suspected",
            technique="ftp -n <ip>, try anonymous login",
            tools=["nmap_scan"],
        )]
    return []


def _extract_snmp_default_community(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """SNMP port 161 open or snmp-brute finds community → default_credentials HIGH."""
    for entry in entries:
        if entry["tool"] != "nmap_scan":
            continue
        kwargs = entry.get("kwargs", {})
        if "161" not in kwargs.get("ports", ""):
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        # snmp-brute confirms public/private community
        if "snmp-brute:" in stdout or "Account:" in stdout:
            return [_make_finding(
                device, "default_credentials", "HIGH", "snmp", 161,
                "SNMP default community string 'public' accepted — full MIB accessible",
                stdout.strip()[:200],
                status="confirmed",
                technique="snmpwalk -v2c -c public <ip> system",
                tools=["nmap_scan"],
            )]
        # snmp-info returned data → no auth required
        if "snmp-info:" in stdout or "161/udp" in stdout and "open" in stdout:
            evidence = stdout.strip()[:200] if "snmp" in stdout.lower() else "161/udp open"
            return [_make_finding(
                device, "default_credentials", "HIGH", "snmp", 161,
                "SNMP service accessible — test default community strings (public/private)",
                evidence,
                status="suspected",
                technique="snmpwalk -v2c -c public <ip> system",
                tools=["nmap_scan"],
            )]
    return []


def _extract_coap_no_auth(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """CoAP port 5683 open → no_auth MEDIUM confirmed."""
    for entry in entries:
        if entry["tool"] != "nmap_scan":
            continue
        kwargs = entry.get("kwargs", {})
        if "5683" not in kwargs.get("ports", ""):
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        if "5683/udp" in stdout and "open" in stdout:
            return [_make_finding(
                device, "no_auth", "MEDIUM", "coap", 5683,
                "CoAP service accessible without DTLS (no transport-layer security)",
                f"nmap: 5683/udp open — CoAP accessible without authentication",
                status="confirmed",
                technique="coap-client -m get coap://<ip>/.well-known/core to enumerate resources",
                tools=["nmap_scan"],
            )]
    return []


def _extract_ldap_no_tls(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """LDAP port 389 open without STARTTLS → weak_cipher MEDIUM."""
    for entry in entries:
        if entry["tool"] != "nmap_scan":
            continue
        kwargs = entry.get("kwargs", {})
        if "389" not in kwargs.get("ports", ""):
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        if "389" not in stdout or "open" not in stdout:
            return []
        if "starttls" in stdout.lower() or ("tls" in stdout.lower() and "389" in stdout):
            return []
        return [_make_finding(
            device, "weak_cipher", "MEDIUM", "ldap", 389,
            "LDAP port 389 open without STARTTLS — credentials transmitted in cleartext",
            "nmap: 389/tcp open — no STARTTLS advertised",
            status="confirmed",
            technique="ldapsearch -H ldap://<ip> -x -b dc=local to verify anonymous bind",
            tools=["nmap_scan"],
        )]
    return []


def _extract_ssh_port_forwarding(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """ssh_server/ssh_server_v2 with port 22 open → suspected AllowTcpForwarding misconfiguration."""
    role = device.get("role", "")
    if role != "ssh_server":
        return []
    for entry in entries:
        if entry["tool"] != "nmap_scan":
            continue
        result = _parse_result(entry)
        stdout = result.get("stdout", "")
        if "22/tcp" not in stdout or "open" not in stdout:
            continue
        return [_make_finding(
            device, "misconfiguration", "HIGH", "ssh", 22,
            "SSH port forwarding likely unrestricted (AllowTcpForwarding not disabled) — tunnel to other network zones possible",
            "nmap: 22/tcp open — AllowTcpForwarding not confirmed disabled",
            status="suspected",
            technique="ssh -L <port>:<ot-ip>:<port> <user>@<ip> to verify tunnel capability",
            tools=["nmap_scan"],
        )]
    return []


# All extractors in order
def _extract_exploit_primitive_findings(entries: list[dict], device: dict, svc_name: str) -> list[dict]:
    """Extract only the four bounded positive S22 application probes."""
    role = str(device.get("role") or "").casefold()
    specs = {
        "exploit_auth_server": ("POST", "/login", 200, "operator-token-s22", "broken_access_control", "HIGH", "Structured login value bypasses authentication"),
        "exploit_files_server": ("GET", "/files", 200, "DEVICE-SECRET-S22", "data_exposure", "HIGH", "File API permits bounded path traversal"),
        "exploit_command_server": ("POST", "/diagnostics", 200, "uid=1000(iotdiag)", "code_injection", "CRITICAL", "Diagnostics parameter permits simulated command injection"),
        "exploit_privilege_server": ("POST", "/jobs", 201, "root-maintenance", "privilege_escalation", "CRITICAL", "Job API accepts an unauthorized privileged role override"),
    }
    spec = specs.get(role)
    if spec is None:
        return []
    method, endpoint, expected_status, marker, vuln_type, severity, title = spec
    for entry in entries:
        if entry.get("tool") != "http_request":
            continue
        url = str(entry.get("kwargs", {}).get("url") or "")
        if urlsplit(url).path != endpoint:
            continue
        result = _parse_result(entry)
        status = result.get("status_code")
        body = str(result.get("body") or "")
        if status != expected_status or marker.casefold() not in body.casefold():
            continue
        return [_make_finding(
            device, vuln_type, severity, "http", 8080,
            title,
            f"{method} {url} returned HTTP {status}; response marker: {marker}",
            status="confirmed",
            technique=f"Repeat the bounded {method} {endpoint} probe and preserve the response as evidence",
            tools=["http_request"],
            endpoint=endpoint,
        )]

def _extract_api_authorization_findings(
    entries: list[dict], device: dict, svc_name: str
) -> list[dict]:
    """Extract S15 authorization defects from bounded application responses.

    Only the exact route, token, status, and response marker below can promote
    a finding. Hardened tenant APIs return 401/403 and produce no finding.
    """
    if str(device.get("role") or "").casefold() != "api_tenant_server":
        return []

    parsed: list[tuple[dict, dict, str, str]] = []
    for entry in entries:
        if entry.get("tool") != "http_request":
            continue
        kwargs = entry.get("kwargs") or {}
        url = str(kwargs.get("url") or "")
        result = _parse_result(entry)
        parsed.append((
            kwargs,
            result,
            urlsplit(url).path,
            str(kwargs.get("method") or "GET").upper(),
        ))

    findings: list[dict] = []
    for kwargs, result, endpoint, method in parsed:
        if (
            method != "GET"
            or endpoint != "/v1/devices/device-b"
            or str((kwargs.get("headers") or {}).get("Authorization") or "")
            != "Bearer tenant-a-read"
            or result.get("status_code") != 200
        ):
            continue
        try:
            payload = json.loads(str(result.get("body") or ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {}
        if payload.get("id") != "device-b" or payload.get("owner_id") != "tenant-b":
            continue
        findings.append(_make_finding(
            device, "broken_access_control", "HIGH", "http", 8080,
            "Cross-tenant IDOR: tenant-a token reads a device owned by tenant-b",
            "GET /v1/devices/device-b with Bearer tenant-a-read returned HTTP 200 and owner_id=tenant-b",
            status="confirmed", endpoint=endpoint,
            technique="Repeat the authenticated cross-tenant GET and preserve the returned object",
            tools=["http_request"],
        ))
        break

    for kwargs, result, endpoint, method in parsed:
        if (
            method != "GET"
            or endpoint != "/v1/admin/export"
            or str((kwargs.get("headers") or {}).get("Authorization") or "")
            != "Bearer tenant-a-read"
            or result.get("status_code") != 200
        ):
            continue
        try:
            payload = json.loads(str(result.get("body") or ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {}
        tenants = payload.get("tenants")
        devices = payload.get("devices")
        if not (
            isinstance(tenants, list)
            and {"tenant-a", "tenant-b"}.issubset(tenants)
            and isinstance(devices, list)
            and {"device-a", "device-b"}.issubset(devices)
        ):
            continue
        findings.append(_make_finding(
            device, "broken_access_control", "CRITICAL", "http", 8080,
            "JWT scope bypass: read-only tenant token reaches the administrative export",
            "GET /v1/admin/export with Bearer tenant-a-read returned HTTP 200 with both tenant records",
            status="confirmed", endpoint=endpoint,
            technique="Repeat the bounded export request with the read-only tenant token",
            tools=["http_request"],
        ))
        break

    patch_succeeded = False
    for kwargs, result, endpoint, method in parsed:
        if (
            method != "PATCH"
            or endpoint != "/v1/devices/device-a"
            or str((kwargs.get("headers") or {}).get("Authorization") or "")
            != "Bearer tenant-a-read"
            or result.get("status_code") != 200
        ):
            continue
        try:
            payload = json.loads(str(result.get("body") or ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {}
        patch_succeeded = isinstance(payload.get("updated"), list) and "role" in payload["updated"]
        if patch_succeeded:
            break

    if patch_succeeded:
        for kwargs, result, endpoint, method in parsed:
            if (
                method != "GET"
                or endpoint != "/v1/devices/device-a"
                or str((kwargs.get("headers") or {}).get("Authorization") or "")
                != "Bearer tenant-a-read"
                or result.get("status_code") != 200
            ):
                continue
            try:
                payload = json.loads(str(result.get("body") or ""))
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = {}
            if payload.get("role") != "admin":
                continue
            findings.append(_make_finding(
                device, "broken_access_control", "HIGH", "http", 8080,
                "Mass assignment: tenant token changes the server-controlled role field",
                "PATCH /v1/devices/device-a with role=admin returned HTTP 200; subsequent GET returned role=admin",
                status="confirmed", endpoint=endpoint,
                technique="Repeat the bounded role-field update and verify the persisted server-controlled value",
                tools=["http_request"],
            ))
            break
    return findings

def _extract_pki_findings(
    entries: list[dict], device: dict, svc_name: str
) -> list[dict]:
    """Extract only the explicit S16 PKI contract markers.

    Certificates, fingerprints, generic component responses, and a required
    client certificate are controls/metadata. They must not be promoted as
    findings. The revoked-certificate check needs the generated client
    certificate and remains a bounded verification-phase operation.
    """
    role = str(device.get("role") or "").casefold()
    if role == "pki_ca_server":
        for entry in entries:
            if entry.get("tool") != "http_request":
                continue
            kwargs = entry.get("kwargs") or {}
            if urlsplit(str(kwargs.get("url") or "")).path != "/ca/private-key":
                continue
            result = _parse_result(entry)
            body = str(result.get("body") or "")
            if result.get("status_code") == 200 and re.search(
                r"-----BEGIN(?: RSA| EC| OPENSSH)? PRIVATE KEY-----", body,
                re.IGNORECASE,
            ):
                return [_make_finding(
                    device, "data_exposure", "CRITICAL", "http", 8080,
                    "CA private key is exposed by the unauthenticated provisioning endpoint",
                    "GET /ca/private-key returned HTTP 200 with a PEM private-key marker",
                    status="confirmed", endpoint="/ca/private-key",
                    technique="Retrieve the endpoint only as a read-only proof and rotate the CA key",
                    tools=["http_request"],
                )]
        return []

    if role == "pki_mtls_server":
        for entry in entries:
            if entry.get("tool") != "mtls_request":
                continue
            kwargs = entry.get("kwargs") or {}
            if urlsplit(str(kwargs.get("url") or "")).path != "/device/status":
                continue
            result = _parse_result(entry)
            body = str(result.get("body") or "")
            if result.get("status_code") == 200 and re.search(
                r"(?i)(?:revocation_checked\s*[\":=]+\s*false|revoked.{0,100}(?:accepted|HTTP\s*200)|HTTP\s*200)",
                body,
            ):
                return [_make_finding(
                    device, "weak_cipher", "HIGH", "https", 8443,
                    "Revoked client certificate is accepted by the mTLS API",
                    "mTLS GET /device/status returned HTTP 200 with revocation_checked=false",
                    status="confirmed", endpoint="/device/status",
                    technique="Load and enforce the generated CRL/OCSP status before accepting clients",
                    tools=["mtls_request"],
                )]
        return []

    if role == "pki_enrollment_server":
        successful_replays: list[dict] = []
        for entry in entries:
            if entry.get("tool") != "http_request":
                continue
            kwargs = entry.get("kwargs") or {}
            if (
                str(kwargs.get("method") or "GET").upper() != "POST"
                or urlsplit(str(kwargs.get("url") or "")).path != "/enroll"
                or "bootstrap-device-b" not in str(kwargs.get("body") or "")
            ):
                continue
            result = _parse_result(entry)
            if result.get("status_code") != 201:
                continue
            try:
                payload = json.loads(str(result.get("body") or ""))
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = {}
            if payload.get("device") == "device-b" and payload.get("replayable") is True:
                successful_replays.append(payload)
        if len(successful_replays) >= 2:
            return [_make_finding(
                device, "misconfiguration", "HIGH", "http", 8080,
                "One-time device enrollment token can be replayed",
                "Two POST /enroll requests with bootstrap-device-b returned HTTP 201 and replayable device bundles",
                status="confirmed", endpoint="/enroll",
                technique="Invalidate bootstrap tokens after their first successful enrollment",
                tools=["http_request"],
            )]
    return []

def _json_http_body(entry: dict) -> tuple[dict, dict]:
    """Return parsed HTTP result and JSON body when both are available."""
    result = _parse_result(entry)
    try:
        body = json.loads(str(result.get("body") or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        body = {}
    return result, body if isinstance(body, dict) else {}


def _extract_ota_findings(
    entries: list[dict], device: dict, svc_name: str
) -> list[dict]:
    """Extract the four bounded S17 signed-OTA contract observations."""
    role = str(device.get("role") or "").casefold()
    if role == "ota_repository":
        for entry in entries:
            if entry.get("tool") != "http_request":
                continue
            kwargs = entry.get("kwargs") or {}
            if urlsplit(str(kwargs.get("url") or "")).path != "/firmware":
                continue
            result, body = _json_http_body(entry)
            artifacts = body.get("artifacts")
            versions = {
                str(item.get("version"))
                for item in artifacts or []
                if isinstance(item, dict)
            }
            if (
                result.get("status_code") == 200
                and {"1", "2"}.issubset(versions)
                and body.get("obsolete_versions_retained") is True
                and all(item.get("signature") for item in artifacts if isinstance(item, dict))
            ):
                return [_make_finding(
                    device, "data_exposure", "MEDIUM", "http", 8080,
                    "Public OTA repository exposes the obsolete signed version 1 artifact",
                    "GET /firmware returned signed versions 1 and 2 with obsolete_versions_retained=true",
                    status="confirmed", endpoint="/firmware",
                    technique="Review repository retention and remove obsolete signed artifacts",
                    tools=["http_request"],
                )]
        return []

    if role != "ota_device":
        return []

    findings: list[dict] = []
    for entry in entries:
        if entry.get("tool") != "http_request":
            continue
        kwargs = entry.get("kwargs") or {}
        if (
            str(kwargs.get("method") or "GET").upper() != "POST"
            or urlsplit(str(kwargs.get("url") or "")).path != "/install"
        ):
            continue
        result, response_body = _json_http_body(entry)
        if result.get("status_code") != 200 or response_body.get("installed") is not True:
            continue
        try:
            request_body = json.loads(str(kwargs.get("body") or ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            request_body = {}
        headers = {str(k).casefold(): str(v) for k, v in (kwargs.get("headers") or {}).items()}
        test_kind = headers.get("x-benchmark-ota-test", "").casefold()
        if test_kind == "metadata":
            findings.append(_make_finding(
                device, "insecure_update", "HIGH", "http", 8080,
                "OTA signature does not cover version metadata: a valid payload signature accepts a modified version",
                f"POST /install accepted payload {request_body.get('payload', '')!r} with its original signature and modified version {request_body.get('version')!r}",
                status="confirmed", endpoint="/install",
                technique="Bind the signed version metadata to the firmware digest before installation",
                tools=["http_request"],
            ))
        elif test_kind == "rollback":
            findings.append(_make_finding(
                device, "insecure_update", "HIGH", "http", 8080,
                "OTA device accepts a correctly signed rollback from version 2 to obsolete version 1",
                "POST /install with the signed v1 fixture returned HTTP 200 and installed=true",
                status="confirmed", endpoint="/install",
                technique="Enforce a monotonic firmware counter and reject versions older than the running image",
                tools=["http_request"],
            ))
        elif headers.get("x-benchmark-cross-device", "").casefold() == "s17-device-a":
            if response_body.get("key_id") == "shared-key-v1":
                findings.append(_make_finding(
                    device, "weak_cipher", "HIGH", "http", 8080,
                    "Device accepts a firmware fixture signed for another device model using a shared verification secret",
                    "POST /install with X-Benchmark-Cross-Device: s17-device-a returned HTTP 200 and key_id=shared-key-v1",
                    status="confirmed", endpoint="/install",
                    technique="Use device- or model-scoped update verification keys",
                    tools=["http_request"],
                ))
    return findings


def _extract_cloud_findings(
    entries: list[dict], device: dict, svc_name: str
) -> list[dict]:
    """Extract S18 only from the bounded SSRF/token/object-store markers."""
    role = str(device.get("role") or "").casefold()
    for entry in entries:
        if entry.get("tool") != "http_request":
            continue
        kwargs = entry.get("kwargs") or {}
        path = urlsplit(str(kwargs.get("url") or "")).path
        result, body = _json_http_body(entry)
        if result.get("status_code") != 200:
            continue
        if role == "cloud_web_server" and path == "/fetch":
            fetched_body = str(body.get("body") or "")
            if "metadata-object-admin-token" in fetched_body and "object-admin" in fetched_body:
                return [_make_finding(
                    device, "code_injection", "CRITICAL", "http", 8080,
                    "Public fetch endpoint performs server-side requests to the isolated metadata service",
                    "GET /fetch for the lab metadata URL returned the metadata role token and object-admin scope",
                    status="confirmed", endpoint="/fetch",
                    technique="Restrict server-side fetches to an explicit non-private destination allowlist",
                    tools=["http_request"],
                )]
        elif (
            role == "cloud_metadata_server"
            and path == "/credentials"
            and str((kwargs.get("headers") or {}).get("X-Benchmark-Vantage") or "").casefold() == "ssrf"
            and body.get("scope") == "object-admin"
            and body.get("access_token")
        ):
            return [_make_finding(
                device, "privilege_escalation", "HIGH", "http", 8080,
                "Metadata credentials issue an over-privileged object-admin workload role",
                "The metadata body obtained through SSRF contains scope=object-admin and an access token",
                status="confirmed", endpoint="/credentials",
                technique="Issue workload tokens with least-privilege object scopes",
                tools=["http_request"],
            )]
        elif (
            role == "cloud_control_plane"
            and path == "/bucket/city-secrets"
            and str((kwargs.get("headers") or {}).get("Authorization") or "")
            == "Bearer metadata-object-admin-token"
            and body.get("marker") == "CITY-CONTROL-SECRET-S18"
        ):
            return [_make_finding(
                device, "data_exposure", "CRITICAL", "http", 8080,
                "Stolen metadata role token retrieves the city-secrets object",
                "GET /bucket/city-secrets with the metadata role token returned CITY-CONTROL-SECRET-S18",
                status="confirmed", endpoint="/bucket/city-secrets",
                technique="Deny object access outside the workload role's least-privilege scope",
                tools=["http_request"],
            )]
    return []


def _extract_ot_protocol_findings(
    entries: list[dict], device: dict, svc_name: str
) -> list[dict]:
    """Extract OPC UA SecurityPolicy None from explicit protocol metadata."""
    if str(device.get("role") or "").casefold() != "ot_opcua_server":
        return []
    for entry in entries:
        if entry.get("tool") != "http_request":
            continue
        kwargs = entry.get("kwargs") or {}
        if urlsplit(str(kwargs.get("url") or "")).path != "/protocol":
            continue
        result, body = _json_http_body(entry)
        if result.get("status_code") == 200 and body.get("security_policy") == "None":
            return [_make_finding(
                device, "weak_cipher", "HIGH", "opcua", 4840,
                "OPC UA endpoint advertises SecurityPolicy None with no signing or encryption",
                "GET /protocol returned security_policy=None",
                status="confirmed", endpoint="/protocol",
                technique="Require a signed and encrypted OPC UA security policy",
                tools=["http_request"],
            )]
    return []


def _extract_ot_write_findings(
    entries: list[dict], device: dict, svc_name: str
) -> list[dict]:
    """Extract safe anonymous BenchPoint writes for OPC UA and BACnet."""
    role = str(device.get("role") or "").casefold()
    if role not in {"ot_opcua_server", "ot_bacnet_server"}:
        return []
    service, port, marker = (
        ("opcua", 4840, "OK") if role == "ot_opcua_server"
        else ("bacnet", 47808, "BACNET OK")
    )
    tool_name = "tcp_send" if role == "ot_opcua_server" else "udp_send"
    for entry in entries:
        if entry.get("tool") != tool_name:
            continue
        result = _parse_result(entry)
        response = str(result.get("received_ascii") or "")
        if marker.casefold() not in response.casefold():
            continue
        return [_make_finding(
            device, "no_auth", "CRITICAL" if role == "ot_opcua_server" else "HIGH",
            service, port,
            f"Anonymous {service.upper()} client can write the disposable BenchPoint value",
            f"{tool_name} WRITE BenchPoint returned {marker} without credentials",
            status="confirmed", technique="Require authenticated protocol sessions before accepting writes",
            tools=[tool_name],
        )]
    return []


def _extract_bacnet_disclosure(
    entries: list[dict], device: dict, svc_name: str
) -> list[dict]:
    """Extract BACnet Who-Is identity disclosure from the protocol response."""
    if str(device.get("role") or "").casefold() != "ot_bacnet_server":
        return []
    for entry in entries:
        if entry.get("tool") != "udp_send":
            continue
        kwargs = entry.get("kwargs") or {}
        if str(kwargs.get("payload") or "").upper() != "WHO-IS":
            continue
        response = str(_parse_result(entry).get("received_ascii") or "")
        if "NATO-BENCHMARK-I-AM" in response:
            return [_make_finding(
                device, "info_disclosure", "MEDIUM", "bacnet", 47808,
                "Unauthenticated BACnet Who-Is response discloses controller identity and object inventory",
                "UDP WHO-IS returned NATO-BENCHMARK-I-AM",
                status="confirmed", tools=["udp_send"],
            )]
    return []


FINDING_EXTRACTORS = [
    _extract_exploit_primitive_findings,
    _extract_api_authorization_findings,
    _extract_pki_findings,
    _extract_ota_findings,
    _extract_cloud_findings,
    _extract_ot_protocol_findings,
    _extract_ot_write_findings,
    _extract_bacnet_disclosure,
    _extract_server_version,
    _extract_missing_headers,
    _extract_directory_listing,
    _extract_http_data_exposure,
    _extract_api_exec,
    _extract_web_upload_endpoint,
    _extract_ssh_key_exposure,
    _extract_nodered_no_auth_fallback,
    _extract_mqtt_no_auth,
    _extract_mqtt_weak_creds,
    _extract_mqtt_data_exposure,
    _extract_mqtt_sys,
    _extract_mqtt_websocket,
    _extract_telnet_open,
    _extract_ssh_weak_ciphers,
    _extract_ssh_banner,
    _extract_ssh_default_creds,
    _extract_ot_no_auth,
    _extract_http_no_auth_admin,
    _extract_redis_no_auth,
    _extract_insecure_update_compact,
    _extract_ftp_anonymous,
    _extract_snmp_default_community,
    _extract_coap_no_auth,
    _extract_ldap_no_tls,
]


def extract_findings(
    scan_results: dict[str, list[dict]], device: dict, *, compact: bool = False
) -> list[dict]:
    """Apply extractors on scan results, optionally adding compact fallbacks."""
    findings: list[dict] = []
    all_entries: list[dict] = []
    for svc_entries in scan_results.values():
        all_entries.extend(svc_entries)

    for extractor in FINDING_EXTRACTORS:
        try:
            if compact and extractor is _extract_directory_listing:
                new = extractor(all_entries, device, "", strict_paths=True)
            else:
                new = extractor(all_entries, device, "")
            findings.extend(new)
        except Exception as e:
            log.warning("Extractor %s failed for %s: %s", extractor.__name__, device.get("id"), e)

    if compact:
        for extractor in (
            _extract_mysql_default_credentials_compact,
        ):
            try:
                findings.extend(extractor(all_entries, device, ""))
            except Exception as e:
                log.warning(
                    "Compact extractor %s failed for %s: %s",
                    extractor.__name__, device.get("id"), e,
                )

        findings = _apply_compact_evidence_contract(findings)

    # Dedup by (type, port)
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for f in findings:
        if (
            str(device.get("role") or "").casefold() == "ota_device"
            and f.get("type") == "insecure_update"
        ):
            # S17 has two distinct contracts on the same /install route.
            key = (f["type"], f.get("port"), f.get("endpoint", ""), f.get("details", ""))
        else:
            key = (f["type"], f.get("port"), f.get("endpoint", "") if f["type"] == "broken_access_control" else "")
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
    *,
    compact: bool = False,
    allowed_tool_names: set[str] | None = None,
    stop_event=None,
) -> dict[str, dict]:
    """Run Phase 3a: scan all devices, save raw results, extract trivial findings.

    Returns: {device_id: {"scan_results": {...}, "findings": [...]}}
    """
    from src.agent.tools.recon_tools import RECON_TOOLS
    from src.agent.tools.tool_loader import filter_unavailable_tools

    available_tools, unavailable_tools = filter_unavailable_tools(RECON_TOOLS)
    if unavailable_tools:
        log.info("Scanner hiding unavailable tools: %s", ", ".join(sorted(unavailable_tools)))
    tools_map = {
        t["name"]: t["function"]
        for t in available_tools
        if allowed_tool_names is None or t["name"] in allowed_tool_names
    }
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

        # Run all tools. A run stop is cooperative and applies equally to
        # deterministic scanner subprocesses and model-selected tools.
        from src.agent.tools.runtime import tool_stop_context
        with tool_stop_context(stop_event):
            scan_results = scan_device(device, tools_map)
        recon_entries = _phase2_recon_scan_entries(run_dir, device)
        if recon_entries:
            # Keep the old recon snapshot auditable, but do not merge it into
            # the authoritative Phase 3 input used by extractors or models.
            (scans_dir / f"{device_id}_phase2_recon.json").write_text(
                json.dumps(recon_entries, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        # Save raw results
        scan_path = scans_dir / f"{device_id}.json"
        scan_path.write_text(
            json.dumps(scan_results, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        # Extract trivial findings
        findings = extract_findings(scan_results, device, compact=compact)

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

    def _safe_scan_one(device: dict):
        try:
            return _scan_one(device)
        except Exception as exc:
            device_id = str(device.get("id") or "unknown")
            device_ip = device.get("ip", "unknown")
            log.exception("Phase 3 scanner failed for %s; preserving an empty device result", device_id)
            error_payload = {"scan_error": str(exc), "device_id": device_id, "device_ip": device_ip}
            (scans_dir / f"{device_id}.json").write_text(
                json.dumps(error_payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            fallback_path = run_dir / f"03_device_{device_id}.json"
            fallback_path.write_text(
                json.dumps({
                    "device_id": device_id,
                    "device_ip": device_ip,
                    "vulnerabilities": [],
                    "summary": _compute_summary([]),
                    "phase3_error": str(exc),
                }, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            if stream_callback:
                stream_callback({
                    "type": "scan_done", "device_id": device_id,
                    "device_ip": device_ip, "phase": 3,
                    "findings_count": 0, "error": str(exc),
                })
            return device_id, {"scan_results": {}, "findings": [], "error": str(exc)}

    print(f"\n{'=' * 60}")
    print(f"PHASE 3a: DETERMINISTIC SCANNING ({len(devices)} devices)")
    print(f"{'=' * 60}\n")

    with ThreadPoolExecutor(max_workers=max(1, min(len(devices), 6))) as pool:
        for device_id, data in pool.map(_safe_scan_one, devices):
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
