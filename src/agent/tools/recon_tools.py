"""Network reconnaissance tools — YAML-defined with Python handlers.

Subprocess tools (nmap, ssh-audit, curl, mosquitto_sub) are loaded from
YAML definitions in definitions/. Python-only tools (nvd_lookup) are
defined here and registered as handlers.

All subprocess tools return {stdout, stderr, return_code} as JSON.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
from datetime import datetime, timezone

from src.cve_lookup import query_nvd
from src.agent.tools.runtime import get_tool_stop_event, run_cooperatively

_ANSI_ESC = re.compile(r'\x1b\[[0-9;]*[mK]')
_SSH_LEGACY_OPTIONS = [
    "-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1",
    "-o", "HostKeyAlgorithms=+ssh-rsa",
    "-o", "Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc",
]


def _run(cmd: list[str], timeout: int = 30) -> dict:
    """Run a command and return structured output (ANSI codes stripped)."""
    stop_event = get_tool_stop_event()
    if stop_event is not None:
        stdout, stderr, return_code, timed_out, cancelled = run_cooperatively(
            cmd, timeout=timeout
        )
        payload = {
            "stdout": _ANSI_ESC.sub("", stdout),
            "stderr": _ANSI_ESC.sub("", stderr),
            "return_code": return_code,
        }
        if timed_out:
            payload["stderr"] = payload["stderr"] or (
                f"Command timed out after {timeout}s: {shlex.join(cmd)}"
            )
        if cancelled:
            payload["cancelled"] = True
        return payload
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


def ssh_exec(ip: str, user: str, password: str, command: str, port: int = 22) -> str:
    """Execute a shell command on a remote host via SSH."""
    cmd = [
        "sshpass", "-p", password,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=no",
        *_SSH_LEGACY_OPTIONS,
        f"-p{port}",
        f"{user}@{ip}",
        command,
    ]
    result = _run(cmd, timeout=30)
    
    # Truncate output to prevent LLM context flooding (e.g. from large file reads)
    if isinstance(result.get("stdout"), str) and len(result["stdout"]) > 8000:
        result["stdout"] = result["stdout"][:8000] + "\n...[TRUNCATED]"
    if isinstance(result.get("stderr"), str) and len(result["stderr"]) > 4000:
        result["stderr"] = result["stderr"][:4000] + "\n...[TRUNCATED]"
        
    result["success"] = result["return_code"] == 0
    return json.dumps(result)


def try_credential(ip: str, service: str, user: str, password: str, port: int | None = None) -> str:
    """Test a username/password credential against a service (ssh|http|ftp|mqtt)."""
    service = service.lower().strip()

    if service == "ssh":
        p = port or 22
        cmd = [
            "sshpass", "-p", password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=no",
            *_SSH_LEGACY_OPTIONS,
            f"-p{p}",
            f"{user}@{ip}",
            "echo __ok__",
        ]
        result = _run(cmd, timeout=15)
        success = result["return_code"] == 0 and "__ok__" in result["stdout"]
        return json.dumps({"success": success, "authenticated": success, "service": "ssh", "port": p,
                           "stdout": result["stdout"][:200], "stderr": result["stderr"][:200]})

    if service == "http":
        p = port or 80
        url = f"http://{ip}:{p}/"
        probe = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--connect-timeout", "10", url]
        anonymous = _run(probe, timeout=15)
        auth_probe = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                      "--connect-timeout", "10", "-u", f"{user}:{password}", url]
        result = _run(auth_probe, timeout=15)
        anon_code = anonymous["stdout"].strip()
        code = result["stdout"].strip()
        auth_required = anon_code in ("401", "403")
        success = auth_required and code not in ("401", "403", "000", "")
        return json.dumps({"success": success, "authenticated": success, "service": "http", "port": p,
                           "http_code": code, "unauthenticated_http_code": anon_code,
                           "anonymous_access": not auth_required and anon_code not in ("000", "")})

    if service == "ftp":
        p = port or 21
        url = f"ftp://{ip}:{p}/"
        anonymous = _run(["curl", "-s", "--ftp-pasv", "--connect-timeout", "10", url, "--head"], timeout=15)
        result = _run(["curl", "-s", "--ftp-pasv", "--connect-timeout", "10",
                       "-u", f"{user}:{password}", url, "--head"], timeout=15)
        anonymous_access = anonymous["return_code"] == 0
        success = result["return_code"] == 0 and not anonymous_access
        return json.dumps({"success": success, "authenticated": success, "service": "ftp", "port": p,
                           "anonymous_access": anonymous_access,
                           "stdout": result["stdout"][:200], "stderr": result["stderr"][:100]})

    if service == "mqtt":
        p = port or 1883
        base = ["mosquitto_sub", "-h", ip, "-p", str(p), "-t", "$SYS/#", "-C", "1", "--quiet", "-W", "5"]
        anonymous = _run(base, timeout=10)
        auth = _run(base + ["-u", user, "-P", password], timeout=10)
        anon_observed = anonymous["return_code"] == 0 or bool(anonymous["stdout"].strip())
        auth_observed = auth["return_code"] == 0 or bool(auth["stdout"].strip())
        success = (not anon_observed) and auth_observed
        return json.dumps({"success": success, "authenticated": success, "service": "mqtt", "port": p,
                           "stdout": auth["stdout"][:200], "anonymous_access": anon_observed,
                           "auth_required": not anon_observed})

    if service == "telnet":
        p = port or 23
        # Use netcat to send credentials and check response
        cmd = ["bash", "-c",
               f"(echo '{user}'; sleep 0.5; echo '{password}'; sleep 1; echo 'id') | "
               f"nc -w 5 {ip} {p} 2>/dev/null"]
        result = _run(cmd, timeout=12)
        stdout = result["stdout"]
        success = "uid=" in stdout or "$" in stdout or "#" in stdout
        return json.dumps({"success": success, "authenticated": success, "service": "telnet", "port": p,
                           "stdout": stdout[:300]})

    if service == "redis":
        p = port or 6379
        # Try AUTH then PING
        cmd = ["bash", "-c",
               f"(echo 'AUTH {password}'; echo 'PING'; echo 'KEYS *') | "
               f"nc -w 5 {ip} {p} 2>/dev/null"]
        result = _run(cmd, timeout=10)
        stdout = result["stdout"]
        success = "+OK" in stdout or "+PONG" in stdout
        return json.dumps({"success": success, "authenticated": success, "service": "redis", "port": p,
                           "stdout": stdout[:300]})

    if service == "mysql":
        p = port or 3306
        cmd = ["mysql", f"-h{ip}", f"-P{p}", f"-u{user}",
               f"-p{password}", "--connect-timeout=5",
               "-e", "SELECT user,host FROM mysql.user LIMIT 5;", "2>/dev/null"]
        result = _run(cmd, timeout=12)
        success = result["return_code"] == 0 and "ERROR" not in result["stderr"]
        return json.dumps({"success": success, "authenticated": success, "service": "mysql", "port": p,
                           "stdout": result["stdout"][:300], "stderr": result["stderr"][:100]})

    return json.dumps({"success": False, "error": f"Unsupported service: {service}. Use ssh|http|ftp|mqtt|telnet|redis|mysql"})


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
                    "compatibility": {
                        "status": r.compatibility_status,
                        "reason": r.compatibility_reason,
                        "matched_cpes": r.matched_cpes,
                    },
                }
                for r in results[:top_k]
            ]
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


def traceroute(target: str, max_hops: int = 10) -> str:
    """Discover network hops to a target using traceroute."""
    import platform
    import re as _re

    system = platform.system()
    if system == "Darwin":
        cmd = ["traceroute", "-n", "-m", str(max_hops), target]
    else:
        # Linux: traceroute or tracepath as fallback
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", target]

    result = _run(cmd, timeout=max_hops * 3 + 5)

    # Parse hop IPs from output lines like:
    #  1  192.168.88.1  1.234 ms
    #  2  10.0.0.1  2.345 ms
    hop_pattern = _re.compile(r"^\s*(\d+)\s+([\d.]+)")
    hops = []
    for line in result["stdout"].splitlines():
        m = hop_pattern.match(line)
        if m:
            hops.append({"hop": int(m.group(1)), "ip": m.group(2)})

    return json.dumps({
        "target": target,
        "hops": hops,
        "hop_count": len(hops),
        "stdout": result["stdout"][:500],
        "return_code": result["return_code"],
    })


# ── Python handlers for newly-added YAML tools ────────────────────


_PYTHON_EXEC_HARD_MAX = 180


def python_exec(script: str, timeout: int = 60) -> str:
    """Run ad-hoc Python via subprocess + tempfile + wall-clock timeout.

    Returns JSON with stdout, stderr, return_code, and timed_out flag. Uses
    the backend interpreter with `-I` (isolated mode), so installed backend
    packages are available without inheriting user-site configuration.
    """
    effective_timeout = max(1, min(int(timeout or 60), _PYTHON_EXEC_HARD_MAX))
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(script)
            tmp_path = tmp.name
        stop_event = get_tool_stop_event()
        if stop_event is None:
            result = subprocess.run(
                [sys.executable, "-I", tmp_path],
                capture_output=True,
                text=True,
                timeout=effective_timeout,
            )
            stdout, stderr, return_code = result.stdout, result.stderr, result.returncode
            timed_out = False
            cancelled = False
        else:
            stdout, stderr, return_code, timed_out, cancelled = run_cooperatively(
                [sys.executable, "-I", tmp_path], timeout=effective_timeout
            )
        return json.dumps({
            "stdout": _ANSI_ESC.sub("", stdout)[:8000],
            "stderr": _ANSI_ESC.sub("", stderr)[:4000],
            "return_code": return_code,
            "timed_out": timed_out,
            "cancelled": cancelled,
            "timeout_seconds": effective_timeout,
        })
    except subprocess.TimeoutExpired as exc:
        return json.dumps({
            "stdout": (exc.stdout or "")[:8000] if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "")[:4000] if isinstance(exc.stderr, str) else "",
            "return_code": -1,
            "timed_out": True,
            "timeout_seconds": effective_timeout,
        })
    except Exception as exc:
        return json.dumps({"error": str(exc), "return_code": -1})
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def http_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
    follow_redirects: bool = True,
    verify_tls: bool = False,
    timeout: int = 10,
) -> str:
    """Full HTTP request via the `requests` library."""
    try:
        import requests
    except ImportError:
        return json.dumps({"error": "requests library not installed"})
    effective_timeout = max(1, min(int(timeout or 10), 30))
    method_norm = (method or "GET").upper()
    try:
        response = requests.request(
            method=method_norm,
            url=url,
            headers=headers or None,
            data=body if body is not None else None,
            allow_redirects=bool(follow_redirects),
            verify=bool(verify_tls),
            timeout=effective_timeout,
        )
    except requests.exceptions.RequestException as exc:
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"})
    body_text = response.text
    if len(body_text) > 8000:
        body_text = body_text[:8000] + "\n[truncated]"
    return json.dumps({
        "status_code": response.status_code,
        "method": method_norm,
        "final_url": response.url,
        "headers": dict(response.headers),
        "body": body_text,
        "elapsed_seconds": response.elapsed.total_seconds(),
        "redirect_chain": [r.url for r in response.history],
    })


def tcp_send(
    host: str,
    port: int,
    payload_hex: str,
    recv_bytes: int = 4096,
    timeout: int = 10,
) -> str:
    """Open raw TCP, send hex-decoded bytes, return hex + ASCII preview."""
    effective_timeout = max(1, min(int(timeout or 10), 30))
    effective_recv = max(0, min(int(recv_bytes or 4096), 65536))
    try:
        payload = bytes.fromhex((payload_hex or "").strip().replace(" ", ""))
    except ValueError as exc:
        return json.dumps({"error": f"invalid payload_hex: {exc}"})
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(effective_timeout)
    received = b""
    try:
        sock.connect((host, int(port)))
        if payload:
            sock.sendall(payload)
        if effective_recv > 0:
            try:
                received = sock.recv(effective_recv)
            except socket.timeout:
                received = b""
    except OSError as exc:
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"})
    finally:
        try:
            sock.close()
        except OSError:
            pass
    ascii_preview = "".join(
        chr(b) if 32 <= b < 127 else "." for b in received[:512]
    )
    return json.dumps({
        "host": host,
        "port": int(port),
        "sent_bytes": len(payload),
        "received_bytes": len(received),
        "received_hex": received.hex()[:4096],
        "received_ascii": ascii_preview,
    })


def udp_send(
    host: str,
    port: int,
    payload: str,
    encoding: str = "text",
    recv_bytes: int = 4096,
    timeout: int = 5,
) -> str:
    """Send one UDP datagram and return the first response as hex and text."""
    effective_timeout = max(1, min(int(timeout or 5), 30))
    effective_recv = max(1, min(int(recv_bytes or 4096), 65536))
    if encoding == "hex":
        try:
            wire_payload = bytes.fromhex((payload or "").strip().replace(" ", ""))
        except ValueError as exc:
            return json.dumps({"error": f"invalid hex payload: {exc}"})
    elif encoding == "text":
        wire_payload = (payload or "").encode("utf-8")
    else:
        return json.dumps({"error": "encoding must be 'text' or 'hex'"})
    if len(wire_payload) > 65507:
        return json.dumps({"error": "UDP payload exceeds 65507 bytes"})

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(effective_timeout)
    try:
        sock.sendto(wire_payload, (host, int(port)))
        received, peer = sock.recvfrom(effective_recv)
    except OSError as exc:
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"})
    finally:
        sock.close()
    ascii_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in received[:512])
    return json.dumps({
        "host": host,
        "port": int(port),
        "peer": f"{peer[0]}:{peer[1]}",
        "sent_bytes": len(wire_payload),
        "received_bytes": len(received),
        "received_hex": received.hex()[:4096],
        "received_ascii": ascii_preview,
    })


def mtls_request(
    url: str,
    certificate_pem: str,
    private_key_pem: str,
    ca_pem: str | None = None,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
    timeout: int = 10,
) -> str:
    """Perform an HTTPS request with an in-memory PEM client identity."""
    try:
        import requests
    except ImportError:
        return json.dumps({"error": "requests library not installed"})
    if not url.lower().startswith("https://"):
        return json.dumps({"error": "mTLS requests require an https:// URL"})
    if "BEGIN CERTIFICATE" not in (certificate_pem or ""):
        return json.dumps({"error": "certificate_pem is not a PEM certificate"})
    if "PRIVATE KEY" not in (private_key_pem or ""):
        return json.dumps({"error": "private_key_pem is not a PEM private key"})
    if max(len(certificate_pem), len(private_key_pem), len(ca_pem or "")) > 65536:
        return json.dumps({"error": "PEM input exceeds 65536 characters"})

    effective_timeout = max(1, min(int(timeout or 10), 30))
    try:
        with tempfile.TemporaryDirectory(prefix="benchmark-mtls-") as temp_dir:
            cert_path = os.path.join(temp_dir, "client.crt")
            key_path = os.path.join(temp_dir, "client.key")
            ca_path = os.path.join(temp_dir, "ca.crt")
            with open(cert_path, "w", encoding="utf-8") as handle:
                handle.write(certificate_pem)
            with open(key_path, "w", encoding="utf-8") as handle:
                handle.write(private_key_pem)
            os.chmod(key_path, 0o600)
            verify: bool | str = False
            if ca_pem:
                with open(ca_path, "w", encoding="utf-8") as handle:
                    handle.write(ca_pem)
                verify = ca_path
            response = requests.request(
                method=(method or "GET").upper(),
                url=url,
                headers=headers or None,
                data=body if body is not None else None,
                cert=(cert_path, key_path),
                verify=verify,
                timeout=effective_timeout,
                allow_redirects=False,
            )
    except requests.exceptions.RequestException as exc:
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"})
    return json.dumps({
        "status_code": response.status_code,
        "final_url": response.url,
        "headers": dict(response.headers),
        "body": response.text[:8000],
    })


def tls_inspect(host: str, port: int = 443, sni: str | None = None) -> str:
    """Fetch leaf cert + cipher info.

    Uses stdlib ssl for the handshake (cipher info + DER bytes), then shells
    out to `openssl x509` to parse the certificate fields. `openssl` is part
    of base apt installs on every fleet/master VM.
    """
    effective_port = int(port or 443)
    server_hostname = sni or host
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, effective_port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=server_hostname) as tls:
                cipher = tls.cipher() or ("", "", 0)
                der = tls.getpeercert(binary_form=True)
    except ssl.SSLError as exc:
        # A Phase 3 analyst can reasonably probe a service whose banner was
        # ambiguous, but a TLS handshake failure on a plain-text service is a
        # negative observation, not a failed tool execution. In particular,
        # probing SSH/22 with tls_inspect raises WRONG_VERSION_NUMBER. Keep
        # that result structured so the model can stop retrying without
        # inflating the run's tool-error metric.
        return json.dumps({
            "status": "not_tls",
            "host": host,
            "port": effective_port,
            "sni": server_hostname,
            "error_kind": "tls_handshake_failed",
            "message": str(exc),
            "hint": "The target did not negotiate TLS; verify the service and port before retrying.",
        })
    except OSError as exc:
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"})

    import hashlib as _h
    fingerprint = _h.sha256(der).hexdigest() if der else ""

    parsed: dict[str, str | list[str]] = {
        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "serial_number": "",
        "subject_alt_names": [],
    }
    if der:
        try:
            cp = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-noout",
                 "-subject", "-issuer", "-dates", "-serial",
                 "-ext", "subjectAltName"],
                input=der,
                capture_output=True,
                timeout=5,
            )
            text = cp.stdout.decode("utf-8", errors="replace")
            for line in text.splitlines():
                if line.startswith("subject="):
                    parsed["subject"] = line.split("=", 1)[1].strip()
                elif line.startswith("issuer="):
                    parsed["issuer"] = line.split("=", 1)[1].strip()
                elif line.startswith("notBefore="):
                    parsed["not_before"] = line.split("=", 1)[1].strip()
                elif line.startswith("notAfter="):
                    parsed["not_after"] = line.split("=", 1)[1].strip()
                elif line.startswith("serial="):
                    parsed["serial_number"] = line.split("=", 1)[1].strip()
                elif "DNS:" in line:
                    sans = re.findall(r"DNS:([^,\s]+)", line)
                    if sans:
                        parsed["subject_alt_names"] = sans
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return json.dumps({
        "host": host,
        "port": effective_port,
        "sni": server_hostname,
        **parsed,
        "cipher": {"name": cipher[0], "tls_version": cipher[1], "bits": cipher[2]},
        "fingerprint_sha256": fingerprint,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })


def decode_value(value: str, kind: str) -> str:
    """Decode base64/url/jwt/hex strings."""
    kind_norm = (kind or "").lower().strip()
    raw = value or ""
    try:
        if kind_norm == "base64":
            padded = raw + "=" * (-len(raw) % 4)
            try:
                decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="replace")
            except Exception:
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
            return json.dumps({"kind": "base64", "decoded": decoded})
        if kind_norm == "url":
            return json.dumps({"kind": "url", "decoded": urllib.parse.unquote_plus(raw)})
        if kind_norm == "hex":
            decoded = bytes.fromhex(raw.replace(" ", "").replace(":", "")).decode("utf-8", errors="replace")
            return json.dumps({"kind": "hex", "decoded": decoded})
        if kind_norm == "jwt":
            parts = raw.split(".")
            if len(parts) < 2:
                return json.dumps({"error": "JWT must have at least 2 dot-separated parts"})
            header_b64, payload_b64 = parts[0], parts[1]
            def _pad_b64(s: str) -> str:
                return s + "=" * (-len(s) % 4)
            try:
                header = json.loads(base64.urlsafe_b64decode(_pad_b64(header_b64)).decode("utf-8"))
                payload = json.loads(base64.urlsafe_b64decode(_pad_b64(payload_b64)).decode("utf-8"))
            except Exception as exc:
                return json.dumps({"error": f"jwt parse failed: {exc}"})
            return json.dumps({
                "kind": "jwt",
                "header": header,
                "payload": payload,
                "signature_present": len(parts) >= 3 and bool(parts[2]),
                "signature_verified": False,
            })
        return json.dumps({"error": f"unsupported kind: {kind!r} (use base64|url|jwt|hex)"})
    except Exception as exc:
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"})


def modbus_write(target: str, register: int, value: int, port: int = 502, unit_id: int = 1) -> str:
    """Write a value to a Modbus holding register."""
    try:
        from pymodbus.client import ModbusTcpClient
        from pymodbus.exceptions import ModbusException
    except ImportError:
        return json.dumps({"error": "pymodbus is not installed in the LANCE backend."})

    try:
        client = ModbusTcpClient(target, port=port)
        if not client.connect():
            return json.dumps({"error": f"Connection Refused: Cannot connect to {target}:{port}"})

        # Write to holding register (function code 6)
        response = client.write_register(register, value, slave=unit_id)
        
        if response.isError():
            result = {"success": False, "error": str(response)}
        else:
            result = {
                "success": True, 
                "message": f"Successfully wrote value {value} to register {register} at {target}:{port} (slave {unit_id})"
            }
        
        client.close()
        return json.dumps(result)
        
    except ModbusException as exc:
        return json.dumps({"success": False, "error": f"Modbus Exception: {exc}"})
    except Exception as exc:
        return json.dumps({"success": False, "error": f"Exception: {exc}"})


# ── Tool definitions (generated from YAML) ───────────────────────

def _load_recon_tools() -> list[dict]:
    """Load recon tools from YAML definitions, attach Python handlers."""
    from src.agent.tools.tool_loader import load_all_tools, register_python_handler

    tools = load_all_tools()
    register_python_handler(tools, "nvd_lookup", nvd_lookup)
    register_python_handler(tools, "modbus_write", modbus_write)
    register_python_handler(tools, "arp_scan", arp_scan)
    register_python_handler(tools, "ssh_exec", ssh_exec)
    register_python_handler(tools, "try_credential", try_credential)
    register_python_handler(tools, "traceroute", traceroute)
    register_python_handler(tools, "python_exec", python_exec)
    register_python_handler(tools, "http_request", http_request)
    register_python_handler(tools, "tcp_send", tcp_send)
    register_python_handler(tools, "udp_send", udp_send)
    register_python_handler(tools, "mtls_request", mtls_request)
    register_python_handler(tools, "tls_inspect", tls_inspect)
    register_python_handler(tools, "decode_value", decode_value)
    return tools


RECON_TOOLS = _load_recon_tools()
