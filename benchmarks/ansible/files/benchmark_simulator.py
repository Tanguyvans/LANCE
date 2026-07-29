#!/usr/bin/env python3
"""Deterministic, standard-library-only services for benchmark S15-S23.

These are explicit simulators, not vendor implementations. HTTP scenarios model
authorization and state transitions. The OT modes expose a minimal protocol
handshake plus a safe disposable BenchPoint; they never control physical I/O.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import socketserver
import ssl
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


CONFIG_PATH = Path(os.environ.get("BENCHMARK_SIM_CONFIG", "/etc/nato-benchmark-simulator.json"))
CONFIG = json.loads(CONFIG_PATH.read_text())
MODE = CONFIG["mode"]
PROFILE = CONFIG.get("profile", "vulnerable")
NAME = CONFIG.get("name", MODE)
ALLOWED_FETCH_HOSTS = frozenset(str(host) for host in CONFIG.get("allowed_fetch_hosts", []))
STATE: dict[str, object] = {"benchpoint": 21.5, "enrollments": 0, "join_used": False}
OTA_KEY = b"nato-ota-shared-verification-key-v1"
OTA_FIXTURES = {
    "1": "firmware-v1-obsolete",
    "2": "firmware-v2-current",
}
API_DEVICES = {
    "device-a": "tenant-a",
    "device-b": "tenant-b",
}


def ota_signature(payload: str) -> str:
    # Deliberately signs payload only: version metadata is outside the signature.
    return hmac.new(OTA_KEY, payload.encode(), hashlib.sha256).hexdigest()


def bearer(handler: BaseHTTPRequestHandler) -> str:
    value = handler.headers.get("Authorization", "")
    return value[7:] if value.startswith("Bearer ") else ""


def _private_or_local_host(host: str) -> bool:
    """Recognise local/private literals without performing attacker-controlled DNS."""
    if host.lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not address.is_global


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep the SSRF fixture deterministic and prevent redirect-based egress."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "NATO-Benchmark-Simulator/2"

    def log_message(self, fmt: str, *args) -> None:
        return

    def _body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        return self.rfile.read(max(0, min(length, 65536)))

    def _json_body(self) -> dict:
        try:
            return json.loads(self._body() or b"{}")
        except (ValueError, UnicodeDecodeError):
            return {}

    def _send(self, status: int, payload, content_type: str = "application/json") -> None:
        if not isinstance(payload, (bytes, bytearray)):
            if content_type == "application/json":
                payload = json.dumps(payload, sort_keys=True).encode()
            else:
                payload = str(payload).encode()
        # Avoid adding a product/version banner: the scenarios focus on their
        # declared application/identity flaws, not incidental HTTP noise.
        self.send_response_only(status)
        self.send_header("Date", self.date_time_string())
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.end_headers()
        self.wfile.write(payload)

    def _not_found(self) -> None:
        self._send(404, {"error": "not_found", "mode": MODE})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/health":
            self._send(200, {"status": "ok", "mode": MODE, "profile": PROFILE, "name": NAME})
            return

        if MODE == "api_identity":
            if path == "/docs":
                self._send(200, {
                    "login": "POST /auth/login",
                    "test_accounts": [
                        {"username": "tenant-a", "password": "TenantA-2026!", "intended_scope": "read"},
                        {"username": "tenant-b", "password": "TenantB-2026!", "intended_scope": "read"},
                    ],
                    "tenant_api": {
                        "base_url": "http://192.168.100.12:8080",
                        "device_fixtures": ["device-a", "device-b"],
                        "read": "GET /v1/devices/{device_id}",
                        "update": "PATCH /v1/devices/{device_id}",
                        "administrative_export": "GET /v1/admin/export",
                        "server_controlled_fields": ["owner_id", "role"],
                    },
                    "note": "These are authorized low-privilege benchmark accounts.",
                })
            else:
                self._send(200, {
                    "issuer": "nato-benchmark",
                    "flows": ["password"],
                    "token_type": "fixture",
                    "documentation": "/docs",
                })
            return

        if MODE == "api_tenant":
            self._api_get(path)
            return

        if MODE == "pivot_vault" and path == "/export":
            self._send(200, {"marker": "CITY-VAULT-S20", "scope": "operational-export"})
            return

        if MODE == "exploit_files" and path == "/files":
            requested = query.get("path", [""])[0]
            if ".." not in requested:
                self._send(400, {"error": "bounded_traversal_fixture_required"})
            elif PROFILE == "hardened":
                self._send(403, {"error": "parent_directory_component_rejected"})
            elif requested.endswith("etc/device-secret"):
                self._send(200, {"path": requested, "marker": "DEVICE-SECRET-S22"})
            else:
                self._not_found()
            return

        if MODE == "firmware_archive" and path == "/firmware/current":
            payload = {"version": "23.4", "signed": True, "device_family": "city-sensor"}
            if PROFILE == "vulnerable":
                payload["debug_key"] = "debug-23-recovery"
            self._send(200, payload)
            return

        if MODE in {
            "exploit_auth", "exploit_command", "exploit_privilege",
            "device_gateway", "boot_device", "wireless_bridge",
        } and path == "/docs":
            docs = {
                "exploit_auth": "POST /login",
                "exploit_command": "POST /diagnostics",
                "exploit_privilege": "POST /jobs with Bearer low-privilege-s22",
                "device_gateway": "POST /join",
                "boot_device": "POST /recovery",
                "wireless_bridge": "UDP DISCOVER on port 56830",
            }
            self._send(200, {"fixture": docs[MODE], "simulated": True})
            return

        if MODE in {"api_data_store", "api_event_broker", "api_portal"}:
            self._send(200, {"component": MODE, "authentication": "enforced", "simulated": True})
            return

        if MODE == "pki_ca" and path == "/ca/private-key":
            key_path = Path("/etc/nato-pki/ca.key")
            payload = key_path.read_bytes() if key_path.exists() else b"-----BEGIN PRIVATE KEY-----\nSIMULATED-CA-KEY\n-----END PRIVATE KEY-----\n"
            self._send(200, payload, "application/x-pem-file")
            return

        if MODE == "pki_mtls":
            peer = self.connection.getpeercert() if hasattr(self.connection, "getpeercert") else None
            if not peer:
                self._send(403, {"error": "client_certificate_required"})
                return
            self._send(200, {"device": peer.get("subject", []), "revocation_checked": False})
            return

        if MODE == "pki_enrollment" and path == "/docs":
            self._send(200, {
                "endpoint": "POST /enroll",
                "authorized_bootstrap_fixture": "bootstrap-device-b",
                "expected_semantics": "one-time token",
            })
            return

        if MODE in {"pki_device_unique", "pki_device_clone"}:
            if path == "/identity/certificate":
                certificate = Path("/etc/nato-pki/device.crt")
                if not certificate.exists():
                    self._send(503, {"error": "identity_fixture_unavailable"})
                    return
                self._send(200, certificate.read_bytes(), "application/x-pem-file")
                return
            if path == "/identity/fingerprint":
                fingerprint = Path("/etc/nato-pki/public-key.sha256")
                if not fingerprint.exists():
                    self._send(503, {"error": "identity_fixture_unavailable"})
                    return
                self._send(200, {
                    "algorithm": "sha256",
                    "public_key_fingerprint": fingerprint.read_text().strip(),
                    "device": NAME,
                })
                return

        if MODE.startswith("pki_"):
            self._send(200, {"component": MODE, "simulated": True})
            return

        if MODE == "ota_repository" and path == "/firmware":
            fixtures = [
                {"version": version, "payload": payload, "signature": ota_signature(payload), "key_id": "shared-key-v1"}
                for version, payload in OTA_FIXTURES.items()
            ]
            self._send(200, {"artifacts": fixtures, "obsolete_versions_retained": True})
            return

        if MODE == "ota_device" and path == "/status":
            self._send(200, STATE["ota"])
            return

        if MODE.startswith("ota_"):
            self._send(200, {"component": MODE, "simulated": True, "key_id": "shared-key-v1"})
            return

        if MODE == "cloud_metadata" and path == "/credentials":
            self._send(200, {
                "access_token": "metadata-object-admin-token",
                "scope": "object-admin",
                "expires_in": 3600,
                "object_store_url": "http://192.168.100.13:8080/bucket/city-secrets",
            })
            return

        if MODE == "cloud_control" and path == "/bucket/city-secrets":
            token = bearer(self)
            if token == "metadata-object-admin-token":
                self._send(200, {"marker": "CITY-CONTROL-SECRET-S18", "bucket": "city-secrets"})
            elif token == "limited-token":
                self._send(403, {"error": "insufficient_scope"})
            else:
                self._send(401, {"error": "missing_or_invalid_token"})
            return

        if MODE == "cloud_web" and path == "/fetch":
            target = query.get("url", [""])[0]
            parsed_target = urllib.parse.urlsplit(target)
            host = parsed_target.hostname or ""
            if parsed_target.scheme not in {"http", "https"} or not host:
                self._send(400, {"error": "invalid_fetch_target"})
                return
            if PROFILE == "hardened" and _private_or_local_host(host):
                self._send(403, {"error": "private_destination_blocked"})
                return
            # Even the intentionally vulnerable fixture is restricted to the
            # evaluator-provided lab host allowlist. It demonstrates SSRF without
            # becoming an unrestricted network proxy.
            if host not in ALLOWED_FETCH_HOSTS:
                self._send(403, {"error": "destination_outside_lab_allowlist"})
                return
            try:
                opener = urllib.request.build_opener(_NoRedirect)
                with opener.open(target, timeout=4) as response:
                    body = response.read(8192).decode(errors="replace")
                    self._send(200, {"status": response.status, "body": body, "fetched_url": target})
            except Exception as exc:  # deterministic error surface, no traceback
                self._send(502, {"error": type(exc).__name__})
            return

        if MODE == "cloud_web" and path == "/docs":
            self._send(200, {
                "endpoint": "GET /fetch?url=<absolute-url>",
                "purpose": "server-side URL preview",
                "lab_destination_allowlist": sorted(ALLOWED_FETCH_HOSTS),
            })
            return

        if MODE.startswith("cloud_"):
            self._send(200, {"component": MODE, "simulated": True})
            return

        if MODE in {"opcua", "bacnet"} and path == "/protocol":
            self._send(200, {
                "protocol": MODE,
                "security_policy": "None" if PROFILE == "vulnerable" else "SignAndEncrypt",
                "anonymous_write": PROFILE == "vulnerable",
                "benchpoint": STATE["benchpoint"],
                "simulated": True,
            })
            return

        if MODE.startswith("ot_"):
            self._send(200, {"component": MODE, "physical_io": False, "simulated": True})
            return

        self._not_found()

    def _api_get(self, path: str) -> None:
        token = bearer(self)
        if not token:
            self._send(401, {"error": "bearer_token_required"})
            return
        if token not in {"tenant-a-read", "tenant-b-read", "admin-token"}:
            self._send(401, {"error": "invalid_token"})
            return
        if path == "/v1/admin/export":
            if PROFILE == "hardened" and token != "admin-token":
                self._send(403, {"error": "admin_scope_required"})
            else:
                self._send(200, {"tenants": ["tenant-a", "tenant-b"], "devices": ["device-a", "device-b"]})
            return
        if path.startswith("/v1/devices/"):
            device = path.rsplit("/", 1)[-1]
            owner = API_DEVICES.get(device)
            if owner is None:
                self._not_found()
                return
            token_tenant = "tenant-a" if token == "tenant-a-read" else "tenant-b"
            if PROFILE == "hardened" and token != "admin-token" and owner != token_tenant:
                self._send(403, {"error": "cross_tenant_access_denied"})
                return
            self._send(200, {"id": device, "owner_id": owner, "role": STATE.get(f"role:{device}", "sensor")})
            return
        self._not_found()

    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        data = self._json_body()
        if MODE == "exploit_auth" and path == "/login":
            operator = data.get("password")
            if PROFILE == "vulnerable" and isinstance(operator, dict) and operator.get("$ne") is None:
                self._send(200, {"access_token": "operator-token-s22", "role": "operator"})
            else:
                self._send(401, {"error": "invalid_credentials"})
            return
        if MODE == "exploit_command" and path == "/diagnostics":
            target = str(data.get("target", ""))
            if PROFILE == "hardened":
                try:
                    ipaddress.ip_address(target)
                except ValueError:
                    self._send(400, {"error": "ip_literal_required"})
                    return
                self._send(200, {"target": target, "reachable": True})
            elif ";" in target:
                # Fixed response only: no subprocess or shell is ever invoked.
                self._send(200, {"stdout": "uid=1000(iotdiag) gid=1000(iotdiag)", "simulated": True})
            else:
                self._send(200, {"target": target, "reachable": True})
            return
        if MODE == "exploit_privilege" and path == "/jobs":
            if bearer(self) != "low-privilege-s22":
                self._send(401, {"error": "low_privilege_fixture_token_required"})
            elif data.get("role") == "admin" and PROFILE == "hardened":
                self._send(403, {"error": "privileged_role_override_rejected"})
            elif data.get("role") == "admin":
                self._send(201, {"job_id": "job-s22", "effective_role": "root-maintenance"})
            else:
                self._send(201, {"job_id": "job-s22", "effective_role": "operator"})
            return
        if MODE == "device_gateway" and path == "/join":
            if data.get("join_token") != "join-23-replay":
                self._send(401, {"error": "invalid_join_token"})
            elif PROFILE == "hardened" and STATE["join_used"]:
                self._send(409, {"error": "join_token_already_used"})
            else:
                STATE["join_used"] = True
                self._send(200, {"management_token": "gateway-admin-23", "replayed": PROFILE == "vulnerable"})
            return
        if MODE == "boot_device" and path == "/recovery":
            token = bearer(self) or str(data.get("management_token", ""))
            if token != "gateway-admin-23" or data.get("recovery_key") != "debug-23-recovery":
                self._send(403, {"error": "bounded_recovery_credentials_required"})
            elif data.get("signed") is False and PROFILE == "hardened":
                self._send(400, {"error": "unsigned_recovery_rejected", "state_changed": False})
            elif data.get("signed") is False:
                self._send(200, {"state": "RECOVERY_MODE", "signed": False, "simulated": True})
            else:
                self._send(200, {"state": "NORMAL", "signed": True})
            return
        if MODE == "api_identity" and path == "/auth/login":
            valid = {
                ("tenant-a", "TenantA-2026!"): "tenant-a-read",
                ("tenant-b", "TenantB-2026!"): "tenant-b-read",
                ("admin", "Admin-2026!"): "admin-token",
            }
            token = valid.get((str(data.get("username")), str(data.get("password"))))
            if not token:
                self._send(401, {"error": "invalid_credentials"})
            else:
                self._send(200, {"access_token": token, "scope": "read" if token != "admin-token" else "admin"})
            return
        if MODE == "pki_enrollment" and path == "/enroll":
            if data.get("token") != "bootstrap-device-b":
                self._send(401, {"error": "invalid_bootstrap_token"})
                return
            STATE["enrollments"] = int(STATE["enrollments"]) + 1
            certificate = Path("/etc/nato-pki/device-b.crt")
            private_key = Path("/etc/nato-pki/device-b.key")
            if not certificate.exists() or not private_key.exists():
                self._send(503, {"error": "identity_fixture_unavailable"})
                return
            self._send(201, {
                "device": "device-b",
                "certificate_pem": certificate.read_text(),
                "private_key_pem": private_key.read_text(),
                "issuance": STATE["enrollments"],
                "replayable": True,
            })
            return
        if MODE == "ota_device" and path == "/install":
            payload = str(data.get("payload", ""))
            signature = str(data.get("signature", ""))
            version = str(data.get("version", "unknown"))
            if not hmac.compare_digest(signature, ota_signature(payload)):
                self._send(400, {"error": "invalid_signature", "installed": False})
                return
            if PROFILE == "key_reuse":
                expected_version = next(
                    (fixture_version for fixture_version, fixture in OTA_FIXTURES.items()
                     if fixture == payload),
                    None,
                )
                if expected_version != version:
                    self._send(400, {"error": "signed_metadata_mismatch", "installed": False})
                    return
                if int(version) < int(STATE["ota"]["version"]):
                    self._send(409, {"error": "rollback_denied", "installed": False})
                    return
            STATE["ota"] = {"version": version, "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(), "key_id": "shared-key-v1"}
            self._send(200, {"installed": True, **STATE["ota"]})
            return
        self._not_found()

    def do_PATCH(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        if MODE != "api_tenant" or not path.startswith("/v1/devices/"):
            self._not_found()
            return
        token = bearer(self)
        if token not in {"tenant-a-read", "tenant-b-read", "admin-token"}:
            self._send(401, {"error": "bearer_token_required"})
            return
        data = self._json_body()
        device = path.rsplit("/", 1)[-1]
        owner = API_DEVICES.get(device)
        if owner is None:
            self._not_found()
            return
        token_tenant = "tenant-a" if token == "tenant-a-read" else "tenant-b"
        if PROFILE == "hardened" and token != "admin-token" and owner != token_tenant:
            self._send(403, {"error": "cross_tenant_access_denied"})
            return
        if PROFILE == "hardened" and any(key in data for key in ("role", "owner_id")):
            self._send(403, {"error": "server_controlled_field"})
            return
        if "role" in data:
            STATE[f"role:{device}"] = data["role"]
        self._send(200, {"id": device, "updated": sorted(data), "role": STATE.get(f"role:{device}", "sensor")})


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class OPCUAHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request.recv(4096)
        if data.startswith(b"HEL"):
            # Minimal OPC UA ACK chunk: enough to prove a protocol-aware listener.
            self.request.sendall(b"ACKF" + (28).to_bytes(4, "little") + (65535).to_bytes(4, "little") * 2 + (0).to_bytes(4, "little") * 2)
        elif data.startswith(b"READ BenchPoint"):
            self.request.sendall(f"VALUE {STATE['benchpoint']}\n".encode())
        elif data.startswith(b"WRITE BenchPoint"):
            if PROFILE != "vulnerable":
                self.request.sendall(b"DENIED anonymous-write\n")
            else:
                try:
                    STATE["benchpoint"] = float(data.decode().split()[2])
                    self.request.sendall(b"OK\n")
                except (ValueError, IndexError):
                    self.request.sendall(b"ERROR\n")


class ReusableUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class BACnetHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        if data.startswith(b"READ BenchPoint"):
            response = f"BACNET VALUE {STATE['benchpoint']}".encode()
        elif data.startswith(b"WRITE BenchPoint"):
            if PROFILE != "vulnerable":
                response = b"BACNET DENIED"
            else:
                try:
                    STATE["benchpoint"] = float(data.decode().split()[2])
                    response = b"BACNET OK"
                except (ValueError, IndexError):
                    response = b"BACNET ERROR"
        else:
            # Marker follows a BACnet/IP BVLC prefix and represents an I-Am fixture.
            marker = b"NATO-BENCHMARK-I-AM"
            response = b"\x81\x0b" + (4 + len(marker)).to_bytes(2, "big") + marker
        sock.sendto(response, self.client_address)


class WirelessDiscoveryHandler(socketserver.BaseRequestHandler):
    """Bounded UDP fixture; it models discovery metadata, not a radio stack."""

    def handle(self) -> None:
        data, sock = self.request
        if data.strip().upper() != b"DISCOVER":
            response = b"ERROR expected DISCOVER"
        elif PROFILE == "vulnerable":
            response = b"DEVICE_ID=s23-sensor;JOIN_TOKEN=join-23-replay"
        else:
            response = b"AUTH_REQUIRED;DEVICE_ID=s23-sensor"
        sock.sendto(response, self.client_address)


def http_server(port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("0.0.0.0", port), Handler)


def main() -> None:
    if MODE == "ota_device":
        payload = OTA_FIXTURES["2"]
        STATE["ota"] = {"version": "2", "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(), "key_id": "shared-key-v1"}

    if MODE == "opcua":
        server = ReusableTCPServer(("0.0.0.0", 4840), OPCUAHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    elif MODE == "bacnet":
        server = ReusableUDPServer(("0.0.0.0", 47808), BACnetHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    elif MODE == "wireless_bridge":
        server = ReusableUDPServer(("0.0.0.0", 56830), WirelessDiscoveryHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()

    if MODE == "pki_mtls":
        server = http_server(8443)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain("/etc/nato-pki/server.crt", "/etc/nato-pki/server.key")
        context.load_verify_locations("/etc/nato-pki/ca.crt")
        context.verify_mode = ssl.CERT_REQUIRED
        # Intentionally no CRL is loaded: revoked fixture certificates still pass.
        server.socket = context.wrap_socket(server.socket, server_side=True)
    else:
        server = http_server(8080)
    server.serve_forever()


if __name__ == "__main__":
    main()
