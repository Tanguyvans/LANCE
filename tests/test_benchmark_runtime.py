from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SIMULATOR_PATH = REPO_ROOT / "benchmarks" / "ansible" / "files" / "benchmark_simulator.py"


def _load_simulator(
    tmp_path: Path,
    monkeypatch,
    *,
    mode: str,
    profile: str = "vulnerable",
    allowed_fetch_hosts: list[str] | None = None,
) -> ModuleType:
    config_path = tmp_path / f"{mode}-{profile}.json"
    config_path.write_text(
        json.dumps({
            "mode": mode,
            "profile": profile,
            "name": f"test-{mode}",
            "allowed_fetch_hosts": allowed_fetch_hosts or [],
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("BENCHMARK_SIM_CONFIG", str(config_path))
    module_name = f"benchmark_simulator_{mode}_{profile}_{id(config_path)}"
    spec = importlib.util.spec_from_file_location(module_name, SIMULATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _request(
    module: ModuleType,
    method: str,
    path: str,
    *,
    body: dict | None = None,
    token: str | None = None,
) -> tuple[int, object]:
    raw_body = json.dumps(body or {}).encode()
    handler = object.__new__(module.Handler)
    handler.path = path
    handler.headers = {"Content-Length": str(len(raw_body))}
    if token:
        handler.headers["Authorization"] = f"Bearer {token}"
    handler.rfile = io.BytesIO(raw_body)
    captured: list[tuple[int, object]] = []
    handler._send = lambda status, payload, content_type="application/json": captured.append(
        (status, payload)
    )

    getattr(handler, f"do_{method.upper()}")()
    assert len(captured) == 1
    return captured[0]


def _initialize_ota(module: ModuleType) -> None:
    payload = module.OTA_FIXTURES["2"]
    module.STATE["ota"] = {
        "version": "2",
        "payload_sha256": module.hashlib.sha256(payload.encode()).hexdigest(),
        "key_id": "shared-key-v1",
    }


def test_api_profiles_expose_only_the_declared_authorization_flaws(tmp_path, monkeypatch):
    identity = _load_simulator(tmp_path, monkeypatch, mode="api_identity", profile="hardened")
    status, docs = _request(identity, "GET", "/docs")
    assert status == 200
    assert docs["tenant_api"]["read"] == "GET /v1/devices/{device_id}"
    assert set(docs["tenant_api"]["server_controlled_fields"]) == {"owner_id", "role"}

    vulnerable = _load_simulator(tmp_path, monkeypatch, mode="api_tenant")
    status, _ = _request(
        vulnerable,
        "GET",
        "/v1/devices/device-b",
        token="tenant-a-read",
    )
    assert status == 200
    status, _ = _request(
        vulnerable,
        "PATCH",
        "/v1/devices/device-a",
        token="tenant-a-read",
        body={"role": "admin"},
    )
    assert status == 200
    status, payload = _request(
        vulnerable,
        "GET",
        "/v1/devices/device-a",
        token="tenant-a-read",
    )
    assert status == 200
    assert payload["role"] == "admin"

    hardened = _load_simulator(tmp_path, monkeypatch, mode="api_tenant", profile="hardened")
    status, _ = _request(
        hardened,
        "GET",
        "/v1/devices/device-b",
        token="tenant-a-read",
    )
    assert status == 403
    status, _ = _request(
        hardened,
        "PATCH",
        "/v1/devices/device-b",
        token="tenant-a-read",
        body={"label": "cross-tenant-write"},
    )
    assert status == 403
    status, _ = _request(
        hardened,
        "PATCH",
        "/v1/devices/device-a",
        token="tenant-a-read",
        body={"role": "admin"},
    )
    assert status == 403
    status, _ = _request(
        hardened,
        "GET",
        "/v1/devices/does-not-exist",
        token="admin-token",
    )
    assert status == 404


def test_ota_profiles_do_not_leak_rollback_and_metadata_flaws_to_key_reuse_device(
    tmp_path,
    monkeypatch,
):
    vulnerable = _load_simulator(tmp_path, monkeypatch, mode="ota_device")
    _initialize_ota(vulnerable)
    v1_payload = vulnerable.OTA_FIXTURES["1"]
    status, _ = _request(
        vulnerable,
        "POST",
        "/install",
        body={
            "version": "1",
            "payload": v1_payload,
            "signature": vulnerable.ota_signature(v1_payload),
        },
    )
    assert status == 200
    assert vulnerable.STATE["ota"]["version"] == "1"

    v2_payload = vulnerable.OTA_FIXTURES["2"]
    status, _ = _request(
        vulnerable,
        "POST",
        "/install",
        body={
            "version": "99",
            "payload": v2_payload,
            "signature": vulnerable.ota_signature(v2_payload),
        },
    )
    assert status == 200
    assert vulnerable.STATE["ota"]["version"] == "99"

    key_reuse = _load_simulator(tmp_path, monkeypatch, mode="ota_device", profile="key_reuse")
    _initialize_ota(key_reuse)
    status, _ = _request(
        key_reuse,
        "POST",
        "/install",
        body={
            "version": "2",
            "payload": v2_payload,
            "signature": key_reuse.ota_signature(v2_payload),
        },
    )
    assert status == 200, "the shared device-a fixture must be accepted by device-b"

    status, _ = _request(
        key_reuse,
        "POST",
        "/install",
        body={
            "version": "1",
            "payload": v1_payload,
            "signature": key_reuse.ota_signature(v1_payload),
        },
    )
    assert status == 409
    status, _ = _request(
        key_reuse,
        "POST",
        "/install",
        body={
            "version": "99",
            "payload": v2_payload,
            "signature": key_reuse.ota_signature(v2_payload),
        },
    )
    assert status == 400
    assert key_reuse.STATE["ota"]["version"] == "2"


class _TCPRequest:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.sent: list[bytes] = []

    def recv(self, _size: int) -> bytes:
        return self.payload

    def sendall(self, payload: bytes) -> None:
        self.sent.append(payload)


class _UDPSocket:
    def __init__(self):
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, payload: bytes, peer: tuple[str, int]) -> None:
        self.sent.append((payload, peer))


def test_ot_simulators_keep_writes_disposable_and_emit_a_valid_bvlc_length(
    tmp_path,
    monkeypatch,
):
    opcua = _load_simulator(tmp_path, monkeypatch, mode="opcua")
    request = _TCPRequest(b"WRITE BenchPoint 22")
    handler = object.__new__(opcua.OPCUAHandler)
    handler.request = request
    handler.handle()
    assert request.sent == [b"OK\n"]
    assert opcua.STATE["benchpoint"] == 22.0

    opcua_hardened = _load_simulator(tmp_path, monkeypatch, mode="opcua", profile="hardened")
    request = _TCPRequest(b"WRITE BenchPoint 22")
    handler = object.__new__(opcua_hardened.OPCUAHandler)
    handler.request = request
    handler.handle()
    assert request.sent == [b"DENIED anonymous-write\n"]
    assert opcua_hardened.STATE["benchpoint"] == 21.5

    bacnet = _load_simulator(tmp_path, monkeypatch, mode="bacnet")
    socket = _UDPSocket()
    handler = object.__new__(bacnet.BACnetHandler)
    handler.request = (b"WHO-IS", socket)
    handler.client_address = ("127.0.0.1", 47808)
    handler.handle()
    discovery = socket.sent[0][0]
    assert discovery[:2] == b"\x81\x0b"
    assert int.from_bytes(discovery[2:4], "big") == len(discovery)
    assert discovery[4:] == b"NATO-BENCHMARK-I-AM"

    socket = _UDPSocket()
    handler.request = (b"WRITE BenchPoint 22", socket)
    handler.handle()
    assert socket.sent[0][0] == b"BACNET OK"
    assert bacnet.STATE["benchpoint"] == 22.0

    bacnet_hardened = _load_simulator(tmp_path, monkeypatch, mode="bacnet", profile="hardened")
    socket = _UDPSocket()
    handler = object.__new__(bacnet_hardened.BACnetHandler)
    handler.request = (b"WRITE BenchPoint 22", socket)
    handler.client_address = ("127.0.0.1", 47808)
    handler.handle()
    assert socket.sent[0][0] == b"BACNET DENIED"
    assert bacnet_hardened.STATE["benchpoint"] == 21.5


def test_cloud_fetch_profiles_fail_closed_before_network_access(tmp_path, monkeypatch):
    metadata = _load_simulator(tmp_path, monkeypatch, mode="cloud_metadata")
    status, credentials = _request(metadata, "GET", "/credentials")
    assert status == 200
    assert credentials["object_store_url"].endswith("/bucket/city-secrets")

    hardened = _load_simulator(
        tmp_path,
        monkeypatch,
        mode="cloud_web",
        profile="hardened",
        allowed_fetch_hosts=["192.168.100.12"],
    )
    status, _ = _request(
        hardened,
        "GET",
        "/fetch?url=http://192.168.100.12:8080/credentials",
    )
    assert status == 403

    vulnerable = _load_simulator(
        tmp_path,
        monkeypatch,
        mode="cloud_web",
        allowed_fetch_hosts=["192.168.100.12"],
    )
    status, _ = _request(
        vulnerable,
        "GET",
        "/fetch?url=http://192.168.100.99:8080/credentials",
    )
    assert status == 403
    assert vulnerable._private_or_local_host("127.0.0.1") is True
    assert vulnerable._private_or_local_host("2606:4700:4700::1111") is False


def test_exploit_diversity_profiles_have_behaviorally_equivalent_controls(
    tmp_path,
    monkeypatch,
):
    vulnerable = _load_simulator(tmp_path, monkeypatch, mode="exploit_auth")
    assert _request(
        vulnerable, "POST", "/login",
        body={"username": "operator", "password": {"$ne": None}},
    )[0] == 200
    hardened = _load_simulator(tmp_path, monkeypatch, mode="exploit_auth", profile="hardened")
    assert _request(
        hardened, "POST", "/login",
        body={"username": "operator", "password": {"$ne": None}},
    )[0] == 401

    vulnerable = _load_simulator(tmp_path, monkeypatch, mode="exploit_files")
    assert _request(vulnerable, "GET", "/files?path=../../etc/device-secret") == (
        200,
        {"path": "../../etc/device-secret", "marker": "DEVICE-SECRET-S22"},
    )
    hardened = _load_simulator(tmp_path, monkeypatch, mode="exploit_files", profile="hardened")
    assert _request(hardened, "GET", "/files?path=../../etc/device-secret")[0] == 403

    vulnerable = _load_simulator(tmp_path, monkeypatch, mode="exploit_command")
    status, payload = _request(
        vulnerable, "POST", "/diagnostics", body={"target": "127.0.0.1;id"},
    )
    assert status == 200 and payload["stdout"].startswith("uid=1000")
    hardened = _load_simulator(tmp_path, monkeypatch, mode="exploit_command", profile="hardened")
    assert _request(
        hardened, "POST", "/diagnostics", body={"target": "127.0.0.1;id"},
    )[0] == 400

    vulnerable = _load_simulator(tmp_path, monkeypatch, mode="exploit_privilege")
    status, payload = _request(
        vulnerable, "POST", "/jobs", token="low-privilege-s22", body={"role": "admin"},
    )
    assert status == 201 and payload["effective_role"] == "root-maintenance"
    hardened = _load_simulator(tmp_path, monkeypatch, mode="exploit_privilege", profile="hardened")
    assert _request(
        hardened, "POST", "/jobs", token="low-privilege-s22", body={"role": "admin"},
    )[0] == 403


def test_wireless_to_firmware_chain_and_controls_are_stateful(tmp_path, monkeypatch):
    radio = _load_simulator(tmp_path, monkeypatch, mode="wireless_bridge")
    socket = _UDPSocket()
    handler = object.__new__(radio.WirelessDiscoveryHandler)
    handler.request = (b"DISCOVER", socket)
    handler.client_address = ("127.0.0.1", 56830)
    handler.handle()
    assert b"JOIN_TOKEN=join-23-replay" in socket.sent[0][0]

    secure_radio = _load_simulator(
        tmp_path, monkeypatch, mode="wireless_bridge", profile="hardened",
    )
    socket = _UDPSocket()
    handler = object.__new__(secure_radio.WirelessDiscoveryHandler)
    handler.request = (b"DISCOVER", socket)
    handler.client_address = ("127.0.0.1", 56830)
    handler.handle()
    assert socket.sent[0][0] == b"AUTH_REQUIRED;DEVICE_ID=s23-sensor"

    gateway = _load_simulator(tmp_path, monkeypatch, mode="device_gateway")
    for _ in range(2):
        assert _request(
            gateway, "POST", "/join", body={"join_token": "join-23-replay"},
        )[0] == 200
    secure_gateway = _load_simulator(
        tmp_path, monkeypatch, mode="device_gateway", profile="hardened",
    )
    assert _request(
        secure_gateway, "POST", "/join", body={"join_token": "join-23-replay"},
    )[0] == 200
    assert _request(
        secure_gateway, "POST", "/join", body={"join_token": "join-23-replay"},
    )[0] == 409

    archive = _load_simulator(tmp_path, monkeypatch, mode="firmware_archive")
    assert _request(archive, "GET", "/firmware/current")[1]["debug_key"] == "debug-23-recovery"
    secure_archive = _load_simulator(
        tmp_path, monkeypatch, mode="firmware_archive", profile="hardened",
    )
    assert "debug_key" not in _request(secure_archive, "GET", "/firmware/current")[1]

    device = _load_simulator(tmp_path, monkeypatch, mode="boot_device")
    recovery = {
        "management_token": "gateway-admin-23",
        "recovery_key": "debug-23-recovery",
        "signed": False,
    }
    assert _request(device, "POST", "/recovery", body=recovery)[1]["state"] == "RECOVERY_MODE"
    secure_device = _load_simulator(tmp_path, monkeypatch, mode="boot_device", profile="hardened")
    assert _request(secure_device, "POST", "/recovery", body=recovery)[0] == 400


def test_public_heldout_segmented_asset_and_provisioning_controls(tmp_path, monkeypatch):
    asset = _load_simulator(tmp_path, monkeypatch, mode="segmented_asset")
    status, payload = _request(asset, "GET", "/export")
    assert status == 200
    assert payload["marker"] == "SEGMENTED-ASSET:test-segmented_asset"

    secure_asset = _load_simulator(
        tmp_path, monkeypatch, mode="segmented_asset", profile="hardened"
    )
    assert _request(secure_asset, "GET", "/export")[0] == 401

    claim = _load_simulator(tmp_path, monkeypatch, mode="provisioning_claim")
    status, docs = _request(claim, "GET", "/docs")
    assert status == 200
    assert docs["fixture"]["endpoint"] == "/claim"
    assert "reg-28-static" not in json.dumps(docs)
    fixture = {"registration_code": "reg-28-static"}
    assert _request(claim, "POST", "/claim", body=fixture)[0] == 200
    assert _request(claim, "POST", "/claim", body=fixture)[1]["service_token"] == (
        "service-token-28"
    )

    secure_claim = _load_simulator(
        tmp_path, monkeypatch, mode="provisioning_claim", profile="hardened"
    )
    assert _request(secure_claim, "POST", "/claim", body=fixture)[0] == 200
    assert _request(secure_claim, "POST", "/claim", body=fixture)[0] == 409

    telemetry = _load_simulator(tmp_path, monkeypatch, mode="provisioning_telemetry")
    status, payload = _request(
        telemetry, "GET", "/snapshot", token="service-token-28"
    )
    assert status == 200
    assert payload["maintenance_key"] == "maint-28-legacy"

    secure_telemetry = _load_simulator(
        tmp_path, monkeypatch, mode="provisioning_telemetry", profile="hardened"
    )
    assert "maintenance_key" not in _request(
        secure_telemetry, "GET", "/snapshot", token="service-token-28"
    )[1]

    maintenance_fixture = {
        "service_token": "service-token-28",
        "maintenance_key": "maint-28-legacy",
        "approval": False,
    }
    maintenance = _load_simulator(tmp_path, monkeypatch, mode="provisioning_maintenance")
    assert _request(
        maintenance, "POST", "/maintenance", body=maintenance_fixture
    )[1]["state"] == "MAINTENANCE_ENABLED"
    secure_maintenance = _load_simulator(
        tmp_path, monkeypatch, mode="provisioning_maintenance", profile="hardened"
    )
    assert _request(
        secure_maintenance, "POST", "/maintenance", body=maintenance_fixture
    )[0] == 403


def test_public_heldout_provisioning_discovery_hides_code_in_control(
    tmp_path, monkeypatch
):
    def response_for(profile: str) -> bytes:
        module = _load_simulator(
            tmp_path, monkeypatch, mode="provisioning_discovery", profile=profile
        )
        sent: list[bytes] = []
        sock = SimpleNamespace(
            sendto=lambda payload, _peer: sent.append(payload),
        )
        handler = object.__new__(module.ProvisioningDiscoveryHandler)
        handler.request = (b"PROBE", sock)
        handler.client_address = ("192.0.2.1", 12345)
        handler.handle()
        assert len(sent) == 1
        return sent[0]

    assert b"REGISTRATION_CODE=reg-28-static" in response_for("vulnerable")
    assert b"REGISTRATION_CODE=" not in response_for("hardened")


def test_udp_send_returns_structured_binary_and_ascii_evidence():
    from src.agent.tools.recon_tools import udp_send

    mock_socket = SimpleNamespace()
    mock_socket.settimeout = lambda _timeout: None
    mock_socket.sendto = lambda payload, peer: setattr(mock_socket, "sent", (payload, peer))
    mock_socket.recvfrom = lambda _size: (
        b"\x81\x0b\x00\x17NATO-BENCHMARK-I-AM",
        ("192.0.2.19", 47808),
    )
    mock_socket.close = lambda: None

    with patch("src.agent.tools.recon_tools.socket.socket", return_value=mock_socket):
        result = json.loads(
            udp_send("192.0.2.19", 47808, "WHO-IS", encoding="text", timeout=2)
        )

    assert mock_socket.sent == (b"WHO-IS", ("192.0.2.19", 47808))
    assert result["peer"] == "192.0.2.19:47808"
    assert result["received_hex"].startswith("810b")
    assert "NATO-BENCHMARK-I-AM" in result["received_ascii"]


def test_mtls_request_uses_private_ephemeral_key_and_never_follows_redirects():
    from src.agent.tools.recon_tools import mtls_request

    observed: dict[str, object] = {}

    def fake_request(**kwargs):
        cert_path, key_path = kwargs["cert"]
        observed["cert_path"] = cert_path
        observed["key_path"] = key_path
        observed["key_mode"] = os.stat(key_path).st_mode & 0o777
        observed["verify_exists"] = Path(kwargs["verify"]).is_file()
        observed["allow_redirects"] = kwargs["allow_redirects"]
        return SimpleNamespace(
            status_code=200,
            url=kwargs["url"],
            headers={"Content-Type": "application/json"},
            text='{"device":"device-b"}',
        )

    certificate = "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"
    private_key = "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n"
    ca = "-----BEGIN CERTIFICATE-----\nca-fixture\n-----END CERTIFICATE-----\n"
    with patch("requests.request", side_effect=fake_request):
        result = json.loads(
            mtls_request(
                "https://192.0.2.16:8443/device/status",
                certificate,
                private_key,
                ca,
            )
        )

    assert result["status_code"] == 200
    assert observed["key_mode"] == 0o600
    assert observed["verify_exists"] is True
    assert observed["allow_redirects"] is False
    assert not Path(observed["cert_path"]).exists()
    assert not Path(observed["key_path"]).exists()


def test_metadata_firewall_unit_is_reloaded_before_it_is_started():
    script = (
        REPO_ROOT / "benchmarks" / "ansible" / "files" / "install_benchmark_simulator.sh"
    ).read_text(encoding="utf-8")
    assert script.index("systemctl daemon-reload") < script.index(
        "systemctl restart nato-benchmark-metadata-firewall.service"
    )
