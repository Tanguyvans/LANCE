"""Phase 3: protocol scanners and bounded evidence extraction."""
import json


def test_compact_mode_requires_protocol_evidence_for_ot_ports_and_preserves_full_mode():
    from src.agent import scanner as scanner_mod

    entries = [{
        "tool": "nmap_scan",
        "kwargs": {"target": "192.0.2.20", "ports": "102"},
        "result": json.dumps({
            "stdout": "102/tcp open iso-tsap Siemens S7",
            "return_code": 0,
        }),
    }]
    device = {"id": "ot", "ip": "192.0.2.20", "role": "ot_opcua_server"}

    full = scanner_mod.extract_findings({"nmap": entries}, device)
    compact = scanner_mod.extract_findings({"nmap": entries}, device, compact=True)
    full_ot = next(finding for finding in full if finding["type"] == "no_auth")
    compact_ot = next(finding for finding in compact if finding["type"] == "no_auth")

    assert full_ot["exploitation_status"] == "confirmed"
    assert compact_ot["exploitation_status"] == "suspected"
    assert compact_ot["compact_evidence_kind"] == "open_service"
    assert compact_ot["compact_required_probe"] == "protocol_response"

    listing = [{
        "tool": "curl_headers",
        "kwargs": {"url": "http://192.0.2.20/backup/"},
        "result": json.dumps({
            "stdout": "HTTP/1.1 200 OK\n<h1>Index of /</h1>",
            "return_code": 0,
        }),
    }]
    web = {"id": "web", "ip": "192.0.2.20", "role": "web_server"}
    assert any(finding["type"] == "directory_listing" for finding in scanner_mod.extract_findings({"http": listing}, web))
    assert not any(finding["type"] == "directory_listing" for finding in scanner_mod.extract_findings({"http": listing}, web, compact=True))


def test_s15_api_probes_require_positive_authorization_evidence():
    from src.agent import scanner as scanner_mod

    def entry(method, path, status, body, headers=None):
        kwargs = {
            "method": method,
            "url": f"http://192.0.2.15:8080{path}",
        }
        if headers:
            kwargs["headers"] = headers
        return {
            "tool": "http_request",
            "kwargs": kwargs,
            "result": json.dumps({"status_code": status, "body": body}),
        }

    token = {"Authorization": "Bearer tenant-a-read"}
    positive = [
        entry("GET", "/v1/devices/device-a", 401, '{"error":"bearer_token_required"}'),
        entry("GET", "/v1/devices/device-b", 200, '{"id":"device-b","owner_id":"tenant-b"}', token),
        entry("GET", "/v1/admin/export", 200, '{"tenants":["tenant-a","tenant-b"],"devices":["device-a","device-b"]}', token),
        entry("PATCH", "/v1/devices/device-a", 200, '{"updated":["role"],"role":"admin"}', token),
        entry("GET", "/v1/devices/device-a", 200, '{"id":"device-a","role":"admin"}', token),
    ]
    findings = scanner_mod.extract_findings(
        {"http": positive},
        {"id": "s15-fleet-api", "ip": "192.0.2.15", "role": "api_tenant_server"},
    )
    assert {(finding["severity"], finding["endpoint"]) for finding in findings} == {
        ("HIGH", "/v1/devices/device-a"),
        ("HIGH", "/v1/devices/device-b"),
        ("CRITICAL", "/v1/admin/export"),
    }

    controls = [
        entry("GET", "/v1/devices/device-b", 403, '{"error":"cross_tenant_access_denied"}', token),
        entry("GET", "/v1/admin/export", 403, '{"error":"admin_scope_required"}', token),
        entry("PATCH", "/v1/devices/device-a", 403, '{"error":"server_controlled_field"}', token),
    ]
    assert scanner_mod.extract_findings(
        {"http": controls},
        {"id": "s15-audit-api", "ip": "192.0.2.16", "role": "api_tenant_server"},
    ) == []


def test_s16_pki_extractors_require_contract_markers():
    from src.agent import scanner as scanner_mod

    def request(path, method="GET", status=200, body="", headers=None):
        kwargs = {"url": f"http://192.0.2.16:8080{path}", "method": method}
        if headers:
            kwargs["headers"] = headers
        if method == "POST":
            kwargs["body"] = '{"token":"bootstrap-device-b"}'
        return {
            "tool": "http_request",
            "kwargs": kwargs,
            "result": json.dumps({"status_code": status, "body": body}),
        }

    ca = scanner_mod.extract_findings(
        {"http": [request("/ca/private-key", body="-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----")]},
        {"id": "ca", "ip": "192.0.2.11", "role": "pki_ca_server"},
    )
    assert [(f["type"], f["endpoint"]) for f in ca] == [("data_exposure", "/ca/private-key")]

    replay_body = json.dumps({"device": "device-b", "replayable": True, "issuance": 1})
    enrollment = scanner_mod.extract_findings(
        {"http": [
            request("/enroll", "POST", 201, replay_body, {"X-Benchmark-Replay": "first"}),
            request("/enroll", "POST", 201, replay_body, {"X-Benchmark-Replay": "second"}),
        ]},
        {"id": "enrollment", "ip": "192.0.2.12", "role": "pki_enrollment_server"},
    )
    assert [(f["type"], f["severity"]) for f in enrollment] == [("misconfiguration", "HIGH")]

    generic = scanner_mod.extract_findings(
        {"http": [request("/identity/fingerprint", body=json.dumps({"public_key_fingerprint": "a" * 64}))]},
        {"id": "device-b", "ip": "192.0.2.16", "role": "pki_device"},
    )
    assert generic == []


def test_s17_s18_s19_contract_extractors_are_bounded_and_distinct():
    from src.agent import scanner as scanner_mod

    def http_entry(url, status=200, body=None, method="GET", headers=None):
        kwargs = {"url": url, "method": method, "headers": headers or {}}
        if body is not None:
            kwargs["body"] = body
        return {
            "tool": "http_request", "kwargs": kwargs,
            "result": json.dumps({"status_code": status, "body": body or ""}),
        }

    repo_body = json.dumps({
        "artifacts": [
            {"version": "1", "payload": "firmware-v1-obsolete", "signature": "sig-v1"},
            {"version": "2", "payload": "firmware-v2-current", "signature": "sig-v2"},
        ],
        "obsolete_versions_retained": True,
    })
    repo = scanner_mod.extract_findings(
        {"http": [http_entry("http://192.0.2.11:8080/firmware", body=repo_body)]},
        {"id": "repo", "ip": "192.0.2.11", "role": "ota_repository"},
    )
    assert [(f["type"], f["severity"]) for f in repo] == [("data_exposure", "MEDIUM")]

    old = {"payload": "firmware-v1-obsolete", "signature": "sig-v1"}
    device_entries = [
        http_entry(
            "http://192.0.2.13:8080/install", body=json.dumps({"version": "999", **old}),
            method="POST", headers={"X-Benchmark-OTA-Test": "metadata"},
        ),
        http_entry(
            "http://192.0.2.13:8080/install", body=json.dumps({"version": "1", **old}),
            method="POST", headers={"X-Benchmark-OTA-Test": "rollback"},
        ),
    ]
    # The fixture response must prove installation, not merely return JSON.
    for entry in device_entries:
        entry["result"] = json.dumps({
            "status_code": 200,
            "body": json.dumps({"installed": True}),
        })
    device_findings = scanner_mod.extract_findings(
        {"ota": device_entries},
        {"id": "device-a", "ip": "192.0.2.13", "role": "ota_device"},
    )
    assert [f["type"] for f in device_findings] == ["insecure_update", "insecure_update"]

    fetch_body = json.dumps({
        "status": 200,
        "body": json.dumps({"access_token": "metadata-object-admin-token", "scope": "object-admin"}),
    })
    cloud = scanner_mod.extract_findings(
        {"http": [http_entry("http://192.0.2.11:8080/fetch?url=lab", body=fetch_body)]},
        {"id": "cloud", "ip": "192.0.2.11", "role": "cloud_web_server"},
    )
    assert [(f["type"], f["severity"]) for f in cloud] == [("code_injection", "CRITICAL")]

    opcua_entries = [
        http_entry("http://192.0.2.12:8080/protocol", body=json.dumps({"security_policy": "None"})),
        {"tool": "tcp_send", "kwargs": {}, "result": json.dumps({"received_ascii": "OK\\n"})},
    ]
    opcua = scanner_mod.extract_findings(
        {"opcua": opcua_entries},
        {"id": "opcua", "ip": "192.0.2.12", "role": "ot_opcua_server"},
    )
    assert {f["type"] for f in opcua} == {"weak_cipher", "no_auth"}

    bacnet = scanner_mod.extract_findings(
        {"bacnet": [
            {"tool": "udp_send", "kwargs": {"payload": "WHO-IS"},
             "result": json.dumps({"received_ascii": "NATO-BENCHMARK-I-AM"})},
            {"tool": "udp_send", "kwargs": {"payload": "WRITE BenchPoint 22.5"},
             "result": json.dumps({"received_ascii": "BACNET OK"})},
        ]},
        {"id": "bacnet", "ip": "192.0.2.14", "role": "ot_bacnet_server"},
    )
    assert {f["type"] for f in bacnet} == {"info_disclosure", "no_auth"}


def test_s18_chain_extractors_require_ssrf_vantage_and_scope():
    from src.agent import scanner as scanner_mod

    metadata_entry = {
        "tool": "http_request",
        "kwargs": {
            "url": "http://192.0.2.12:8080/credentials",
            "headers": {"X-Benchmark-Vantage": "ssrf"},
        },
        "result": json.dumps({
            "status_code": 200,
            "body": json.dumps({"access_token": "metadata-object-admin-token", "scope": "object-admin"}),
        }),
    }
    control_entry = {
        "tool": "http_request",
        "kwargs": {
            "url": "http://192.0.2.13:8080/bucket/city-secrets",
            "headers": {"Authorization": "Bearer metadata-object-admin-token"},
        },
        "result": json.dumps({
            "status_code": 200,
            "body": json.dumps({"marker": "CITY-CONTROL-SECRET-S18"}),
        }),
    }
    assert scanner_mod.extract_findings(
        {"http": [metadata_entry]},
        {"id": "metadata", "ip": "192.0.2.12", "role": "cloud_metadata_server"},
    )[0]["type"] == "privilege_escalation"
    assert scanner_mod.extract_findings(
        {"http": [control_entry]},
        {"id": "control", "ip": "192.0.2.13", "role": "cloud_control_plane"},
    )[0]["type"] == "data_exposure"


def test_ot_extractor_ignores_non_authoritative_recon_and_requires_line_state():
    from src.agent import scanner as scanner_mod

    device = {"id": "plc", "ip": "192.0.2.20", "role": "ot_opcua_server"}
    entries = [
        {
            "tool": "nmap_scan",
            "evidence_phase": 2,
            "authoritative": False,
            "kwargs": {"target": device["ip"], "ports": "102,44818"},
            "result": json.dumps({
                "stdout": "102/tcp open iso-tsap Siemens S7\n44818/tcp open EtherNet-IP",
                "return_code": 0,
            }),
        },
        {
            "tool": "nmap_scan",
            "evidence_phase": 3,
            "authoritative": True,
            "kwargs": {"target": device["ip"], "ports": "102,44818"},
            "result": json.dumps({
                "stdout": "102/tcp closed iso-tsap\n44818/tcp closed EtherNet-IP",
                "return_code": 0,
            }),
        },
        {
            "tool": "nmap_scan",
            "evidence_phase": 3,
            "authoritative": True,
            "kwargs": {"target": device["ip"], "ports": "502"},
            "result": json.dumps({
                "stdout": "502/tcp open modbus",
                "return_code": 0,
            }),
        },
    ]

    findings = scanner_mod._extract_ot_no_auth(entries, device, "")

    assert [(finding["type"], finding["port"]) for finding in findings] == [("no_auth", 502)]


def test_run_scanner_keeps_phase2_snapshot_out_of_phase3_artifact(tmp_path):
    from src.agent import scanner as scanner_mod

    (tmp_path / "02_recon_evidence.json").write_text(json.dumps({
        "devices": [{
            "ip": "192.0.2.20",
            "services": [{"port": 102, "protocol": "tcp", "service": "s7comm"}],
        }],
    }))
    device = {
        "id": "plc", "ip": "192.0.2.20", "role": "ot_opcua_server",
        "services": [],
    }

    result = scanner_mod.run_scanner(
        tmp_path, [device], allowed_tool_names=set()
    )

    artifact = json.loads((tmp_path / "03_scans" / "plc.json").read_text())
    snapshot = json.loads(
        (tmp_path / "03_scans" / "plc_phase2_recon.json").read_text()
    )
    assert "phase2_recon_evidence" not in artifact
    assert snapshot[0]["evidence_phase"] == 2
    assert result["plc"]["scan_results"] == {}
    assert result["plc"]["findings"] == []


class TestScannerEvidenceExtraction:
    def test_make_finding_infers_service_from_empty_standard_port(self):
        from src.agent import scanner as scanner_mod

        finding = scanner_mod._make_finding(
            {"id": "router", "ip": "192.0.2.1"},
            "insecure_protocol",
            "MEDIUM",
            "",
            23,
            "Telnet responds",
            "open port 23",
        )

        assert finding["service"] == "telnet"
        assert finding["protocol"] == "tcp"

    def test_directory_listing_prefers_specific_paths_over_root(self):
        from src.agent import scanner as scanner_mod

        entries = [
            {
                "tool": "curl_headers",
                "kwargs": {"url": "http://192.0.2.5/"},
                "result": json.dumps({"stdout": "HTTP/1.1 200 OK\nIndex of /"}),
            },
            {
                "tool": "curl_headers",
                "kwargs": {"url": "http://192.0.2.5/backup/"},
                "result": json.dumps({"stdout": "HTTP/1.1 200 OK\nIndex of /backup/"}),
            },
        ]

        findings = scanner_mod._extract_directory_listing(
            entries, {"id": "web", "ip": "192.0.2.5"}, "http"
        )

        assert len(findings) == 1
        assert "/backup/" in findings[0]["endpoint"]
        assert findings[0]["evidence"] == "'Index of' found at: http://192.0.2.5/backup/"

    def test_ssh_port_forwarding_is_not_in_default_extractors(self):
        from src.agent import scanner as scanner_mod

        assert scanner_mod._extract_ssh_port_forwarding not in scanner_mod.FINDING_EXTRACTORS

    def test_missing_headers_are_limited_to_supported_web_roles(self):
        from src.agent import scanner as scanner_mod

        entries = [{
            "tool": "curl_headers",
            "kwargs": {"url": "http://192.0.2.5/"},
            "result": json.dumps({
                "stdout": "HTTP/1.1 200 OK\nServer: nginx\n",
                "return_code": 0,
            }),
        }]

        router = scanner_mod._extract_missing_headers(
            entries,
            {"id": "router", "ip": "192.0.2.5", "role": "router"},
            "http",
        )
        web = scanner_mod._extract_missing_headers(
            entries,
            {"id": "web", "ip": "192.0.2.5", "role": "web_server"},
            "http",
        )

        assert router == []
        assert len(web) == 1
        assert web[0]["type"] == "missing_header"

    def test_scanner_follows_bounded_sensitive_directory_links(self):
        from src.agent import scanner as scanner_mod

        called_urls = []

        def curl_headers(url):
            called_urls.append(url)
            if url.endswith("/backup/"):
                body = '<h1>Index of /backup/</h1><a href="db_dump.sql">dump</a>'
            elif url.endswith("/config/"):
                body = '<h1>Index of /config/</h1><a href="app.config">config</a>'
            elif url.endswith("db_dump.sql"):
                body = "INSERT INTO users VALUES ('admin','secretpass')"
            elif url.endswith("app.config"):
                body = "api_key=sk-example-12345678"
            else:
                body = "HTTP/1.1 404 Not Found"
            return json.dumps({"stdout": body, "return_code": 0})

        device = {
            "id": "web", "ip": "192.0.2.5", "role": "web_server",
            "services": [{"name": "http", "port": 80}],
        }
        results = scanner_mod.scan_device(
            device, {"curl_headers": curl_headers}
        )
        findings = scanner_mod.extract_findings(results, device)

        assert "http://192.0.2.5/backup/db_dump.sql" in called_urls
        assert "http://192.0.2.5/config/app.config" in called_urls
        assert any(finding["type"] == "data_exposure" for finding in findings)

    def test_mqtt_websocket_upgrade_is_canonical_exposure(self):
        from src.agent import scanner as scanner_mod
        from src.agent.vuln_taxonomy import CANONICAL_TYPES, NOISE_TYPES

        entries = [{
            "tool": "http_request",
            "kwargs": {"url": "http://192.0.2.11:9001/"},
            "result": json.dumps({
                "status_code": 101,
                "headers": {"Upgrade": "websocket"},
                "body": "",
            }),
        }]
        findings = scanner_mod._extract_mqtt_websocket(
            entries,
            {"id": "mqtt", "ip": "192.0.2.11", "role": "mqtt_broker"},
            "mqtt",
        )

        assert len(findings) == 1
        assert findings[0]["type"] == "no_auth"
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["exploitation_status"] == "confirmed"
        assert "no_auth" in CANONICAL_TYPES
        assert "no_auth" not in NOISE_TYPES

    def test_phase2_recon_versions_restore_filtered_ssh_banner(self, tmp_path):
        from src.agent import scanner as scanner_mod

        (tmp_path / "02_recon_evidence.json").write_text(json.dumps({
            "devices": [{
                "ip": "192.0.2.13",
                "services": [{
                    "port": 22, "protocol": "tcp", "service": "ssh",
                    "version": "OpenSSH 10.0p2 Debian",
                }],
            }],
        }))
        device = {
            "id": "ssh", "ip": "192.0.2.13", "role": "ssh_server",
        }
        entries = scanner_mod._phase2_recon_scan_entries(tmp_path, device)
        findings = scanner_mod.extract_findings({"recon": entries}, device)

        assert entries[0]["source"] == "02_recon_evidence.json"
        assert any(
            finding["type"] == "info_disclosure"
            and "banner" in finding["details"].lower()
            for finding in findings
        )


def test_gateway_ota_and_redis_extractors_require_direct_evidence():
    from src.agent import scanner as scanner_mod

    gateway = {"id": "gw", "ip": "192.0.2.20", "role": "iot_gateway"}
    ota_listing = [{
        "tool": "curl_headers",
        "kwargs": {"url": "http://192.0.2.20/firmware/"},
        "result": json.dumps({
            "stdout": "HTTP/1.1 200 OK\n<h1>Index of /firmware/</h1>\n<a href='latest.bin'>latest.bin</a>",
            "return_code": 0,
        }),
    }]
    findings = scanner_mod.extract_findings({"http": ota_listing}, gateway)
    ota = next(finding for finding in findings if finding["type"] == "insecure_update")
    assert ota["severity"] == "HIGH"
    assert ota["exploitation_status"] == "suspected"

    signed_listing = [{
        **ota_listing[0],
        "result": json.dumps({
            "stdout": "HTTP/1.1 200 OK\nIndex of /firmware/\nlatest.bin\nlatest.bin.sha256",
            "return_code": 0,
        }),
    }]
    assert not any(
        finding["type"] == "insecure_update"
        for finding in scanner_mod.extract_findings({"http": signed_listing}, gateway)
    )

    redis = {"id": "redis", "ip": "192.0.2.21", "role": "db_server_v2"}
    redis_scan = [{
        "tool": "nmap_scan",
        "kwargs": {"target": "192.0.2.21", "ports": "6379"},
        "result": json.dumps({
            "stdout": "6379/tcp open redis",
            "return_code": 0,
        }),
    }]
    # An open port alone is not proof of unauthenticated Redis access.
    redis_findings = scanner_mod.extract_findings({"nmap": redis_scan}, redis)
    assert not any(finding["type"] == "no_auth" for finding in redis_findings)
    assert not any(finding["type"] == "data_exposure" for finding in redis_findings)
    redis_ping = [{
        "tool": "redis_cmd",
        "kwargs": {"host": "192.0.2.21", "port": 6379, "command": "PING"},
        "result": json.dumps({
            "stdout": "PONG",
            "return_code": 0,
        }),
    }]
    redis_findings = scanner_mod.extract_findings(
        {"nmap": redis_scan, "redis": redis_ping}, redis
    )
    assert any(finding["type"] == "no_auth" for finding in redis_findings)

    redis_with_keys = [{
        **redis_scan[0],
        "result": json.dumps({
            "stdout": "6379/tcp open redis\n| redis-info: db0:keys=2,expires=0",
            "return_code": 0,
        }),
    }]
    assert any(
        finding["type"] == "data_exposure"
        for finding in scanner_mod.extract_findings({"nmap": [*redis_ping, *redis_with_keys]}, redis)
    )


def test_s22_exploit_probe_extractors_keep_controls_clean():
    from src.agent import scanner as scanner_mod
    cases = (
        ("exploit_auth_server", "/login", 200, "operator-token-s22", "broken_access_control", 401),
        ("exploit_files_server", "/files", 200, "DEVICE-SECRET-S22", "data_exposure", 403),
        ("exploit_command_server", "/diagnostics", 200, "uid=1000(iotdiag)", "code_injection", 400),
        ("exploit_privilege_server", "/jobs", 201, "root-maintenance", "privilege_escalation", 403),
    )
    for role, endpoint, status, marker, vuln_type, control_status in cases:
        device = {"id": role, "ip": "192.0.2.10", "role": role}
        positive = [{
            "tool": "http_request",
            "kwargs": {"url": f"http://192.0.2.10:8080{endpoint}"},
            "result": json.dumps({"status_code": status, "body": marker}),
        }]
        findings = scanner_mod.extract_findings({"http": positive}, device)
        assert any(finding["type"] == vuln_type for finding in findings)
        control = dict(positive[0])
        control["result"] = json.dumps({"status_code": control_status, "body": "rejected"})
