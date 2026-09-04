"""Tests for pipeline module."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.agent.pipeline import (
    Pipeline,
    TOOL_GROUPS,
    _has_positive_exploit_evidence,
    _phase4_local_verification_tools,
    _phase4_verification_plan,
    _is_verified_report_finding,
    _report_phase4_summary,
    _phase4_requirement_matches,
    _local_report_memo_contradicts_context,
    _looks_unusable_model_memo,
    _deliverable_template_path,
    _resolve_model_provider,
    _synthesize_exploit_result,
    _enrich_finding_structure,
    _make_test_entry,
    _finding_semantic_issue,
    _normalise_full_finding_semantics,
    _sanitize_suggested_tools,
    _extract_endpoint_paths,
    _expand_phase_selection,
)
from src.agent.registry import AgentConfig, AGENTS

def test_phase6_context_excludes_unsupported_confirmations(mock_provider, output_dir):
    pipeline = Pipeline(provider=mock_provider)
    pipeline.context = {"device_count": 1}
    run_dir = pipeline.run_dir
    (run_dir / "03_vuln_analysis.json").write_text(json.dumps({
        "vulnerabilities": [
            {
                "id": "V1", "device_id": "device-1", "device_ip": "192.0.2.1",
                "type": "no_auth", "severity": "HIGH", "service": "mqtt",
                "port": 1883,
            },
            {
                "id": "V2", "device_id": "device-1", "device_ip": "192.0.2.1",
                "type": "default_credentials", "severity": "HIGH",
                "service": "mqtt", "port": 1883,
            },
        ],
    }))
    tests = [
        {
            "vuln_id": "V1", "device_id": "device-1", "device_ip": "192.0.2.1",
            "vuln_type": "no_auth", "status": "CONFIRMED", "evidence_level": 2,
            "tool_used": "mqtt_listen", "evidence": "anonymous messages",
        },
        {
            "vuln_id": "V2", "device_id": "device-1", "device_ip": "192.0.2.1",
            "vuln_type": "default_credentials", "status": "CONFIRMED",
            "evidence_level": 1, "evidence": "model claim only",
        },
    ]
    (run_dir / "04_exploitation.json").write_text(json.dumps({
        "summary": {"total_tested": 2, "confirmed": 2, "not_exploitable": 0, "errors": 0},
        "tests": tests,
    }))

    assert _report_phase4_summary({"confirmed": 2}, tests) == {
        "confirmed": 1, "verified_confirmed": 1, "unverified_confirmed": 1,
    }

    pipeline._generate_phase6_context()
    context = json.loads((run_dir / "06_phase6_context.json").read_text())
    assert context["phase4_summary"]["confirmed"] == 1
    assert context["phase4_summary"]["unverified_confirmed"] == 1
    assert [test["vuln_id"] for test in context["phase4_tests"]] == ["V1"]
    assert _is_verified_report_finding(tests[0])
    assert not _is_verified_report_finding(tests[1])

    local_context = pipeline._build_local_report_analysis_context()
    assert [test["vuln_id"] for test in local_context["phase6"]["phase4_tests"]] == ["V1"]




def test_discovery_followup_maps_declared_ports_to_scanner_services():
    assert Pipeline._service_for_discovered_port(3306) == ("mysql", "tcp")
    assert Pipeline._service_for_discovered_port(161) == ("snmp", "udp")
    assert Pipeline._service_for_discovered_port(5683) == ("coap", "udp")
    assert Pipeline._service_for_discovered_port(9999) == ("unknown", "tcp")

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


def test_full_phase3_normalizes_nullable_schema_fields_without_changing_compact():
    compact_finding = {
        "service": "mysql",
        "protocol": "tcp",
        "endpoint": None,
        "product": "MariaDB",
        "version": "11.8",
    }
    _enrich_finding_structure(compact_finding)
    assert compact_finding["endpoint"] is None

    full_finding = dict(compact_finding)
    _enrich_finding_structure(full_finding, strict_schema=True)
    assert full_finding["endpoint"] == ""



def test_full_phase3_normalizes_application_protocol_to_transport():
    finding = {
        "service": "http",
        "protocol": "http",
        "endpoint": "/v1/devices/device-b",
        "product": "",
        "version": "",
    }
    _enrich_finding_structure(finding, strict_schema=True)
    assert finding["protocol"] == "tcp"


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


def test_s15_generic_api_fixture_is_not_a_model_finding():
    finding = {
        "type": "data_exposure",
        "service": "http",
        "port": 8080,
        "protocol": "tcp",
        "endpoint": "/credentials",
        "details": 'HTTP 200 body {"authentication":"enforced"} may expose credentials',
        "evidence": 'GET /credentials returned {"authentication":"enforced"}',
    }
    assert "generic API fixture" in _finding_semantic_issue(
        finding,
        source_kind="model",
        device_role="api_data_store",
    )


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


def test_s14_s19_profile_controls_and_role_mismatch_are_not_published():
    assert _finding_semantic_issue(
        {"type": "weak_cipher", "service": "ssh", "port": 22},
        source_kind="model", device_role="ssh_server", device_profile="hardened", scenario_id="S14",
    )
    assert "sparse contract" in _finding_semantic_issue(
        {"type": "weak_cipher", "service": "ssh", "port": 22},
        source_kind="model", device_role="ssh_server", device_profile="vulnerable", scenario_id="S14",
    )
    assert "non-SSH role" in _finding_semantic_issue(
        {"type": "weak_cipher", "service": "ssh", "port": 22},
        source_kind="model", device_role="mqtt_broker", scenario_id=19,
    )
    assert _finding_semantic_issue(
        {"type": "info_disclosure", "service": "bacnet", "port": 47808},
        source_kind="scanner_full", device_role="ot_bacnet_server", device_profile="hardened", scenario_id=19,
    )
    assert "Modbus role" in _finding_semantic_issue(
        {"type": "weak_cipher", "service": "ssh", "port": 22},
        source_kind="model", device_role="modbus_server", scenario_id=19,
    )


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


def test_s14_authenticated_redis_and_pki_metadata_are_rejected():
    redis_noauth = {
        "type": "no_auth", "service": "redis", "port": 6379,
        "details": "Redis PING returned -NOAUTH Authentication required",
    }
    assert "authentication" in _finding_semantic_issue(
        redis_noauth, source_kind="model", device_role="db_server_v2"
    )

    redis_data = {
        "type": "data_exposure", "service": "redis", "port": 6379,
        "details": "Unauthenticated Redis exposes credentials and secrets: database password and API keys",
    }
    assert "retrieved" in _finding_semantic_issue(
        redis_data, source_kind="model", device_role="db_server_v2"
    )

    pki_metadata = {
        "type": "info_disclosure", "service": "http", "port": 8080,
        "endpoint": "/identity/certificate",
        "details": "Device certificate is publicly accessible and reveals the public identity",
    }
    assert "PKI" in _finding_semantic_issue(
        pki_metadata, source_kind="model", device_role="pki_device"
    )


def test_suggested_tools_are_restricted_to_canonical_catalog_names():
    finding = {
        "suggested_tools": [
            "ssh-audit",
            "nmap ssh-vulnscan",
            "modbus-cli",
            "http_get",
            "mysql CLI client, sqlmap, Metasploit mysql_hashdump",
        ]
    }

    assert _sanitize_suggested_tools(
        finding, catalog_names={"ssh_audit", "http_get", "sqlmap"}
    ) == ["ssh_audit", "http_get", "sqlmap"]
    assert finding["suggested_tools"] == ["ssh_audit", "http_get", "sqlmap"]

@pytest.mark.parametrize("profile", ["full", "compact"])
def test_phase5_scope_guard_is_only_enforced_for_compact(
    mock_provider, output_dir, profile
):
    if profile == "compact":
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
    pipeline = Pipeline(provider=mock_provider, execution_profile=profile)
    pipeline.context = {"target_subnet": "192.168.100.0/24"}
    calls = []

    def execute(**kwargs):
        calls.append(kwargs)
        return json.dumps({"success": True})

    guarded = pipeline._wrap_tool({
        "name": "ssh_exec",
        "description": "ssh",
        "input_schema": {},
        "function": execute,
    }, phase=5, agent="intrusion")
    result = json.loads(guarded["function"](
        ip="192.168.100.1",
        user="root",
        password="root",
        command="ls ~/.ssh/; sshpass -p 'P@ssw0rd123' ssh root@192.168.100.11 'id'",
    ))

    if profile == "compact":
        assert result["error_kind"] == "intrusion_command_hostname_unverifiable"
        assert calls == []
    else:
        assert result["success"] is True
        assert len(calls) == 1


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


def test_phase6_resolves_legacy_report_template_for_full_agents():
    template_path = _deliverable_template_path(AGENTS["report"])

    assert template_path.name == "05_report.md"
    assert "{{SECTION_5_TABLE}}" in template_path.read_text(encoding="utf-8")


def test_compact_phase4_protocol_contract_rejects_open_port_only():
    vuln = {
        "type": "no_auth", "service": "s7comm",
        "device_ip": "192.0.2.20", "port": 102,
    }
    compact_plan = _phase4_verification_plan(vuln, compact=True)
    full_plan = _phase4_verification_plan(vuln)

    assert compact_plan["tool"] == "tcp_send"
    assert compact_plan["port"] == 102
    assert compact_plan["required_payload"]
    assert _phase4_requirement_matches(
        compact_plan, "tcp_send", compact_plan["args_hint"]
    )
    assert not _phase4_requirement_matches(
        compact_plan, "tcp_send",
        {**compact_plan["args_hint"], "payload_hex": "00"},
    )
    assert "required_payload" not in full_plan

    record = [{
        "tool": "tcp_send",
        "args": compact_plan["args_hint"],
        "result": json.dumps({
            "received_bytes": 4,
            "received_hex": "03000016",
            "return_code": 0,
        }),
    }]
    assert _synthesize_exploit_result(vuln, record)["status"] == "EXPLOITED"
    assert _synthesize_exploit_result(vuln, record, compact=True)["status"] == "EXPLOITED"


def test_phase4_verification_plan_selects_precise_probe_per_finding():
    ws = _phase4_verification_plan({
        "type": "network_exposure", "service": "mqtt-ws",
        "device_ip": "192.168.100.11", "port": 9001,
    })
    assert ws["tool"] == "http_request"
    assert ws["args_hint"]["url"].endswith(":9001/")

    ws_no_auth = _phase4_verification_plan({
        "type": "no_auth", "service": "mqtt-ws",
        "device_ip": "192.168.100.11", "port": 9001,
    })
    assert ws_no_auth["tool"] == "http_request"
    assert ws_no_auth["args_hint"]["url"].endswith(":9001/")

    listing = _phase4_verification_plan({
        "type": "directory_listing", "service": "http",
        "device_ip": "192.168.100.12", "port": 80, "endpoint": "/backup/",
    })
    assert listing["tool"] == "http_get"
    assert listing["args_hint"]["url"].endswith("/backup/")

    sys_topics = _phase4_verification_plan({
        "type": "info_disclosure", "service": "mqtt",
        "device_ip": "192.168.100.11", "port": 1883,
    })
    assert sys_topics["tool"] == "mqtt_listen"
    assert sys_topics["args_hint"]["topic"] == "$SYS/#"


def test_phase4_compact_probes_repair_http_endpoint_and_mysql_auth_check():
    upload = _phase4_verification_plan({
        "type": "code_injection", "service": "http",
        "device_ip": "192.168.100.12", "port": 80, "endpoint": "/uploads/:",
    }, compact=True)
    assert upload["args_hint"]["url"].endswith("/uploads/")

    mysql = _phase4_verification_plan({
        "type": "default_credentials", "service": "mysql",
        "device_ip": "192.168.100.17", "port": 3306,
    }, compact=True)
    assert mysql["tool"] == "mysql_query"
    assert mysql["args_hint"]["user"] == "root"
    assert _phase4_requirement_matches(mysql, "mysql_query", mysql["args_hint"])
    assert not _phase4_requirement_matches(
        mysql, "mysql_query", {**mysql["args_hint"], "skip_ssl": False}
    )
    assert not _phase4_requirement_matches(
        mysql, "mysql_query", {**mysql["args_hint"], "user": "admin"}
    )

    result = _synthesize_exploit_result(
        {"type": "default_credentials", "service": "mysql", "port": 3306},
        [{
            "tool": "mysql_query",
            "args": mysql["args_hint"],
            "result": json.dumps({"stdout": "root@localhost", "return_code": 0}),
        }],
        compact=True,
    )
    assert result["status"] == "EXPLOITED"


def test_phase4_compact_selects_bounded_snmp_coap_and_ftp_probes():
    snmp = _phase4_verification_plan({
        "type": "default_credentials", "service": "snmp",
        "device_ip": "192.0.2.15", "port": 161,
    }, compact=True)
    assert snmp["tool"] == "udp_send"
    assert snmp["args_hint"]["encoding"] == "hex"
    assert _phase4_requirement_matches(snmp, "udp_send", snmp["args_hint"])
    assert _synthesize_exploit_result(
        {"type": "default_credentials", "service": "snmp", "port": 161},
        [{
            "tool": "udp_send", "args": snmp["args_hint"],
            "result": json.dumps({"received_bytes": 32, "received_hex": "3020", "return_code": 0}),
        }], compact=True,
    )["status"] == "EXPLOITED"

    coap = _phase4_verification_plan({
        "type": "no_auth", "service": "coap",
        "device_ip": "192.0.2.14", "port": 5683,
    }, compact=True)
    assert coap["tool"] == "udp_send"
    assert coap["args_hint"]["timeout"] == 5
    assert _phase4_requirement_matches(coap, "udp_send", coap["args_hint"])

    ftp = _phase4_verification_plan({
        "type": "data_exposure", "service": "ftp",
        "device_ip": "192.0.2.22", "port": 21,
    }, compact=True)
    assert ftp["tool"] == "ftp_list"
    assert _synthesize_exploit_result(
        {"type": "data_exposure", "service": "ftp", "port": 21},
        [{
            "tool": "ftp_list", "args": ftp["args_hint"],
            "result": json.dumps({"stdout": "drwxr-xr-x config\ndrwxr-xr-x backup", "return_code": 0}),
        }], compact=True,
    )["status"] == "EXPLOITED"


def test_phase4_known_cve_without_matching_audit_evidence_is_inconclusive():
    result = _synthesize_exploit_result(
        {
            "type": "known_cve", "service": "ssh", "port": 22,
            "cve_ids": ["CVE-2021-36369"],
        },
        [{
            "tool": "ssh_audit",
            "args": {"host": "192.0.2.20", "port": 22},
            "result": json.dumps({
                "stdout": "[warn] vulnerable to Terrapin (CVE-2023-48795)",
                "return_code": 3,
            }),
        }],
        compact=True,
    )
    assert result["status"] == "ERROR"
    assert "CVE-specific" in result["evidence"]



def test_phase4_default_credentials_mqtt_uses_authenticated_probe():
    vuln = {
        "type": "default_credentials", "service": "mqtt",
        "device_ip": "192.0.2.11", "port": 1883,
    }
    requirement = _phase4_verification_plan(vuln)

    assert requirement["tool"] == "mqtt_listen"
    assert requirement["args_hint"]["username"] == "test"
    assert requirement["args_hint"]["password"] == "test"
    assert not _phase4_requirement_matches(
        requirement, "mqtt_listen", {"broker": "192.0.2.11", "topic": "#"}
    )
    assert _phase4_requirement_matches(
        requirement, "mqtt_listen", requirement["args_hint"]
    )

    anonymous = _synthesize_exploit_result(
        vuln, [{
            "tool": "mqtt_listen",
            "args": {"broker": "192.0.2.11", "topic": "#"},
            "result": json.dumps({"stdout": "sensors/temp 22.5", "return_code": 27}),
        }],
    )
    assert anonymous["status"] == "ERROR"

    authenticated = _synthesize_exploit_result(
        vuln, [{
            "tool": "mqtt_listen",
            "args": requirement["args_hint"],
            "result": json.dumps({"stdout": "sensors/temp 22.5", "return_code": 27}),
        }],
    )
    assert authenticated["status"] == "EXPLOITED"


def test_no_auth_nmap_open_port_requires_protocol_evidence():
    vuln = {
        "type": "no_auth", "service": "unknown",
        "device_ip": "192.0.2.12", "port": 1234,
    }
    open_only = _synthesize_exploit_result(
        vuln, [{
            "tool": "nmap_scan",
            "args": {"target": "192.0.2.12", "ports": "1234"},
            "result": json.dumps({
                "stdout": "1234/tcp open mystery", "return_code": 0,
            }),
        }],
    )
    assert open_only["status"] == "FAILED"

    protocol = _synthesize_exploit_result(
        vuln, [{
            "tool": "nmap_scan",
            "args": {"target": "192.0.2.12", "ports": "1234"},
            "result": json.dumps({
                "stdout": "1234/tcp open mystery\nAnonymous login allowed",
                "return_code": 0,
            }),
        }],
    )
    assert protocol["status"] == "EXPLOITED"


def test_model_finding_metadata_rejects_non_http_header_claims():
    assert "requires an HTTP" in _finding_semantic_issue({
        "type": "missing_header", "service": "telnet", "port": 23,
    })
    assert _finding_semantic_issue({
        "type": "missing_header", "service": "http", "port": 80,
    }) == ""


def test_semantic_contract_rejects_cross_family_findings():
    assert "plain HTTP" in _finding_semantic_issue({
        "type": "weak_cipher", "service": "http", "port": 80,
    })
    assert "not SSH or HTTP" in _finding_semantic_issue({
        "type": "insecure_protocol", "service": "ssh", "port": 22,
    })
    assert "intentional upload" in _finding_semantic_issue({
        "type": "directory_listing", "service": "http", "port": 80,
        "endpoint": "/uploads/",
    })
    assert "firmware binaries" in _finding_semantic_issue({
        "type": "data_exposure", "service": "http", "port": 80,
        "details": "firmware.bin is downloadable",
    })


def test_full_phase4_missing_header_requires_absence_of_named_headers():
    vuln = {
        "type": "missing_header", "service": "http", "port": 80,
        "details": "Missing HTTP security headers: x-frame-options",
    }
    present = _synthesize_exploit_result(vuln, [{
        "tool": "curl_headers",
        "args": {"url": "http://192.0.2.20/"},
        "result": json.dumps({
            "stdout": "HTTP/1.1 200 OK\nX-Frame-Options: DENY",
            "return_code": 0,
        }),
    }])
    absent = _synthesize_exploit_result(vuln, [{
        "tool": "curl_headers",
        "args": {"url": "http://192.0.2.20/"},
        "result": json.dumps({
            "stdout": "HTTP/1.1 200 OK\nServer: nginx/1.22.1",
            "return_code": 0,
        }),
    }])
    assert present["status"] == "FAILED"
    assert absent["status"] == "EXPLOITED"
    assert absent["evidence_level"] >= 2


def test_full_phase4_does_not_confirm_open_ssh_as_insecure_protocol():
    result = _synthesize_exploit_result(
        {"type": "insecure_protocol", "service": "ssh", "port": 22},
        [{
            "tool": "nmap_scan",
            "args": {"target": "192.0.2.20", "ports": "22"},
            "result": json.dumps({
                "stdout": "22/tcp open ssh OpenSSH 9.2",
                "return_code": 0,
            }),
        }],
    )
    assert result["status"] == "FAILED"


def test_full_phase4_does_not_map_ssh_cipher_warning_to_info_disclosure():
    result = _synthesize_exploit_result(
        {"type": "info_disclosure", "service": "ssh", "port": 22},
        [{
            "tool": "ssh_audit",
            "args": {"host": "192.0.2.20", "port": 22},
            "result": json.dumps({
                "stdout": "[fail] weak MAC algorithm diffie-hellman-group1-sha1",
                "return_code": 3,
            }),
        }],
    )
    assert result["status"] == "FAILED"


def test_full_phase4_http_info_disclosure_requires_explicit_version():
    bare = _synthesize_exploit_result(
        {"type": "info_disclosure", "service": "http", "port": 80},
        [{
            "tool": "curl_headers",
            "args": {"url": "http://192.0.2.20/"},
            "result": json.dumps({"stdout": "HTTP/1.1 200 OK\nServer: nginx", "return_code": 0}),
        }],
    )
    versioned = _synthesize_exploit_result(
        {"type": "info_disclosure", "service": "http", "port": 80},
        [{
            "tool": "curl_headers",
            "args": {"url": "http://192.0.2.20/"},
            "result": json.dumps({"stdout": "HTTP/1.1 200 OK\nServer: nginx/1.22.1", "return_code": 0}),
        }],
    )
    assert bare["status"] == "FAILED"
    assert versioned["status"] == "EXPLOITED"


def test_full_semantic_filters_reject_contradictory_claims():
    assert "contradicted" in _finding_semantic_issue(
        {
            "type": "no_auth",
            "service": "http",
            "port": 80,
            "details": "LuCI login returns HTTP 403 and requires authentication",
            "evidence": "HTTP 403",
        }
    )
    assert "speculative" in _finding_semantic_issue(
        {
            "type": "misconfiguration",
            "service": "ssh",
            "port": 22,
            "details": "Bastion may allow unrestricted TCP forwarding; no evidence of AllowTcpForwarding=no",
            "evidence": "SSH is open",
        }
    )
    assert "protocol properties" in _finding_semantic_issue(
        {
            "type": "insecure_protocol",
            "service": "modbus",
            "port": 502,
            "details": "Modbus protocol specification lacks authentication; traffic is plaintext and unauthenticated",
            "evidence": "Modbus protocol description",
        }
    )
    assert "platform fingerprint" in _finding_semantic_issue(
        {
            "type": "info_disclosure",
            "service": "network",
            "port": 0,
            "details": "MAC address identifies a Proxmox virtual machine",
            "evidence": "BC:24:11",
        }
    )


def test_full_aggregation_keeps_model_queue_and_semantic_filter_raw(
    mock_provider, output_dir, monkeypatch
):
    monkeypatch.setattr(
        "src.agent.pipeline.get_attack_surface",
        lambda: json.dumps([{
            "id": "web-1", "ip": "192.0.2.30", "role": "web_server",
        }]),
    )
    pipeline = Pipeline(provider=mock_provider)
    (pipeline.run_dir / "03_device_web-1.json").write_text(json.dumps({
        "vulnerabilities": [
            {
                "device_id": "web-1", "device_ip": "192.0.2.30",
                "type": "info_disclosure", "severity": "LOW",
                "service": "http", "port": 80,
                "details": "Server version disclosure (nginx)",
                "evidence": "Server: nginx",
                "exploitation_status": "confirmed",
            },
            {
                "device_id": "web-1", "device_ip": "192.0.2.30",
                "type": "weak_cipher", "severity": "LOW",
                "service": "http", "port": 80,
                "details": "HTTP uses weak ciphers", "evidence": "80/tcp open http",
            },
        ]
    }))
    (pipeline.run_dir / "03_scans").mkdir()
    (pipeline.run_dir / "03_scans" / "web-1.json").write_text(json.dumps({
        "http": [{
            "tool": "curl_headers",
            "kwargs": {"url": "http://192.0.2.30/"},
            "result": json.dumps({
                "stdout": "HTTP/1.1 200 OK\nServer: nginx/1.22.1",
                "return_code": 0,
            }),
        }]
    }))

    pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])

    canonical = json.loads((pipeline.run_dir / "03_vuln_analysis.json").read_text())
    raw = json.loads((pipeline.run_dir / "03_vuln_analysis_raw.json").read_text())
    assert {finding["type"] for finding in canonical["vulnerabilities"]} == {
        "info_disclosure",
    }
    info = next(
        finding for finding in canonical["vulnerabilities"]
        if finding["type"] == "info_disclosure"
    )
    assert info["canonical_source"] == "model"
    assert any(
        candidate["decision_reason"] == "weak_cipher requires SSH/TLS evidence, not plain HTTP"
        for candidate in raw["candidates"]
    )
    assert raw["candidate_count"] == 2



def test_full_aggregation_accepts_catalog_validated_terrapin_without_nvd_cpe(
    mock_provider, output_dir, monkeypatch
):
    monkeypatch.setattr(
        "src.agent.pipeline.get_attack_surface",
        lambda: json.dumps([{
            "id": "gw-1", "ip": "192.0.2.31", "role": "iot_gateway",
        }]),
    )
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    (pipeline.run_dir / "03_device_gw-1.json").write_text(json.dumps({
        "vulnerabilities": [{
            "device_id": "gw-1", "device_ip": "192.0.2.31",
            "type": "known_cve", "severity": "HIGH",
            "service": "ssh", "port": 22, "product": "Dropbear sshd",
            "version": "2020.81", "cve_ids": ["CVE-2023-48795"],
            "details": "Dropbear 2020.81 is vulnerable to CVE-2023-48795 Terrapin",
            "evidence": "ssh_audit detected CVE-2023-48795 on Dropbear 2020.81",
            "cve_validation": {
                "query": "CVE-2023-48795 Dropbear",
                "observed_product": "Dropbear sshd",
                "observed_version": "2020.81",
            },
        }]
    }))

    pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])

    canonical = json.loads((pipeline.run_dir / "03_vuln_analysis.json").read_text())
    finding = canonical["vulnerabilities"][0]
    assert finding["type"] == "known_cve"
    assert finding["cve_claim_status"] == "validated_catalog"
    assert finding["accepted_for_scoring"] is True



def test_full_aggregation_rejects_catalog_cve_outside_product_range(
    mock_provider, output_dir, monkeypatch
):
    monkeypatch.setattr(
        "src.agent.pipeline.get_attack_surface",
        lambda: json.dumps([{
            "id": "ssh-1", "ip": "192.0.2.33", "role": "ssh_server",
        }]),
    )
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    (pipeline.run_dir / "03_device_ssh-1.json").write_text(json.dumps({
        "vulnerabilities": [{
            "device_id": "ssh-1", "device_ip": "192.0.2.33",
            "type": "known_cve", "severity": "HIGH", "service": "ssh", "port": 22,
            "product": "OpenSSH", "version": "10.0p2",
            "cve_ids": ["CVE-2023-48795"],
            "details": "OpenSSH 10.0p2 is vulnerable to CVE-2023-48795",
            "evidence": "ssh_audit detected CVE-2023-48795 on OpenSSH 10.0p2",
            "cve_validation": {
                "observed_product": "OpenSSH",
                "observed_version": "10.0p2",
            },
        }]
    }))

    pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])

    canonical = json.loads((pipeline.run_dir / "03_vuln_analysis.json").read_text())
    assert canonical["vulnerabilities"] == []



def test_full_semantic_normalization_preserves_precise_claim_types():
    listing = {
        "device_ip": "192.0.2.40",
        "type": "directory_listing",
        "service": "http",
        "port": 80,
        "endpoint": "/backup/",
        "details": "Directory listing enabled on /backup/",
        "evidence": "'Index of' found at /backup/",
    }
    exposure = {
        "device_ip": "192.0.2.40",
        "type": "data_exposure",
        "service": "http",
        "port": 80,
        "endpoint": "/backup/db.sql",
        "details": "SQL backup contains credentials",
        "evidence": "password=secret",
    }
    _normalise_full_finding_semantics(listing, [listing, exposure])
    assert listing["type"] == "data_exposure"

    coap = {
        "device_ip": "192.0.2.41",
        "type": "insecure_protocol",
        "service": "coap",
        "port": 5683,
        "details": "CoAP is accessible without DTLS",
    }
    _normalise_full_finding_semantics(coap, [coap])
    assert coap["type"] == "misconfiguration"

    mqtt = {
        "device_ip": "192.0.2.42",
        "type": "no_auth",
        "service": "mqtt",
        "port": 1883,
        "details": "MQTT accepts weak default credentials test:test",
    }
    _normalise_full_finding_semantics(mqtt, [mqtt])
    assert mqtt["type"] == "default_credentials"


def test_full_semantic_filter_rejects_redundant_claims_and_keeps_real_contracts():
    assert _finding_semantic_issue(
        {
            "type": "broken_access_control",
            "service": "http",
            "details": "API key exposed in a static configuration file",
        }
    ).startswith("broken_access_control requires")
    assert _finding_semantic_issue(
        {
            "type": "misconfiguration",
            "service": "ssh",
            "details": "ssh-auth-methods returned Not allowed at this time",
        }
    ).startswith("blocked or rate-limited")
    assert _finding_semantic_issue(
        {
            "type": "data_exposure",
            "service": "coap",
            "endpoint": "/sensor/data",
            "details": "sensor telemetry is available without encryption",
        }
    ).startswith("generic sensor telemetry")
    assert _finding_semantic_issue(
        {
            "type": "missing_header",
            "service": "http",
            "port": 80,
        },
        device_role="iot_gateway",
    ).startswith("generic gateway headers")
    assert _finding_semantic_issue(
        {
            "type": "info_disclosure",
            "service": "ssh",
            "details": "NIST P-256 elliptic curve suspected as backdoored",
        }
    ).startswith("SSH algorithm properties")


def test_endpoint_extraction_keeps_prose_paths_without_url_host_artifacts():
    assert _extract_endpoint_paths(
        "GET http://192.0.2.44/.env and POST /update; /firmware/"
    ) == ["/.env", "/update", "/firmware/"]


def test_full_canonical_projection_deduplicates_surfaces_but_preserves_raw(
    mock_provider, output_dir, monkeypatch
):
    monkeypatch.setattr(
        "src.agent.pipeline.get_attack_surface",
        lambda: json.dumps([
            {"id": "mqtt-1", "ip": "192.0.2.45", "role": "mqtt_broker"},
            {"id": "web-1", "ip": "192.0.2.46", "role": "web_server"},
            {"id": "ssh-1", "ip": "192.0.2.47", "role": "ssh_server"},
            {"id": "ssh-2", "ip": "192.0.2.48", "role": "ssh_server"},
        ]),
    )
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    (pipeline.run_dir / "03_device_mixed.json").write_text(json.dumps({
        "vulnerabilities": [
            {
                "id": "M1", "device_id": "mqtt-1", "device_ip": "192.0.2.45",
                "type": "no_auth", "severity": "HIGH", "service": "mqtt",
                "port": 1883, "product": "Mosquitto",
                "details": "Anonymous MQTT subscribe succeeded",
            },
            {
                "id": "M2", "device_id": "mqtt-1", "device_ip": "192.0.2.45",
                "type": "data_exposure", "severity": "MEDIUM", "service": "mqtt",
                "port": 1883, "endpoint": "smartcity/admin/credentials",
                "details": "Credentials exposed on MQTT topic",
            },
            {
                "id": "M3", "device_id": "mqtt-1", "device_ip": "192.0.2.45",
                "type": "data_exposure", "severity": "MEDIUM", "service": "mqtt",
                "port": 1883, "endpoint": "smartcity/config/network",
                "details": "Network secrets exposed on MQTT topic",
            },
            {
                "id": "W1", "device_id": "ssh-1", "device_ip": "192.0.2.47",
                "type": "weak_cipher", "severity": "LOW", "service": "ssh",
                "port": 22, "details": "SSH uses weak SHA-1 MAC",
            },
            {
                "id": "W2", "device_id": "ssh-2", "device_ip": "192.0.2.48",
                "type": "weak_cipher", "severity": "LOW", "service": "ssh",
                "port": 22, "details": "SSH uses weak CBC cipher",
            },
            {
                "id": "L1", "device_id": "web-1", "device_ip": "192.0.2.46",
                "type": "directory_listing", "severity": "MEDIUM", "service": "http",
                "port": 80, "endpoint": "/backup/",
                "details": "Directory listing enabled on /backup/ and /config/",
            },
            {
                "id": "L2", "device_id": "web-1", "device_ip": "192.0.2.46",
                "type": "data_exposure", "severity": "MEDIUM", "service": "http",
                "port": 80, "endpoint": "/config/app.config",
                "details": "Config contains database password and API key",
            },
        ]
    }))

    pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])
    canonical = json.loads((pipeline.run_dir / "03_vuln_analysis.json").read_text())
    raw = json.loads((pipeline.run_dir / "03_vuln_analysis_raw.json").read_text())
    findings = canonical["vulnerabilities"]

    assert len(findings) == 4
    assert sum(f["type"] == "weak_cipher" for f in findings) == 1
    mqtt = next(f for f in findings if f["device_ip"] == "192.0.2.45" and f["type"] == "data_exposure")
    assert mqtt["endpoint"] in {"smartcity/admin/credentials", "smartcity/config/network"}
    web = next(f for f in findings if f["device_ip"] == "192.0.2.46")
    assert web["type"] == "data_exposure"
    assert {"/backup/", "/config/", "/config/app.config"}.issubset(web["endpoints"])
    assert raw["candidate_count"] == 7
    assert raw["canonical_count"] == 4


def test_phase4_plan_for_coap_misconfiguration_uses_protocol_probe():
    plan = _phase4_verification_plan(
        {
            "type": "misconfiguration",
            "device_ip": "192.0.2.43",
            "service": "coap",
            "port": 5683,
        }
    )
    assert plan["tool"] == "udp_send"
    assert plan["port"] == 5683


def test_phase4_profile_keeps_full_tools_but_routes_compact(
    mock_provider, output_dir
):
    all_names = {"http_get", "http_request", "curl_headers", "nmap_scan", "ssh_audit", "save_deliverable"}
    tool_defs = [
        {"name": name, "description": name, "input_schema": {}, "function": lambda **_: "{}"}
        for name in all_names
    ]

    for profile in ("full", "compact"):
        mock_provider.reset_mock()
        if profile == "compact":
            mock_provider.provider = "local-moe"
            mock_provider.model = "lance-moe"
        else:
            mock_provider.provider = "openrouter"
            mock_provider.model = "MiniMax-M2.7"
        pipeline = Pipeline(provider=mock_provider, execution_profile=profile)
        pipeline._resolve_tools = lambda _config: tool_defs
        (pipeline.run_dir / "03_vuln_analysis.json").write_text(json.dumps({
            "vulnerabilities": [{
                "id": "V1", "device_id": "web-1", "device_ip": "192.0.2.32",
                "type": "no_auth", "severity": "HIGH", "service": "http", "port": 80,
                "details": "HTTP admin endpoint", "evidence": "HTTP endpoint observed",
            }]
        }))
        mock_provider.chat_with_tools.return_value = "done"
        pipeline._run_exploit_agents(AGENTS["vuln_analysis"])
        names = {tool["name"] for tool in mock_provider.chat_with_tools.call_args.kwargs["tools"]}
        if profile == "full":
            assert names == all_names
        else:
            assert names == {"http_get"}


def test_phase4_compact_synthesis_distinguishes_update_acceptance_and_ssh_failure():
    get_only = _synthesize_exploit_result(
        {"type": "insecure_update", "service": "http", "port": 80},
        [{
            "tool": "http_get",
            "args": {"url": "http://192.168.100.13/update"},
            "result": json.dumps({
                "stdout": '{"status":"update accepted","version":"2.1.4"}',
                "return_code": 0,
            }),
        }],
        compact=True,
    )
    assert get_only["status"] == "FAILED"

    update = _synthesize_exploit_result(
        {"type": "insecure_update", "service": "http", "port": 80},
        [{
            "tool": "http_request",
            "args": {
                "url": "http://192.168.100.13/update",
                "method": "POST",
                "body": '{"firmware":"phase4-probe","signature":""}',
            },
            "result": json.dumps({
                "status_code": 200,
                "body": '{"status":"update accepted"}',
            }),
        }],
        compact=True,
    )
    assert update["status"] == "EXPLOITED"

    ssh = _synthesize_exploit_result(
        {"type": "default_credentials", "service": "ssh", "port": 22},
        [{
            "tool": "ssh_login",
            "args": {"command_string": "sshpass -p admin ssh admin@192.168.100.11 id"},
            "result": json.dumps({
                "stdout": "", "stderr": "Connection closed by remote host", "return_code": 255,
            }),
        }],
        compact=True,
    )
    assert ssh["status"] == "FAILED"

def test_phase4_requirement_rejects_wrong_endpoint_or_transport():
    requirement = _phase4_verification_plan({
        "type": "network_exposure", "service": "mqtt-ws",
        "device_ip": "192.168.100.11", "port": 9001,
    })
    assert not _phase4_requirement_matches(
        requirement, "mqtt_listen", {"broker": "192.168.100.11", "topic": "#"}
    )
    assert not _phase4_requirement_matches(
        requirement,
        "http_request",
        {"url": "http://192.168.100.11:9001/", "method": "GET", "headers": {}},
    )
    assert _phase4_requirement_matches(
        requirement, "http_request", requirement["args_hint"]
    )


def test_phase4_nonlocal_tools_are_restricted_to_evaluable_surface():
    def tool(name):
        return {"name": name, "description": name, "input_schema": {}, "function": lambda **_: "{}"}

    tools = [
        tool("http_get"), tool("http_request"), tool("curl_headers"),
        tool("mtls_request"), tool("sqlmap"), tool("nikto_scan"),
        tool("whatweb"), tool("modbus_scan"), tool("modbus_write"),
        tool("save_deliverable"),
    ]

    https = {
        item["name"] for item in _phase4_local_verification_tools(
            tools, category="data", service="https", include_deliverable=True,
        )
    }
    modbus = {
        item["name"] for item in _phase4_local_verification_tools(
            tools, category="no_auth", service="modbus", include_deliverable=True,
        )
    }

    assert {"http_get", "http_request", "curl_headers", "mtls_request", "save_deliverable"} <= https
    assert {"sqlmap", "nikto_scan", "whatweb"}.isdisjoint(https)
    assert "modbus_scan" in modbus
    assert "modbus_write" not in modbus
    assert "save_deliverable" in modbus


def test_synthesize_exploit_result_accepts_evaluable_scan_and_socket_evidence():
    nmap = _synthesize_exploit_result(
        {
            "id": "VULN-010",
            "device_id": "s1-modbus",
            "device_ip": "192.168.100.50",
            "type": "no_auth",
            "service": "modbus",
            "port": 502,
        },
        [{
            "tool": "modbus_scan",
            "result": json.dumps({
                "stdout": "502/tcp open modbus\nUnit identifiers discovered",
                "return_code": 0,
            }),
            "evidence_ref": "tc-modbus",
        }],
    )
    ssh = _synthesize_exploit_result(
        {
            "id": "VULN-011",
            "device_id": "s1-ssh",
            "device_ip": "192.168.100.22",
            "type": "weak_cipher",
            "service": "ssh",
            "port": 22,
        },
        [{
            "tool": "ssh_audit",
            "result": json.dumps({"stdout": "[fail] chacha20-poly1305 vulnerable to Terrapin", "return_code": 0}),
            "evidence_ref": "tc-ssh",
        }],
    )
    tcp = _synthesize_exploit_result(
        {
            "id": "VULN-012",
            "device_id": "s1-opcua",
            "device_ip": "192.168.100.60",
            "type": "info_disclosure",
            "service": "opcua",
            "port": 4840,
        },
        [{
            "tool": "tcp_send",
            "result": json.dumps({"received_bytes": 4, "received_ascii": "ACK", "return_code": 0}),
            "evidence_ref": "tc-tcp",
        }],
    )

    assert nmap["status"] == "EXPLOITED"
    assert nmap["evidence_level"] == 2
    assert ssh["status"] == "EXPLOITED"
    assert ssh["evidence_level"] == 2
    assert tcp["status"] == "EXPLOITED"
    assert tcp["evidence_level"] == 2


def test_synthesize_exploit_result_accepts_unauthenticated_mqtt_websocket_upgrade():
    result = _synthesize_exploit_result(
        {
            "id": "VULN-WS",
            "device_ip": "192.168.100.11",
            "type": "no_auth",
            "service": "mqtt-ws",
            "port": 9001,
        },
        [{
            "tool": "http_request",
            "args": {"url": "http://192.168.100.11:9001/"},
            "result": json.dumps({
                "status_code": 101,
                "headers": {"Upgrade": "websocket"},
            }),
            "evidence_ref": "tc-ws",
        }],
    )
    assert result["status"] == "EXPLOITED"
    assert result["evidence_level"] == 2


def test_http_data_exposure_preserves_all_endpoints():
    finding = _enrich_finding_structure({
        "device_ip": "192.168.100.12",
        "service": "http",
        "type": "data_exposure",
        "endpoint": "/backup/db_backup_2024-01-15.sql",
        "details": (
            "Retrieved http://192.168.100.12/backup/db_backup_2024-01-15.sql "
            "and http://192.168.100.12/config/app.config"
        ),
    })
    assert finding["endpoints"] == [
        "/backup/db_backup_2024-01-15.sql",
        "/config/app.config",
    ]
    entry = _make_test_entry(finding, status="CONFIRMED", result={})
    assert entry["endpoints"] == finding["endpoints"]


def test_exploit_prompt_requires_fresh_phase4_verification():
    prompt = Path("src/agent/prompts/exploit_device_vuln.txt").read_text(encoding="utf-8")
    assert "Run at least one fresh verification tool" in prompt
    assert "Never emit CONFIRMED" in prompt
    assert "Do not use modbus_write" in prompt


def test_resolve_model_provider_uses_registry(monkeypatch):
    monkeypatch.setattr(
        "src.db.database.get_model",
        lambda model: {"provider": "local-moe"} if model == "lance-moe" else None,
    )

    assert _resolve_model_provider("lance-moe") == "local-moe"
    assert _resolve_model_provider("MiniMax-M2.7") == "minimax"
    assert _resolve_model_provider("openai/gpt-4o") == "openrouter"


def test_local_memo_guard_rejects_placeholders_and_empty_evidence_blocks():
    assert _looks_unusable_model_memo("Evidence:\n```json\n\n```\n")
    assert _looks_unusable_model_memo("Prepared by: [Your Name]")


def test_local_report_memo_guard_rejects_false_compromise_claim():
    context = {
        "intrusion": {
            "summary": {"devices_compromised": 0},
            "compromised_devices": [],
        }
    }

    assert _local_report_memo_contradicts_context(
        "The web server was confirmed to be compromised.",
        context,
    )


@pytest.fixture
def mock_provider():
    provider = MagicMock()
    provider.model = "test-model"
    provider.chat_with_tools.return_value = "Done."
    return provider


@pytest.fixture
def output_dir(tmp_path, monkeypatch):
    import src.agent.pipeline as mod
    import src.agent.validators as val_mod
    monkeypatch.setattr(mod, "OUTPUT_DIR", tmp_path)
    return tmp_path


class TestResolveTools:
    def test_resolve_graph_tools(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=1, prompt_template="t",
            deliverable_file="t.md", tools=["graph"],
        )
        tools = pipeline._resolve_tools(config)
        assert len(tools) == len(TOOL_GROUPS["graph"])

    def test_resolve_multiple_groups(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=1, prompt_template="t",
            deliverable_file="t.md", tools=["graph", "deliverable"],
        )
        tools = pipeline._resolve_tools(config)
        expected = len(TOOL_GROUPS["graph"]) + len(TOOL_GROUPS["deliverable"])
        assert len(tools) == expected

    def test_dry_run_skips_recon(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider, dry_run=True)
        config = AgentConfig(
            name="test", phase=1, prompt_template="t",
            deliverable_file="t.md", tools=["graph", "recon", "deliverable"],
        )
        tools = pipeline._resolve_tools(config)
        recon_names = {t["name"] for t in TOOL_GROUPS["recon"]}
        resolved_names = {t["name"] for t in tools}
        assert recon_names.isdisjoint(resolved_names)


class TestPhase4LocalToolScope:
    def test_telnet_scope_excludes_unrelated_exploit_tools(self):
        from src.agent import pipeline as pipeline_mod

        tools = [
            {"name": name, "function": lambda: "{}"}
            for name in (
                "telnet_connect", "try_credential", "mqtt_listen",
                "http_get", "exploit_iot_kit", "save_deliverable",
                "search_knowledge",
            )
        ]

        scoped = pipeline_mod._phase4_local_verification_tools(
            tools, category="data_access", service="telnet"
        )
        names = {tool["name"] for tool in scoped}

        assert "telnet_connect" in names
        assert "try_credential" in names
        assert "search_knowledge" in names
        assert "mqtt_listen" not in names
        assert "http_get" not in names
        assert "exploit_iot_kit" not in names
        assert "save_deliverable" not in names


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


class TestPrepare3BDatasets:
    def test_phase5_examples_remain_single_atomic_evidence_chain(self):
        from training.prepare_3b_datasets import build_chunks

        class Tokenizer:
            def apply_chat_template(
                self, messages, tools=None, tokenize=False, add_generation_prompt=False
            ):
                return "\n".join(str(message.get("content", "")) for message in messages)

            def encode(self, text, add_special_tokens=False):
                return text.split()

        row = {
            "metadata": {"phase": 5},
            "tools": [],
            "messages": [
                {"role": "system", "content": "intrusion system"},
                {"role": "user", "content": "use tool evidence"},
                {"role": "assistant", "content": "try credential"},
                {"role": "tool", "content": "try_credential success false"},
                {"role": "assistant", "content": "final no compromise"},
            ],
        }

        chunks, stats = build_chunks(Tokenizer(), row, max_length=100, distractors=0)

        assert stats["chunks"] == 1
        assert len(chunks) == 1
        assert chunks[0]["metadata"]["evidence_chain_atomic"] is True
        contents = [message.get("content") for message in chunks[0]["messages"]]
        assert "try_credential success false" in contents
        assert "final no compromise" in contents


class TestReconToolContract:
    def test_requires_minimum_evidence_without_prescribing_call_order(
        self, mock_provider, output_dir, monkeypatch
    ):
        import src.agent.tools.graph_tools as graph_tools

        monkeypatch.setattr(graph_tools, "_scenario_topology", {
            "nodes": [
                {"id": "router", "ip": "192.168.100.1", "role": "router"},
                {"id": "mqtt", "ip": "192.168.100.11", "role": "mqtt_broker"},
            ]
        })
        pipeline = Pipeline(provider=mock_provider)
        pipeline.context = {"target_subnet": "192.168.100.0/24"}

        calls = []

        def tool(name, result='{"status":"ok"}'):
            def execute(**kwargs):
                calls.append((name, kwargs))
                return result
            return {
                "name": name,
                "description": name,
                "input_schema": {},
                "function": execute,
            }

        tools = [
            tool("arp_scan", '{"hosts":[]}'),
            tool("nmap_discovery", '{"stdout":"discovery"}'),
            tool("nmap_scan", '{"stdout":"scan"}'),
            tool("read_deliverable", '{"content":"phase1"}'),
            tool("save_deliverable", '{"status":"saved"}'),
            tool("ssh_audit"),
            tool("ssh_exec"),
        ]
        guarded = {
            item["name"]: item["function"]
            for item in pipeline._apply_recon_tool_contract(tools)
        }

        assert "ssh_audit" in guarded
        assert "ssh_exec" not in guarded
        early = json.loads(guarded["save_deliverable"](
            filename="02_recon.md", content="report"
        ))
        assert early["error_kind"] == "recon_contract_incomplete"
        requirements = {item["requirement"] for item in early["missing_requirements"]}
        assert requirements == {
            "local_discovery", "subnet_discovery", "phase1_context",
            "minimum_port_coverage",
        }

        # A specialized safe probe may run before the mandatory baseline.
        guarded["ssh_audit"](host="192.168.100.1")
        guarded["arp_scan"]()
        guarded["nmap_discovery"](target="192.168.100.0/24")
        guarded["read_deliverable"](filename="01_graph_analysis.md")
        for item in pipeline._recon_scan_plan(graph_tools._scenario_topology["nodes"]):
            guarded["nmap_scan"](
                target=item["target"],
                ports=item["ports"],
                skip_discovery=True,
            )

        saved = json.loads(guarded["save_deliverable"](
            filename="02_recon.md", content="report"
        ))
        assert saved["status"] == "saved"
        assert [name for name, _ in calls].count("nmap_scan") == 2
        assert calls[0][0] == "ssh_audit"

    @pytest.mark.parametrize(
        ("profile", "expected_completion_required", "expected_read_calls"),
        [
            ("compact", True, 1),
            ("full", False, 2),
        ],
    )
    def test_compact_local_moe_allows_only_save_after_recon_is_ready(
        self, output_dir, monkeypatch, profile, expected_completion_required, expected_read_calls
    ):
        import src.agent.tools.graph_tools as graph_tools

        monkeypatch.setattr(graph_tools, "_scenario_topology", {
            "nodes": [{
                "id": "web", "ip": "192.168.100.12", "role": "web_server",
            }]
        })
        provider = MagicMock()
        provider.provider = "local-moe"
        provider.model = "lance-moe"
        pipeline = Pipeline(provider=provider, execution_profile=profile)
        pipeline.context = {"target_subnet": "192.168.100.0/24"}
        read = MagicMock(return_value='{"content":"phase1"}')

        def constant(result):
            return lambda **kwargs: result

        guarded = {
            item["name"]: item["function"]
            for item in pipeline._apply_recon_tool_contract([
                {"name": "arp_scan", "description": "arp", "input_schema": {},
                 "function": constant('{"hosts":[]}')},
                {"name": "nmap_discovery", "description": "discovery",
                 "input_schema": {},
                 "function": constant('{"stdout":"ok","return_code":0}')},
                {"name": "read_deliverable", "description": "read",
                 "input_schema": {}, "function": read},
                {"name": "nmap_scan", "description": "scan", "input_schema": {},
                 "function": constant('{"stdout":"ok","return_code":0}')},
                {"name": "save_deliverable", "description": "save",
                 "input_schema": {},
                 "function": constant('{"status":"saved"}')},
            ])
        }
        guarded["arp_scan"]()
        guarded["nmap_discovery"](target="192.168.100.0/24")
        guarded["read_deliverable"](filename="01_graph_analysis.md")
        item = pipeline._recon_scan_plan(
            graph_tools._scenario_topology["nodes"]
        )[0]
        guarded["nmap_scan"](
            target=item["target"], ports=item["ports"], skip_discovery=True
        )

        late_read = json.loads(guarded["read_deliverable"](
            filename="01_graph_analysis.md"
        ))
        assert read.call_count == expected_read_calls
        if expected_completion_required:
            assert late_read["error_kind"] == "recon_completion_required"
            assert late_read["allowed_tool"] == "save_deliverable"
            assert late_read["recon_progress"]["ready_to_save"] is True
        else:
            assert late_read["content"] == "phase1"

    def test_two_identical_scan_failures_end_retry_loop_as_failed_evidence(
        self, mock_provider, output_dir, monkeypatch
    ):
        import src.agent.tools.graph_tools as graph_tools

        monkeypatch.setattr(graph_tools, "_scenario_topology", {
            "nodes": [{"id": "web", "ip": "192.168.100.12", "role": "web_server"}]
        })
        pipeline = Pipeline(provider=mock_provider)
        pipeline.context = {"target_subnet": "192.168.100.0/24"}
        failure = '{"stdout":"","stderr":"timeout","return_code":-1}'

        def constant(result):
            return lambda **kwargs: result

        guarded = {
            item["name"]: item["function"]
            for item in pipeline._apply_recon_tool_contract([
                {"name": "arp_scan", "description": "arp", "input_schema": {},
                 "function": constant('{"hosts":[]}')},
                {"name": "nmap_discovery", "description": "discovery", "input_schema": {},
                 "function": constant('{"stdout":"ok","return_code":0}')},
                {"name": "read_deliverable", "description": "read", "input_schema": {},
                 "function": constant('{"content":"phase1"}')},
                {"name": "nmap_scan", "description": "scan", "input_schema": {},
                 "function": MagicMock(return_value=failure)},
                {"name": "save_deliverable", "description": "save", "input_schema": {},
                 "function": constant('{"status":"saved"}')},
            ])
        }
        guarded["arp_scan"]()
        guarded["nmap_discovery"](target="192.168.100.0/24")
        guarded["read_deliverable"](filename="01_graph_analysis.md")
        ports = pipeline._recon_scan_plan(
            graph_tools._scenario_topology["nodes"]
        )[0]["ports"]

        first = json.loads(guarded["nmap_scan"](
            target="192.168.100.12", ports=ports
        ))
        assert first["recon_progress"]["ready_to_save"] is False
        second = json.loads(guarded["nmap_scan"](
            target="192.168.100.12", ports=ports
        ))
        progress = second["recon_progress"]
        assert progress["ready_to_save"] is True
        assert progress["targets"][0]["failed_ports"] == [22, 80, 443, 8080, 8443]
        assert progress["targets"][0]["missing_ports"] == []

    def test_wider_split_and_repeated_scans_are_valid_strategies(
        self, mock_provider, output_dir, monkeypatch
    ):
        """A capable model may widen, split, reorder, and repeat its scans."""
        import src.agent.tools.graph_tools as graph_tools

        monkeypatch.setattr(graph_tools, "_scenario_topology", {
            "nodes": [
                {"id": "router", "ip": "192.168.100.1", "role": "router"},
                {"id": "mqtt", "ip": "192.168.100.11", "role": "mqtt_broker"},
                {"id": "web", "ip": "192.168.100.12", "role": "web_server"},
                {"id": "ssh", "ip": "192.168.100.13", "role": "ssh_server"},
            ]
        })
        pipeline = Pipeline(provider=mock_provider)
        pipeline.context = {"target_subnet": "192.168.100.0/24"}
        execute = MagicMock(return_value='{"status":"ok"}')
        tools = [{
            "name": name,
            "description": name,
            "input_schema": {},
            "function": execute,
        } for name in (
            "arp_scan", "nmap_discovery", "nmap_scan",
            "read_deliverable", "save_deliverable",
        )]
        guarded = {
            item["name"]: item["function"]
            for item in pipeline._apply_recon_tool_contract(tools)
        }

        guarded["arp_scan"]()
        # Extra discovery arguments from the model are ignored by the contract.
        guarded["nmap_discovery"](
            target="192.168.100.0/24", ports="22,80", skip_discovery=True
        )
        guarded["read_deliverable"](filename="01_graph_analysis.md")
        plan = pipeline._recon_scan_plan(graph_tools._scenario_topology["nodes"])
        for item in plan:
            if item["target"] in {"192.168.100.1", "192.168.100.11"}:
                continue
            guarded["nmap_scan"](
                target=item["target"], ports=item["ports"], skip_discovery=True
            )

        # A broad range satisfies the router's smaller minimum baseline.
        guarded["nmap_scan"](
            target="192.168.100.1", ports="1-9000", scripts="default,vuln"
        )

        early = json.loads(guarded["save_deliverable"](
            filename="02_recon.md", content="report"
        ))
        coverage = [
            item for item in early["missing_requirements"]
            if item["requirement"] == "minimum_port_coverage"
        ]
        assert coverage == [{
            "requirement": "minimum_port_coverage",
            "target": "192.168.100.11",
            "missing_ports": [22, 80, 1883, 8883],
            "suggested_tool": "nmap_scan",
        }]

        outside = json.loads(guarded["nmap_scan"](
            target="198.51.100.10", ports="22,80,443", skip_discovery=True
        ))
        assert outside["error_kind"] == "invalid_recon_target"

        # Two complementary scans satisfy MQTT coverage; an exactly equivalent
        # repetition is served from the Recon cache instead of hitting nmap.
        guarded["nmap_scan"](target="192.168.100.11", ports="22,80")
        guarded["nmap_scan"](target="192.168.100.11", ports="1883,8883")
        duplicate = json.loads(guarded["nmap_scan"](
            target="192.168.100.11", ports="8883,1883"
        ))
        assert duplicate["recon_cache"]["hit"] is True
        saved = json.loads(guarded["save_deliverable"](
            filename="02_recon.md", content="report"
        ))
        assert saved["status"] == "ok"
        assert execute.call_count == 9

    def test_duplicate_in_scope_scan_is_cached_but_new_probe_executes(
        self, mock_provider, output_dir, monkeypatch
    ):
        import src.agent.tools.graph_tools as graph_tools

        monkeypatch.setattr(graph_tools, "_scenario_topology", {"nodes": []})
        pipeline = Pipeline(provider=mock_provider)
        pipeline.context = {"target_subnet": "192.168.100.0/24"}
        execute = MagicMock(return_value='{"stdout":"ok"}')
        guarded = pipeline._apply_recon_tool_contract([{
            "name": "nmap_scan",
            "description": "scan",
            "input_schema": {},
            "function": execute,
        }])[0]["function"]

        kwargs = {"target": "192.168.100.10", "ports": "80", "skip_discovery": True}
        first = json.loads(guarded(**kwargs))
        duplicate = json.loads(guarded(**kwargs))
        assert first["stdout"] == "ok"
        assert duplicate["stdout"] == "ok"
        assert duplicate["recon_cache"]["hit"] is True
        assert execute.call_count == 1

        fresh_probe = json.loads(guarded(
            **kwargs, scripts="http-title"
        ))
        assert "recon_cache" not in fresh_probe
        assert execute.call_count == 2

    def test_every_recon_result_exposes_next_requirement(
        self, mock_provider, output_dir, monkeypatch
    ):
        import src.agent.tools.graph_tools as graph_tools

        monkeypatch.setattr(graph_tools, "_scenario_topology", {
            "nodes": [{
                "id": "web", "ip": "192.168.100.12", "role": "web_server",
            }]
        })
        pipeline = Pipeline(provider=mock_provider)
        pipeline.context = {"target_subnet": "192.168.100.0/24"}
        guarded = {
            item["name"]: item["function"]
            for item in pipeline._apply_recon_tool_contract([{
                "name": name,
                "description": name,
                "input_schema": {},
                "function": MagicMock(return_value='{"status":"ok"}'),
            } for name in (
                "arp_scan", "nmap_discovery", "nmap_scan",
                "read_deliverable", "save_deliverable",
            )])
        }

        arp_result = json.loads(guarded["arp_scan"]())
        progress = arp_result["recon_progress"]
        assert progress["completed"]["local_discovery"] is True
        assert progress["next_requirement"] == {
            "requirement": "subnet_discovery",
            "target": "192.168.100.0/24",
            "tool": "nmap_discovery",
        }
        assert progress["targets"][0]["missing_ports"] == [22, 80, 443, 8080, 8443]

    def test_failed_scan_does_not_satisfy_minimum_coverage(
        self, mock_provider, output_dir, monkeypatch
    ):
        import src.agent.tools.graph_tools as graph_tools

        monkeypatch.setattr(graph_tools, "_scenario_topology", {
            "nodes": [{"id": "web", "ip": "192.168.100.12", "role": "web_server"}]
        })
        pipeline = Pipeline(provider=mock_provider)
        pipeline.context = {"target_subnet": "192.168.100.0/24"}
        scan = MagicMock(side_effect=[
            '{"stdout":"","stderr":"timeout","return_code":-1}',
            '{"stdout":"open","stderr":"","return_code":0}',
        ])

        def constant(result):
            return lambda **kwargs: result

        tools = [
            {"name": "arp_scan", "description": "arp", "input_schema": {},
             "function": constant('{"hosts":[]}')},
            {"name": "nmap_discovery", "description": "discovery", "input_schema": {},
             "function": constant('{"stdout":"ok","return_code":0}')},
            {"name": "read_deliverable", "description": "read", "input_schema": {},
             "function": constant('{"content":"phase1"}')},
            {"name": "nmap_scan", "description": "scan", "input_schema": {},
             "function": scan},
            {"name": "save_deliverable", "description": "save", "input_schema": {},
             "function": constant('{"status":"saved"}')},
        ]
        guarded = {
            item["name"]: item["function"]
            for item in pipeline._apply_recon_tool_contract(tools)
        }
        guarded["arp_scan"]()
        guarded["nmap_discovery"](target="192.168.100.0/24")
        guarded["read_deliverable"](filename="01_graph_analysis.md")
        ports = pipeline._recon_scan_plan(graph_tools._scenario_topology["nodes"])[0]["ports"]

        guarded["nmap_scan"](target="192.168.100.12", ports=ports)
        rejected = json.loads(guarded["save_deliverable"](
            filename="02_recon.md", content="report"
        ))
        assert rejected["error_kind"] == "recon_contract_incomplete"

        guarded["nmap_scan"](target="192.168.100.12", ports=ports)
        saved = json.loads(guarded["save_deliverable"](
            filename="02_recon.md", content="report"
        ))
        assert saved["status"] == "saved"


class TestExploitEvidenceGuard:
    def test_cache_or_timeout_is_not_positive_evidence(self):
        assert not _has_positive_exploit_evidence({
            "evidence": "[CACHE] Only duplicate messages received. Timed out.",
            "evidence_level": 2,
        })

    def test_concrete_extracted_data_is_positive_evidence(self):
        assert _has_positive_exploit_evidence({
            "evidence": "Anonymous subscribe accepted; payload captured",
            "evidence_level": 3,
            "data_extracted": ["sensors/temp 21.4"],
        })

    def test_unsupported_exploited_verdict_is_downgraded(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        exploit_file = pipeline.run_dir / "result.json"
        exploit_file.write_text(json.dumps({
            "status": "EXPLOITED",
            "evidence": "[CACHE] Only duplicate messages received",
            "evidence_level": 2,
        }))
        verdict = pipeline._resolve_exploit_verdict(
            {"id": "VULN-001", "device_id": "mqtt", "type": "no_auth"},
            exploit_file,
        )
        assert verdict["status"] == "ERROR"
        assert verdict["evidence_level"] == 0

    def test_confirmed_verdict_requires_semantic_tool_evidence(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        exploit_file = pipeline.run_dir / "result.json"
        exploit_file.write_text(json.dumps({
            "status": "CONFIRMED",
            "evidence": "The model observed a vulnerable service",
            "evidence_level": 3,
        }))
        verdict = pipeline._resolve_exploit_verdict(
            {"id": "VULN-001", "device_id": "mqtt", "type": "no_auth"},
            exploit_file,
        )
        assert verdict["status"] == "ERROR"
        assert verdict["evidence_level"] == 0

    def test_http_404_is_failed_not_exploited(self):
        result = _synthesize_exploit_result(
            {
                "id": "VULN-004",
                "device_id": "s1-router",
                "device_ip": "192.168.100.1",
                "type": "data_exposure",
                "service": "http",
                "port": 80,
            },
            [{
                "tool": "http_get",
                "args": {"url": "http://192.168.100.1/backup/db_backup.sql"},
                "result": json.dumps({
                    "stdout": "<h1>Not Found</h1>The requested URL was not found",
                    "stderr": "",
                    "return_code": 0,
                }),
                "evidence_ref": "tc-404",
            }],
        )

        assert result["status"] == "FAILED"
        assert "404" in result["evidence"] or "Not Found" in result["evidence"]

    def test_mqtt_websocket_is_not_confirmed_by_plain_mqtt_tool(self):
        result = _synthesize_exploit_result(
            {
                "id": "VULN-008",
                "device_id": "s1-mqtt",
                "device_ip": "192.168.100.11",
                "type": "no_auth",
                "service": "mqtt-ws",
                "port": 9001,
            },
            [{
                "tool": "mqtt_listen",
                "args": {"broker": "192.168.100.11", "topic": "#"},
                "result": json.dumps({
                    "stdout": "sensors/temp {\"value\":22.5}",
                    "return_code": 0,
                }),
                "evidence_ref": "tc-mqtt",
            }],
        )

        assert result["status"] == "ERROR"
        assert "WebSocket" in result["evidence"]

    def test_mqtt_payload_with_timeout_exit_code_is_confirmed(self):
        result = _synthesize_exploit_result(
            {
                "id": "VULN-001",
                "device_id": "s1-mqtt",
                "device_ip": "192.168.100.11",
                "type": "no_auth",
                "service": "mqtt",
                "port": 1883,
            },
            [{
                "tool": "mqtt_listen",
                "args": {"broker": "192.168.100.11", "topic": "#"},
                "result": json.dumps({
                    "stdout": "smartcity/admin/credentials {\"db_pass\":\"P@ssw0rd123\"}",
                    "stderr": "Timed out\n",
                    "return_code": 27,
                    "interpretation": "anonymous_access_confirmed_broker_idle",
                }),
                "evidence_ref": "tc-mqtt",
            }],
        )

        assert result["status"] == "EXPLOITED"
        assert result["evidence_level"] == 3

    def test_exploited_verdict_is_downgraded_when_tool_evidence_contradicts_it(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        exploit_file = pipeline.run_dir / "result.json"
        exploit_file.write_text(json.dumps({
            "status": "EXPLOITED",
            "evidence": "http_get returned HTTP 200 and exposed credentials",
            "evidence_level": 3,
        }))
        verdict = pipeline._resolve_exploit_verdict(
            {
                "id": "VULN-004",
                "device_id": "s1-router",
                "device_ip": "192.168.100.1",
                "type": "data_exposure",
                "service": "http",
                "port": 80,
            },
            exploit_file,
            tool_records=[{
                "tool": "http_get",
                "args": {"url": "http://192.168.100.1/backup/db_backup.sql"},
                "result": json.dumps({"stdout": "<h1>Not Found</h1>", "return_code": 0}),
                "evidence_ref": "tc-404",
            }],
        )

        assert verdict["status"] == "FAILED"
        assert verdict["evidence_level"] == 1

    def test_missing_exploit_file_uses_archived_tool_records(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        verdict = pipeline._resolve_exploit_verdict(
            {
                "id": "VULN-001",
                "device_id": "mqtt_broker",
                "device_ip": "192.168.100.11",
                "type": "no_auth",
                "service": "mqtt",
                "port": 1883,
            },
            pipeline.run_dir / "04_exploits" / "mqtt_broker" / "no_auth_VULN-001.json",
            tool_records=[{
                "tool": "mqtt_listen",
                "args": {"broker": "192.168.100.11", "topic": "#"},
                "result": json.dumps({
                    "stdout": "sensors/temp {\"value\":22.5}",
                    "return_code": 27,
                }),
                "evidence_ref": "tc-mqtt",
            }],
        )

        assert verdict["status"] == "CONFIRMED"
        assert verdict["evidence_level"] == 3
        assert verdict["evidence_refs"] == ["tc-mqtt"]

    def test_exploited_mqtt_result_is_not_downgraded_when_tools_confirm(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        exploit_file = pipeline.run_dir / "mqtt.json"
        exploit_file.write_text(json.dumps({
            "status": "EXPLOITED",
            "evidence": "mqtt_listen anonymous subscription received messages",
            "evidence_level": 3,
            "tool_used": "mqtt_listen",
        }))

        verdict = pipeline._resolve_exploit_verdict(
            {
                "id": "VULN-001",
                "device_id": "s1-mqtt",
                "device_ip": "192.168.100.11",
                "type": "no_auth",
                "service": "mqtt",
                "port": 1883,
            },
            exploit_file,
            tool_records=[{
                "tool": "mqtt_listen",
                "args": {"broker": "192.168.100.11", "topic": "#"},
                "result": json.dumps({
                    "stdout": "smartcity/admin/credentials {\"db_user\":\"root\",\"db_pass\":\"P@ssw0rd123\"}",
                    "stderr": "Timed out\n",
                    "return_code": 27,
                }),
                "evidence_ref": "tc-mqtt",
            }],
        )

        assert verdict["status"] == "CONFIRMED"
        assert verdict["data_extracted"]


class TestPrerequisites:
    def test_no_prerequisites(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=1, prompt_template="t",
            deliverable_file="t.md", tools=["graph"], prerequisites=[],
        )
        assert pipeline._check_prerequisites(config, {})

    def test_completed_prerequisite(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=2, prompt_template="t",
            deliverable_file="t.md", tools=["graph"],
            prerequisites=["graph_analysis"],
        )
        results = {"graph_analysis": "completed"}
        assert pipeline._check_prerequisites(config, results)

    def test_synthesized_completed_prerequisite(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="vuln_analysis", phase=3, prompt_template="t",
            deliverable_file="03_vuln_analysis.json", tools=["graph"],
            prerequisites=["recon"],
        )
        results = {"recon": "completed:synthesized"}
        assert pipeline._check_prerequisites(config, results)

    def test_phase4_worker_errors_keep_validated_results_usable(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="intrusion", phase=5, prompt_template="t",
            deliverable_file="05_intrusion.json", tools=["graph"],
            prerequisites=["exploitation"],
        )
        assert pipeline._check_prerequisites(
            config, {"exploitation": "executed_with_worker_errors"}
        )

    @pytest.mark.parametrize("status", [
        "failed:Deliverable missing",
        "blocked:phase_no_observable_actions",
        "partial",
    ])
    def test_unsuccessful_status_is_not_a_completed_prerequisite(
        self, mock_provider, output_dir, status
    ):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="vuln_analysis", phase=3, prompt_template="t",
            deliverable_file="03_vuln_analysis.json", tools=["graph"],
            prerequisites=["recon"],
        )
        assert not pipeline._check_prerequisites(config, {"recon": status})

    def test_skipped_conditional_counts(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=5, prompt_template="t",
            deliverable_file="t.md", tools=["graph"],
            prerequisites=["exploitation"],
        )
        results = {"exploitation": "skipped:conditional"}
        assert pipeline._check_prerequisites(config, results)

    def test_failed_prerequisite(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=2, prompt_template="t",
            deliverable_file="t.md", tools=["graph"],
            prerequisites=["graph_analysis"],
        )
        results = {}  # Not run, and no file on disk
        assert not pipeline._check_prerequisites(config, results)

    def test_failed_prerequisite_status_is_not_overridden_by_disk_file(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        (pipeline.run_dir / "04_exploitation.json").write_text(json.dumps({"tests": []}))
        config = AgentConfig(
            name="intrusion", phase=5, prompt_template="t",
            deliverable_file="05_intrusion.json", tools=["graph"],
            prerequisites=["exploitation"],
        )

        assert not pipeline._check_prerequisites(
            config,
            {"exploitation": "failed:Missing per-vulnerability Phase 4 exploit result"},
        )

    def test_prerequisite_on_disk(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        # Write the prerequisite deliverable to the pipeline's run dir
        (pipeline.run_dir / "01_graph_analysis.md").write_text("## S1\n## S2\n")
        config = AgentConfig(
            name="test", phase=2, prompt_template="t",
            deliverable_file="t.md", tools=["graph"],
            prerequisites=["graph_analysis"],
        )
        results = {}  # Not in current run results, but file exists
        assert pipeline._check_prerequisites(config, results)


class TestConditional:
    def test_no_conditional(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=1, prompt_template="t",
            deliverable_file="t.md", tools=["graph"],
        )
        assert pipeline._check_conditional(config)

    def test_missing_conditional_file(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=4, prompt_template="t",
            deliverable_file="t.md", tools=["recon"],
            conditional="03_vuln_analysis.json",
        )
        assert not pipeline._check_conditional(config)

    def test_empty_queue(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        (pipeline.run_dir / "03_vuln_analysis.json").write_text(
            json.dumps({"vulnerabilities": []})
        )
        config = AgentConfig(
            name="test", phase=4, prompt_template="t",
            deliverable_file="t.md", tools=["recon"],
            conditional="03_vuln_analysis.json",
        )
        assert not pipeline._check_conditional(config)

    def test_non_empty_queue(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        (pipeline.run_dir / "03_vuln_analysis.json").write_text(
            json.dumps({"vulnerabilities": [{"id": "VULN-001"}]})
        )
        config = AgentConfig(
            name="test", phase=4, prompt_template="t",
            deliverable_file="t.md", tools=["recon"],
            conditional="03_vuln_analysis.json",
        )
        assert pipeline._check_conditional(config)

    def test_invalid_json(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        (pipeline.run_dir / "03_vuln_analysis.json").write_text("not json")
        config = AgentConfig(
            name="test", phase=4, prompt_template="t",
            deliverable_file="t.md", tools=["recon"],
            conditional="03_vuln_analysis.json",
        )
        assert not pipeline._check_conditional(config)

    def test_full_phase5_reconciles_executed_failed_phase4_but_compact_does_not(
        self, mock_provider, output_dir
    ):
        phase4 = {
            "summary": {"execution_state": "executed"},
            "tests": [{"vuln_id": "V1", "status": "FAILED"}],
        }
        config = AgentConfig(
            name="intrusion", phase=5, prompt_template="t",
            deliverable_file="05_intrusion.json", tools=["intrusion"],
            conditional="04_exploitation.json",
        )

        full = Pipeline(provider=mock_provider, execution_profile="full")
        (full.run_dir / "04_exploitation.json").write_text(json.dumps(phase4))
        assert full._check_conditional(config)

        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        compact = Pipeline(provider=mock_provider, execution_profile="compact")
        (compact.run_dir / "04_exploitation.json").write_text(json.dumps(phase4))
        assert not compact._check_conditional(config)


class TestListDeliverables:
    def test_empty(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        result = pipeline._list_previous_deliverables()
        # run_dir exists but is empty
        assert "None" in result or result == ""

    def test_with_files(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        (pipeline.run_dir / "01_graph_analysis.md").write_text("content")
        (pipeline.run_dir / "02_recon.md").write_text("content")
        result = pipeline._list_previous_deliverables()
        assert "01_graph_analysis.md" in result
        assert "02_recon.md" in result


class TestRunDir:
    def test_run_dir_is_timestamped(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        assert pipeline.run_dir.parent == output_dir
        # Directory name should match YYYY-MM-DD_HHMMSS pattern
        import re
        assert re.match(r"\d{4}-\d{2}-\d{2}_\d{6}", pipeline.run_dir.name)
        assert pipeline.run_dir.is_dir()


class TestGitCommit:
    def test_get_git_commit_returns_string_or_none(self):
        from src.agent.pipeline import _get_git_commit
        result = _get_git_commit()
        assert result is None or (isinstance(result, str) and len(result) > 0)

    def test_get_git_commit_mock_success(self):
        from src.agent.pipeline import _get_git_commit
        with patch("src.agent.pipeline.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="abc1234\n")
            assert _get_git_commit() == "abc1234"

    def test_get_git_commit_mock_failure(self):
        from src.agent.pipeline import _get_git_commit
        with patch("src.agent.pipeline.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert _get_git_commit() is None

    def test_get_git_commit_exception(self):
        from src.agent.pipeline import _get_git_commit
        with patch("src.agent.pipeline.subprocess.run", side_effect=FileNotFoundError):
            assert _get_git_commit() is None

    def test_run_meta_written_on_init(self, mock_provider, output_dir):
        with patch("src.agent.pipeline._get_git_commit", return_value="deadbeef"):
            pipeline = Pipeline(provider=mock_provider, phases=[999])
        # run_meta.json is written during run(), not __init__ — verify after run
        with patch("src.agent.pipeline.load_lab_context", return_value={
            "device_count": 1, "link_count": 1, "cve_count": 0, "top_risk": "none",
        }):
            pipeline.run()
        meta_file = pipeline.run_dir / "run_meta.json"
        assert meta_file.exists()
        meta = json.loads(meta_file.read_text())
        assert meta["git_commit"] == "deadbeef"
        assert meta["model"] == "test-model"


class TestBlindMode:
    """Blind mode: scenario VMs deployed, but topology hidden from the agent."""

    def test_init_sets_target_network_when_blind_with_scenario(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider, scenario_id=1, blind=True)
        assert pipeline.blind is True
        assert pipeline.target_network == "192.168.100.0/24"

    def test_init_no_target_network_when_blind_without_scenario(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider, blind=True)
        assert pipeline.target_network is None

    def test_init_preserves_explicit_target_network(self, mock_provider, output_dir):
        pipeline = Pipeline(
            provider=mock_provider, scenario_id=1, blind=True,
            target_network="10.0.0.0/24",
        )
        assert pipeline.target_network == "10.0.0.0/24"

    def test_blind_skips_scenario_context(self, mock_provider, output_dir):
        """In blind mode, _load_scenario_context must not be called — otherwise
        the agent would receive a list of all target IPs through the prompt."""
        pipeline = Pipeline(
            provider=mock_provider, scenario_id=1, blind=True, dry_run=True,
            phases=[],  # don't run any agents
        )
        with patch("src.agent.tools.graph_tools.load_discovery_context", return_value={
            "device_count": 0, "link_count": 0, "cve_count": 0, "top_risk": "none",
        }), patch.object(Pipeline, "_load_scenario_context") as mock_ctx, \
             patch.object(Pipeline, "_save_ground_truth"):
            pipeline.run()
        mock_ctx.assert_not_called()

    def test_non_blind_loads_scenario_context(self, mock_provider, output_dir):
        """Sanity check: without blind, the scenario context is loaded."""
        pipeline = Pipeline(
            provider=mock_provider, scenario_id=1, blind=False, dry_run=True,
            phases=[],
        )
        with patch("src.agent.tools.graph_tools.load_scenario_topology", return_value={
            "device_count": 0, "link_count": 0, "cve_count": 0, "top_risk": "none",
        }), patch.object(Pipeline, "_load_scenario_context", return_value="") as mock_ctx, \
             patch.object(Pipeline, "_save_ground_truth"):
            pipeline.run()
        mock_ctx.assert_called_once_with(1)


class TestScenarioDeployment:
    def test_failed_injection_aborts_and_cleans_scenario(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider, scenario_id=1)
        events = []
        with (
            patch.object(pipeline, "_teardown_all_running_scenarios") as pre_teardown,
            patch.object(pipeline, "_run_playbook", side_effect=[True, False]) as playbook,
            patch.object(pipeline, "_run_teardown") as cleanup,
        ):
            success = pipeline._run_scenario_deploy(events.append)

        assert success is False
        pre_teardown.assert_called_once()
        assert [call.args[0] for call in playbook.call_args_list] == [
            "03_deploy_scenario.yml", "04_inject_vulns.yml",
        ]
        cleanup.assert_called_once_with(events.append)

    def test_failed_verification_aborts_and_cleans_scenario(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider, scenario_id=1)
        with (
            patch.object(pipeline, "_teardown_all_running_scenarios"),
            patch.object(pipeline, "_run_playbook", side_effect=[True, True, False]),
            patch.object(pipeline, "_run_teardown") as cleanup,
        ):
            success = pipeline._run_scenario_deploy()

        assert success is False
        cleanup.assert_called_once_with(None)


class TestDeviceAgents:
    """Tests for the per-device sub-agent flow."""

    FAKE_SURFACE = json.dumps([
        {
            "id": "mikrotik",
            "name": "MikroTik hAP ac³",
            "type": "router",
            "ip": "192.168.88.1",
            "services": [
                {"name": "ssh", "port": 22, "version": "9.8"},
                {"name": "http", "port": 80, "version": None},
            ],
        },
        {
            "id": "rpi5",
            "name": "Raspberry Pi 5",
            "type": "compute",
            "ip": "192.168.88.247",
            "services": [
                {"name": "mqtt", "port": 1883, "version": "2.0.21"},
            ],
        },
    ])

    FAKE_SCORES = json.dumps([
        {"device_id": "mikrotik", "risk_score": 6.6, "cve_count": 12},
        {"device_id": "rpi5", "risk_score": 3.2, "cve_count": 2},
    ])

    FAKE_DEVICE_INFO = json.dumps({
        "id": "mikrotik",
        "os_version": "RouterOS 7.18.2",
        "firmware": "7.18.2",
    })

    @patch("src.agent.pipeline.get_device_info")
    @patch("src.agent.pipeline.get_risk_scores")
    @patch("src.agent.pipeline.get_attack_surface")
    @patch("src.agent.pipeline.load_prompt")
    def test_run_agent_triggers_device_agents(
        self, mock_prompt, mock_surface, mock_scores, mock_device_info,
        mock_provider, output_dir
    ):
        mock_surface.return_value = self.FAKE_SURFACE
        mock_scores.return_value = self.FAKE_SCORES
        mock_device_info.return_value = self.FAKE_DEVICE_INFO
        mock_prompt.return_value = "System prompt"

        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir

        # Side effect: device agents save valid files, aggregator saves the final deliverable
        call_count = {"n": 0}
        def side_effect(**kwargs):
            call_count["n"] += 1
            user_msg = kwargs.get("user_message", "")
            for dev_id in ("mikrotik", "rpi5"):
                if dev_id in user_msg:
                    (run_dir / f"03_device_{dev_id}.json").write_text(
                        json.dumps({"device_id": dev_id, "vulnerabilities": []})
                    )
                    return "Done."
            # aggregator call
            (run_dir / "03_vuln_analysis.json").write_text(
                json.dumps({
                    "vulnerabilities": [{
                        "id": "VULN-001",
                        "service": "http",
                        "port": 80,
                        "protocol": "tcp",
                        "endpoint": "/",
                        "product": "RouterOS",
                        "version": "7.18.2",
                    }],
                    "summary": {
                        "total": 1, "high": 1, "medium": 0, "low": 0, "info": 0,
                    },
                })
            )
            return "Done."
        mock_provider.chat_with_tools.side_effect = side_effect

        config = AgentConfig(
            name="vuln_analysis", phase=3, prompt_template="vuln_analysis",
            deliverable_file="03_vuln_analysis.json",
            tools=["graph", "recon", "deliverable"],
            has_device_agents=True, max_turns=10,
            validator="json_vuln_queue",
        )

        scan_results = {
            device_id: {"scan_results": {}, "findings": []}
            for device_id in ("mikrotik", "rpi5")
        }
        with patch("src.agent.pipeline.run_scanner", return_value=scan_results):
            status = pipeline._run_agent(config)

        # 2 device agents (no reflector) + 1 aggregator = 3 total calls
        assert mock_provider.chat_with_tools.call_count == 3
        assert status == "completed"

    def test_no_device_agents_when_flag_false(self, mock_provider, output_dir):
        """When has_device_agents=False, _run_phase3 should NOT be called."""
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=1, prompt_template="graph_analysis",
            deliverable_file="01_graph_analysis.md", tools=["graph"],
            has_device_agents=False,
        )
        run_dir = pipeline.run_dir

        def side_effect(**kwargs):
            (run_dir / "01_graph_analysis.md").write_text("## S1\n## S2\n")
            return "Done."
        mock_provider.chat_with_tools.side_effect = side_effect

        with patch("src.agent.pipeline.load_prompt", return_value="prompt"):
            status = pipeline._run_agent(config)

        # Only 1 call (no device agents)
        assert mock_provider.chat_with_tools.call_count == 1
        assert status == "completed"


class TestSkillFiltering:
    def test_no_filter_returns_empty(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=1, prompt_template="t",
            deliverable_file="t.md", tools=["graph"],
            skill_filter=None,
        )
        result = pipeline._filter_skills(config)
        assert result == ""

    def test_filter_by_tags(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=2, prompt_template="t",
            deliverable_file="t.md", tools=["graph", "skill"],
            skill_filter={"tags": ["mqtt"]},
        )
        result = pipeline._filter_skills(config)
        assert "mqtt_security" in result
        # Should not include unrelated skills
        assert "report_methodology" not in result

    def test_filter_report_tags(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=5, prompt_template="t",
            deliverable_file="t.md", tools=["graph", "skill"],
            skill_filter={"tags": ["report", "methodology"]},
        )
        result = pipeline._filter_skills(config)
        assert "report_methodology" in result

    def test_skill_tools_resolved(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=2, prompt_template="t",
            deliverable_file="t.md", tools=["graph", "skill"],
        )
        tools = pipeline._resolve_tools(config)
        tool_names = {t["name"] for t in tools}
        assert "list_skills" in tool_names
        assert "load_skill" in tool_names
        assert "search_history" in tool_names


class TestRepeatingToolDetector:
    """Tests for the repeating tool detector in LLMProvider loops."""

    def test_openai_loop_warns_on_repeat(self):
        """Calling the same tool 3x in a row injects a warning instead of executing."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        call_count = {"n": 0}

        def dummy_tool():
            call_count["n"] += 1
            return "result"

        tool_map = {"dummy": dummy_tool}

        # Simulate 4 turns: each turn the model calls dummy() with same args
        turn = [0]
        responses = []
        for i in range(4):
            msg = MagicMock()
            msg.content = None
            msg.tool_calls = [MagicMock()]
            msg.tool_calls[0].function.name = "dummy"
            msg.tool_calls[0].function.arguments = "{}"
            msg.tool_calls[0].id = f"call_{i}"
            choice = MagicMock()
            choice.finish_reason = "tool_calls"
            choice.message = msg
            responses.append(MagicMock(choices=[choice], usage=None))

        # 5th response: no tool call, end loop
        final_msg = MagicMock()
        final_msg.content = "Done."
        final_msg.tool_calls = None
        final_choice = MagicMock()
        final_choice.finish_reason = "stop"
        final_choice.message = final_msg
        responses.append(MagicMock(choices=[final_choice], usage=None))

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = responses

        api_tools = [{"type": "function", "function": {"name": "dummy", "description": "d", "parameters": {}}}]
        tools = [{"name": "dummy", "description": "d", "input_schema": {}, "function": dummy_tool}]

        provider.chat_with_tools(
            system_prompt="sys", user_message="go", tools=tools, max_turns=10
        )

        # Warning triggers on 3rd identical call — only 2 actual executions
        assert call_count["n"] == 2

    def test_openai_loop_can_disable_generic_repeat_guard(self):
        """Recon's own contract can retain control after repeated model calls."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"
        execute = MagicMock(return_value='{"status":"ok"}')

        responses = []
        for index in range(4):
            tool_call = MagicMock()
            tool_call.function.name = "scan"
            tool_call.function.arguments = '{}'
            tool_call.id = f"call_{index}"
            message = MagicMock(content=None, tool_calls=[tool_call])
            responses.append(MagicMock(
                choices=[MagicMock(finish_reason="tool_calls", message=message)],
                usage=None,
            ))
        responses.append(MagicMock(
            choices=[MagicMock(
                finish_reason="stop",
                message=MagicMock(content="Done.", tool_calls=None),
            )],
            usage=None,
        ))
        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = responses

        provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[{
                "name": "scan", "description": "scan",
                "input_schema": {}, "function": execute,
            }],
            max_turns=10,
            repeat_guard=False,
        )

        assert execute.call_count == 4

    def test_unadvertised_save_deliverable_returns_structured_rejection(self):
        """A learned completion call must not become a KeyError in memo mode."""
        from src.agent.provider import LLMProvider

        result = json.loads(LLMProvider._execute_tool(
            "save_deliverable",
            {"filename": "04_exploits/result.json", "content": "{}"},
            {"mqtt_listen": MagicMock()},
        ))

        assert result["ok"] is False
        assert result["error_kind"] == "tool_not_available"
        assert result["tool"] == "save_deliverable"
        assert result["available_tools"] == ["mqtt_listen"]

    def test_openai_loop_can_terminate_legacy_unavailable_save_without_tool_event(self):
        """Local memo mode can stop old save calls without executing or streaming them."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        save_call = MagicMock()
        save_call.function.name = "save_deliverable"
        save_call.function.arguments = '{"filename":"05_intrusion.json","content":"{}"}'
        save_call.id = "call_save"
        message = MagicMock(content="Memo only.", tool_calls=[save_call])
        provider.client = MagicMock()
        provider.client.chat.completions.create.return_value = MagicMock(
            choices=[MagicMock(finish_reason="tool_calls", message=message)],
            usage=None,
        )
        stream_events = []
        execute = MagicMock(return_value='{"ok": true}')

        result = provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[{
                "name": "try_credential", "description": "try",
                "input_schema": {}, "function": execute,
            }],
            max_turns=10,
            stream_callback=stream_events.append,
            terminate_on_unavailable_tools={"save_deliverable"},
        )

        assert result == "Memo only."
        execute.assert_not_called()
        assert provider.client.chat.completions.create.call_count == 1
        assert not [event for event in stream_events if event.get("type") == "tool_call"]
        assert stream_events[-1]["terminated_by"] == "save_deliverable"

    def test_openai_loop_terminates_after_successful_tool(self):
        """A successful terminal tool call must not trigger another model turn."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        save_call = MagicMock()
        save_call.function.name = "save_deliverable"
        save_call.function.arguments = '{"filename":"result.md","content":"done"}'
        save_call.id = "call_save"

        message = MagicMock()
        message.content = "Saving the completed deliverable."
        message.tool_calls = [save_call]
        choice = MagicMock(finish_reason="tool_calls", message=message)

        provider.client = MagicMock()
        provider.client.chat.completions.create.return_value = MagicMock(
            choices=[choice], usage=None
        )
        save = MagicMock(return_value='{"status":"saved"}')
        tools = [{
            "name": "save_deliverable",
            "description": "save",
            "input_schema": {},
            "function": save,
        }]

        result = provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=tools,
            max_turns=10,
            required_tool="save_deliverable",
            terminate_after_tool="save_deliverable",
        )

        assert result == "Saving the completed deliverable."
        assert provider.client.chat.completions.create.call_count == 1
        save.assert_called_once_with(filename="result.md", content="done")

    def test_openai_loop_skips_calls_after_successful_terminal_tool(self):
        """Sibling calls after a successful terminal save must not execute."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        def tool_call(name, arguments, call_id):
            call = MagicMock()
            call.function.name = name
            call.function.arguments = json.dumps(arguments)
            call.id = call_id
            return call

        message = MagicMock(
            content="Campaign complete.",
            tool_calls=[
                tool_call("action", {"step": "before"}, "call_before"),
                tool_call(
                    "save_deliverable",
                    {"filename": "05_intrusion.json", "content": "{}"},
                    "call_save",
                ),
                tool_call("action", {"step": "after"}, "call_after"),
            ],
        )
        provider.client = MagicMock()
        provider.client.chat.completions.create.return_value = MagicMock(
            choices=[MagicMock(finish_reason="tool_calls", message=message)],
            usage=None,
        )
        action = MagicMock(return_value='{"ok":true}')
        save = MagicMock(return_value='{"status":"saved"}')

        provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[
                {"name": "action", "description": "act", "input_schema": {}, "function": action},
                {"name": "save_deliverable", "description": "save", "input_schema": {}, "function": save},
            ],
            max_turns=10,
            required_tool="save_deliverable",
            terminate_after_tool="save_deliverable",
        )

        action.assert_called_once_with(step="before")
        save.assert_called_once_with(filename="05_intrusion.json", content="{}")

    def test_openai_loop_strict_required_tool_reprompts_after_text_only_turn(self):
        """Strict required tools prevent compact agents from ending with prose only."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        text_message = MagicMock(content="Trying", tool_calls=None)
        complete_call = MagicMock()
        complete_call.function.name = "complete_intrusion_campaign"
        complete_call.function.arguments = '{}'
        complete_call.id = "call_complete"
        complete_message = MagicMock(content=None, tool_calls=[complete_call])

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(finish_reason="stop", message=text_message)], usage=None),
            MagicMock(choices=[MagicMock(finish_reason="tool_calls", message=complete_message)], usage=None),
        ]
        complete = MagicMock(return_value='{"ok": true}')

        result = provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[{
                "name": "complete_intrusion_campaign",
                "description": "complete",
                "input_schema": {},
                "function": complete,
            }],
            max_turns=10,
            required_tool="complete_intrusion_campaign",
            terminate_after_tool="complete_intrusion_campaign",
            strict_required_tool=True,
            force_tool_on_stall=True,
        )

        assert result == "Trying"
        assert provider.client.chat.completions.create.call_count == 2
        first_request = provider.client.chat.completions.create.call_args_list[0].kwargs
        second_request = provider.client.chat.completions.create.call_args_list[1].kwargs
        assert "tool_choice" not in first_request
        assert second_request["tool_choice"] == "required"
        complete.assert_called_once_with()

    def test_openai_loop_stops_strict_required_tool_no_tool_stall(self):
        """Strict required-tool mode must not burn the full turn budget on empty prose."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"
        empty_message = MagicMock(content=None, tool_calls=None)
        provider.client = MagicMock()
        provider.client.chat.completions.create.return_value = MagicMock(
            choices=[MagicMock(finish_reason="stop", message=empty_message)],
            usage=None,
        )
        complete = MagicMock(return_value='{"ok": true}')

        result = provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[{
                "name": "complete_intrusion_campaign",
                "description": "complete",
                "input_schema": {},
                "function": complete,
            }],
            max_turns=50,
            required_tool="complete_intrusion_campaign",
            terminate_after_tool="complete_intrusion_campaign",
            strict_required_tool=True,
        )

        assert result == "(required tool complete_intrusion_campaign not called after repeated reminders)"
        assert provider.client.chat.completions.create.call_count == 3
        complete.assert_not_called()

    def test_openai_loop_recovers_compact_required_tool_after_stalls(self):
        """Compact Phase 5 keeps forcing an action instead of returning after 3 stalls."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        empty_message = MagicMock(content=None, tool_calls=None)
        terminal_call = MagicMock()
        terminal_call.function.name = "complete_intrusion_campaign"
        terminal_call.function.arguments = "{}"
        terminal_call.id = "call_complete"
        terminal_message = MagicMock(content=None, tool_calls=[terminal_call])

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(finish_reason="stop", message=empty_message)], usage=None),
            MagicMock(choices=[MagicMock(finish_reason="stop", message=empty_message)], usage=None),
            MagicMock(choices=[MagicMock(finish_reason="stop", message=empty_message)], usage=None),
            MagicMock(choices=[MagicMock(finish_reason="tool_calls", message=terminal_message)], usage=None),
        ]
        complete = MagicMock(return_value='{"ok": true}')

        provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[{
                "name": "complete_intrusion_campaign",
                "description": "complete",
                "input_schema": {},
                "function": complete,
            }],
            max_turns=10,
            required_tool="complete_intrusion_campaign",
            terminate_after_tool="complete_intrusion_campaign",
            strict_required_tool=True,
            force_tool_on_stall=True,
            recover_required_tool_on_stall=True,
        )

        assert provider.client.chat.completions.create.call_count == 4
        complete.assert_called_once_with()
        for call in provider.client.chat.completions.create.call_args_list[1:]:
            assert call.kwargs["tool_choice"] == "required"

    def test_openai_loop_forces_recon_save_after_completion_signal(self):
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        def response(tool_name, call_id):
            tool_call = MagicMock()
            tool_call.function.name = tool_name
            tool_call.function.arguments = '{}'
            tool_call.id = call_id
            message = MagicMock(content=None, tool_calls=[tool_call])
            return MagicMock(
                choices=[MagicMock(finish_reason="tool_calls", message=message)],
                usage=None,
            )

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = [
            response("read_deliverable", "call_read"),
            response("save_deliverable", "call_save"),
        ]
        read = MagicMock(return_value=json.dumps({
            "ok": False,
            "error_kind": "recon_completion_required",
        }))
        save = MagicMock(return_value='{"status":"saved"}')

        provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[
                {"name": "read_deliverable", "description": "read", "input_schema": {}, "function": read},
                {"name": "save_deliverable", "description": "save", "input_schema": {}, "function": save},
            ],
            max_turns=10,
            required_tool="save_deliverable",
            terminate_after_tool="save_deliverable",
            strict_required_tool=True,
            force_tool_on_stall=True,
        )

        second_request = provider.client.chat.completions.create.call_args_list[1].kwargs
        assert second_request["tool_choice"] == "required"
        assert [
            tool["function"]["name"] for tool in second_request["tools"]
        ] == ["save_deliverable"]
        read.assert_called_once_with()
        save.assert_called_once_with()

    @pytest.mark.parametrize(
        ("force_ready", "expected_tools", "expected_required"),
        [
            (True, ["save_deliverable"], True),
            (False, ["nmap_scan", "read_deliverable", "save_deliverable"], False),
        ],
    )
    def test_openai_loop_scopes_recon_ready_completion_to_opt_in(
        self, force_ready, expected_tools, expected_required
    ):
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        def response(tool_name, call_id):
            tool_call = MagicMock()
            tool_call.function.name = tool_name
            tool_call.function.arguments = "{}"
            tool_call.id = call_id
            message = MagicMock(content=None, tool_calls=[tool_call])
            return MagicMock(
                choices=[MagicMock(finish_reason="tool_calls", message=message)],
                usage=None,
            )

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = [
            response("nmap_scan", "call_scan"),
            response("save_deliverable", "call_save"),
        ]
        scan = MagicMock(return_value=json.dumps({
            "stdout": "baseline complete",
            "recon_progress": {"ready_to_save": True},
        }))
        save = MagicMock(return_value="{\"status\":\"saved\"}")

        provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[
                {"name": "nmap_scan", "description": "scan", "input_schema": {},
                 "function": scan},
                {"name": "read_deliverable", "description": "read",
                 "input_schema": {}, "function": MagicMock()},
                {"name": "save_deliverable", "description": "save",
                 "input_schema": {}, "function": save},
            ],
            max_turns=10,
            required_tool="save_deliverable",
            terminate_after_tool="save_deliverable",
            strict_required_tool=True,
            force_tool_on_stall=True,
            force_completion_on_recon_ready=force_ready,
        )

        second_request = provider.client.chat.completions.create.call_args_list[1].kwargs
        if expected_required:
            assert second_request["tool_choice"] == "required"
        else:
            assert "tool_choice" not in second_request
        assert [
            tool["function"]["name"] for tool in second_request["tools"]
        ] == expected_tools
        scan.assert_called_once_with()
        save.assert_called_once_with()


    def test_openai_loop_reopens_compact_intrusion_tools_after_rejected_completion(self):
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        def response(tool_name, call_id):
            tool_call = MagicMock()
            tool_call.function.name = tool_name
            tool_call.function.arguments = "{}"
            tool_call.id = call_id
            message = MagicMock(content=None, tool_calls=[tool_call])
            return MagicMock(
                choices=[MagicMock(finish_reason="tool_calls", message=message)],
                usage=None,
            )

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = [
            response("mqtt_listen", "mqtt-1"),
            response("mqtt_listen", "mqtt-2"),
            response("mqtt_listen", "mqtt-3"),
            response("complete_intrusion_campaign", "complete-1"),
            response("try_credential", "try-1"),
            response("complete_intrusion_campaign", "complete-2"),
        ]
        mqtt = MagicMock(return_value="{\"status\":\"ok\"}")
        try_credential = MagicMock(return_value="{\"success\":false}")
        complete = MagicMock(side_effect=[
            "{\"ok\":false,\"error_kind\":\"intrusion_contract_incomplete\"}",
            "{\"ok\":true,\"status\":\"campaign_complete\"}",
        ])

        provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[
                {"name": "mqtt_listen", "description": "mqtt", "input_schema": {},
                 "function": mqtt},
                {"name": "try_credential", "description": "try", "input_schema": {},
                 "function": try_credential},
                {"name": "complete_intrusion_campaign", "description": "complete",
                 "input_schema": {}, "function": complete},
            ],
            max_turns=10,
            required_tool="complete_intrusion_campaign",
            terminate_after_tool="complete_intrusion_campaign",
            strict_required_tool=True,
            force_tool_on_stall=True,
            reopen_intrusion_tools_on_contract_error=True,
        )

        repair_request = provider.client.chat.completions.create.call_args_list[4].kwargs
        assert repair_request["tool_choice"] == "required"
        assert [
            tool["function"]["name"] for tool in repair_request["tools"]
        ] == ["mqtt_listen", "try_credential", "complete_intrusion_campaign"]
        try_credential.assert_called_once_with()
        assert complete.call_count == 2


    def test_openai_loop_detects_interleaved_cycle_and_forces_completion(self):
        """Interleaved duplicate calls must switch the model to save-only mode."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        def response(tool_name, arguments, call_id):
            tool_call = MagicMock()
            tool_call.function.name = tool_name
            tool_call.function.arguments = arguments
            tool_call.id = call_id
            message = MagicMock(content=None, tool_calls=[tool_call])
            choice = MagicMock(finish_reason="tool_calls", message=message)
            return MagicMock(choices=[choice], usage=None)

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = [
            response("scan", '{"target":"a"}', "call_a1"),
            response("scan", '{"target":"b"}', "call_b1"),
            response("scan", '{"target":"a"}', "call_a2"),
            response("scan", '{"target":"b"}', "call_b2"),
            response("scan", '{"target":"a"}', "call_a3"),
            response(
                "save_deliverable",
                '{"filename":"result.md","content":"done"}',
                "call_save",
            ),
        ]
        scan = MagicMock(return_value='{"status":"scanned"}')
        save = MagicMock(return_value='{"status":"saved"}')
        tools = [
            {"name": "scan", "description": "scan", "input_schema": {}, "function": scan},
            {
                "name": "save_deliverable",
                "description": "save",
                "input_schema": {},
                "function": save,
            },
        ]

        provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=tools,
            max_turns=10,
            required_tool="save_deliverable",
            terminate_after_tool="save_deliverable",
        )

        assert scan.call_count == 4
        save.assert_called_once_with(filename="result.md", content="done")
        final_request_tools = (
            provider.client.chat.completions.create.call_args_list[-1]
            .kwargs["tools"]
        )
        assert [tool["function"]["name"] for tool in final_request_tools] == [
            "save_deliverable"
        ]


class TestStripCodeFences:
    """Tests for _strip_code_fences — the fallback content sanitizer."""

    def test_strips_json_fence(self, mock_provider, output_dir):
        raw = '```json\n{"key": "value"}\n```'
        result = Pipeline._strip_code_fences(raw)
        assert result == '{"key": "value"}'

    def test_strips_plain_fence(self, mock_provider, output_dir):
        raw = '```\n{"key": "value"}\n```'
        result = Pipeline._strip_code_fences(raw)
        assert result == '{"key": "value"}'

    def test_strips_mqtt_pattern(self, mock_provider, output_dir):
        # Exact pattern from s2-mqtt fallback: "json\n{...}" (backticks stripped by provider)
        raw = 'json\n{"device_id": "s2-mqtt", "vulnerabilities": []}'
        result = Pipeline._strip_code_fences(raw)
        # "json\n..." with no opening ``` is NOT a fence — should be unchanged
        # This confirms the fallback alone doesn't fix the mqtt case; pipeline must strip ``` first
        assert result == raw

    def test_no_fence_unchanged(self, mock_provider, output_dir):
        raw = '{"key": "value"}'
        assert Pipeline._strip_code_fences(raw) == raw

    def test_strips_whitespace(self, mock_provider, output_dir):
        raw = '  \n```json\n{"key": "value"}\n```\n  '
        result = Pipeline._strip_code_fences(raw)
        assert result == '{"key": "value"}'

    def test_prose_unchanged(self, mock_provider, output_dir):
        raw = "The device has weak ciphers and exposed admin panel."
        assert Pipeline._strip_code_fences(raw) == raw


class TestPhase5Context:
    """Tests for _generate_intrusion_context."""

    def test_generates_intrusion_context(self, mock_provider, output_dir, monkeypatch):
        """Phase 5 context should extract confirmed exploits and entry points."""
        monkeypatch.setattr("src.agent.pipeline.get_attack_surface", lambda: '{"nodes": []}')
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir

        # Write Phase 4 exploitation results with CONFIRMED entries
        exploit_data = {
            "summary": {"total_tested": 3, "confirmed": 2, "not_exploitable": 1, "errors": 0},
            "tests": [
                {"vuln_id": "VULN-001", "status": "CONFIRMED", "device_id": "router",
                 "device_ip": "10.0.0.1", "evidence": "SSH login root:password succeeded"},
                {"vuln_id": "VULN-002", "status": "FAILED", "device_id": "router",
                 "device_ip": "10.0.0.1", "evidence": ""},
                {"vuln_id": "VULN-003", "status": "CONFIRMED", "device_id": "sensor",
                 "device_ip": "10.0.0.2", "evidence": "redis-cli KEYS * returned 5 keys"},
            ],
        }
        (run_dir / "04_exploitation.json").write_text(json.dumps(exploit_data))

        pipeline._generate_intrusion_context()

        ctx_path = run_dir / "05_intrusion_context.json"
        assert ctx_path.exists()
        ctx = json.loads(ctx_path.read_text())

        # Check required keys
        assert "generated_for" in ctx
        assert ctx["generated_for"] == "phase5_intrusion"
        assert "entry_points" in ctx
        assert "all_targets" in ctx
        assert "confirmed_exploits" in ctx
        assert "recovered_credentials" in ctx
        assert ctx["confirmed_exploits"] == 2

    def test_full_context_keeps_path_data_and_filters_non_footholds(
        self, mock_provider, output_dir, monkeypatch
    ):
        pipeline = Pipeline(provider=mock_provider, execution_profile="full")
        run_dir = pipeline.run_dir
        monkeypatch.setattr(
            "src.agent.pipeline.get_attack_surface",
            lambda: json.dumps({
                "nodes": [
                    {
                        "id": "opcua", "ip": "192.168.100.20",
                        "role": "ot_opcua_server",
                        "services": [{"name": "opcua", "port": 4840, "protocol": "tcp"}],
                    },
                    {
                        "id": "metadata", "ip": "192.168.100.21",
                        "role": "cloud_metadata_server",
                        "services": [{"name": "http", "port": 80, "protocol": "tcp"}],
                    },
                ],
            }),
        )
        (run_dir / "03_vuln_analysis.json").write_text(json.dumps({
            "attack_chain_hints": [{
                "src_ip": "192.168.100.20", "dst_ip": "192.168.100.21",
            }],
            "vulnerabilities": [{
                "id": "SCANNER-OPCUA", "device_id": "opcua",
                "device_ip": "192.168.100.20", "type": "no_auth",
                "service": "opcua", "port": 4840,
                "canonical_source": "scanner_full",
                "exploitation_status": "confirmed",
                "evidence": "deterministic OPC-UA contract",
            }],
        }))
        (run_dir / "04_exploitation.json").write_text(json.dumps({
            "summary": {"confirmed": 1},
            "tests": [{
                "vuln_id": "INFO-METADATA", "device_id": "metadata",
                "device_ip": "192.168.100.21", "type": "info_disclosure",
                "status": "CONFIRMED", "evidence_level": 3,
                "evidence": "HTTP banner",
            }],
        }))

        pipeline._generate_intrusion_context()
        context = json.loads((run_dir / "05_intrusion_context.json").read_text())

        assert [entry["device_ip"] for entry in context["entry_points"]] == [
            "192.168.100.20"
        ]
        assert context["entry_points"][0]["evidence_source"] == "phase3_scanner_contract"
        assert context["entry_points"][0]["phase4_verified"] is False
        target = next(item for item in context["all_targets"] if item["device_ip"] == "192.168.100.20")
        assert target["primary_service"] == "opcua"
        assert target["service_details"] == [{"name": "opcua", "port": 4840, "protocol": "tcp"}]
        assert context["attack_chains"] == [{
            "src_ip": "192.168.100.20", "dst_ip": "192.168.100.21",
        }]

    def test_handles_missing_phase4(self, mock_provider, output_dir, monkeypatch):
        """Context should still generate if Phase 4 was skipped."""
        monkeypatch.setattr("src.agent.pipeline.get_attack_surface", lambda: '{"nodes": []}')
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir

        pipeline._generate_intrusion_context()

        ctx_path = run_dir / "05_intrusion_context.json"
        assert ctx_path.exists()
        ctx = json.loads(ctx_path.read_text())
        assert ctx["confirmed_exploits"] == 0
        assert ctx["entry_points"] == []
        assert ctx["recovered_credentials"] == []

    def test_handles_list_format_phase4(self, mock_provider, output_dir, monkeypatch):
        """Context should handle Phase 4 output as a plain list."""
        monkeypatch.setattr("src.agent.pipeline.get_attack_surface", lambda: '{"nodes": []}')
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir

        exploit_list = [
            {"vuln_id": "VULN-001", "status": "CONFIRMED", "device_id": "gw",
             "device_ip": "10.0.0.5", "evidence": "login ok"},
        ]
        (run_dir / "04_exploitation.json").write_text(json.dumps(exploit_list))

        pipeline._generate_intrusion_context()

        ctx = json.loads((run_dir / "05_intrusion_context.json").read_text())
        assert ctx["confirmed_exploits"] == 1

    def test_mqtt_confirmed_exploit_feeds_recovered_credentials(
        self, mock_provider, output_dir, monkeypatch
    ):
        monkeypatch.setattr("src.agent.pipeline.get_attack_surface", lambda: '{"nodes": []}')
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        exploit_data = {
            "summary": {"total_tested": 1, "confirmed": 1, "not_exploitable": 0, "errors": 0},
            "tests": [{
                "vuln_id": "VULN-002",
                "status": "CONFIRMED",
                "device_id": "s1-mqtt",
                "device_ip": "192.168.100.11",
                "vuln_type": "data_exposure",
                "service": "mqtt",
                "port": 1883,
                "evidence": "mqtt_listen captured sensitive MQTT messages",
                "data_extracted": [
                    "smartcity/admin/credentials {\"db_user\":\"root\",\"db_pass\":\"P@ssw0rd123\"}"
                ],
            }],
        }
        (run_dir / "04_exploitation.json").write_text(json.dumps(exploit_data))

        pipeline._generate_intrusion_context()

        ctx = json.loads((run_dir / "05_intrusion_context.json").read_text())
        assert ctx["confirmed_exploits"] == 1
        assert ctx["recovered_credentials"] == [{
            "user": "root",
            "password": "P@ssw0rd123",
            "source_ip": "192.168.100.11",
            "source_device": "s1-mqtt",
        }]

    def test_compact_intrusion_contract_requires_context_and_target_attempts(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "all_targets": [
                {"device_id": "s1-router", "device_ip": "192.168.100.1"},
                {"device_id": "s1-ssh", "device_ip": "192.168.100.13"},
            ],
        }))
        tools = pipeline._apply_compact_intrusion_tool_contract([
            {
                "name": "read_deliverable",
                "description": "read",
                "input_schema": {},
                "function": lambda **kwargs: json.dumps({
                    "filename": kwargs["filename"],
                    "content": (run_dir / kwargs["filename"]).read_text(),
                }),
            },
            {
                "name": "try_credential",
                "description": "try",
                "input_schema": {},
                "function": lambda **_kwargs: '{"success": false}',
            },
            {
                "name": "ssh_exec",
                "description": "ssh",
                "input_schema": {},
                "function": lambda **_kwargs: '{"return_code": 255}',
            },
        ])
        tool_map = {tool["name"]: tool["function"] for tool in tools}

        before_read = json.loads(tool_map["complete_intrusion_campaign"]())
        assert before_read["ok"] is False
        assert before_read["error_kind"] == "intrusion_context_required"

        tool_map["read_deliverable"](filename="05_intrusion_context.json")
        tool_map["try_credential"](
            ip="192.168.100.1", service="ssh", user="root", password="root"
        )
        missing_one = json.loads(tool_map["complete_intrusion_campaign"]())
        assert missing_one["ok"] is False
        assert missing_one["error_kind"] == "intrusion_contract_incomplete"
        assert missing_one["intrusion_progress"]["missing_targets"] == ["192.168.100.13"]

        tool_map["ssh_exec"](ip="192.168.100.13", user="root", password="root", command="id")
        complete = json.loads(tool_map["complete_intrusion_campaign"]())
        assert complete["ok"] is True
        assert complete["intrusion_progress"]["ready_to_complete"] is True


    def test_compact_intrusion_contract_requires_each_target_service(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "all_targets": [
                {"device_id": "router", "device_ip": "192.168.100.1",
                 "role": "router", "services": [22, 23, 80]},
            ],
        }))
        tools = pipeline._apply_compact_intrusion_tool_contract([
            {"name": "read_deliverable", "description": "read", "input_schema": {},
             "function": lambda **kwargs: json.dumps({
                 "filename": kwargs["filename"],
                 "content": (run_dir / kwargs["filename"]).read_text(),
             })},
            {"name": "try_credential", "description": "try", "input_schema": {},
             "function": lambda **_kwargs: '{"success":false}'},
            {"name": "telnet_connect", "description": "telnet", "input_schema": {},
             "function": lambda **_kwargs: '{"return_code":124}'},
            {"name": "http_get", "description": "http", "input_schema": {},
             "function": lambda **_kwargs: '{"status_code":200}'},
        ])
        tool_map = {tool["name"]: tool["function"] for tool in tools}
        tool_map["read_deliverable"](filename="05_intrusion_context.json")
        tool_map["try_credential"](
            ip="192.168.100.1", service="ssh", user="root", password="root"
        )
        complete = json.loads(tool_map["complete_intrusion_campaign"]())
        assert complete["ok"] is True
        assert complete["intrusion_progress"]["missing_target_services"] == []


    def test_compact_intrusion_contract_counts_http_mqtt_and_recovered_credentials(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [
                {"device_id": "s1-mqtt", "device_ip": "192.168.100.11", "service": "mqtt"},
                {"device_id": "s1-web", "device_ip": "192.168.100.12", "service": "http"},
            ],
            "all_targets": [
                {"device_id": "s1-mqtt", "device_ip": "192.168.100.11", "role": "mqtt_broker"},
                {"device_id": "s1-web", "device_ip": "192.168.100.12", "role": "web_server"},
            ],
            "recovered_credentials": [
                {
                    "user": "root",
                    "password": "P@ssw0rd123",
                    "source_ip": "192.168.100.11",
                    "source_device": "s1-mqtt",
                },
            ],
        }))
        tools = pipeline._apply_compact_intrusion_tool_contract([
            {
                "name": "read_deliverable",
                "description": "read",
                "input_schema": {},
                "function": lambda **kwargs: json.dumps({
                    "filename": kwargs["filename"],
                    "content": (run_dir / kwargs["filename"]).read_text(),
                }),
            },
            {
                "name": "mqtt_listen",
                "description": "mqtt",
                "input_schema": {},
                "function": lambda **_kwargs: json.dumps({"return_code": 27}),
            },
            {
                "name": "http_get",
                "description": "http",
                "input_schema": {},
                "function": lambda **_kwargs: json.dumps({"status_code": 200}),
            },
            {
                "name": "try_credential",
                "description": "try",
                "input_schema": {},
                "function": lambda **_kwargs: json.dumps({"success": True, "authenticated": True}),
            },
        ])
        tool_map = {tool["name"]: tool["function"] for tool in tools}

        tool_map["read_deliverable"](filename="05_intrusion_context.json")
        wrong_target = json.loads(tool_map["mqtt_listen"](
            broker="192.168.100.1", topic="#", count=1
        ))
        assert wrong_target["error_kind"] == "invalid_intrusion_target"
        assert wrong_target["suggested_args"]["broker"] == "192.168.100.11"
        tool_map["mqtt_listen"](broker="192.168.100.11", topic="#", count=1)
        tool_map["http_get"](url="http://192.168.100.12/")

        missing_credential = json.loads(tool_map["complete_intrusion_campaign"]())
        assert missing_credential["ok"] is False
        progress = missing_credential["intrusion_progress"]
        assert progress["missing_targets"] == ["192.168.100.11", "192.168.100.12"]
        assert progress["missing_entry_points"] == []
        assert progress["missing_credentials"] == [
            "root@192.168.100.11", "root@192.168.100.12"
        ]

        tool_map["try_credential"](
            ip="192.168.100.11", service="mqtt", user="root", password="P@ssw0rd123"
        )
        intermediate = json.loads(tool_map["complete_intrusion_campaign"]())
        assert intermediate["ok"] is False
        assert intermediate["intrusion_progress"]["missing_credentials"] == [
            "root@192.168.100.12"
        ]
        tool_map["try_credential"](
            ip="192.168.100.12", service="http", user="root", password="P@ssw0rd123"
        )
        complete = json.loads(tool_map["complete_intrusion_campaign"]())
        assert complete["ok"] is True
        assert complete["intrusion_progress"]["ready_to_complete"] is True
        assert complete["intrusion_progress"]["missing_successful_access"] is False
        assert complete["intrusion_progress"]["successful_accesses"] == [
            {"target": "192.168.100.11", "service": "mqtt"},
            {"target": "192.168.100.12", "service": "http"},
        ]

    def test_compact_intrusion_rejects_wrong_ports_and_authenticated_mqtt_entry_credentials(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [{
                "device_id": "mqtt", "device_ip": "192.168.100.11",
                "service": "mqtt", "port": 1883, "vuln_type": "no_auth",
            }],
            "all_targets": [{
                "device_id": "mqtt", "device_ip": "192.168.100.11",
                "role": "mqtt_broker", "services": [1883],
            }],
            "recovered_credentials": [{
                "user": "root", "password": "root",
                "source_ip": "192.168.100.11",
            }],
        }))
        mqtt = MagicMock(return_value=json.dumps({"return_code": 0, "stdout": "msg"}))
        credential = MagicMock(return_value=json.dumps({
            "success": True, "authenticated": True, "service": "mqtt", "port": 1883,
        }))
        tools = pipeline._apply_compact_intrusion_tool_contract([
            {"name": "read_deliverable", "description": "read", "input_schema": {},
             "function": lambda **kwargs: json.dumps({
                 "filename": kwargs["filename"],
                 "content": (run_dir / kwargs["filename"]).read_text(),
             })},
            {"name": "mqtt_listen", "description": "mqtt", "input_schema": {}, "function": mqtt},
            {"name": "try_credential", "description": "try", "input_schema": {}, "function": credential},
        ])
        tool_map = {tool["name"]: tool["function"] for tool in tools}
        tool_map["read_deliverable"](filename="05_intrusion_context.json")

        anonymous_error = json.loads(tool_map["mqtt_listen"](
            broker="192.168.100.11", username="root", password="root"
        ))
        assert anonymous_error["error_kind"] == "anonymous_entry_requires_no_credentials"
        mqtt.assert_not_called()

        port_error = json.loads(tool_map["try_credential"](
            ip="192.168.100.11", service="mqtt", user="root", password="root", port=80
        ))
        assert port_error["error_kind"] == "invalid_intrusion_port"
        credential.assert_not_called()

        tool_map["mqtt_listen"](broker="192.168.100.11", topic="#", count=1)
        tool_map["try_credential"](
            ip="192.168.100.11", service="mqtt", user="root", password="root", port=1883
        )
        complete = json.loads(tool_map["complete_intrusion_campaign"]())
        assert complete["ok"] is True

    def test_compact_intrusion_rejects_invented_credentials(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "all_targets": [{
                "device_id": "mqtt", "device_ip": "192.168.100.11",
                "role": "mqtt_broker", "services": [1883],
            }],
            "recovered_credentials": [{
                "user": "root", "password": "recovered",
                "source_ip": "192.168.100.10",
            }],
        }))
        credential = MagicMock(return_value=json.dumps({
            "success": True, "authenticated": True, "service": "mqtt", "port": 1883,
        }))
        tools = pipeline._apply_compact_intrusion_tool_contract([
            {"name": "read_deliverable", "description": "read", "input_schema": {},
             "function": lambda **kwargs: json.dumps({
                 "filename": kwargs["filename"],
                 "content": (run_dir / kwargs["filename"]).read_text(),
             })},
            {"name": "try_credential", "description": "try", "input_schema": {},
             "function": credential},
        ])
        tool_map = {tool["name"]: tool["function"] for tool in tools}
        tool_map["read_deliverable"](filename="05_intrusion_context.json")

        rejected = json.loads(tool_map["try_credential"](
            ip="192.168.100.11", service="mqtt", user="admin", password="smartcity",
            port=1883,
        ))
        assert rejected["error_kind"] == "unknown_intrusion_credential"
        credential.assert_not_called()

        tool_map["try_credential"](
            ip="192.168.100.11", service="mqtt", user="root", password="recovered",
            port=1883,
        )
        assert credential.call_count == 1

    def test_compact_intrusion_completion_is_logged(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "all_targets": [],
        }))

        tools = pipeline._apply_compact_intrusion_tool_contract(
            [], phase=5, agent="intrusion"
        )
        tool_map = {tool["name"]: tool["function"] for tool in tools}

        result = json.loads(tool_map["complete_intrusion_campaign"]())

        assert result["ok"] is False
        log_entry = json.loads((run_dir / "tool_calls.jsonl").read_text())
        assert log_entry["tool"] == "complete_intrusion_campaign"
        assert log_entry["phase"] == 5
        assert log_entry["agent"] == "intrusion"


    def test_compact_intrusion_terminal_commits_deliverable(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        pipeline.context = {"target_subnet": "192.0.2.0/24"}
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [{
                "device_id": "s1-ssh",
                "device_ip": "192.0.2.10",
                "service": "ssh",
                "port": 22,
            }],
            "all_targets": [{
                "device_id": "s1-ssh",
                "device_ip": "192.0.2.10",
                "role": "ssh_server",
                "services": [22],
            }],
            "recovered_credentials": [{"user": "admin", "password": "admin"}],
        }))
        base_tools = [
            {"name": "read_deliverable", "description": "read", "input_schema": {},
             "function": lambda **kwargs: json.dumps({
                 "filename": kwargs["filename"],
                 "content": (run_dir / kwargs["filename"]).read_text(),
             })},
            {"name": "ssh_login", "description": "ssh", "input_schema": {},
             "function": lambda **_kwargs: json.dumps({
                 "return_code": 0, "stdout": "uid=1000(admin)",
             })},
            {"name": "try_credential", "description": "try", "input_schema": {},
             "function": lambda **_kwargs: json.dumps({
                 "success": True, "authenticated": True, "service": "ssh", "port": 22,
             })},
        ]
        tools = pipeline._apply_compact_intrusion_tool_contract(
            [pipeline._wrap_tool(tool, phase=5, agent="intrusion") for tool in base_tools],
            phase=5,
            agent="intrusion",
        )
        tool_map = {tool["name"]: tool["function"] for tool in tools}

        tool_map["read_deliverable"](filename="05_intrusion_context.json")
        tool_map["ssh_login"](
            command_string="sshpass -p admin ssh admin@192.0.2.10 'id'"
        )
        tool_map["try_credential"](
            ip="192.0.2.10", service="ssh", user="admin", password="admin", port=22
        )
        complete = json.loads(tool_map["complete_intrusion_campaign"]())

        assert complete["ok"] is True
        assert complete["finalized"] is True
        assert complete["deliverable"] == "05_intrusion.json"
        final = json.loads((run_dir / "05_intrusion.json").read_text())
        assert final["status"] == "completed"
        assert final["completion_source"] == "complete_intrusion_campaign"
        assert final["summary"]["devices_attempted"] == 1

    def test_compact_intrusion_modbus_probe_and_full_surface(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [{
                "device_id": "s4-plc",
                "device_ip": "192.168.100.15",
                "service": "modbus",
                "port": 502,
                "vuln_type": "no_auth",
            }],
            "all_targets": [{
                "device_id": "s4-plc",
                "device_ip": "192.168.100.15",
                "role": "modbus_server",
                "services": [502],
            }],
            "recovered_credentials": [],
        }))
        tools = pipeline._apply_compact_intrusion_tool_contract([
            {
                "name": "read_deliverable", "description": "read", "input_schema": {},
                "function": lambda **kwargs: json.dumps({
                    "filename": kwargs["filename"],
                    "content": (run_dir / kwargs["filename"]).read_text(),
                }),
            },
            {
                "name": "nmap_scan", "description": "nmap", "input_schema": {},
                "function": lambda **_kwargs: json.dumps({
                    "return_code": 0,
                    "stdout": "502/tcp open modbus\n| modbus-discover",
                }),
            },
        ])
        tool_map = {tool["name"]: tool["function"] for tool in tools}
        tool_map["read_deliverable"](filename="05_intrusion_context.json")
        probe = json.loads(tool_map["nmap_scan"](
            target="192.168.100.15", ports="502",
            scripts="modbus-discover", skip_discovery=True,
        ))
        assert probe["intrusion_progress"]["missing_entry_points"] == []

        (run_dir / "tool_calls.jsonl").write_text(json.dumps({
            "phase": 5,
            "tool": "nmap_scan",
            "args": {
                "target": "192.168.100.15", "ports": "502",
                "scripts": "modbus-discover", "skip_discovery": True,
            },
            "result": json.dumps({
                "return_code": 0, "stdout": "502/tcp open modbus\n| modbus-discover",
            }),
        }) + "\n")
        coverage_ok, coverage = pipeline._compact_intrusion_coverage()
        assert coverage_ok is True
        assert coverage["missing_entry_points"] == []
        assert "nmap_scan" not in {tool["name"] for tool in TOOL_GROUPS["intrusion"]}

    def test_compact_intrusion_coap_udp_probe_counts_as_entry_point(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        context = {
            "entry_points": [{
                "device_id": "s9-coap",
                "device_ip": "192.168.100.14",
                "service": "coap",
                "port": 5683,
                "vuln_type": "no_auth",
            }],
            "all_targets": [{
                "device_id": "s9-coap",
                "device_ip": "192.168.100.14",
                "primary_service": "coap",
                "services": [5683],
            }],
            "recovered_credentials": [],
        }
        (run_dir / "05_intrusion_context.json").write_text(json.dumps(context))
        tools = pipeline._apply_compact_intrusion_tool_contract([
            {
                "name": "read_deliverable", "description": "read", "input_schema": {},
                "function": lambda **kwargs: json.dumps({
                    "filename": kwargs["filename"],
                    "content": (run_dir / kwargs["filename"]).read_text(),
                }),
            },
            {
                "name": "udp_send", "description": "udp", "input_schema": {},
                "function": lambda **_kwargs: json.dumps({
                    "ok": True, "received_bytes": 32,
                }),
            },
        ])
        tool_map = {tool["name"]: tool["function"] for tool in tools}

        tool_map["read_deliverable"](filename="05_intrusion_context.json")
        rejected = json.loads(tool_map["complete_intrusion_campaign"]())
        assert rejected["suggested_tool"] == "udp_send"
        assert rejected["suggested_args"]["host"] == "192.168.100.14"
        assert rejected["suggested_args"]["port"] == 5683

        probe_args = rejected["suggested_args"]
        probe = json.loads(tool_map["udp_send"](**probe_args))
        assert probe["intrusion_progress"]["missing_entry_points"] == []

        (run_dir / "tool_calls.jsonl").write_text(json.dumps({
            "phase": 5,
            "tool": "udp_send",
            "args": probe_args,
            "result": json.dumps({"ok": True, "received_bytes": 32}),
        }) + "\n")
        coverage_ok, coverage = pipeline._compact_intrusion_coverage()
        assert coverage_ok is True
        assert coverage["missing_entry_points"] == []

    def test_compact_intrusion_service_prefers_explicit_context_service(self):
        assert Pipeline._compact_intrusion_service({
            "primary_service": "mqtt",
            "services": [22, 1883],
        }) == "mqtt"

    def test_compact_intrusion_proxy_error_returns_for_ledger_recovery(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        mock_provider.chat_with_tools.side_effect = ConnectionError("proxy unavailable")

        status = pipeline._run_agent(AGENTS["intrusion"])

        assert status.startswith("failed:")
        assert "05_intrusion.json" not in {
            path.name for path in pipeline.run_dir.iterdir()
        }

    def test_compact_intrusion_run_agent_finalizes_completed_ledger(
        self, mock_provider, output_dir, monkeypatch
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        pipeline.context = {"target_subnet": "192.0.2.0/24"}
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [{
                "device_id": "s1-mqtt",
                "device_ip": "192.0.2.11",
                "service": "mqtt",
                "port": 1883,
                "vuln_type": "no_auth",
            }],
            "all_targets": [{
                "device_id": "s1-mqtt",
                "device_ip": "192.0.2.11",
                "role": "mqtt_broker",
                "primary_service": "mqtt",
                "services": [1883],
            }],
            "recovered_credentials": [],
        }))

        def fake_chat_with_tools(**kwargs):
            tool_map = {tool["name"]: tool["function"] for tool in kwargs["tools"]}
            tool_map["read_deliverable"](filename="05_intrusion_context.json")
            tool_map["mqtt_listen"](broker="192.0.2.11", topic="#", count=1)
            return "model stopped after actions"

        def fake_resolve(config):
            base_tools = [
                {"name": "read_deliverable", "description": "read", "input_schema": {},
                 "function": lambda **kwargs: json.dumps({
                     "filename": kwargs["filename"],
                     "content": (run_dir / kwargs["filename"]).read_text(),
                 })},
                {"name": "mqtt_listen", "description": "mqtt", "input_schema": {},
                 "function": lambda **_kwargs: json.dumps({"return_code": 0, "stdout": "msg"})},
            ]
            return [
                pipeline._wrap_tool(tool, phase=config.phase, agent=config.name)
                for tool in base_tools
            ]

        monkeypatch.setattr(pipeline, "_resolve_tools", fake_resolve)
        mock_provider.chat_with_tools.side_effect = fake_chat_with_tools

        status = pipeline._run_agent(AGENTS["intrusion"])

        assert status == "completed"
        final = json.loads((run_dir / "05_intrusion.json").read_text())
        assert final["status"] == "completed"
        assert final["completion_source"] == "complete_intrusion_campaign"

    def test_local_moe_intrusion_rewrites_hallucinated_compromise(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        pipeline.context = {"target_subnet": "192.168.100.0/24"}
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [{"device_id": "s1-router", "device_ip": "192.168.100.1"}],
            "all_targets": [{"device_id": "s1-router", "device_ip": "192.168.100.1"}],
            "recovered_credentials": [{
                "user": "root",
                "password": "P@ssw0rd123",
                "service": "mqtt",
                "source_ip": "192.168.100.11",
                "source_device": "s1-mqtt",
            }],
        }))
        (run_dir / "tool_calls.jsonl").write_text(json.dumps({
            "tool": "try_credential",
            "args": {
                "ip": "192.168.100.1",
                "service": "ssh",
                "user": "admin",
                "password": "admin",
            },
            "result": json.dumps({
                "success": False,
                "service": "ssh",
                "port": 22,
                "stderr": "Permission denied",
            }),
        }) + "\n")
        with (run_dir / "tool_calls.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "phase": 4,
                "vuln_id": "VULN-004",
                "tool": "try_credential",
                "args": {
                    "ip": "192.168.100.1",
                    "service": "ssh",
                    "user": "operator",
                    "password": "operator",
                },
                "result": json.dumps({
                    "success": True,
                    "service": "ssh",
                    "port": 22,
                    "stdout": "uid=1000(operator)",
                }),
            }) + "\n")
        (run_dir / "05_intrusion.json").write_text(json.dumps({
            "summary": {
                "devices_attempted": 1,
                "devices_compromised": 1,
                "credentials_harvested": 1,
                "crown_jewels_reached": [],
                "total_hops": 1,
            },
            "credential_pool": [],
            "compromised_devices": [{
                "device_id": "s1-router",
                "device_ip": "192.168.100.1",
                "access_method": "hallucinated",
            }],
            "chains": [],
        }))

        results = {"intrusion": "completed"}
        pipeline._ensure_intrusion_deliverable(AGENTS["intrusion"], results)

        final = json.loads((run_dir / "05_intrusion.json").read_text())
        assert results["intrusion"] == "failed:phase5_contract_incomplete"
        assert final["status"] == "incomplete"
        assert final["summary"]["devices_compromised"] == 0
        assert final["summary"]["devices_attempted"] == 1
        assert final["compromised_devices"] == []
        assert final["credential_pool"] == [{
            "user": "root",
            "password": "P@ssw0rd123",
            "service": "mqtt",
            "source_ip": "192.168.100.11",
            "source_device": "s1-mqtt",
        }]

    def test_compact_intrusion_controller_finalizes_after_fallback(
        self, mock_provider, output_dir, monkeypatch
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        pipeline.context = {"target_subnet": "192.0.2.0/24"}
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [{
                "device_id": "mqtt",
                "device_ip": "192.0.2.11",
                "service": "mqtt",
                "port": 1883,
                "vuln_type": "no_auth",
            }],
            "all_targets": [{
                "device_id": "mqtt",
                "device_ip": "192.0.2.11",
                "role": "mqtt_broker",
                "services": [1883],
            }],
            "recovered_credentials": [],
        }))

        def read_deliverable(**kwargs):
            return json.dumps({
                "filename": kwargs["filename"],
                "content": (run_dir / kwargs["filename"]).read_text(),
            })

        def mqtt_listen(**_kwargs):
            return json.dumps({"return_code": 0, "stdout": "message"})

        base_tools = [
            {"name": "read_deliverable", "description": "read", "input_schema": {},
             "function": read_deliverable},
            {"name": "mqtt_listen", "description": "mqtt", "input_schema": {},
             "function": mqtt_listen},
        ]
        monkeypatch.setattr(
            pipeline,
            "_resolve_tools",
            lambda _config: [
                pipeline._wrap_tool(tool, phase=5, agent="intrusion")
                for tool in base_tools
            ],
        )
        runtime_tools = pipeline._apply_compact_intrusion_tool_contract(
            [
                pipeline._wrap_tool(tool, phase=5, agent="intrusion")
                for tool in base_tools
            ],
            phase=5,
            agent="intrusion",
        )
        pipeline._compact_intrusion_runtime_tools = runtime_tools

        executed = pipeline._run_compact_intrusion_fallback(AGENTS["intrusion"])
        assert executed == 1
        assert pipeline._invoke_compact_intrusion_completion(runtime_tools) is True

        final = json.loads((run_dir / "05_intrusion.json").read_text())
        assert final["status"] == "completed"
        assert final["completion_source"] == "complete_intrusion_campaign"

    def test_compact_intrusion_fallback_prioritizes_missing_credential_targets(
        self, mock_provider, output_dir, monkeypatch
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [],
            "all_targets": [
                {"device_id": "s1-router", "device_ip": "192.168.100.1", "role": "router"},
                {"device_id": "s1-mqtt", "device_ip": "192.168.100.11", "role": "mqtt_broker"},
                {"device_id": "s1-web", "device_ip": "192.168.100.12", "role": "web_server"},
                {"device_id": "s1-ssh", "device_ip": "192.168.100.13", "role": "ssh_server"},
            ],
            "recovered_credentials": [
                {"user": "admin", "password": "admin", "source_ip": "192.168.100.13"},
                {"user": "root", "password": "P@ssw0rd123", "source_ip": "192.168.100.11"},
                {"user": "root", "password": "root", "source_ip": "192.168.100.13"},
            ],
        }))
        calls = []

        def try_credential(**kwargs):
            calls.append(kwargs)
            return json.dumps({"success": False, "authenticated": False})

        monkeypatch.setattr(pipeline, "_resolve_tools", lambda _config: [{
            "name": "try_credential",
            "description": "try",
            "input_schema": {},
            "function": try_credential,
        }])
        monkeypatch.setattr(
            pipeline,
            "_compact_intrusion_coverage",
            lambda: (False, {
                "missing_entry_points": [],
                "missing_credentials": [
                    "admin@192.168.100.12",
                    "admin@192.168.100.13",
                ],
                "missing_credential_keys": [
                    ["192.168.100.12", "admin", "admin"],
                    ["192.168.100.13", "admin", "admin"],
                ],
                "missing_targets": [],
            }),
        )

        executed = pipeline._run_compact_intrusion_fallback(AGENTS["intrusion"])

        assert executed == 2
        assert calls == [
            {
                "ip": "192.168.100.12",
                "service": "http",
                "user": "admin",
                "password": "admin",
            },
            {
                "ip": "192.168.100.13",
                "service": "ssh",
                "user": "admin",
                "password": "admin",
            },
        ]

    def test_compact_intrusion_fallback_probes_ssh_entry_before_credentials(
        self, mock_provider, output_dir, monkeypatch
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [
                {
                    "device_id": "s1-ssh",
                    "device_ip": "192.0.2.10",
                    "service": "ssh",
                    "port": 22,
                },
            ],
            "all_targets": [
                {
                    "device_id": "s1-ssh",
                    "device_ip": "192.0.2.10",
                    "role": "ssh_server",
                    "services": [22],
                },
            ],
            "recovered_credentials": [
                {
                    "user": "admin",
                    "password": "admin",
                    "source_ip": "192.0.2.10",
                },
            ],
        }))
        calls = []

        def ssh_login(**kwargs):
            calls.append(("ssh_login", kwargs))
            return json.dumps({"return_code": 0, "stdout": "uid=1000(admin)"})

        def try_credential(**kwargs):
            calls.append(("try_credential", kwargs))
            return json.dumps({"success": False, "authenticated": False})

        monkeypatch.setattr(pipeline, "_resolve_tools", lambda _config: [
            {"name": "ssh_login", "description": "ssh", "input_schema": {}, "function": ssh_login},
            {"name": "try_credential", "description": "try", "input_schema": {}, "function": try_credential},
        ])

        executed = pipeline._run_compact_intrusion_fallback(AGENTS["intrusion"])

        assert executed == 2
        assert calls[0][0] == "ssh_login"
        assert "admin@192.0.2.10" in calls[0][1]["command_string"]
        assert calls[1][0] == "try_credential"


    def test_compact_post_access_harvest_runs_after_authenticated_ssh(
        self, mock_provider, output_dir, monkeypatch
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        run_dir = pipeline.run_dir
        calls = []

        (run_dir / "tool_calls.jsonl").write_text(json.dumps({
            "phase": 5,
            "tool": "try_credential",
            "args": {
                "ip": "192.0.2.10",
                "service": "ssh",
                "user": "admin",
                "password": "admin",
            },
            "result": json.dumps({
                "success": True,
                "authenticated": True,
                "service": "ssh",
                "stdout": "__ok__",
            }),
        }) + "\n")

        def ssh_exec(**kwargs):
            calls.append(kwargs)
            return json.dumps({
                "success": True,
                "return_code": 0,
                "stdout": 'uid=1000(admin) {"db_user":"root","db_pass":"secret"}',
            })

        monkeypatch.setattr(pipeline, "_resolve_tools", lambda _config: [{
            "name": "ssh_exec",
            "description": "ssh",
            "input_schema": {},
            "function": ssh_exec,
        }])

        executed = pipeline._run_compact_intrusion_post_access(AGENTS["intrusion"])

        assert executed == 1
        assert calls[0]["ip"] == "192.0.2.10"
        assert calls[0]["user"] == "admin"
        assert "config.json" in calls[0]["command"]

    def test_compact_intrusion_synthesis_reconstructs_harvest_and_chains(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        pipeline.context = {"target_subnet": "192.0.2.0/24"}
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [
                {"device_id": "s1-router", "device_ip": "192.0.2.1", "service": "telnet"},
                {"device_id": "s1-ssh", "device_ip": "192.0.2.10", "service": "ssh"},
            ],
            "all_targets": [
                {"device_id": "s1-router", "device_ip": "192.0.2.1", "role": "router", "services": [22, 23]},
                {"device_id": "s1-ssh", "device_ip": "192.0.2.10", "role": "ssh_server", "services": [22]},
            ],
            "recovered_credentials": [
                {"user": "root", "password": "root", "source_ip": "192.0.2.1", "source_device": "s1-router"},
                {"user": "admin", "password": "admin", "source_ip": "192.0.2.10", "source_device": "s1-ssh"},
            ],
            "attack_chains": [{
                "chain": "s1-router -> s1-ssh",
                "src_device": "s1-router",
                "src_ip": "192.0.2.1",
                "dst_device": "s1-ssh",
                "dst_ip": "192.0.2.10",
                "pivot_vuln": "VULN-006",
                "target_vuln_ids": ["VULN-010"],
            }],
        }))
        records = [
            {
                "phase": 5,
                "tool": "try_credential",
                "args": {
                    "ip": "192.0.2.1", "service": "ssh",
                    "user": "root", "password": "root",
                },
                "result": json.dumps({
                    "success": True, "authenticated": True,
                    "service": "ssh", "stdout": "__ok__",
                }),
            },
            {
                "phase": 5,
                "tool": "ssh_exec",
                "args": {
                    "ip": "192.0.2.1", "user": "root",
                    "password": "root", "command": "id",
                },
                "result": json.dumps({
                    "success": True, "return_code": 0,
                    "stdout": 'uid=0(root) {"db_user":"dbadmin","db_pass":"db-secret"}',
                }),
            },
            {
                "phase": 5,
                "tool": "ssh_login",
                "args": {
                    "command_string": "sshpass -p admin ssh admin@192.0.2.10 'id'",
                },
                "result": json.dumps({
                    "return_code": 0, "stdout": "uid=1000(admin)",
                }),
            },
        ]
        (run_dir / "tool_calls.jsonl").write_text(
            "".join(json.dumps(record) + "\n" for record in records)
        )

        data = pipeline._synthesize_intrusion_from_tools()

        assert data["summary"]["credentials_harvested"] == 3
        assert any(
            credential["password"] == "db-secret"
            for credential in data["credential_pool"]
        )
        assert data["compromised_devices"][0]["credentials_found"][0]["password"] == "db-secret"
        assert len(data["chains"]) == 1
        assert [hop["device_id"] for hop in data["chains"][0]["hops"]] == [
            "s1-router", "s1-ssh",
        ]
        assert data["summary"]["total_hops"] == 1

    def test_compact_post_access_recovery_is_disabled_for_full_profile(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="full")
        assert pipeline._run_compact_intrusion_post_access(AGENTS["intrusion"]) == 0

    def test_compact_coverage_counts_matching_credential_as_entry_probe(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [
                {"device_id": "s1-web", "device_ip": "192.168.100.12", "service": "http"},
                {"device_id": "s1-ssh", "device_ip": "192.168.100.13", "service": "ssh"},
            ],
            "all_targets": [
                {"device_id": "s1-web", "device_ip": "192.168.100.12", "role": "web_server", "services": [80]},
                {"device_id": "s1-ssh", "device_ip": "192.168.100.13", "role": "ssh_server", "services": [22]},
            ],
            "recovered_credentials": [{"user": "root", "password": "root"}],
        }))
        calls = [
            {
                "phase": 5,
                "tool": "try_credential",
                "args": {"ip": "192.168.100.12", "service": "http", "user": "root", "password": "root", "port": 80},
                "result": json.dumps({"success": True, "authenticated": True}),
            },
            {
                "phase": 5,
                "tool": "try_credential",
                "args": {"ip": "192.168.100.13", "service": "ssh", "user": "root", "password": "root", "port": 22},
                "result": json.dumps({"success": True, "authenticated": True}),
            },
        ]
        (run_dir / "tool_calls.jsonl").write_text(
            "".join(json.dumps(item) + "\n" for item in calls)
        )

        coverage_ok, coverage = pipeline._compact_intrusion_coverage()

        assert coverage_ok is True
        assert coverage["missing_entry_points"] == []
        assert coverage["missing_credential_keys"] == []


    def test_intrusion_synthesis_blocks_context_only_trace(
        self, mock_provider, output_dir, monkeypatch
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [{"device_id": "s1-router", "device_ip": "192.168.100.1"}],
            "all_targets": [{"device_id": "s1-router", "device_ip": "192.168.100.1"}],
            "recovered_credentials": [],
        }))
        (run_dir / "tool_calls.jsonl").write_text(json.dumps({
            "phase": 5,
            "agent": "intrusion",
            "tool": "read_deliverable",
            "args": {"filename": "05_intrusion_context.json"},
            "result": json.dumps({"content": "{}"}),
        }) + "\n")

        monkeypatch.setattr(pipeline, "_run_compact_intrusion_fallback", lambda *_args, **_kwargs: 0)
        results = {"intrusion": "failed:empty"}
        pipeline._ensure_intrusion_deliverable(AGENTS["intrusion"], results)

        final = json.loads((run_dir / "05_intrusion.json").read_text())
        assert results["intrusion"] == "blocked:phase5_no_observable_actions"
        assert final["status"] == "blocked"
        assert final["summary"]["devices_attempted"] == 0
        assert final["summary"]["devices_compromised"] == 0

    def test_intrusion_synthesis_counts_noncredential_actions(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "all_targets": [{"device_id": "s1-web", "device_ip": "192.168.100.12"}],
        }))
        (run_dir / "tool_calls.jsonl").write_text(json.dumps({
            "phase": 5,
            "agent": "intrusion",
            "tool": "http_get",
            "args": {"url": "http://192.168.100.12/admin"},
            "result": json.dumps({"status_code": 200}),
        }) + "\n")

        data = pipeline._synthesize_intrusion_from_tools()

        assert data["summary"]["devices_attempted"] == 1
        assert pipeline._intrusion_synthesis_has_observable_actions(data) is True

    def test_non_local_intrusion_keeps_valid_model_deliverable(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "openrouter"
        mock_provider.model = "large-model"
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        model_output = {
            "summary": {"devices_compromised": 1},
            "compromised_devices": [{"device_ip": "192.0.2.10"}],
        }
        (run_dir / "05_intrusion.json").write_text(json.dumps(model_output))

        results = {"intrusion": "completed"}
        pipeline._ensure_intrusion_deliverable(AGENTS["intrusion"], results)

        assert json.loads((run_dir / "05_intrusion.json").read_text()) == model_output
        assert results["intrusion"] == "completed"


    def test_local_moe_intrusion_runs_as_tool_memo_without_save_requirement(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        (pipeline.run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [],
            "all_targets": [],
            "recovered_credentials": [],
        }))

        status = pipeline._run_agent(AGENTS["intrusion"])

        kwargs = mock_provider.chat_with_tools.call_args.kwargs
        tool_names = {tool["name"] for tool in kwargs["tools"]}
        assert status.startswith("failed:")
        assert "try_credential" in tool_names
        assert "ssh_exec" in tool_names
        assert "ssh_login" in tool_names
        if "mqtt_listen" in pipeline.runtime_unavailable_tools:
            assert "mqtt_listen" not in tool_names
        else:
            assert "mqtt_listen" in tool_names
        assert "http_get" in tool_names
        assert "curl_headers" in tool_names
        assert "complete_intrusion_campaign" in tool_names
        assert "save_deliverable" not in tool_names
        assert kwargs["required_tool"] == "complete_intrusion_campaign"
        assert kwargs["terminate_after_tool"] == "complete_intrusion_campaign"
        assert kwargs["terminate_on_unavailable_tools"] is None
        assert kwargs["strict_required_tool"] is True
        assert kwargs["force_tool_on_stall"] is True
        assert kwargs["reopen_intrusion_tools_on_contract_error"] is True
        assert kwargs["recover_required_tool_on_stall"] is True
        assert "Complete compact campaign" in kwargs["system_prompt"]
        assert "commits 05_intrusion.json" in kwargs["system_prompt"]


    def test_compact_intrusion_defers_failed_phase_event_until_reconciliation(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        (pipeline.run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [],
            "all_targets": [],
            "recovered_credentials": [],
        }))
        events = []

        status = pipeline._run_agent(AGENTS["intrusion"], events.append)

        assert status.startswith("failed:")
        assert not [event for event in events if event.get("type") == "phase_done"]

    def test_full_local_moe_intrusion_uses_standard_full_contract(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "future-full-local-model"
        pipeline = Pipeline(provider=mock_provider, execution_profile="full")
        (pipeline.run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [],
            "all_targets": [],
            "recovered_credentials": [],
        }))

        status = pipeline._run_agent(AGENTS["intrusion"])

        kwargs = mock_provider.chat_with_tools.call_args.kwargs
        tool_names = {tool["name"] for tool in kwargs["tools"]}
        assert status.startswith("failed:")
        assert pipeline._uses_local_moe() is True
        assert pipeline._uses_compact_local_moe() is False
        assert "save_deliverable" in tool_names
        assert kwargs["required_tool"] == "save_deliverable"
        assert kwargs["terminate_after_tool"] == "save_deliverable"
        assert kwargs["terminate_on_unavailable_tools"] is None
        assert kwargs["strict_required_tool"] is False
        assert kwargs["reopen_intrusion_tools_on_contract_error"] is False
        assert kwargs["force_tool_on_stall"] is False
        assert kwargs["recover_required_tool_on_stall"] is False
        assert "ssh_login" not in {tool["name"] for tool in kwargs["tools"]}
        assert kwargs["max_turns"] == 80
        assert kwargs["max_tokens"] == 16384

        model_output = {
            "summary": {"devices_compromised": 1},
            "compromised_devices": [{"device_ip": "192.0.2.10"}],
        }
        (pipeline.run_dir / "05_intrusion.json").write_text(
            json.dumps(model_output)
        )
        results = {"intrusion": "completed"}
        pipeline._ensure_intrusion_deliverable(AGENTS["intrusion"], results)

        assert json.loads(
            (pipeline.run_dir / "05_intrusion.json").read_text()
        ) == model_output
        assert results["intrusion"] == "completed"

    @pytest.mark.parametrize(
        ("profile", "expected_strict", "expected_force", "expected_ready_force"),
        [("compact", True, True, True), ("full", False, False, False)],
    )
    def test_local_moe_recon_requires_successful_save_only_for_compact(
        self, mock_provider, output_dir, profile, expected_strict, expected_force,
        expected_ready_force
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile=profile)
        pipeline.context = {"target_subnet": "192.168.100.0/24"}

        status = pipeline._run_agent(AGENTS["recon"])

        kwargs = mock_provider.chat_with_tools.call_args.kwargs
        assert status.startswith("failed:")
        assert kwargs["required_tool"] == "save_deliverable"
        assert kwargs["terminate_after_tool"] == "save_deliverable"
        assert kwargs["strict_required_tool"] is expected_strict
        assert kwargs["force_completion_on_recon_ready"] is expected_ready_force
        assert kwargs["force_tool_on_stall"] is expected_force
        if profile == "compact":
            assert "SHORT narrative seed only" in kwargs["system_prompt"]
            assert "Do not include tables" in kwargs["system_prompt"]

def test_downstream_phase_selection_includes_prerequisites():
    assert _expand_phase_selection([1]) == [1]
    assert _expand_phase_selection([3, 6]) == [1, 2, 3, 4, 5, 6]
    assert _expand_phase_selection([5]) == [1, 2, 3, 4, 5]
    assert _expand_phase_selection([]) == []


class TestPipelineRun:
    @patch("src.agent.pipeline.load_lab_context")
    @patch("src.agent.pipeline.reset_tool_cache")
    def test_run_resets_process_tool_cache(
        self, mock_reset_cache, mock_lab, mock_provider, output_dir
    ):
        mock_lab.return_value = {
            "device_count": 0, "link_count": 0,
            "cve_count": 0, "top_risk": "none",
        }
        pipeline = Pipeline(provider=mock_provider, dry_run=True, phases=[])

        pipeline.run()

        mock_reset_cache.assert_called_once_with()

    @patch("src.agent.pipeline.load_lab_context")
    def test_full_run_keeps_dashboard_stop_event(self, mock_lab, mock_provider, output_dir):
        from threading import Event

        mock_lab.return_value = {
            "device_count": 0, "link_count": 0,
            "cve_count": 0, "top_risk": "none",
        }
        pipeline = Pipeline(provider=mock_provider, dry_run=True, phases=[], execution_profile="full")
        stop_event = Event()

        pipeline.run(stop_event=stop_event)

        assert pipeline._stop_event is stop_event

    @patch("src.agent.pipeline.load_lab_context")
    @patch("src.agent.pipeline.load_prompt")
    def test_dry_run_single_phase(
        self, mock_load_prompt, mock_lab, mock_provider, output_dir
    ):
        mock_lab.return_value = {
            "device_count": 15, "link_count": 16,
            "cve_count": 24, "top_risk": "mikrotik",
        }
        mock_load_prompt.return_value = "System prompt"

        pipeline = Pipeline(provider=mock_provider, dry_run=True, phases=[1])
        run_dir = pipeline.run_dir

        # Make provider return text, and also write deliverable
        def side_effect(**kwargs):
            (run_dir / "01_graph_analysis.md").write_text(
                "## Section 1\nContent\n## Section 2\nMore"
            )
            return "Done."
        mock_provider.chat_with_tools.side_effect = side_effect

        results = pipeline.run()

        assert "graph_analysis" in results
        assert results["graph_analysis"] == "completed"
        assert (
            mock_provider.chat_with_tools.call_args.kwargs["terminate_after_tool"]
            == "save_deliverable"
        )
        # cost_summary.json should be saved
        assert (run_dir / "cost_summary.json").exists()
        cost_data = json.loads((run_dir / "cost_summary.json").read_text())
        assert "model" in cost_data
        assert "total_cost_usd" in cost_data

    @patch("src.agent.pipeline.load_lab_context")
    def test_phase_filter(self, mock_lab, mock_provider, output_dir):
        mock_lab.return_value = {
            "device_count": 1, "link_count": 1,
            "cve_count": 0, "top_risk": "none",
        }
        pipeline = Pipeline(provider=mock_provider, phases=[1])
        run_dir = pipeline.run_dir

        # Phase 1 (graph_analysis) has no prerequisites, so it should run
        with patch("src.agent.pipeline.load_prompt", return_value="prompt"):
            def write_deliverable(**kwargs):
                (run_dir / "01_graph_analysis.md").write_text("## A\n## B\n")
                return "Done."
            mock_provider.chat_with_tools.side_effect = write_deliverable
            results = pipeline.run()

        assert len(results) == 1
        assert "graph_analysis" in results


class TestInformationPreservingArchitecture:
    def test_transaction_rejects_without_overwrite_then_promotes_valid(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="graph_analysis",
            phase=1,
            prompt_template="graph_analysis",
            deliverable_file="01_graph_analysis.md",
            tools=["deliverable"],
            validator="markdown_with_sections",
        )
        tools = pipeline._apply_deliverable_transaction(
            pipeline._resolve_tools(config), config
        )
        save = next(tool["function"] for tool in tools if tool["name"] == "save_deliverable")

        rejected = json.loads(save(
            filename="01_graph_analysis.md",
            content="## Only one section",
        ))
        assert rejected["ok"] is False
        assert rejected["error_kind"] == "deliverable_validation"
        assert not (pipeline.run_dir / "01_graph_analysis.md").exists()
        assert (pipeline.run_dir / rejected["attempt_ref"]).read_text() == "## Only one section"

        valid_content = "## Section one\nEvidence\n## Section two\nAnalysis"
        accepted = json.loads(save(
            filename="01_graph_analysis.md",
            content=valid_content,
        ))
        assert accepted["validated"] is True
        assert (pipeline.run_dir / "01_graph_analysis.md").read_text() == valid_content
        attempts = [
            json.loads(line)
            for line in (pipeline.run_dir / "deliverable_attempts.jsonl").read_text().splitlines()
        ]
        assert [attempt["valid"] for attempt in attempts] == [False, True]

    def test_phase3_prompt_projection_is_bounded_and_references_full_scan(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        scan_data = {
            "scan_results": {
                "http": [
                    {
                        "tool": "http_get",
                        "kwargs": {"url": f"http://device/{index}"},
                        "result": ("A" * 1800) + f" evidence-{index}",
                    }
                    for index in range(20)
                ]
            }
        }

        projection = pipeline._phase3_scan_results_for_prompt(scan_data, "device")

        rendered = json.dumps(projection)
        assert len(rendered) < 8000
        assert projection["_evidence_projection"]["omitted_entries"] > 0
        assert projection["_evidence_projection"]["full_scan_artifact"].startswith(
            "03_scans/"
        )


    def test_full_phase3_prompt_preserves_complete_scanner_evidence(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "future-full-local-model"
        pipeline = Pipeline(provider=mock_provider, execution_profile="full")
        scan_data = {
            "scan_results": {
                "http": [{
                    "tool": "http_get",
                    "kwargs": {"url": "http://device/large"},
                    "result": "complete-evidence-" + ("A" * 12000),
                }]
            },
            "findings": [{"type": "header", "evidence": "complete"}],
        }

        assert pipeline._phase3_scan_results_for_prompt(scan_data, "device") is scan_data
        assert "_evidence_projection" not in scan_data
    def test_local_moe_phase3_uses_one_worker(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")

        assert pipeline._phase3_worker_count(4) == 1

        full_pipeline = Pipeline(provider=mock_provider, execution_profile="full")
        assert full_pipeline._phase3_worker_count(4) == 1
        assert full_pipeline._uses_compact_local_moe() is False

        mock_provider.provider = "openrouter"
        mock_provider.model = "large-model"
        assert pipeline._phase3_worker_count(4) == 4

    @patch("src.agent.pipeline.get_device_info")
    @patch("src.agent.pipeline.get_attack_surface")
    @patch("src.agent.pipeline.load_prompt")
    def test_local_phase3_preserves_memo_without_overwriting_scanner_json(
        self, mock_load_prompt, mock_surface, mock_device_info, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        mock_provider.chat_with_tools.return_value = "Local memo: reject generic CVE claims."
        mock_surface.return_value = json.dumps({"nodes": [{
            "id": "s1-router",
            "ip": "192.168.100.1",
            "type": "router",
            "role": "router",
            "services": [{"name": "ssh", "port": 22}, {"name": "http", "port": 80}],
        }]})
        mock_device_info.return_value = json.dumps({"os_version": "OpenWrt"})
        mock_load_prompt.return_value = "legacy json prompt should not control local path"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        run_dir = pipeline.run_dir
        fallback = {
            "device_id": "s1-router",
            "device_ip": "192.168.100.1",
            "vulnerabilities": [{
                "type": "missing_header",
                "severity": "LOW",
                "service": "http",
                "port": 80,
            }],
            "summary": {"total": 1},
        }

        def scanner_side_effect(run_dir_arg, devices, stream_callback=None, *, compact=False, stop_event=None):
            (run_dir / "03_device_s1-router.json").write_text(json.dumps(fallback))
            return {"s1-router": {"scan_results": {}, "findings": fallback["vulnerabilities"]}}

        config = AgentConfig(
            name="vuln_analysis",
            phase=3,
            prompt_template="vuln_analysis",
            deliverable_file="03_vuln_analysis.json",
            tools=[],
            has_device_agents=True,
        )
        with patch("src.agent.pipeline.run_scanner", side_effect=scanner_side_effect), \
             patch("src.agent.tools.graph_tools.get_network_neighbors", return_value={
                 "upstream": [], "downstream": [], "role": "entrypoint",
             }):
            pipeline._run_phase3(config)

        kwargs = mock_provider.chat_with_tools.call_args.kwargs
        assert kwargs["tools"] == []
        assert kwargs["max_turns"] == 1
        assert "not JSON and not a tool call" in kwargs["system_prompt"]
        assert json.loads((run_dir / "03_device_s1-router.json").read_text()) == fallback
        assert (run_dir / "03_device_s1-router_analysis.md").read_text().strip() == "Local memo: reject generic CVE claims."
        assert "Local memo" in (run_dir / "model_outputs.jsonl").read_text()
        assert not (run_dir / "deliverable_attempts.jsonl").exists()

    def test_local_report_phase_is_one_shot_and_composes_final_report(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        memo = "Model memo: recon saw MQTT on 192.168.100.11 and one intrusion path."
        mock_provider.chat_with_tools.return_value = memo
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        pipeline.context = {"target_subnet": "192.168.100.0/24"}
        run_dir = pipeline.run_dir
        (run_dir / "06_phase6_context.json").write_text(json.dumps({
            "device_count": 4,
            "total_vulnerabilities": 2,
            "severity_counts": {"CRITICAL": 1, "HIGH": 1},
            "exploitation_summary": {"confirmed": 1, "failed": 1},
            "top_devices_by_risk": [{"device_id": "s1-web", "score": 9.0}],
            "critical_findings": [{
                "device_id": "s1-web",
                "type": "directory_listing",
                "service": "http",
                "title": "Directory listing exposed",
            }],
            "cve_list": ["CVE-2023-48795"],
        }))
        (run_dir / "01_graph_evidence.json").write_text(json.dumps({
            "scenario": "Reseau plat",
            "subnet": "192.168.100.0/24",
            "node_count": 4,
            "edge_count": 3,
            "service_count": 8,
            "nodes": [
                {"id": "s1-router", "ip": "192.168.100.1", "type": "router", "role": "router"},
                {"id": "s1-mqtt", "ip": "192.168.100.11", "type": "server", "role": "mqtt_broker"},
            ],
        }))
        (run_dir / "02_recon_evidence.json").write_text(json.dumps({
            "device_count": 2,
            "devices": [
                {
                    "device": "s1-router",
                    "ip": "192.168.100.1",
                    "open_ports": [22, 23, 80],
                    "services": [{"service": "ssh", "port": 22, "version": "Dropbear"}],
                },
                {
                    "device": "s1-mqtt",
                    "ip": "192.168.100.11",
                    "open_ports": [1883],
                    "services": [{"service": "mqtt", "port": 1883, "version": "Mosquitto 2.0.21"}],
                },
            ],
        }))
        (run_dir / "05_intrusion.json").write_text(json.dumps({
            "summary": {
                "devices_attempted": 2,
                "devices_compromised": 1,
                "credentials_harvested": 1,
                "crown_jewels_reached": 0,
            },
            "compromised_devices": [{
                "device_id": "s1-web",
                "device_ip": "192.168.100.12",
                "access_method": "http data exposure",
            }],
        }))
        long_table = "\n".join(
            f"| VULN-{index:03d} | s1-web | HIGH | Evidence row {index} |"
            for index in range(1, 18)
        )
        prefill = (
            "## 5. Vulnerability Inventory\n\n"
            "| ID | Device | Severity | Evidence |\n"
            "|----|--------|----------|----------|\n"
            f"{long_table}\n\n"
            "## 6. Exploitation Results\n\n"
            "| Test | Status | Evidence |\n"
            "|------|--------|----------|\n"
            "| directory_listing | EXPLOITED | Index page observed |\n"
        )
        (run_dir / "06_report_prefill.md").write_text(prefill)
        events = []

        status = pipeline._run_local_report_phase(AGENTS["report"], events.append)

        assert status == "completed"
        kwargs = mock_provider.chat_with_tools.call_args.kwargs
        assert kwargs["tools"] == []
        assert kwargs["max_turns"] == 1
        assert kwargs["deadline"] > 0
        assert "192.168.100.11" in kwargs["system_prompt"]
        report = (run_dir / "06_report.md").read_text()
        assert "## 1." in report and "## 10." in report
        assert "{{SECTION_5_TABLE}}" not in report
        assert "{{SECTION_6_TABLES}}" not in report
        assert "192.168.100.11" in report
        assert memo in report
        assert (run_dir / "06_report_analysis.md").read_text().strip() == memo
        assert memo in (run_dir / "model_outputs.jsonl").read_text()
        phase_done = [event for event in events if event.get("type") == "phase_done"]
        assert len(phase_done) == 1
        assert phase_done[0]["status"] == "completed"

    def test_tool_log_preserves_full_result(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        payload = "x" * 7000
        wrapped = pipeline._wrap_tool({
            "name": "large_result",
            "function": lambda: payload,
        }, phase=5, agent="intrusion")

        assert wrapped["function"]() == payload
        record = json.loads(
            (pipeline.run_dir / "tool_calls.jsonl").read_text().strip()
        )
        assert record["result"] == payload
        assert record["phase"] == 5
        assert record["agent"] == "intrusion"

    def test_tool_log_records_exception_before_reraising(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)

        def fail():
            raise RuntimeError("connection failed")

        wrapped = pipeline._wrap_tool({
            "name": "failing_tool",
            "function": fail,
        }, phase=3, agent="vuln_analysis")

        with pytest.raises(RuntimeError, match="connection failed"):
            wrapped["function"]()

        record = json.loads(
            (pipeline.run_dir / "tool_calls.jsonl").read_text().strip()
        )
        result = json.loads(record["result"])
        assert record["sequence"] == 1
        assert record["tool"] == "failing_tool"
        assert record["phase"] == 3
        assert record["agent"] == "vuln_analysis"
        assert result == {
            "error": "connection failed",
            "exception_type": "RuntimeError",
        }

    def test_model_text_is_archived_without_diminution(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        forwarded = []
        callback = pipeline._model_stream_callback(
            forwarded.append, phase=2, agent="recon"
        )
        rich_text = "Unexpected service nuance with full model reasoning."
        callback({"type": "text_chunk", "text": rich_text})

        record = json.loads(
            (pipeline.run_dir / "model_outputs.jsonl").read_text().strip()
        )
        assert record["text"] == rich_text
        assert forwarded == [{"type": "text_chunk", "text": rich_text}]

    def test_graph_projection_does_not_invent_precomputed_paths(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        records = [
            {
                "tool": "get_network_topology",
                "args": {},
                "result": json.dumps({
                    "scenario": "Flat network",
                    "subnet": "192.168.100.0/24",
                    "nodes": [{"id": f"d{i}"} for i in range(4)],
                    "edges": [{"source": "d0", "target": f"d{i}"} for i in range(1, 4)],
                }),
                "evidence_ref": "tc-topology",
            },
            {
                "tool": "get_attack_surface",
                "args": {},
                "result": json.dumps([
                    {"id": "d0", "services": [{"name": "ssh"}, {"name": "http"}]},
                    {"id": "d1", "services": [{"name": "mqtt"}]},
                ]),
                "evidence_ref": "tc-surface",
            },
            {
                "tool": "get_attack_paths",
                "args": {},
                "result": json.dumps({
                    "note": "Attack paths not pre-computed; discover via active recon.",
                    "subnet": "192.168.100.0/24",
                }),
                "evidence_ref": "tc-paths",
            },
        ]
        (pipeline.run_dir / "tool_calls.jsonl").write_text(
            "\n".join(json.dumps(record) for record in records) + "\n"
        )

        projection = pipeline._build_graph_evidence_projection()

        assert projection["node_count"] == 4
        assert projection["edge_count"] == 3
        assert projection["service_count"] == 3
        assert projection["attack_path_count"] == 0
        assert "not pre-computed" in projection["attack_paths_note"]
        assert (pipeline.run_dir / "01_graph_evidence.json").exists()

    def test_compact_local_graph_rebuilds_facts_before_validation(
        self, output_dir
    ):
        provider = MagicMock()
        provider.provider = "local-moe"
        provider.model = "lance-moe"
        pipeline = Pipeline(provider=provider, execution_profile="compact")
        records = [
            {
                "tool": "get_network_topology",
                "args": {},
                "result": json.dumps({
                    "scenario": "Flat network",
                    "subnet": "192.0.2.0/24",
                    "nodes": [
                        {"id": "router", "ip": "192.0.2.1", "type": "router", "role": "router"},
                        {"id": "mqtt", "ip": "192.0.2.11", "type": "server", "role": "mqtt_broker"},
                    ],
                    "edges": [{"source": "router", "target": "mqtt"}],
                }),
                "evidence_ref": "tc-graph-topology",
            },
            {
                "tool": "get_attack_surface",
                "args": {},
                "result": json.dumps([
                    {
                        "id": "router", "ip": "192.0.2.1", "type": "router",
                        "services": [{"name": "ssh", "port": 22}],
                    },
                    {
                        "id": "mqtt", "ip": "192.0.2.11", "type": "server",
                        "services": [{"name": "mqtt", "port": 1883}],
                    },
                ]),
                "evidence_ref": "tc-graph-surface",
            },
            {
                "tool": "get_attack_paths",
                "args": {},
                "result": json.dumps({
                    "note": "Attack paths not pre-computed; discover via active recon.",
                }),
                "evidence_ref": "tc-graph-paths",
            },
            {
                "tool": "get_risk_scores",
                "args": {},
                "result": json.dumps({
                    "note": "Risk scores not pre-computed.",
                    "devices": [{"id": "router"}, {"id": "mqtt"}],
                }),
                "evidence_ref": "tc-graph-risks",
            },
        ]
        (pipeline.run_dir / "tool_calls.jsonl").write_text(
            "\n".join(json.dumps(record) for record in records) + "\n"
        )
        captured = {}

        def save(filename, content):
            captured.update(filename=filename, content=content)
            return json.dumps({"status": "saved"})

        config = AgentConfig(
            name="graph_analysis", phase=1, prompt_template="graph_analysis",
            deliverable_file="01_graph_analysis.md", tools=[],
            validator="markdown_with_sections",
        )
        wrapped = pipeline._apply_deliverable_transaction([{
            "name": "save_deliverable", "description": "save",
            "input_schema": {}, "function": save,
        }], config)[0]["function"]
        result = json.loads(wrapped(
            filename="01_graph_analysis.md",
            content=(
                "## 1. Executive Summary\n9 services and one attack path.\n"
                "## 2. Invented facts\nRisk score 99."
            ),
        ))

        assert result["validated"] is True
        assert "**Declared devices:** 2" in captured["content"]
        assert "**Theoretical attack surface:** 2 declared services" in captured["content"]
        assert "**Estimated main risk:** Not pre-computed" in captured["content"]
        assert "Attack paths not pre-computed" in captured["content"]
        assert "Risk score 99" not in captured["content"]

    def test_graph_projection_uses_device_info_only_to_fill_surface_gaps(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        records = [
            {
                "tool": "get_network_topology",
                "args": {},
                "result": json.dumps({
                    "nodes": [{"id": "router"}, {"id": "mqtt"}],
                    "edges": [],
                }),
                "evidence_ref": "tc-topology",
            },
            {
                "tool": "get_attack_surface",
                "args": {},
                "result": json.dumps([{
                    "id": "router", "ip": "192.0.2.1",
                    "services": [{"name": "ssh", "port": 22}],
                }]),
                "evidence_ref": "tc-surface",
            },
            {
                "tool": "get_device_info",
                "args": {"device_id": "mqtt"},
                "result": json.dumps({
                    "id": "mqtt", "ip": "192.0.2.11",
                    "services": [{"name": "mqtt", "port": 1883}],
                }),
                "evidence_ref": "tc-mqtt-detail",
            },
        ]
        (pipeline.run_dir / "tool_calls.jsonl").write_text(
            "\n".join(json.dumps(record) for record in records) + "\n"
        )

        projection = pipeline._build_graph_evidence_projection()

        assert [item["id"] for item in projection["attack_surface"]] == [
            "router", "mqtt",
        ]
        assert projection["device_coverage"] == {
            "router": "get_attack_surface",
            "mqtt": "get_device_info",
        }
        assert projection["service_count"] == 2

    def test_full_local_graph_preserves_autonomous_report(self, output_dir):
        provider = MagicMock()
        provider.provider = "local-moe"
        provider.model = "future-full-local-model"
        pipeline = Pipeline(provider=provider, execution_profile="full")
        captured = {}

        def save(filename, content):
            captured.update(filename=filename, content=content)
            return json.dumps({"status": "saved"})

        config = AgentConfig(
            name="graph_analysis", phase=1, prompt_template="graph_analysis",
            deliverable_file="01_graph_analysis.md", tools=[],
            validator="markdown_with_sections",
        )
        wrapped = pipeline._apply_deliverable_transaction([{
            "name": "save_deliverable", "description": "save",
            "input_schema": {}, "function": save,
        }], config)[0]["function"]
        autonomous = "## Section one\nFull reasoning.\n## Section two\nFull analysis."
        result = json.loads(wrapped(
            filename="01_graph_analysis.md", content=autonomous,
        ))

        assert result["validated"] is True
        assert captured["content"] == autonomous

    def test_recon_projection_keeps_raw_evidence_and_builds_rows(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        records = [
            {
                "tool": "arp_scan",
                "args": {},
                "result": json.dumps({
                    "hosts": [{"ip": "192.0.2.10", "mac": "aa:bb", "vendor": "Lab"}]
                }),
            },
            {
                "tool": "nmap_scan",
                "args": {"target": "192.0.2.10"},
                "result": json.dumps({
                    "stdout": (
                        "23/tcp open telnet?\n"
                        "80/tcp open http OpenWrt uHTTPd"
                    ),
                    "return_code": 0,
                }),
            },
        ]
        (pipeline.run_dir / "tool_calls.jsonl").write_text(
            "\n".join(json.dumps(record) for record in records) + "\n"
        )

        projection = pipeline._build_recon_evidence_projection()

        assert projection["device_count"] == 1
        assert projection["devices"][0]["open_ports"] == [23, 80]
        services = projection["devices"][0]["services"]
        assert services[0]["service"] == "telnet?"
        assert services[0]["version"] == ""
        assert services[1]["service"] == "http"
        assert services[1]["version"] == "OpenWrt uHTTPd"
        assert (pipeline.run_dir / "02_recon_evidence.json").exists()

    def test_phase2_recon_reconciles_custom_scenario_services(
        self, mock_provider, output_dir, monkeypatch
    ):
        import src.agent.tools.graph_tools as graph_tools

        nodes = [
            {
                "id": "s22-router", "ip": "192.0.2.1", "role": "router",
                "services": [],
            },
            {
                "id": "s22-custom-a", "ip": "192.0.2.11",
                "role": "custom_public_role", "services": [{"name": "mqtt", "port": 1883, "protocol": "tcp"}],
            },
            {
                "id": "s22-custom-b", "ip": "192.0.2.12",
                "role": "custom_control_role", "services": [],
            },
            {
                "id": "s22-unobserved", "ip": "192.0.2.13",
                "role": "custom_role", "services": [],
            },
        ]
        monkeypatch.setattr(
            graph_tools,
            "_scenario_topology",
            {"nodes": nodes, "node_index": {node["id"]: node for node in nodes}},
        )
        pipeline = Pipeline(provider=mock_provider, scenario_id=22)
        projection = {
            "devices": [
                {
                    "ip": "192.0.2.1",
                    "services": [
                        {"port": 80, "protocol": "tcp", "service": "http"},
                        {"port": 443, "protocol": "tcp", "service": "ssl/http"},
                    ],
                },
                {
                    "ip": "192.0.2.11",
                    "services": [
                        {"port": 8080, "protocol": "tcp", "service": "http-proxy"},
                    ],
                },
                {
                    "ip": "192.0.2.12",
                    "services": [
                        {"port": 8080, "protocol": "tcp", "service": "http-proxy"},
                    ],
                },
            ],
        }

        result = pipeline._reconcile_phase2_attack_surface(projection)

        assert result["reconciled_nodes"] == [
            "s22-custom-a", "s22-custom-b", "s22-router",
        ]
        assert result["unresolved_nodes"] == ["s22-unobserved"]
        by_id = {node["id"]: node for node in nodes}
        assert [service["name"] for service in by_id["s22-custom-a"]["services"]] == ["mqtt", "http"]
        assert [service["name"] for service in by_id["s22-router"]["services"]] == [
            "http", "https",
        ]
        assert {
            node["id"] for node in json.loads(graph_tools.get_attack_surface())
        } == {node["id"] for node in nodes}

    def test_compact_local_recon_rebuilds_fact_sections_before_validation(
        self, output_dir, monkeypatch
    ):
        import src.agent.tools.graph_tools as graph_tools

        monkeypatch.setattr(graph_tools, "_scenario_topology", {
            "nodes": [
                {"id": "router", "ip": "192.0.2.10", "role": "router"},
                {"id": "mqtt", "ip": "192.0.2.11", "role": "mqtt_broker"},
                {"id": "offline", "ip": "192.0.2.12", "role": "server"},
            ]
        })
        provider = MagicMock()
        provider.provider = "local-moe"
        provider.model = "lance-moe"
        pipeline = Pipeline(provider=provider, execution_profile="compact")
        records = [
            {
                "tool": "arp_scan",
                "args": {},
                "result": json.dumps({"hosts": [
                    {"ip": "192.0.2.10"}, {"ip": "192.0.2.11"},
                ]}),
            },
            {
                "tool": "nmap_discovery",
                "args": {"target": "192.0.2.0/24"},
                "result": json.dumps({"stdout": (
                    "Nmap scan report for 192.0.2.10\n"
                    "Nmap scan report for 192.0.2.11\n"
                    "Nmap scan report for 192.0.2.200"
                )}),
            },
            {
                "tool": "nmap_scan",
                "args": {"target": "192.0.2.10"},
                "result": json.dumps({"stdout": (
                    "23/tcp open telnet?\n80/tcp open http OpenWrt uHTTPd"
                )}),
            },
            {
                "tool": "nmap_scan",
                "args": {"target": "192.0.2.11"},
                "result": json.dumps({"stdout": "1883/tcp open mqtt Mosquitto 2.0"}),
            },
            {
                "tool": "nmap_scan",
                "args": {"target": "192.0.2.12"},
                "result": json.dumps({
                    "stdout": "Host seems down.", "return_code": 0,
                }),
            },
        ]
        (pipeline.run_dir / "tool_calls.jsonl").write_text(
            "\n".join(json.dumps(record) for record in records) + "\n",
            encoding="utf-8",
        )
        captured = {}

        def save(filename, content):
            captured.update(filename=filename, content=content)
            return json.dumps({"status": "saved"})

        config = AgentConfig(
            name="recon", phase=2, prompt_template="recon",
            deliverable_file="02_recon.md", tools=[],
            validator="recon_markdown",
        )
        wrapped = pipeline._apply_deliverable_transaction([{
            "name": "save_deliverable",
            "description": "save",
            "input_schema": {},
            "function": save,
        }], config)[0]["function"]
        result = json.loads(wrapped(
            filename="02_recon.md",
            content=(
                "# Recon\n\n## 1. Summary\n\nDraft\n\n"
                "## 2. Discovered Services per Device\n\n"
                "No table yet.\n\n## 3. Key Findings\n\n"
                "- The model keeps this autonomous narrative."
            ),
        ))

        assert result["validated"] is True
        assert "| Total live hosts (ARP) | 2 |" in captured["content"]
        assert "| YAML devices confirmed | 2 |" in captured["content"]
        assert "| Undocumented devices | 1 |" in captured["content"]
        assert "| Unreachable YAML devices | 1 |" in captured["content"]
        assert "| router | 192.0.2.10 | 23,80 |" in captured["content"]
        assert "| offline | 192.0.2.12 | unreachable |" in captured["content"]
        assert (
            "| undocumented | 192.0.2.200 | not service-scanned |"
            in captured["content"]
        )
        assert "The model keeps this autonomous narrative." in captured["content"]

    def test_compact_recon_recovers_missing_deliverable_from_tool_evidence(
        self, output_dir, monkeypatch
    ):
        import src.agent.tools.graph_tools as graph_tools

        monkeypatch.setattr(graph_tools, "_scenario_topology", {
            "nodes": [
                {"id": "router", "ip": "192.0.2.10", "role": "router"},
                {"id": "mqtt", "ip": "192.0.2.11", "role": "mqtt_broker"},
            ]
        })
        provider = MagicMock()
        provider.provider = "local-moe"
        provider.model = "lance-moe"
        pipeline = Pipeline(provider=provider, execution_profile="compact")
        records = [
            {"tool": "arp_scan", "args": {}, "result": json.dumps({
                "hosts": [{"ip": "192.0.2.10"}, {"ip": "192.0.2.11"}],
            })},
            {"tool": "nmap_scan", "args": {"target": "192.0.2.10"},
             "result": json.dumps({"stdout": "22/tcp open ssh Dropbear"})},
            {"tool": "nmap_scan", "args": {"target": "192.0.2.11"},
             "result": json.dumps({"stdout": "1883/tcp open mqtt Mosquitto"})},
        ]
        (pipeline.run_dir / "tool_calls.jsonl").write_text(
            "\n".join(json.dumps(record) for record in records) + "\n"
        )

        def save(filename, content):
            (pipeline.run_dir / filename).write_text(content)
            return json.dumps({"status": "saved"})

        events = []
        recovered = pipeline._recover_compact_recon_deliverable(
            AGENTS["recon"],
            [{"name": "save_deliverable", "function": save}],
            events.append,
        )

        assert recovered is True
        content = (pipeline.run_dir / "02_recon.md").read_text()
        assert "| router | 192.0.2.10 | 22 |" in content
        assert "| mqtt | 192.0.2.11 | 1883 |" in content
        assert "compact model completed the required discovery" in content
        assert [event["type"] for event in events] == ["tool_call", "tool_result"]

    def test_compact_recon_run_recovers_after_model_omits_save(
        self, output_dir, monkeypatch
    ):
        import src.agent.tools.graph_tools as graph_tools

        monkeypatch.setattr(graph_tools, "_scenario_topology", {
            "nodes": [
                {"id": "router", "ip": "192.0.2.10", "role": "router", "services": [{"port": 22}]},
                {"id": "mqtt", "ip": "192.0.2.11", "role": "mqtt_broker", "services": [{"port": 1883}]},
            ]
        })
        provider = MagicMock()
        provider.provider = "local-moe"
        provider.model = "lance-moe"
        pipeline = Pipeline(provider=provider, execution_profile="compact")
        pipeline.context = {"target_subnet": "192.0.2.0/24"}
        projection = {
            "device_count": 2,
            "devices": [
                {"device": "router", "ip": "192.0.2.10", "sources": ["arp_scan", "nmap_scan"], "open_ports": [22]},
                {"device": "mqtt", "ip": "192.0.2.11", "sources": ["arp_scan", "nmap_scan"], "open_ports": [1883]},
            ],
            "markdown_service_rows": [
                "| router | 192.0.2.10 | 22 | ssh:22 Dropbear |",
                "| mqtt | 192.0.2.11 | 1883 | mqtt:1883 Mosquitto |",
            ],
        }

        def build_projection():
            (pipeline.run_dir / "02_recon_evidence.json").write_text(json.dumps(projection))
            return projection

        monkeypatch.setattr(pipeline, "_build_recon_evidence_projection", build_projection)

        def tool(name, function):
            return {"name": name, "description": name, "input_schema": {}, "function": function}

        def save(filename, content):
            (pipeline.run_dir / filename).write_text(content)
            return json.dumps({"status": "saved"})

        tools = [
            tool("arp_scan", lambda: json.dumps({"hosts": [{"ip": "192.0.2.10"}, {"ip": "192.0.2.11"}]})),
            tool("nmap_discovery", lambda target: json.dumps({"stdout": "Nmap scan report for 192.0.2.10\nNmap scan report for 192.0.2.11"})),
            tool("read_deliverable", lambda filename: json.dumps({"filename": filename, "content": "# Graph"})),
            tool("nmap_scan", lambda target, **_kwargs: json.dumps({"stdout": (
                "22/tcp open ssh Dropbear" if target == "192.0.2.10"
                else "1883/tcp open mqtt Mosquitto"
            )})),
            tool("save_deliverable", save),
        ]
        monkeypatch.setattr(pipeline, "_resolve_tools", lambda _config: tools)

        def model_without_save(**kwargs):
            exposed = {item["name"]: item["function"] for item in kwargs["tools"]}
            exposed["arp_scan"]()
            exposed["nmap_discovery"](target="192.0.2.0/24")
            exposed["read_deliverable"](filename="01_graph_analysis.md")
            for item in pipeline._recon_scan_plan(graph_tools._scenario_topology["nodes"]):
                exposed["nmap_scan"](
                    target=item["target"], ports=item["ports"], skip_discovery=True
                )
            return "Writing 02_recon.md."

        provider.chat_with_tools.side_effect = model_without_save
        events = []

        status = pipeline._run_agent(AGENTS["recon"], events.append)

        assert status == "completed:synthesized"
        assert (pipeline.run_dir / "02_recon.md").exists()
        phase_done = [event for event in events if event.get("type") == "phase_done"]
        assert len(phase_done) == 1
        assert phase_done[0]["status"] == "completed:synthesized"

    def test_full_recon_never_uses_compact_recovery(self, output_dir):
        provider = MagicMock()
        provider.provider = "local-moe"
        provider.model = "lance-moe"
        pipeline = Pipeline(provider=provider, execution_profile="full")

        assert pipeline._recover_compact_recon_deliverable(
            AGENTS["recon"], [], None
        ) is False

    def test_full_local_recon_does_not_rewrite_model_report(
        self, output_dir
    ):
        provider = MagicMock()
        provider.provider = "local-moe"
        provider.model = "lance-moe"
        pipeline = Pipeline(provider=provider, execution_profile="full")
        save = MagicMock(return_value='{"status":"saved"}')
        config = AgentConfig(
            name="recon", phase=2, prompt_template="recon",
            deliverable_file="02_recon.md", tools=[],
            validator="recon_markdown",
        )
        wrapped = pipeline._apply_deliverable_transaction([{
            "name": "save_deliverable",
            "description": "save",
            "input_schema": {},
            "function": save,
        }], config)[0]["function"]
        result = json.loads(wrapped(
            filename="02_recon.md",
            content=(
                "# Recon\n\n## 1. Summary\n\nDraft\n\n"
                "## 2. Discovered Services per Device\n\n"
                "No table yet.\n\n## 3. Key Findings\n\nAutonomous."
            ),
        ))

        assert result["error_kind"] == "deliverable_validation"
        assert "found 0" in result["error"]
        save.assert_not_called()

    def test_local_moe_phase3_cve_validation_logs_and_feeds_aggregation(
        self, mock_provider, output_dir, monkeypatch
    ):
        monkeypatch.setattr("src.agent.pipeline.get_attack_surface", lambda: "[]")
        monkeypatch.setattr(
            "src.agent.pipeline.cve_search",
            lambda query, top_k=5: json.dumps([{
                "id": "CVE-2023-48795",
                "severity": "HIGH",
                "description": "Terrapin affects this OpenSSH range",
                "compatibility": {
                    "status": "compatible",
                    "reason": "OpenSSH 9.2 is in the affected range",
                },
            }]),
        )
        pipeline = Pipeline(provider=mock_provider)
        device = {
            "id": "ssh-1",
            "ip": "192.0.2.10",
            "services": [{"name": "ssh", "port": 22, "protocol": "tcp"}],
        }
        scanner_results = {
            "ssh-1": {
                "scan_results": {
                    "ssh": [{
                        "tool": "nmap_scan",
                        "kwargs": {"target": "192.0.2.10", "ports": "22"},
                        "result": json.dumps({
                            "stdout": "22/tcp open ssh OpenSSH 9.2 Debian-2",
                            "stderr": "",
                            "return_code": 0,
                        }),
                    }],
                },
                "findings": [],
            },
        }

        pipeline._run_phase3_local_cve_validation(scanner_results, [device])

        validation = json.loads((pipeline.run_dir / "03_cve_validation.json").read_text())
        assert validation["queries"] == 1
        assert validation["compatible_cves"] == 1
        assert validation["records"][0]["query"] == "OpenSSH 9.2"
        tool_log = (pipeline.run_dir / "tool_calls.jsonl").read_text()
        assert '"tool": "cve_search"' in tool_log
        fallback = json.loads((pipeline.run_dir / "03_device_ssh-1.json").read_text())
        finding = fallback["vulnerabilities"][0]
        assert finding["type"] == "known_cve"
        assert finding["cve_ids"] == ["CVE-2023-48795"]
        assert finding["cve_validation"]["query"] == "OpenSSH 9.2"

        pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])
        canonical = json.loads((pipeline.run_dir / "03_vuln_analysis.json").read_text())
        assert len(canonical["vulnerabilities"]) == 1
        assert canonical["vulnerabilities"][0]["cve_claim_status"] == "validated"

    def test_local_moe_phase3_cve_validation_requires_explicit_version(
        self, mock_provider, output_dir, monkeypatch
    ):
        calls = []
        monkeypatch.setattr(
            "src.agent.pipeline.cve_search",
            lambda query, top_k=5: calls.append(query) or "[]",
        )
        pipeline = Pipeline(provider=mock_provider)
        device = {
            "id": "router-1",
            "ip": "192.0.2.1",
            "services": [
                {"name": "ssh", "port": 22, "protocol": "tcp"},
                {"name": "http", "port": 80, "protocol": "tcp"},
            ],
        }
        scanner_results = {
            "router-1": {
                "scan_results": {
                    "ssh": [{
                        "tool": "nmap_scan",
                        "kwargs": {"ports": "22"},
                        "result": json.dumps({"stdout": "22/tcp open ssh Dropbear sshd (protocol 2.0)"}),
                    }],
                    "http": [{
                        "tool": "curl_headers",
                        "kwargs": {"url": "http://192.0.2.1/"},
                        "result": json.dumps({"stdout": "HTTP/1.1 200 OK\nServer: nginx"}),
                    }],
                },
                "findings": [],
            },
        }

        pipeline._run_phase3_local_cve_validation(scanner_results, [device])

        validation = json.loads((pipeline.run_dir / "03_cve_validation.json").read_text())
        assert validation["queries"] == 0
        assert calls == []
        fallback = json.loads((pipeline.run_dir / "03_device_router-1.json").read_text())
        assert fallback["vulnerabilities"] == []

    def test_aggregation_preserves_raw_candidates_and_uses_evidence_quality(
        self, mock_provider, output_dir, monkeypatch
    ):
        monkeypatch.setattr("src.agent.pipeline.get_attack_surface", lambda: "[]")
        pipeline = Pipeline(provider=mock_provider)

        common = {
            "device_id": "device-a",
            "device_ip": "192.0.2.20",
            "type": "known_cve",
            "service": "ssh",
            "port": 22,
            "protocol": "tcp",
            "endpoint": "",
            "product": "OpenSSH",
            "version": "9.2",
            "cve_ids": ["CVE-2023-48795"],
            "exploitation_status": "suspected",
            "cve_validation": {"query": "OpenSSH 9.2"},
        }
        low = {**common, "id": "A", "severity": "LOW", "details": "short", "evidence": ""}
        high = {
            **common,
            "id": "B",
            "severity": "HIGH",
            "details": "range checked",
            "evidence": "ssh-audit observed the affected product and version",
            "cve_validation": {
                "compatibility_status": "compatible",
                "query": "OpenSSH 9.2",
                "compatibility_reason": "affected range",
                "observed_product": "OpenSSH",
                "observed_version": "9.2",
            },
        }
        noise = {
            **common,
            "id": "C",
            "type": "entry_point",
            "severity": "INFO",
            "details": "topology metadata",
        }
        (pipeline.run_dir / "03_device_a.json").write_text(json.dumps({
            "vulnerabilities": [low, noise],
        }))
        (pipeline.run_dir / "03_device_b.json").write_text(json.dumps({
            "vulnerabilities": [high],
        }))
        (pipeline.run_dir / "tool_calls.jsonl").write_text(
            json.dumps({
                "tool": "cve_search",
                "args": {"query": "OpenSSH 9.2"},
                "result": json.dumps([{
                    "id": "CVE-2023-48795",
                    "compatibility": {
                        "status": "compatible",
                        "reason": "affected range",
                    },
                }]),
                "evidence_ref": "tc-compatible",
            }) + "\n"
        )

        pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])

        raw = json.loads(
            (pipeline.run_dir / "03_vuln_analysis_raw.json").read_text()
        )
        canonical = json.loads(
            (pipeline.run_dir / "03_vuln_analysis.json").read_text()
        )
        assert raw["candidate_count"] == 3
        assert len(raw["candidates"]) == 3
        assert canonical["summary"]["raw_candidates"] == 3
        assert len(canonical["vulnerabilities"]) == 1
        selected = canonical["vulnerabilities"][0]
        assert selected["severity"] == "HIGH"
        assert selected["cve_claim_status"] == "validated"
        assert len(selected["_provenance"]["candidate_ids"]) == 2
        assert any(
            candidate["decision"] == "excluded_from_canonical"
            for candidate in raw["candidates"]
        )

    def test_compact_observations_require_phase2_support_and_defer_exploitation(
        self, mock_provider, output_dir, monkeypatch
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        monkeypatch.setattr("src.agent.pipeline.get_attack_surface", lambda: "[]")
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")

        ssh_finding = {
            "id": "ssh-observation",
            "device_id": "device-a",
            "device_ip": "192.0.2.20",
            "type": "info_disclosure",
            "severity": "LOW",
            "service": "ssh",
            "port": 22,
            "protocol": "tcp",
            "details": "SSH banner discloses a custom service message",
            "evidence": "SSH service returns: 'Not allowed at this time'",
            "exploitation_status": "confirmed",
        }
        generic_ssh_finding = {
            **ssh_finding,
            "id": "generic-ssh-observation",
            "device_id": "device-b",
            "device_ip": "192.0.2.21",
            "details": "SSH banner discloses software version",
            "evidence": "22/tcp open ssh OpenSSH 9.2",
        }
        generic_http_finding = {
            **ssh_finding,
            "id": "generic-http-observation",
            "device_id": "device-c",
            "device_ip": "192.0.2.22",
            "service": "http",
            "port": 80,
            "details": "Server version disclosure (nginx)",
            "evidence": "Server: nginx",
        }
        header_finding = {
            "id": "header-observation",
            "device_id": "device-a",
            "device_ip": "192.0.2.20",
            "type": "missing_header",
            "severity": "LOW",
            "service": "http",
            "port": 80,
            "protocol": "tcp",
            "details": "Security headers are missing",
            "evidence": "X-Frame-Options is absent",
            "exploitation_status": "confirmed",
        }
        directory_finding = {
            **header_finding,
            "id": "directory-observation",
            "type": "directory_listing",
            "details": "Directory listing enabled on /backup/",
            "evidence": "'Index of' found at /backup/",
        }
        (pipeline.run_dir / "03_device_device-a.json").write_text(json.dumps({
            "vulnerabilities": [ssh_finding, header_finding, directory_finding],
        }))
        (pipeline.run_dir / "03_device_device-b.json").write_text(json.dumps({
            "vulnerabilities": [generic_ssh_finding],
        }))
        (pipeline.run_dir / "03_device_device-c.json").write_text(json.dumps({
            "vulnerabilities": [generic_http_finding],
        }))
        (pipeline.run_dir / "tool_calls.jsonl").write_text(json.dumps({
            "tool": "nmap_scan",
            "phase": 2,
            "args": {"target": "192.0.2.20", "ports": "22"},
            "result": json.dumps({
                "stdout": "22/tcp open ssh OpenSSH 9.2",
                "return_code": 0,
            }),
        }) + "\n" + json.dumps({
            "tool": "nmap_scan",
            "phase": 2,
            "args": {"target": "192.0.2.21", "ports": "22"},
            "result": json.dumps({
                "stdout": "22/tcp open ssh OpenSSH 9.2",
                "return_code": 0,
            }),
        }) + "\n" + json.dumps({
            "tool": "nmap_scan",
            "phase": 2,
            "args": {"target": "192.0.2.22", "ports": "80"},
            "result": json.dumps({
                "stdout": "80/tcp open http nginx",
                "return_code": 0,
            }),
        }) + "\n")

        pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])

        canonical = json.loads(
            (pipeline.run_dir / "03_vuln_analysis.json").read_text()
        )
        observations = json.loads(
            (pipeline.run_dir / "03_config_observations.json").read_text()
        )
        assert len(canonical["vulnerabilities"]) == 1
        assert canonical["vulnerabilities"][0]["type"] == "info_disclosure"
        assert canonical["vulnerabilities"][0]["compact_detection_only"] is True
        assert {
            (item["device_ip"], item["type"])
            for item in observations["observations"]
        } == {
            ("192.0.2.20", "missing_header"),
            ("192.0.2.20", "directory_listing"),
            ("192.0.2.21", "info_disclosure"),
            ("192.0.2.22", "info_disclosure"),
        }

        pipeline._run_exploit_agents(AGENTS["exploitation"])
        aggregate = json.loads(
            (pipeline.run_dir / "04_exploitation.json").read_text()
        )
        assert pipeline._phase4_schedule["scheduled_count"] == 0
        assert pipeline._phase4_schedule["skipped_count"] == 1
        assert aggregate["summary"]["skipped_count"] == 1
        assert aggregate["tests"][0]["status"] == "SKIPPED"

    def test_log_regression_unverified_cves_stay_raw_not_canonical(
        self, mock_provider, output_dir, monkeypatch
    ):
        monkeypatch.setattr("src.agent.pipeline.get_attack_surface", lambda: "[]")
        pipeline = Pipeline(provider=mock_provider)
        claims = [
            ("router", "Dropbear sshd (protocol 2.0)", "CVE-2023-48795"),
            ("mqtt", "Mosquitto 2.0.21", "CVE-2024-99999"),
            ("web", "nginx 1.22", "CVE-2023-48795"),
            ("ssh", "ssh version 22", "CVE-2001-0572"),
        ]
        for index, (device_id, query, cve_id) in enumerate(claims, 1):
            finding = {
                "id": f"claim-{index}",
                "device_id": device_id,
                "device_ip": f"192.168.100.{index + 9}",
                "type": "known_cve",
                "severity": "HIGH",
                "service": "ssh",
                "port": 22,
                "protocol": "tcp",
                "endpoint": "",
                "product": query.split()[0],
                "version": query.split()[-1],
                "details": "model claim",
                "evidence": "banner only",
                "cve_ids": [cve_id],
                "exploitation_status": "suspected",
                "cve_validation": {"query": query},
            }
            (pipeline.run_dir / f"03_device_{device_id}.json").write_text(
                json.dumps({"vulnerabilities": [finding]})
            )

        searches = [
            {
                "tool": "cve_search",
                "args": {"query": "Dropbear sshd (protocol 2.0)"},
                "result": json.dumps([{
                    "id": "CVE-2025-14282",
                    "compatibility": {"status": "compatible", "reason": "different CVE"},
                }]),
                "evidence_ref": "tc-dropbear",
            },
            {
                "tool": "cve_search",
                "args": {"query": "Mosquitto 2.0.21"},
                "result": "[]",
                "evidence_ref": "tc-mqtt",
            },
            {
                "tool": "cve_search",
                "args": {"query": "nginx 1.22"},
                "result": json.dumps([{
                    "id": "CVE-2018-16843",
                    "compatibility": {"status": "incompatible", "reason": "fixed before 1.22"},
                }]),
                "evidence_ref": "tc-nginx",
            },
            {
                "tool": "cve_search",
                "args": {"query": "ssh version 22"},
                "result": json.dumps([{
                    "id": "CVE-2001-0572",
                    "compatibility": {"status": "incompatible", "reason": "version mismatch"},
                }]),
                "evidence_ref": "tc-ssh",
            },
        ]
        (pipeline.run_dir / "tool_calls.jsonl").write_text(
            "\n".join(json.dumps(record) for record in searches) + "\n"
        )

        pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])

        canonical = json.loads(
            (pipeline.run_dir / "03_vuln_analysis.json").read_text()
        )
        raw = json.loads(
            (pipeline.run_dir / "03_vuln_analysis_raw.json").read_text()
        )
        assert canonical["vulnerabilities"] == []
        assert canonical["summary"]["raw_candidates"] == 4
        assert len(raw["candidates"]) == 4
        assert all(
            candidate["decision"] == "excluded_from_canonical"
            for candidate in raw["candidates"]
        )
        reasons = " ".join(
            candidate["decision_reason"] for candidate in raw["candidates"]
        )
        assert "not corroborated" in reasons

    def test_phase4_empty_schedule_is_explicit_skip(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        finding = {
            "id": "VULN-001",
            "device_id": "device-a",
            "device_ip": "192.0.2.20",
            "type": "known_cve",
            "severity": "HIGH",
            "service": "ssh",
            "port": 22,
            "protocol": "tcp",
            "endpoint": "",
            "product": "OpenSSH",
            "version": "9.2",
            "evidence": "version evidence",
            "exploitation_status": "suspected",
            "cve_ids": ["CVE-2023-48795"],
        }
        (pipeline.run_dir / "03_vuln_analysis.json").write_text(json.dumps({
            "vulnerabilities": [finding],
        }))

        pipeline._run_exploit_agents(AGENTS["exploitation"])

        aggregate = json.loads(
            (pipeline.run_dir / "04_exploitation.json").read_text()
        )
        assert pipeline._phase4_execution_status is None
        assert aggregate["summary"]["total_tested"] == 1
        assert aggregate["summary"]["candidate_count"] == 1
        assert aggregate["summary"]["skipped_count"] == 0
        assert aggregate["summary"]["errors"] == 1
        assert aggregate["tests"][0]["status"] == "ERROR"

    def test_phase4_compact_worker_receives_local_exploit_instructions(
        self, output_dir, monkeypatch
    ):
        provider = MagicMock()
        provider.provider = "local-moe"
        provider.model = "lance-moe"
        pipeline = Pipeline(provider=provider, execution_profile="compact")
        finding = {
            "id": "VULN-001",
            "device_id": "router",
            "device_ip": "192.0.2.1",
            "type": "insecure_protocol",
            "severity": "MEDIUM",
            "service": "telnet",
            "port": 23,
            "protocol": "tcp",
            "endpoint": "",
            "details": "Telnet is exposed",
            "evidence": "23/tcp open",
            "exploitation_status": "confirmed",
            "cve_ids": [],
        }
        (pipeline.run_dir / "03_vuln_analysis.json").write_text(json.dumps({
            "vulnerabilities": [finding],
        }))

        def telnet_connect(**kwargs):
            return json.dumps({
                "stdout": "OpenWrt telnet banner",
                "stderr": "",
                "return_code": 0,
            })

        monkeypatch.setattr(pipeline, "_resolve_tools", lambda config: [{
            "name": "telnet_connect",
            "description": "telnet",
            "input_schema": {},
            "function": telnet_connect,
        }, {
            "name": "http_get",
            "description": "http",
            "input_schema": {},
            "function": telnet_connect,
        }, {
            "name": "try_credential",
            "description": "credentials",
            "input_schema": {},
            "function": telnet_connect,
        }, {
            "name": "search_knowledge",
            "description": "search",
            "input_schema": {},
            "function": telnet_connect,
        }])

        def chat_with_tools(*, system_prompt, tools, **kwargs):
            assert "telnet" in system_prompt.lower()
            assert [tool["name"] for tool in tools] == ["telnet_connect"]
            assert kwargs["force_tool_on_stall"] is True
            assert kwargs["recover_required_tool_on_stall"] is True
            result = tools[0]["function"](
                command_string="echo quit | timeout 3 nc 192.0.2.1 23"
            )
            with (pipeline.run_dir / "tool_calls.jsonl").open(
                "a", encoding="utf-8"
            ) as handle:
                handle.write(json.dumps({
                    "tool": "telnet_connect",
                    "args": {
                        "command_string": "echo quit | timeout 3 nc 192.0.2.1 23",
                    },
                    "result": result,
                    "vuln_id": "VULN-001",
                    "evidence_ref": "tc-phase4-telnet",
                }) + "\n")
            return "Telnet exposure verified."

        provider.chat_with_tools.side_effect = chat_with_tools

        pipeline._run_exploit_agents(AGENTS["exploitation"])

        aggregate = json.loads(
            (pipeline.run_dir / "04_exploitation.json").read_text()
        )
        assert provider.chat_with_tools.call_count == 1
        assert aggregate["summary"]["confirmed"] == 1
        assert aggregate["summary"]["errors"] == 0
        assert aggregate["tests"][0]["evidence_refs"] == ["tc-phase4-telnet"]

    def test_phase4_compact_fallback_runs_after_provider_timeout(
        self, output_dir
    ):
        provider = MagicMock()
        provider.provider = "local-moe"
        provider.model = "lance-moe"
        pipeline = Pipeline(provider=provider, execution_profile="compact")
        finding = {
            "id": "VULN-TIMEOUT",
            "device_id": "router",
            "device_ip": "192.0.2.1",
            "type": "insecure_protocol",
            "severity": "MEDIUM",
            "service": "telnet",
            "port": 23,
            "protocol": "tcp",
            "endpoint": "",
            "details": "Telnet is exposed",
            "evidence": "23/tcp open",
            "exploitation_status": "confirmed",
            "cve_ids": [],
        }
        (pipeline.run_dir / "03_vuln_analysis.json").write_text(json.dumps({
            "vulnerabilities": [finding],
        }))

        def telnet_connect(**kwargs):
            return json.dumps({
                "stdout": "OpenWrt telnet banner",
                "stderr": "",
                "return_code": 0,
            })

        tool = pipeline._wrap_tool({
            "name": "telnet_connect",
            "description": "telnet",
            "input_schema": {},
            "function": telnet_connect,
        }, phase=4, agent="exploitation")
        pipeline._resolve_tools = lambda config: [tool]
        provider.chat_with_tools.side_effect = TimeoutError("local provider timeout")

        pipeline._run_exploit_agents(AGENTS["exploitation"])

        aggregate = json.loads(
            (pipeline.run_dir / "04_exploitation.json").read_text()
        )
        assert provider.chat_with_tools.call_count == 1
        assert aggregate["summary"]["confirmed"] == 1
        assert aggregate["summary"]["errors"] == 0
        assert aggregate["tests"][0]["evidence_refs"]


def test_full_semantic_filters_run_artifact_noise_without_losing_contracts():
    http_default = {
        "type": "default_credentials",
        "service": "http",
        "port": 80,
        "details": "Admin panel displays default creds admin:admin",
        "evidence": "GET /admin returned the text 'default creds admin:admin'",
    }
    assert "successful credential" in _finding_semantic_issue(http_default)

    http_success = {
        **http_default,
        "details": "Login with admin:admin succeeded",
        "evidence": "credential accepted and authenticated session returned",
    }
    assert _finding_semantic_issue(http_success) == ""

    ftp_default = {
        "type": "default_credentials",
        "service": "ftp",
        "port": 21,
        "details": "Anonymous FTP login allows access without authentication",
        "evidence": "FTP code 230",
    }
    assert "anonymous FTP" in _finding_semantic_issue(ftp_default)

    ftp_firmware = {
        "type": "insecure_update",
        "service": "ftp",
        "port": 21,
        "details": "Firmware directory is downloadable through anonymous FTP",
        "evidence": "firmware.bin listed in the directory",
    }
    assert "not an update mechanism" in _finding_semantic_issue(ftp_firmware)

    speculative_redis = {
        "type": "data_exposure",
        "service": "redis",
        "port": 6379,
        "details": "Stored keys may contain sensitive credentials and tokens",
        "evidence": "Redis is accessible without authentication",
    }
    assert "speculative data exposure" in _finding_semantic_issue(speculative_redis)

    modbus_noise = {
        "type": "insecure_protocol",
        "service": "modbus",
        "port": 502,
        "device_ip": "192.0.2.10",
        "details": "Modbus has no built-in encryption or authentication",
        "evidence": "502/tcp open",
    }
    modbus_auth = {
        "type": "no_auth",
        "service": "modbus",
        "port": 502,
        "device_ip": "192.0.2.10",
    }
    assert "proven no_auth" in _finding_semantic_issue(
        modbus_noise, context_findings=[modbus_noise, modbus_auth]
    )

    redis_bind = {
        "type": "misconfiguration",
        "service": "redis",
        "port": 6379,
        "device_ip": "192.0.2.11",
        "details": "Redis bind address: 0.0.0.0",
    }
    redis_auth = {
        "type": "no_auth",
        "service": "redis",
        "port": 6379,
        "device_ip": "192.0.2.11",
    }
    assert "proven no_auth" in _finding_semantic_issue(
        redis_bind, context_findings=[redis_bind, redis_auth]
    )

    assert "platform fingerprint" in _finding_semantic_issue({
        "type": "info_disclosure",
        "service": "modbus",
        "port": 502,
        "details": "Slave ID Pymodbus reveals implementation details",
    })

    listing = {
        "type": "directory_listing",
        "service": "http",
        "port": 80,
        "device_ip": "192.0.2.12",
        "endpoint": "/firmware/",
        "details": "Directory listing enabled on /firmware/; firmware files have no .sig or .sha256 sidecar",
        "evidence": "Index of found at /firmware/ and no signature files were listed",
    }
    _normalise_full_finding_semantics(
        listing, [listing], device_role="iot_gateway"
    )
    assert listing["type"] == "insecure_update"
    assert listing["severity"] == "HIGH"

    unproven_listing = {
        "type": "directory_listing",
        "service": "http",
        "port": 80,
        "device_ip": "192.0.2.13",
        "endpoint": "/firmware/",
        "details": "Directory listing enabled on /firmware/",
        "evidence": "Index of found at /firmware/",
    }
    _normalise_full_finding_semantics(
        unproven_listing, [unproven_listing], device_role="iot_gateway"
    )
    assert unproven_listing["type"] == "directory_listing"
    assert "lacks proof" in _finding_semantic_issue(
        unproven_listing, device_role="iot_gateway"
    )

    ssh_crypto = {
        "type": "misconfiguration",
        "service": "ssh",
        "port": 22,
        "details": "Terrapin mitigation still permits CBC ciphers and hmac-sha1",
    }
    _normalise_full_finding_semantics(ssh_crypto, [ssh_crypto])
    assert ssh_crypto["type"] == "weak_cipher"


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
