"""Phase 4: observable proof and exploit verdicts."""
import json
from pathlib import Path
from src.agent.pipeline import Pipeline
from src.agent.exploit_evidence import (
    has_positive_exploit_evidence as _has_positive_exploit_evidence,
    synthesize_exploit_result as _synthesize_exploit_result,
    extract_endpoint_paths as _extract_endpoint_paths,
)
from src.agent.phases.analysis.evidence import _enrich_finding_structure
from src.agent.phases.verification.evidence import _make_test_entry


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


def test_endpoint_extraction_keeps_prose_paths_without_url_host_artifacts():
    assert _extract_endpoint_paths(
        "GET http://192.0.2.44/.env and POST /update; /firmware/"
    ) == ["/.env", "/update", "/firmware/"]


def test_synthesize_exploit_result_does_not_treat_ack_as_disclosure():
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
    assert tcp["status"] == "FAILED"


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
