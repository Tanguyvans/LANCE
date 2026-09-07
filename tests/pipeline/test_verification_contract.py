"""Phase 4: verification plans, scope, and protocol requirements."""
import json
from src.agent.pipeline import Pipeline
from src.agent.exploit_evidence import (
    synthesize_exploit_result as _synthesize_exploit_result,
)
from src.agent.phases.verification.contract import (
    _phase4_local_verification_tools,
    _phase4_verification_plan,
    _phase4_requirement_matches,
)
from src.agent.registry import AGENTS


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


class TestPhase4LocalToolScope:
    def test_telnet_scope_excludes_unrelated_exploit_tools(self):
        tools = [
            {"name": name, "function": lambda: "{}"}
            for name in (
                "telnet_connect", "try_credential", "mqtt_listen",
                "http_get", "exploit_iot_kit", "save_deliverable",
                "search_knowledge",
            )
        ]

        scoped = _phase4_local_verification_tools(
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
