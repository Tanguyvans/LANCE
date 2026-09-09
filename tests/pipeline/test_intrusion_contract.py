"""Phase 5: compact tool scope and completion requirements."""
import json
from unittest.mock import MagicMock
import pytest
from src.agent.pipeline import Pipeline
from src.agent.core.runtime import TOOL_GROUPS
from src.agent.registry import AGENTS


@pytest.mark.parametrize("profile", ["full", "compact"])
def test_phase5_scope_guard_is_common_to_full_and_compact(
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

    assert result["error_kind"] == "intrusion_command_hostname_unverifiable"
    assert calls == []

    positive = json.loads(guarded["function"](
        ip="192.168.100.1", user="root", password="root", command="id",
    ))
    assert positive["success"] is True
    assert len(calls) == 1


class TestPhase5Context:
    """Tests for _generate_intrusion_context."""

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
