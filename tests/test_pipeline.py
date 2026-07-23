"""Tests for pipeline module."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.agent.pipeline import (
    Pipeline,
    TOOL_GROUPS,
    _has_positive_exploit_evidence,
    _local_report_memo_contradicts_context,
    _looks_unusable_model_memo,
    _resolve_model_provider,
    _synthesize_exploit_result,
)
from src.agent.registry import AgentConfig, AGENTS


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

    def test_generates_intrusion_context(self, mock_provider, output_dir):
        """Phase 5 context should extract confirmed exploits and entry points."""
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

    def test_handles_missing_phase4(self, mock_provider, output_dir):
        """Context should still generate if Phase 4 was skipped."""
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir

        pipeline._generate_intrusion_context()

        ctx_path = run_dir / "05_intrusion_context.json"
        assert ctx_path.exists()
        ctx = json.loads(ctx_path.read_text())
        assert ctx["confirmed_exploits"] == 0
        assert ctx["entry_points"] == []
        assert ctx["recovered_credentials"] == []

    def test_handles_list_format_phase4(self, mock_provider, output_dir):
        """Context should handle Phase 4 output as a plain list."""
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


class TestPipelineRun:
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
        pipeline = Pipeline(provider=mock_provider)
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

        projection = pipeline._compact_phase3_scan_results(scan_data)

        rendered = json.dumps(projection)
        assert len(rendered) < 8000
        assert projection["_evidence_projection"]["omitted_entries"] > 0
        assert projection["_evidence_projection"]["full_scan_artifact"].startswith(
            "03_scans/"
        )

    def test_local_moe_phase3_uses_one_worker(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider)

        assert pipeline._phase3_worker_count(4) == 1

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
        pipeline = Pipeline(provider=mock_provider)
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

        def scanner_side_effect(run_dir_arg, devices, stream_callback=None):
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
        pipeline = Pipeline(provider=mock_provider)
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
        })

        assert wrapped["function"]() == payload
        record = json.loads(
            (pipeline.run_dir / "tool_calls.jsonl").read_text().strip()
        )
        assert record["result"] == payload

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
                    "stdout": "22/tcp open ssh OpenSSH 9.2",
                    "return_code": 0,
                }),
            },
        ]
        (pipeline.run_dir / "tool_calls.jsonl").write_text(
            "\n".join(json.dumps(record) for record in records) + "\n"
        )

        projection = pipeline._build_recon_evidence_projection()

        assert projection["device_count"] == 1
        assert projection["devices"][0]["open_ports"] == [22]
        assert "OpenSSH 9.2" in projection["markdown_service_rows"][0]
        assert (pipeline.run_dir / "02_recon_evidence.json").exists()

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
        assert pipeline._phase4_execution_status == (
            "skipped:no_safely_exploitable_candidates"
        )
        assert aggregate["summary"]["total_tested"] == 0
        assert aggregate["summary"]["skipped_count"] == 1
        assert aggregate["summary"]["errors"] == 0
