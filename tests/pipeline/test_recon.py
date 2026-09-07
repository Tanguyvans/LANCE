"""Phase 2: reconnaissance contracts, projections, and recovery."""
import json
from unittest.mock import MagicMock
import pytest
from src.agent.pipeline import Pipeline
from src.agent.registry import AgentConfig, AGENTS


def test_discovery_followup_maps_declared_ports_to_scanner_services():
    assert Pipeline._service_for_discovered_port(3306) == ("mysql", "tcp")
    assert Pipeline._service_for_discovered_port(161) == ("snmp", "udp")
    assert Pipeline._service_for_discovered_port(5683) == ("coap", "udp")
    assert Pipeline._service_for_discovered_port(9999) == ("unknown", "tcp")


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


class TestPhase5Context:
    """Tests for _generate_intrusion_context."""

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


class TestInformationPreservingArchitecture:
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
