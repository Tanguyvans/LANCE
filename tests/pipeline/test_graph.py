"""Phase 1: graph facts and model projections."""
import json
from unittest.mock import MagicMock
from src.agent.pipeline import Pipeline
from src.agent.registry import AgentConfig


class TestInformationPreservingArchitecture:
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
