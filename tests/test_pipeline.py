"""Tests for pipeline module."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.agent.pipeline import Pipeline, TOOL_GROUPS
from src.agent.registry import AgentConfig, AGENTS


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
        assert "Aucun" in result or result == ""

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
    def test_device_agents_called_for_each_device(
        self, mock_prompt, mock_surface, mock_scores, mock_device_info,
        mock_provider, output_dir
    ):
        mock_surface.return_value = self.FAKE_SURFACE
        mock_scores.return_value = self.FAKE_SCORES
        mock_device_info.return_value = self.FAKE_DEVICE_INFO
        mock_prompt.return_value = "Device prompt"

        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="vuln_analysis", phase=3, prompt_template="vuln_analysis",
            deliverable_file="03_vuln_analysis.json",
            tools=["graph", "recon", "deliverable"],
            has_device_agents=True, max_turns=10,
        )

        pipeline._run_device_agents(config)

        # Provider should be called once per device (2 devices)
        assert mock_provider.chat_with_tools.call_count == 2

    @patch("src.agent.pipeline.get_device_info")
    @patch("src.agent.pipeline.get_risk_scores")
    @patch("src.agent.pipeline.get_attack_surface")
    @patch("src.agent.pipeline.load_prompt")
    def test_device_variables_injected_in_prompt(
        self, mock_prompt, mock_surface, mock_scores, mock_device_info,
        mock_provider, output_dir
    ):
        mock_surface.return_value = self.FAKE_SURFACE
        mock_scores.return_value = self.FAKE_SCORES
        mock_device_info.return_value = self.FAKE_DEVICE_INFO
        mock_prompt.return_value = "Device prompt"

        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="vuln_analysis", phase=3, prompt_template="vuln_analysis",
            deliverable_file="03_vuln_analysis.json",
            tools=["graph", "recon", "deliverable"],
            has_device_agents=True, max_turns=10,
        )

        pipeline._run_device_agents(config)

        # Check that load_prompt was called with device-specific variables
        calls = mock_prompt.call_args_list
        assert len(calls) == 2

        # First call should be for mikrotik
        _, kwargs_or_args = calls[0]
        variables = calls[0][0][1]  # second positional arg
        assert variables["device_id"] == "mikrotik"
        assert variables["device_ip"] == "192.168.88.1"
        assert variables["device_type"] == "router"
        assert "ssh:22" in variables["device_services"]
        assert variables["expected_deliverable"] == "03_device_mikrotik.json"

        # Second call should be for rpi5
        variables2 = calls[1][0][1]
        assert variables2["device_id"] == "rpi5"
        assert variables2["device_ip"] == "192.168.88.247"
        assert variables2["expected_deliverable"] == "03_device_rpi5.json"

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

        # Provider writes the aggregated deliverable on the 3rd call (after 2 device agents)
        call_count = {"n": 0}
        def side_effect(**kwargs):
            call_count["n"] += 1
            if call_count["n"] == 3:  # aggregator call
                (run_dir / "03_vuln_analysis.json").write_text(
                    json.dumps({"vulnerabilities": [{"id": "VULN-001"}], "summary": {"total": 1, "high": 1, "medium": 0, "low": 0, "info": 0}})
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

        status = pipeline._run_agent(config)

        # 2 device agents + 1 aggregator = 3 total calls
        assert mock_provider.chat_with_tools.call_count == 3
        assert status == "completed"

    def test_no_device_agents_when_flag_false(self, mock_provider, output_dir):
        """When has_device_agents=False, _run_device_agents should NOT be called."""
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
        pipeline = Pipeline(provider=mock_provider, phases=[5])
        run_dir = pipeline.run_dir

        # Phase 5 (report) has no prerequisites, so it should run
        with patch("src.agent.pipeline.load_prompt", return_value="prompt"):
            def write_deliverable(**kwargs):
                (run_dir / "05_report.md").write_text("## A\n## B\n")
                return "Done."
            mock_provider.chat_with_tools.side_effect = write_deliverable
            results = pipeline.run()

        assert len(results) == 1
        assert "report" in results
