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
            pipeline = Pipeline(provider=mock_provider)
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

        # Side effect: write a valid JSON file so reflector is NOT triggered
        def write_device_file(**kwargs):
            user_msg = kwargs.get("user_message", "")
            for dev_id in ("mikrotik", "rpi5"):
                if dev_id in user_msg:
                    path = pipeline.run_dir / f"03_device_{dev_id}.json"
                    path.write_text(json.dumps({"device_id": dev_id, "vulnerabilities": []}))
            return "Done."
        mock_provider.chat_with_tools.side_effect = write_device_file

        config = AgentConfig(
            name="vuln_analysis", phase=3, prompt_template="vuln_analysis",
            deliverable_file="03_vuln_analysis.json",
            tools=["graph", "recon", "deliverable"],
            has_device_agents=True, max_turns=10,
        )

        pipeline._run_device_agents(config)

        # Provider should be called once per device (2 devices), reflector not triggered
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

        # 2 device agents (no reflector) + 1 aggregator = 3 total calls
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


class TestReflectorRetry:
    """Tests for the reflector retry mechanic in _run_single_device."""

    FAKE_SURFACE = json.dumps([{
        "id": "s2-jump", "type": "ssh_server", "ip": "192.168.100.15",
        "services": [{"name": "ssh", "port": 22}],
    }])
    FAKE_SCORES = json.dumps([{"device_id": "s2-jump", "risk_score": 2.0, "cve_count": 0}])
    FAKE_DEVICE_INFO = json.dumps({"id": "s2-jump", "os_version": "Debian 12"})

    @patch("src.agent.pipeline.get_device_info")
    @patch("src.agent.pipeline.get_risk_scores")
    @patch("src.agent.pipeline.get_attack_surface")
    @patch("src.agent.pipeline.load_prompt")
    def test_reflector_triggered_when_file_missing(
        self, mock_prompt, mock_surface, mock_scores, mock_device_info,
        mock_provider, output_dir
    ):
        """If device agent never saves a file, reflector must be called."""
        mock_surface.return_value = self.FAKE_SURFACE
        mock_scores.return_value = self.FAKE_SCORES
        mock_device_info.return_value = self.FAKE_DEVICE_INFO
        mock_prompt.return_value = "Device prompt"
        # Provider never writes a file
        mock_provider.chat_with_tools.return_value = ""

        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="vuln_analysis", phase=3, prompt_template="vuln_analysis",
            deliverable_file="03_vuln_analysis.json",
            tools=["graph", "deliverable"],
            has_device_agents=True, max_turns=10,
        )
        pipeline._run_device_agents(config)

        # First call = device agent, second call = reflector retry
        assert mock_provider.chat_with_tools.call_count == 2
        reflector_call = mock_provider.chat_with_tools.call_args_list[1]
        assert reflector_call.kwargs.get("required_tool") == "save_deliverable"
        assert reflector_call.kwargs.get("max_turns") == 5

    @patch("src.agent.pipeline.get_device_info")
    @patch("src.agent.pipeline.get_risk_scores")
    @patch("src.agent.pipeline.get_attack_surface")
    @patch("src.agent.pipeline.load_prompt")
    def test_reflector_not_triggered_when_file_valid(
        self, mock_prompt, mock_surface, mock_scores, mock_device_info,
        mock_provider, output_dir
    ):
        """If device agent saves a valid JSON file, reflector must NOT be called."""
        mock_surface.return_value = self.FAKE_SURFACE
        mock_scores.return_value = self.FAKE_SCORES
        mock_device_info.return_value = self.FAKE_DEVICE_INFO
        mock_prompt.return_value = "Device prompt"

        pipeline = Pipeline(provider=mock_provider)

        def write_valid_file(**kwargs):
            path = pipeline.run_dir / "03_device_s2-jump.json"
            path.write_text(json.dumps({
                "device_id": "s2-jump", "device_ip": "192.168.100.15",
                "vulnerabilities": [], "summary": {"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            }))
            return "Done."
        mock_provider.chat_with_tools.side_effect = write_valid_file

        config = AgentConfig(
            name="vuln_analysis", phase=3, prompt_template="vuln_analysis",
            deliverable_file="03_vuln_analysis.json",
            tools=["graph", "deliverable"],
            has_device_agents=True, max_turns=10,
        )
        pipeline._run_device_agents(config)

        # Only 1 call — no reflector
        assert mock_provider.chat_with_tools.call_count == 1

    @patch("src.agent.pipeline.get_device_info")
    @patch("src.agent.pipeline.get_risk_scores")
    @patch("src.agent.pipeline.get_attack_surface")
    @patch("src.agent.pipeline.load_prompt")
    def test_reflector_triggered_when_file_invalid_json(
        self, mock_prompt, mock_surface, mock_scores, mock_device_info,
        mock_provider, output_dir
    ):
        """If device agent saves invalid JSON, reflector must be called."""
        mock_surface.return_value = self.FAKE_SURFACE
        mock_scores.return_value = self.FAKE_SCORES
        mock_device_info.return_value = self.FAKE_DEVICE_INFO
        mock_prompt.return_value = "Device prompt"

        pipeline = Pipeline(provider=mock_provider)

        def write_invalid_file(**kwargs):
            path = pipeline.run_dir / "03_device_s2-jump.json"
            path.write_text("Based on my analysis the device has weak ciphers.")
            return "Based on my analysis the device has weak ciphers."
        mock_provider.chat_with_tools.side_effect = write_invalid_file

        config = AgentConfig(
            name="vuln_analysis", phase=3, prompt_template="vuln_analysis",
            deliverable_file="03_vuln_analysis.json",
            tools=["graph", "deliverable"],
            has_device_agents=True, max_turns=10,
        )
        pipeline._run_device_agents(config)

        assert mock_provider.chat_with_tools.call_count == 2
        reflector_call = mock_provider.chat_with_tools.call_args_list[1]
        assert reflector_call.kwargs.get("required_tool") == "save_deliverable"


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


class TestFallbackSave:
    """Tests that fallback saves stripped content when save_deliverable is never called."""

    DEVICE_JSON = json.dumps({
        "device_id": "s2-mqtt",
        "device_ip": "192.168.100.12",
        "vulnerabilities": [{"id": "VULN-001", "type": "no_auth", "severity": "HIGH"}],
        "summary": {"total": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
    })

    FAKE_SURFACE = json.dumps([{
        "id": "s2-mqtt", "type": "server", "ip": "192.168.100.12",
        "services": [{"name": "mqtt", "port": 1883}],
    }])
    FAKE_SCORES = json.dumps([{"device_id": "s2-mqtt", "risk_score": 3.0, "cve_count": 0}])
    FAKE_DEVICE_INFO = json.dumps({"id": "s2-mqtt", "os_version": "Debian"})

    @patch("src.agent.pipeline.get_device_info")
    @patch("src.agent.pipeline.get_risk_scores")
    @patch("src.agent.pipeline.get_attack_surface")
    @patch("src.agent.pipeline.load_prompt")
    def test_fallback_saves_valid_json_from_code_fence(
        self, mock_prompt, mock_surface, mock_scores, mock_device_info,
        mock_provider, output_dir
    ):
        """When LLM returns ```json {...}``` instead of calling save_deliverable, fallback strips fences."""
        mock_surface.return_value = self.FAKE_SURFACE
        mock_scores.return_value = self.FAKE_SCORES
        mock_device_info.return_value = self.FAKE_DEVICE_INFO
        mock_prompt.return_value = "Device prompt"
        mock_provider.chat_with_tools.return_value = f"```json\n{self.DEVICE_JSON}\n```"

        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="vuln_analysis", phase=3, prompt_template="vuln_device",
            deliverable_file="03_vuln_analysis.json",
            tools=["graph", "deliverable"],
            has_device_agents=True, max_turns=10,
        )
        pipeline._run_device_agents(config)

        saved = pipeline.run_dir / "03_device_s2-mqtt.json"
        assert saved.exists(), "Fallback file should have been created"
        parsed = json.loads(saved.read_text())
        assert parsed["device_id"] == "s2-mqtt"
        assert len(parsed["vulnerabilities"]) == 1

    @patch("src.agent.pipeline.get_device_info")
    @patch("src.agent.pipeline.get_risk_scores")
    @patch("src.agent.pipeline.get_attack_surface")
    @patch("src.agent.pipeline.load_prompt")
    def test_fallback_not_triggered_when_file_exists(
        self, mock_prompt, mock_surface, mock_scores, mock_device_info,
        mock_provider, output_dir
    ):
        """If save_deliverable was called, fallback must NOT overwrite the file."""
        mock_surface.return_value = self.FAKE_SURFACE
        mock_scores.return_value = self.FAKE_SCORES
        mock_device_info.return_value = self.FAKE_DEVICE_INFO
        mock_prompt.return_value = "Device prompt"

        pipeline = Pipeline(provider=mock_provider)
        expected_file = pipeline.run_dir / "03_device_s2-mqtt.json"
        original_content = json.dumps({"device_id": "s2-mqtt", "vulnerabilities": [], "summary": {}})

        def side_effect(**kwargs):
            expected_file.write_text(original_content)
            return "Done."
        mock_provider.chat_with_tools.side_effect = side_effect

        config = AgentConfig(
            name="vuln_analysis", phase=3, prompt_template="vuln_device",
            deliverable_file="03_vuln_analysis.json",
            tools=["graph", "deliverable"],
            has_device_agents=True, max_turns=10,
        )
        pipeline._run_device_agents(config)

        assert expected_file.read_text() == original_content


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
