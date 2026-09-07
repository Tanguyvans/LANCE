"""Pipeline orchestration, prerequisites, tools, and artifact lifecycle."""
import json
from unittest.mock import MagicMock, patch
import pytest
from src.agent.pipeline import Pipeline
from src.agent.core.runtime import (
    TOOL_GROUPS,
    _resolve_model_provider,
    _expand_phase_selection,
)
from src.agent.core.memo import _looks_unusable_model_memo
from src.agent.registry import AgentConfig


def test_resolve_model_provider_uses_registry(monkeypatch):
    monkeypatch.setattr(
        "src.db.database.get_model",
        lambda model: {"provider": "local-moe"} if model == "lance-moe" else None,
    )

    assert _resolve_model_provider("lance-moe") == "local-moe"
    assert _resolve_model_provider("MiniMax-M2.7") == "minimax"
    assert _resolve_model_provider("openai/gpt-4o") == "openrouter"
    assert _resolve_model_provider("gpt-5.6-sol") == "codex"


def test_local_memo_guard_rejects_placeholders_and_empty_evidence_blocks():
    assert _looks_unusable_model_memo("Evidence:\n```json\n\n```\n")
    assert _looks_unusable_model_memo("Prepared by: [Your Name]")


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
        (pipeline.run_dir / "01_graph_analysis.md").write_text("## S1\n## S2\n")
        assert pipeline._check_prerequisites(config, results)

    def test_synthesized_completed_prerequisite(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="vuln_analysis", phase=3, prompt_template="t",
            deliverable_file="03_vuln_analysis.json", tools=["graph"],
            prerequisites=["recon"],
        )
        results = {"recon": "completed:synthesized"}
        (pipeline.run_dir / "02_recon.md").write_text("## S1\n## S2\n")
        assert pipeline._check_prerequisites(config, results)

    def test_phase4_worker_errors_keep_validated_results_usable(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        (pipeline.run_dir / "04_exploitation.json").write_text('{"tests": []}')
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

    def test_skipped_conditional_requires_artifact(self, mock_provider, output_dir):
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=5, prompt_template="t",
            deliverable_file="t.md", tools=["graph"],
            prerequisites=["exploitation"],
        )
        results = {"exploitation": "skipped:conditional"}
        assert not pipeline._check_prerequisites(config, results)
        (pipeline.run_dir / "04_exploitation.json").write_text('{"tests": []}')
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
        from src.agent.core.runtime import _get_git_commit
        result = _get_git_commit()
        assert result is None or (isinstance(result, str) and len(result) > 0)

    def test_get_git_commit_mock_success(self):
        from src.agent.core.runtime import _get_git_commit
        with patch("src.agent.core.runtime.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="abc1234\n")
            assert _get_git_commit() == "abc1234"

    def test_get_git_commit_mock_failure(self):
        from src.agent.core.runtime import _get_git_commit
        with patch("src.agent.core.runtime.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert _get_git_commit() is None

    def test_get_git_commit_exception(self):
        from src.agent.core.runtime import _get_git_commit
        with patch("src.agent.core.runtime.subprocess.run", side_effect=FileNotFoundError):
            assert _get_git_commit() is None

    def test_run_meta_written_on_init(self, mock_provider, output_dir):
        with patch("src.agent.core.runtime._get_git_commit", return_value="deadbeef"):
            pipeline = Pipeline(provider=mock_provider, phases=[999])
        # run_meta.json is written during run(), not __init__ — verify after run
        with patch("src.agent.core.runtime.load_lab_context", return_value={
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


def test_downstream_phase_selection_includes_prerequisites():
    assert _expand_phase_selection([1]) == [1]
    assert _expand_phase_selection([3, 6]) == [1, 2, 3, 4, 5, 6]
    assert _expand_phase_selection([5]) == [1, 2, 3, 4, 5]
    assert _expand_phase_selection([]) == []


class TestPipelineRun:
    @patch("src.agent.core.runtime.load_lab_context")
    @patch("src.agent.core.runtime.reset_tool_cache")
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

    @patch("src.agent.core.runtime.load_lab_context")
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

    @patch("src.agent.core.runtime.load_lab_context")
    @patch("src.agent.core.runtime.load_prompt")
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

    @patch("src.agent.core.runtime.load_lab_context")
    def test_phase_filter(self, mock_lab, mock_provider, output_dir):
        mock_lab.return_value = {
            "device_count": 1, "link_count": 1,
            "cve_count": 0, "top_risk": "none",
        }
        pipeline = Pipeline(provider=mock_provider, phases=[1])
        run_dir = pipeline.run_dir

        # Phase 1 (graph_analysis) has no prerequisites, so it should run
        with patch("src.agent.core.runtime.load_prompt", return_value="prompt"):
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
