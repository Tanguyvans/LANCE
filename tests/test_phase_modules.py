"""Verify physical phase boundaries and profile routing without running tools."""
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.agent.pipeline import Pipeline
from src.agent.phases.registry import PHASE_MODULES, run_phase
from src.agent.core import runtime
from src.agent.registry import AGENTS


def test_phase_routing_covers_the_configured_agents():
    assert set(PHASE_MODULES) == {config.phase for config in AGENTS.values()}


@pytest.mark.parametrize("profile", ["compact", "full"])
@pytest.mark.parametrize("phase", range(1, 7))
def test_both_profiles_use_the_phase_entry(profile, phase):
    module = PHASE_MODULES[phase]
    assert callable(module.run)
    context = SimpleNamespace(
        execution_profile=SimpleNamespace(name=profile),
        _run_agent=Mock(return_value="completed"),
        _uses_compact_local_moe=Mock(return_value=profile == "compact"),
        _run_local_report_phase=Mock(return_value="completed:local"),
        _update_run_meta=Mock(),
        _merge_report_with_prefill=Mock(),
    )
    config = SimpleNamespace(phase=phase)
    callback = Mock()
    local_report = phase == 6
    assert run_phase(context, config, callback) == ("completed:local" if local_report else "completed")
    if local_report:
        context._run_local_report_phase.assert_called_once_with(config, callback)
        context._run_agent.assert_not_called()
    else:
        context._run_agent.assert_called_once_with(config, callback)
        context._run_local_report_phase.assert_not_called()
    assert context._merge_report_with_prefill.call_count == int(phase == 6 and not local_report)


@pytest.mark.parametrize("profile", ["compact", "full"])
def test_report_profiles_share_the_bounded_entry(profile):
    context = SimpleNamespace(
        execution_profile=SimpleNamespace(name=profile),
        _uses_compact_local_moe=lambda: False,
        _run_agent=Mock(side_effect=RuntimeError("old report path must not run")),
        _run_local_report_phase=Mock(return_value="partial:provider_error"),
        _update_run_meta=Mock(),
        _merge_report_with_prefill=Mock(),
    )
    assert run_phase(context, SimpleNamespace(phase=6)) == "partial:provider_error"
    context._run_local_report_phase.assert_called_once()
    context._run_agent.assert_not_called()
    context._merge_report_with_prefill.assert_not_called()


@pytest.mark.parametrize("method,module", [
    ("_build_graph_evidence_projection", "src.agent.phases.graph.run"),
    ("_render_compact_graph_markdown", "src.agent.phases.graph.compact"),
    ("_apply_recon_tool_contract", "src.agent.phases.recon.run"),
    ("_run_phase3", "src.agent.phases.analysis.run"),
    ("_aggregate_device_vulns", "src.agent.phases.analysis.aggregation"),
    ("_run_exploit_agents", "src.agent.phases.verification.run"),
    ("_apply_compact_intrusion_tool_contract", "src.agent.phases.intrusion.compact"),
    ("_generate_intrusion_context", "src.agent.phases.intrusion.run"),
    ("_run_local_report_phase", "src.agent.phases.report.run"),
    ("_run_agent", "src.agent.core.runner"),
    ("_run_teardown", "src.agent.core.lifecycle"),
])
def test_execution_methods_are_not_hidden_in_the_facade(method, module):
    assert method not in Pipeline.__dict__
    assert getattr(Pipeline, method).__module__ == module


def test_moved_code_keeps_repository_and_template_paths():
    root = Path(__file__).resolve().parents[1]
    assert runtime.REPO_ROOT == root
    assert runtime.AGENT_DIR == root / "src/agent"


def test_unknown_profile_does_not_silently_select_full():
    context = SimpleNamespace(execution_profile=SimpleNamespace(name="typo"))
    with pytest.raises(ValueError, match="Unsupported execution profile"):
        run_phase(context, SimpleNamespace(phase=1))


def test_full_report_uses_the_same_bounded_entry():
    context = SimpleNamespace(
        execution_profile=SimpleNamespace(name="full"),
        _uses_compact_local_moe=Mock(return_value=True),
        _run_agent=Mock(return_value="completed"),
        _run_local_report_phase=Mock(return_value="completed"),
        _update_run_meta=Mock(),
        _merge_report_with_prefill=Mock(),
    )
    assert run_phase(context, SimpleNamespace(phase=6)) == "completed"
    context._uses_compact_local_moe.assert_not_called()
    context._run_local_report_phase.assert_called_once()
    context._run_agent.assert_not_called()
    context._merge_report_with_prefill.assert_not_called()


@pytest.mark.parametrize("phase", ["graph", "recon", "analysis", "intrusion", "report"])
def test_compact_modules_only_define_adaptations(phase):
    module = import_module(f"src.agent.phases.{phase}.compact")
    assert not hasattr(module, "run")


@pytest.mark.parametrize("folder", ["shared", "full", "compact"])
def test_obsolete_profile_directories_have_no_python_sources(folder):
    phase_root = Path(__file__).resolve().parents[1] / "src/agent/phases"
    assert not list((phase_root / folder).rglob("*.py"))


def test_phase_policy_lives_with_its_owner_not_in_runtime():
    from src.agent.phases.intrusion.scope import _intrusion_scope_violation
    from src.agent.phases.verification.contract import _phase4_verification_plan
    from src.agent.phases.report.validation import _local_report_memo_contradicts_context

    for helper in (
        _intrusion_scope_violation,
        _phase4_verification_plan,
        _local_report_memo_contradicts_context,
    ):
        assert not hasattr(runtime, helper.__name__)


@pytest.mark.parametrize("module", PHASE_MODULES.values(), ids=lambda module: module.__name__)
def test_phase_can_be_imported_without_the_pipeline_facade(module):
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-c", (
            "import importlib, sys; "
            f"importlib.import_module('{module.__name__}'); "
            "assert 'src.agent.pipeline' not in sys.modules"
        )],
        cwd=root, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
