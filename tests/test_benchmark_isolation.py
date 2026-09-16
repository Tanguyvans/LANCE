"""Cross-component guards that keep the sealed oracle outside the worker."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import yaml

from src.agent.core.lifecycle import ScenarioLifecycle
from src.agent.pipeline import Pipeline
from src.benchmark.contracts import ChallengeContract, ChallengeScope, RunLimits


def _provider():
    provider = MagicMock()
    provider.model = "test-model"
    provider.provider = "test-provider"
    provider.chat_with_tools.return_value = "Done."
    return provider


def _contract() -> ChallengeContract:
    return ChallengeContract(
        session_id="12345678-1234-4234-8234-123456789abc",
        scenario_id="20",
        benchmark_version="2.0.0",
        scope=ChallengeScope(ingress_cidrs=("10.77.20.0/24",)),
        limits=RunLimits(
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            max_cost_usd=1.0,
            max_tool_calls=10,
        ),
    )


def test_sealed_pipeline_refuses_repository_filesystem():
    with pytest.raises(RuntimeError, match="Refusing sealed evaluation"):
        Pipeline(
            provider=_provider(),
            scenario_id="20",
            execution_context=_contract(),
            benchmark_split="eval-sealed",
        )


def test_sealed_worker_forces_blind_and_never_touches_oracle_or_ansible(
    tmp_path, monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    import src.agent.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "output")
    pipeline = Pipeline(
        provider=_provider(),
        scenario_id="20",
        execution_context=_contract(),
        benchmark_split="eval-sealed",
        phases=[99],
        dry_run=True,
    )

    assert pipeline.blind is True
    assert pipeline.manage_scenario is False
    assert pipeline.auto_teardown is False
    assert pipeline.target_network == "10.77.20.0/24"
    assert pipeline.max_tool_calls == 10

    with patch.object(pipeline, "_save_ground_truth") as save_gt, \
         patch.object(pipeline, "_load_scenario_context") as load_context, \
         patch.object(pipeline, "_run_scenario_deploy") as deploy, \
         patch.object(pipeline, "_run_teardown") as teardown:
        pipeline.run()

    save_gt.assert_not_called()
    load_context.assert_not_called()
    deploy.assert_not_called()
    teardown.assert_not_called()
    assert not (pipeline.run_dir / "ground_truth.yaml").exists()


def test_public_preset_no_longer_copies_ground_truth(tmp_path, monkeypatch):
    import src.agent.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "output")
    pipeline = Pipeline(
        provider=_provider(), scenario_id="1", benchmark_split="dev-public",
        phases=[99], dry_run=True,
    )
    with patch.object(pipeline, "_save_ground_truth") as save_gt:
        pipeline.run()
    save_gt.assert_not_called()
    assert not (pipeline.run_dir / "ground_truth.yaml").exists()


@pytest.fixture
def custom_gt_context(tmp_path):
    context = SimpleNamespace(
        sealed=False,
        custom_config={"architecture": "test-topology"},
        scenario_id="1",
        run_dir=tmp_path,
        _generate_custom_gt=MagicMock(),
    )
    with patch(
        "src.agent.core.lifecycle.runtime.resolve_ground_truth_path",
        side_effect=AssertionError("Worker must not resolve preset ground truth"),
    ) as resolve_gt:
        yield context
        resolve_gt.assert_not_called()


def test_save_ground_truth_preset_is_noop(custom_gt_context):
    context = custom_gt_context
    context.custom_config = None
    ScenarioLifecycle._save_ground_truth(context)
    context._generate_custom_gt.assert_not_called()
    assert not (context.run_dir / "ground_truth.yaml").exists()


@pytest.mark.parametrize("custom_config", [None, {"architecture": "test-topology"}])
def test_save_ground_truth_sealed_refuses_even_direct_calls(custom_gt_context, custom_config):
    context = custom_gt_context
    context.sealed = True
    context.custom_config = custom_config
    with pytest.raises(RuntimeError, match="Ground truth access is forbidden"):
        ScenarioLifecycle._save_ground_truth(context)
    context._generate_custom_gt.assert_not_called()
    assert not (context.run_dir / "ground_truth.yaml").exists()


def test_save_ground_truth_writes_custom_generation(custom_gt_context):
    context = custom_gt_context
    generated = {"scenario_id": "custom", "vulnerabilities": [{"id": "custom-1"}]}
    context._generate_custom_gt.return_value = generated
    ScenarioLifecycle._save_ground_truth(context)
    context._generate_custom_gt.assert_called_once_with()
    assert yaml.safe_load((context.run_dir / "ground_truth.yaml").read_text()) == generated


@pytest.mark.parametrize("generated", [None, {}])
def test_save_ground_truth_empty_custom_has_no_preset_fallback(custom_gt_context, generated):
    context = custom_gt_context
    context._generate_custom_gt.return_value = generated
    ScenarioLifecycle._save_ground_truth(context)
    context._generate_custom_gt.assert_called_once_with()
    assert not (context.run_dir / "ground_truth.yaml").exists()


def test_save_ground_truth_generation_failure_propagates(custom_gt_context):
    context = custom_gt_context
    context._generate_custom_gt.side_effect = ValueError("Invalid custom topology")
    with pytest.raises(ValueError, match="Invalid custom topology"):
        ScenarioLifecycle._save_ground_truth(context)
    assert not (context.run_dir / "ground_truth.yaml").exists()


@pytest.mark.parametrize("preset", [True, False])
def test_save_ground_truth_noop_preserves_existing_file(custom_gt_context, preset):
    context = custom_gt_context
    if preset:
        context.custom_config = None
    context._generate_custom_gt.return_value = None
    gt_file = context.run_dir / "ground_truth.yaml"
    gt_file.write_text("historical: unchanged\n")
    ScenarioLifecycle._save_ground_truth(context)
    assert gt_file.read_text() == "historical: unchanged\n"


def test_sealed_tool_groups_remove_history_and_python(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import src.agent.pipeline as pipeline_module
    from src.agent.registry import AgentConfig

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "output")
    pipeline = Pipeline(
        provider=_provider(), scenario_id="20", execution_context=_contract(),
        benchmark_split="eval-sealed", phases=[99], dry_run=True,
    )
    config = AgentConfig(
        name="sealed", phase=1, prompt_template="x", deliverable_file="x.md",
        tools=["recon", "skill"],
    )
    names = {tool["name"] for tool in pipeline._resolve_tools(config)}
    assert "python_exec" not in names
    assert "search_history" not in names
