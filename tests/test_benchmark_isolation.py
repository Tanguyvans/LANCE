"""Cross-component guards that keep the sealed oracle outside the worker."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

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


def test_blind_tool_groups_remove_cross_run_semantic_memory(tmp_path, monkeypatch):
    import src.agent.pipeline as pipeline_module
    from src.agent.registry import AgentConfig

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "output")
    pipeline = Pipeline(
        provider=_provider(), scenario_id="20", blind=True, phases=[99], dry_run=True,
    )
    config = AgentConfig(
        name="blind", phase=2, prompt_template="x", deliverable_file="x.md",
        tools=["skill"],
    )

    names = {tool["name"] for tool in pipeline._resolve_tools(config)}

    assert "search_history" not in names
    assert "search_knowledge" not in names
    assert "cve_search" in names
