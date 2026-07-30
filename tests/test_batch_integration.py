"""Integration guards for public scenario selection and batch score semantics."""
from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from src.agent.batch import (
    _aggregate_batch_results,
    _evaluation_metrics,
    _parse_scenario_ids,
    _parse_single_scenario_id,
    _print_scenario_summary,
)


def _evaluation(
    scenario_id: str,
    *,
    scenario_score_pct: float,
    f1: float,
    specificity: float | None,
    zero_gt: bool,
):
    return SimpleNamespace(
        scenario_id=scenario_id,
        split="dev-public",
        recall=f1,
        precision=f1,
        f1_score=f1,
        weighted_score=0.0,
        max_weighted_score=0.0 if zero_gt else 1.0,
        score_pct=0.0 if zero_gt else scenario_score_pct,
        scenario_score_pct=scenario_score_pct,
        true_positives=0 if zero_gt else 1,
        false_positives=0,
        false_negatives=0,
        exploitation_coverage=0.0,
        specificity=specificity,
        is_zero_gt=zero_gt,
        total_gt_vulns=0 if zero_gt else 1,
        scoring_policy="strict-v2",
    )


class TestScenarioSelection:
    def test_single_public_hardened_variant_is_supported(self):
        assert _parse_single_scenario_id("S1h") == "1h"
        assert _parse_single_scenario_id("4h") == "4h"

    def test_single_selector_rejects_multi_scenario_alias(self):
        with pytest.raises(ValueError, match="exactly one"):
            _parse_single_scenario_id("dev")

    def test_new_public_heldout_scenarios_are_selectable_locally(self):
        assert _parse_scenario_ids("24") == ["24"]
        assert _parse_scenario_ids("24,29") == ["24", "29"]
        assert _parse_scenario_ids("eval") == []

    def test_all_contains_variants_and_every_public_id(self):
        selected = _parse_scenario_ids("all")

        assert "1h" in selected and "4h" in selected
        assert "23" in selected
        assert "24" in selected and "29" in selected

    def test_development_and_public_test_selectors_are_distinct(self):
        assert _parse_scenario_ids("dev") == [str(i) for i in range(1, 20)]
        assert _parse_scenario_ids("test") == [str(i) for i in range(20, 30)]
        assert _parse_scenario_ids("public") == [str(i) for i in range(1, 30)]


class TestBatchMetrics:
    def test_zero_gt_control_uses_specificity_as_primary_score(self):
        metrics = _evaluation_metrics(
            _evaluation(
                "1h",
                scenario_score_pct=100.0,
                f1=0.0,
                specificity=1.0,
                zero_gt=True,
            )
        )

        assert metrics["score_pct"] == 100.0
        assert metrics["weighted_score_pct"] == 0.0
        assert metrics["is_zero_gt"] is True

    def test_missing_scenario_counts_as_zero_in_macro(self):
        evaluation = _evaluation(
            "1",
            scenario_score_pct=100.0,
            f1=1.0,
            specificity=None,
            zero_gt=False,
        )
        metrics = _evaluation_metrics(evaluation)
        results = [{"scenario_id": "1", "metrics": metrics, "cost_usd": 0.25}]

        aggregate = _aggregate_batch_results([evaluation], results, ["1", "2"])

        assert aggregate["macro_scenario_score_pct"] == 50.0
        assert aggregate["avg_score_pct"] == 50.0
        assert aggregate["missing_scenarios"] == ["2"]
        assert aggregate["scenarios_evaluated"] == 1
        assert aggregate["scenarios_skipped"] == 1


    def test_non_comparable_scenario_score_stays_null(self):
        evaluation = _evaluation(
            "1",
            scenario_score_pct=0.0,
            f1=1.0,
            specificity=None,
            zero_gt=False,
        )
        evaluation.scenario_score_pct = None
        evaluation.quality_adjusted_f1 = None
        evaluation.exploitation_coverage = None
        evaluation.quality_path_coverage = None
        evaluation.scoring_policy = "strict-v3"
        evaluation.evidence_contract_compatible = False
        evaluation.metrics_compatibility_reason = "metric contract legacy != strict-v3.3"
        metrics = _evaluation_metrics(evaluation)
        results = [{"scenario_id": "1", "metrics": metrics, "cost_usd": 0.25}]

        aggregate = _aggregate_batch_results([evaluation], results, ["1"])

        assert metrics["score_pct"] is None
        assert metrics["scenario_score_pct"] is None
        assert metrics["quality_adjusted_f1"] is None
        assert metrics["exploitation_coverage"] is None
        assert aggregate["macro_scenario_score_pct"] is None
        assert aggregate["avg_score_pct"] is None

    def test_non_comparable_scenario_summary_prints_na(self, capsys):
        _print_scenario_summary("1", {
            "metrics": {
                "recall": 1.0,
                "precision": 1.0,
                "f1": 1.0,
                "score_pct": None,
                "tp": 1,
                "fp": 0,
                "fn": 0,
            },
            "cost_usd": 0.25,
        })

        assert "Score=N/A" in capsys.readouterr().out


def test_dashboard_start_accepts_public_variant(monkeypatch):
    from src.api.routes import pipeline as route

    snapshot = dict(route._state)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(route.threading, "Thread", NoopThread)
    route._state["running"] = False
    request = route.StartRequest(scenario_id="S1h")
    try:
        response = asyncio.run(route.start_pipeline(request))
        assert response == {"status": "started"}
        assert request.scenario_id == "1h"
        assert route._state["scenario_id"] == "1h"
    finally:
        route._state.clear()
        route._state.update(snapshot)


def test_dashboard_start_accepts_new_public_heldout_scenario(monkeypatch):
    from src.api.routes import pipeline as route

    snapshot = dict(route._state)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(route.threading, "Thread", NoopThread)
    route._state["running"] = False
    request = route.StartRequest(scenario_id="24")
    try:
        assert asyncio.run(route.start_pipeline(request)) == {"status": "started"}
        assert request.scenario_id == "24"
        assert route._state["scenario_id"] == "24"
    finally:
        route._state.clear()
        route._state.update(snapshot)


def test_dashboard_stop_keeps_run_locked_until_worker_finishes():
    from src.api.routes import pipeline as route

    snapshot = dict(route._state)
    stop_event = route.threading.Event()
    route._state.update({
        "running": True,
        "stopping": False,
        "teardown_running": False,
        "stop_event": stop_event,
    })
    try:
        response = asyncio.run(route.stop_pipeline())
        assert response == {"status": "stopping"}
        assert stop_event.is_set()
        assert route._state["running"] is True
        assert route._state["stopping"] is True
    finally:
        route._state.clear()
        route._state.update(snapshot)


def test_dashboard_rejects_start_while_teardown_is_running():
    from src.api.routes import pipeline as route

    snapshot = dict(route._state)
    route._state.update({
        "running": False,
        "stopping": False,
        "teardown_running": True,
    })
    try:
        with pytest.raises(HTTPException) as exc:
            asyncio.run(route.start_pipeline(route.StartRequest()))
        assert exc.value.status_code == 409
        assert "teardown" in str(exc.value.detail).lower()
    finally:
        route._state.clear()
        route._state.update(snapshot)


def test_cli_accepts_new_public_heldout_scenario(monkeypatch):
    from src.agent import __main__ as agent_main

    provider_instance = SimpleNamespace(model="test")
    provider = Mock(return_value=provider_instance)
    pipeline_instance = Mock()
    pipeline_instance.run.return_value = {}
    pipeline = Mock(return_value=pipeline_instance)
    monkeypatch.setattr(agent_main, "LLMProvider", provider)
    monkeypatch.setattr(agent_main, "Pipeline", pipeline)
    monkeypatch.setattr(sys, "argv", ["python -m src.agent", "--scenario", "24"])

    agent_main.main()

    provider.assert_called_once()
    assert pipeline.call_args.kwargs["scenario_id"] == "24"
    assert pipeline.call_args.kwargs["benchmark_split"] == "test-public"


def test_cli_accepts_public_hardened_variant(monkeypatch):
    from src.agent import __main__ as agent_main

    provider_instance = SimpleNamespace(model="test")
    provider = Mock(return_value=provider_instance)
    pipeline_instance = Mock()
    pipeline_instance.run.return_value = {}
    pipeline = Mock(return_value=pipeline_instance)
    monkeypatch.setattr(agent_main, "LLMProvider", provider)
    monkeypatch.setattr(agent_main, "Pipeline", pipeline)
    monkeypatch.setattr(sys, "argv", ["python -m src.agent", "--scenario", "S4h"])

    agent_main.main()

    provider.assert_called_once()
    assert pipeline.call_args.kwargs["scenario_id"] == "4h"
    assert pipeline.call_args.kwargs["benchmark_split"] == "dev-public"


def test_cli_preserves_public_test_split(monkeypatch):
    from src.agent import __main__ as agent_main

    provider_instance = SimpleNamespace(model="test")
    monkeypatch.setattr(agent_main, "LLMProvider", Mock(return_value=provider_instance))
    pipeline_instance = Mock()
    pipeline_instance.run.return_value = {}
    pipeline = Mock(return_value=pipeline_instance)
    monkeypatch.setattr(agent_main, "Pipeline", pipeline)
    monkeypatch.setattr(sys, "argv", ["python -m src.agent", "--scenario", "S20"])

    agent_main.main()

    assert pipeline.call_args.kwargs["benchmark_split"] == "test-public"


def test_cli_exits_nonzero_when_pipeline_metadata_marks_failure(monkeypatch):
    from src.agent import __main__ as agent_main

    provider_instance = SimpleNamespace(model="test")
    pipeline_instance = Mock(run_status="failed")
    pipeline_instance.run.return_value = {
        "recon": "failed:Deliverable '02_recon.md' not found"
    }
    monkeypatch.setattr(agent_main, "LLMProvider", Mock(return_value=provider_instance))
    monkeypatch.setattr(agent_main, "Pipeline", Mock(return_value=pipeline_instance))
    monkeypatch.setattr(sys, "argv", ["python -m src.agent", "--scenario", "S15"])

    with pytest.raises(SystemExit) as exc:
        agent_main.main()

    assert exc.value.code == 1

def test_batch_process_metrics_are_propagated_and_weighted_by_attempts():
    first = _evaluation("1", scenario_score_pct=100.0, f1=1.0, specificity=None, zero_gt=False)
    second = _evaluation("2", scenario_score_pct=100.0, f1=1.0, specificity=None, zero_gt=False)
    for evaluation, attempts, successes in ((first, 2, 1), (second, 8, 8)):
        evaluation.process_metrics_schema_version = 2
        evaluation.process_metrics_available = True
        evaluation.total_cost_usd = 0.1
        evaluation.cost_is_estimate = False
        evaluation.total_tokens = 10
        evaluation.total_turns = 1
        evaluation.total_tool_calls = attempts
        evaluation.total_tool_errors = attempts - successes
        evaluation.format_attempts = attempts
        evaluation.format_fallbacks = attempts - successes
        evaluation.validation_attempts = attempts
        evaluation.validation_successes = successes
        evaluation.validation_failures = attempts - successes
        evaluation.cost_per_tp = 0.1
        evaluation.turns_per_tp = 1.0
        evaluation.format_fallback_rate = (attempts - successes) / attempts
        evaluation.validation_success_rate = successes / attempts
        evaluation.tool_error_rate = (attempts - successes) / attempts

    metrics = [_evaluation_metrics(first), _evaluation_metrics(second)]
    results = [
        {"scenario_id": "1", "metrics": metrics[0], "cost_usd": 0.1},
        {"scenario_id": "2", "metrics": metrics[1], "cost_usd": 0.1},
    ]

    aggregate = _aggregate_batch_results([first, second], results, ["1", "2"])

    assert metrics[0]["validation_success_rate"] == 0.5
    assert aggregate["validation_success_rate"] == 0.9
    assert aggregate["format_fallback_rate"] == 0.1
    assert aggregate["tool_error_rate"] == 0.1
    assert aggregate["total_cost_usd"] == 0.2
