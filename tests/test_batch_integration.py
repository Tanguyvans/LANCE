"""Integration guards for public scenario selection and batch score semantics."""
from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from src.agent.batch import (
    SealedScenarioError,
    _aggregate_batch_results,
    _evaluation_metrics,
    _parse_scenario_ids,
    _parse_single_scenario_id,
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

    def test_local_selectors_reject_sealed_scenarios(self):
        with pytest.raises(SealedScenarioError):
            _parse_scenario_ids("20")
        with pytest.raises(SealedScenarioError):
            _parse_scenario_ids("eval")

    def test_all_contains_public_variants_but_no_sealed_ids(self):
        selected = _parse_scenario_ids("all")

        assert "1h" in selected and "4h" in selected
        assert "19" in selected
        assert "20" not in selected


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


def test_dashboard_start_rejects_sealed_scenario(monkeypatch):
    from src.api.routes import pipeline as route

    route._state["running"] = False
    with pytest.raises(HTTPException) as exc:
        asyncio.run(route.start_pipeline(route.StartRequest(scenario_id="20")))

    assert exc.value.status_code == 503


def test_cli_rejects_sealed_before_provider_construction(monkeypatch):
    from src.agent import __main__ as agent_main

    provider = Mock(side_effect=AssertionError("provider must not be constructed"))
    monkeypatch.setattr(agent_main, "LLMProvider", provider)
    monkeypatch.setattr(sys, "argv", ["python -m src.agent", "--scenario", "20"])

    with pytest.raises(SystemExit) as exc:
        agent_main.main()

    assert exc.value.code == 2
    provider.assert_not_called()


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
