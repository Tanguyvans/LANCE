"""Integration guards for public scenario selection and batch score semantics."""
from __future__ import annotations

import asyncio
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
import yaml

from src.agent.batch import (
    _aggregate_batch_results,
    _evaluation_metrics,
    _parse_scenario_ids,
    _phase5_summary,
    _parse_single_scenario_id,
    _print_scenario_summary,
)
from src.benchmark.scenario_exports import resolve_scenario_split
from src.benchmark.aggregate import aggregate_evaluations
from src.benchmark.evaluator import evaluate
from src.benchmark.evaluator import EvaluationResult
from src.benchmark.metric_contract import EVIDENCE_CONTRACT_VERSION, METRIC_CONTRACT_VERSION


_COMPARABILITY_IDENTITY = {
    "provider": "fixture-provider", "model": "fixture-model",
    "execution_profile": "full", "execution_profile_policy": "full",
    "blind": False, "max_cost_usd": None, "max_tool_calls": None,
    "effective_phases": [1, 2, 3, 4, 5, 6], "phase_models": {},
    "execution_profile_config": {"schema_version": "2", "name": "full"},
    "prompt_manifest_sha256": "fixture-prompts", "tool_manifest_sha256": "fixture-tools",
    "scoring_policy": "strict-v2", "metric_contract_version": METRIC_CONTRACT_VERSION,
    "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
}


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
        split=resolve_scenario_split(scenario_id),
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
        comparability_identity=dict(_COMPARABILITY_IDENTITY),
    )


@pytest.fixture
def real_run_metadata(tmp_path, monkeypatch):
    """Create producer metadata through Pipeline, with every external step mocked."""
    import src.agent.pipeline as pipeline_module
    import src.agent.tools.graph_tools as graph_tools
    from src.agent.core import runtime

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "producer")
    monkeypatch.setattr(runtime, "load_lab_context", lambda: {
        "device_count": 0, "link_count": 0, "cve_count": 0, "top_risk": "none",
    })
    monkeypatch.setattr(runtime, "init_weighted_graph", lambda: None)
    monkeypatch.setattr(graph_tools, "_scenario_topology", None)
    monkeypatch.setattr(graph_tools, "_backend", None)
    monkeypatch.setattr(runtime, "set_output_dir", lambda *_: None)
    monkeypatch.setattr(runtime, "set_cve_cache_only", lambda *_: None)
    monkeypatch.setattr(pipeline_module, "run_phase", lambda *_: "completed")

    run = pipeline_module.Pipeline(
        provider=SimpleNamespace(model="review-model", provider="review-provider"),
        execution_profile="full", phases=[1, 2, 3, 4], auto_teardown=False,
        benchmark_split="dev-public", max_cost_usd=2.0,
    )
    run._check_prerequisites = lambda *_: True
    run._check_conditional = lambda *_: True
    run._build_graph_evidence_projection = lambda: None
    run._build_recon_evidence_projection = lambda: None
    run._persist_run = Mock()
    run.run()
    return json.loads((run.run_dir / "run_meta.json").read_text())


def _evaluate_real_fixture(tmp_path, metadata, *, name="run", scenario="demo"):
    run = tmp_path / name
    run.mkdir()
    finding = {
        "id": "F1", "device_ip": "192.0.2.1", "device_id": "web",
        "type": "data_exposure", "severity": "high", "service": "http",
        "port": 80, "protocol": "tcp", "endpoint": "/backup.sql", "cve_ids": [],
    }
    (run / "run_meta.json").write_text(json.dumps(metadata))
    (run / "03_vuln_analysis_raw.json").write_text(json.dumps({"candidates": [{"candidate_finding": finding}]}))
    (run / "03_vuln_analysis.json").write_text(json.dumps({"vulnerabilities": [finding]}))
    (run / "04_exploitation.json").write_text(json.dumps({"tests": [{
        "vuln_id": "F1", "status": "CONFIRMED", "evidence_level": 2,
        "tool_used": "http_get", "tools_used": ["http_get"], "evidence_refs": ["P1"],
        "evidence": "password=secret",
    }]}))
    (run / "tool_calls.jsonl").write_text(json.dumps({
        "vuln_id": "F1", "evidence_ref": "P1", "tool": "http_get",
        "args": {"url": "http://192.0.2.1/backup.sql"},
        "result": {"return_code": 0, "status_code": 200, "body": "password=secret"},
    }) + "\n")
    gt = run / "gt.yaml"
    gt.write_text(yaml.safe_dump({
        "scenario_id": scenario,
        "vulnerabilities": [{
            "id": "G1", "title": "Exposed backup", "ip": "192.0.2.1",
            "category": "data_exposure", "severity": "high",
            "accepted_types": ["data_exposure"], "services": ["http"],
            "ports": [80], "protocols": ["tcp"], "endpoints": ["/backup.sql"],
        }],
    }))
    return evaluate(run, gt, policy="strict-v3")


def test_real_producer_metadata_reaches_evaluator_and_batch(tmp_path, real_run_metadata, monkeypatch):
    evaluation = _evaluate_real_fixture(tmp_path, real_run_metadata)
    assert evaluation.scenario_score_pct == 100.0
    assert evaluation.comparability_identity is not None

    metrics = _evaluation_metrics(evaluation)
    assert metrics["comparability_identity"] == evaluation.comparability_identity
    direct = aggregate_evaluations([evaluation, evaluation])
    assert direct["macro_scenario_score_pct"] == 100.0
    assert direct["metric_coverage"]["macro_scenario_score_pct"]["evaluated"] == 1
    serialized = {"scenario_id": evaluation.scenario_id, **metrics}
    assert aggregate_evaluations([serialized, serialized])["macro_scenario_score_pct"] == 100.0

    monkeypatch.setattr("src.agent.batch.resolve_scenario_split", lambda _: "dev-public")
    batch = _aggregate_batch_results(
        [evaluation], [{"scenario_id": "demo", "metrics": metrics}], ["demo"]
    )
    assert batch["avg_score_pct"] == 100.0

    missing = _evaluate_real_fixture(tmp_path, {}, name="missing", scenario="missing")
    partial_metadata = dict(real_run_metadata)
    partial_metadata.pop("model")
    partial = _evaluate_real_fixture(
        tmp_path, partial_metadata, name="partial", scenario="partial"
    )
    for invalid in (missing, partial):
        assert invalid.comparability_identity is None
        invalid_metrics = _evaluation_metrics(invalid)
        rejected = _aggregate_batch_results(
            [invalid],
            [{"scenario_id": invalid.scenario_id, "metrics": invalid_metrics}],
            [invalid.scenario_id],
        )
        assert rejected["avg_score_pct"] is None
        assert rejected["comparability_status"] == "not_comparable"


def test_batch_keeps_failed_repetition_in_attempt_denominator(monkeypatch):
    evaluation = _evaluation(
        "1", scenario_score_pct=100.0, f1=1.0, specificity=None, zero_gt=False
    )
    metrics = _evaluation_metrics(evaluation)
    monkeypatch.setattr("src.agent.batch.resolve_scenario_split", lambda _: "dev-public")
    aggregate = _aggregate_batch_results(
        [evaluation],
        [
            {"scenario_id": "1", "metrics": metrics},
            {"scenario_id": "1", "metrics": None, "status": "failed"},
        ],
        ["1", "1"],
    )
    assert aggregate["attempts"] == {
        "unit": "attempts", "expected": 2, "observed": 2,
        "evaluated": 1, "missing": 0, "unavailable": 1,
    }
    assert aggregate["per_scenario"]["1"]["metric_coverage"]["scenario_score_pct"]["unavailable"] == 1
    assert aggregate["scenarios_evaluated"] == 1


def test_batch_population_metadata_rejects_invalid_gt_values_without_stringifying():
    evaluation = EvaluationResult(
        scenario_id="1", run_dir="/tmp/run", ground_truth_file="/tmp/gt",
        scenario_score_pct=100.0, total_gt_vulns=1,
    )
    evaluation.matches = [{"gt_severity": None, "gt_hop_depth": "unknown"}]
    metrics = _evaluation_metrics(evaluation)
    assert metrics["gt_by_severity"] == {}
    direct = aggregate_evaluations([evaluation])
    serialized = aggregate_evaluations([{"scenario_id": "1", **metrics}])
    for metric in ("critical_recall", "mhr_1"):
        assert direct["per_scenario"]["1"]["metric_coverage"][metric] == serialized[
            "per_scenario"
        ]["1"]["metric_coverage"][metric]


def test_phase_model_metadata_preserves_integer_key_precedence():
    from src.agent.pipeline import Pipeline

    assert Pipeline._archived_phase_models({4: "model-a", "4": "model-b"}) == {
        "4": "model-a"
    }
    assert Pipeline._archived_phase_models({"4": "model-b", 4: "model-a"}) == {
        "4": "model-a"
    }


class TestScenarioSelection:
    def test_single_public_hardened_variant_is_supported(self):
        assert _parse_single_scenario_id("S1h") == "1h"
        assert _parse_single_scenario_id("4h") == "4h"

    def test_single_selector_rejects_multi_scenario_alias(self):
        with pytest.raises(ValueError, match="exactly one"):
            _parse_single_scenario_id("dev")

    def test_public_test_scenarios_are_selectable_locally(self):
        assert _parse_scenario_ids("20") == ["20"]
        assert _parse_scenario_ids("20,29") == ["20", "29"]
        assert _parse_scenario_ids("test") == [str(i) for i in range(20, 30)]
        assert _parse_scenario_ids("eval") == []

    def test_all_contains_variants_and_every_public_id(self):
        selected = _parse_scenario_ids("all")

        assert "1h" in selected and "4h" in selected
        assert "19" in selected
        assert "20" in selected and "29" in selected

    def test_public_test_split_is_preserved_in_run_metadata(self):
        assert resolve_scenario_split("1") == "dev-public"
        assert resolve_scenario_split("20") == "test-public"
        assert resolve_scenario_split("29") == "test-public"
        assert resolve_scenario_split("1h") == "dev-public"


class TestBatchPhase5Reporting:
    def test_incomplete_phase5_is_exposed_separately_from_evaluation_metrics(self, tmp_path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "05_intrusion.json").write_text(
            '{"status":"incomplete","blocked_reason":"completion missing"}',
            encoding="utf-8",
        )

        summary = _phase5_summary(
            run_dir,
            {"intrusion": "failed:phase5_completion_missing"},
        )

        assert summary["status"] == "incomplete"
        assert summary["artifact_status"] == "incomplete"
        assert summary["pipeline_status"] == "failed:phase5_completion_missing"
        assert summary["blocked_reason"] == "completion missing"


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

    def test_missing_scenario_is_unavailable_in_macro(self):
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

        assert aggregate["macro_scenario_score_pct"] is None
        assert aggregate["avg_score_pct"] is None
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


def test_dashboard_start_accepts_public_test_scenario(monkeypatch):
    from src.api.routes import pipeline as route

    snapshot = dict(route._state)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(route.threading, "Thread", NoopThread)
    route._state["running"] = False
    request = route.StartRequest(scenario_id="20")
    try:
        assert asyncio.run(route.start_pipeline(request)) == {"status": "started"}
        assert request.scenario_id == "20"
        assert route._state["scenario_id"] == "20"
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


def test_cli_help_describes_current_public_splits(monkeypatch, capsys):
    from src.agent import __main__ as agent_main

    monkeypatch.setattr("sys.argv", ["agent", "--help"])
    with pytest.raises(SystemExit) as exc:
        agent_main.main()

    assert exc.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "S1-S19 for development, S20-S29 for held-out public tests" in help_text
    assert "'dev', 'test', 'public', or 'all'" in help_text


def test_cli_accepts_public_test_scenario(monkeypatch):
    from src.agent import __main__ as agent_main

    provider_instance = SimpleNamespace(model="test")
    provider = Mock(return_value=provider_instance)
    pipeline_instance = Mock()
    pipeline_instance.run.return_value = {}
    pipeline = Mock(return_value=pipeline_instance)
    monkeypatch.setattr(agent_main, "LLMProvider", provider)
    monkeypatch.setattr(agent_main, "Pipeline", pipeline)
    monkeypatch.setattr(sys, "argv", ["python -m src.agent", "--scenario", "20"])

    agent_main.main()

    provider.assert_called_once()
    assert pipeline.call_args.kwargs["scenario_id"] == "20"
    assert pipeline.call_args.kwargs["benchmark_split"] == "test-public"


@pytest.mark.parametrize("selection", [
    ["--scenario", "20", "--split", "dev-public"],
    ["--scenario", "1", "--split", "test-public"],
    ["--batch", "1,20", "--split", "dev-public"],
    ["--batch", "1,20", "--split", "test-public"],
])
def test_cli_rejects_conflicting_split_before_provider(monkeypatch, selection):
    from src.agent import __main__ as agent_main

    provider = Mock()
    monkeypatch.setattr(agent_main, "LLMProvider", provider)
    monkeypatch.setattr(sys, "argv", ["agent", *selection])
    with pytest.raises(SystemExit) as exc:
        agent_main.main()
    assert exc.value.code == 2
    provider.assert_not_called()


def test_mixed_batch_has_only_per_split_scores_including_missing_tests():
    dev = _evaluation("1", scenario_score_pct=100, f1=1, specificity=None, zero_gt=False)
    test = _evaluation("20", scenario_score_pct=50, f1=0.5, specificity=None, zero_gt=False)
    aggregate = _aggregate_batch_results([dev, test], [], ["1", "20", "29"])
    assert aggregate["mixed_splits"] is True
    assert aggregate["avg_score_pct"] is None
    assert aggregate["avg_f1"] is None
    assert aggregate["per_split"]["dev-public"]["macro_scenario_score_pct"] == 100
    assert aggregate["per_split"]["test-public"]["macro_scenario_score_pct"] is None
    assert aggregate["per_scenario"]["29"]["split"] == "test-public"
    assert aggregate["missing_scenarios"] == ["29"]


def test_batch_aggregate_rejects_incompatible_configurations_but_keeps_rows():
    first = _evaluation("1", scenario_score_pct=100, f1=1, specificity=None, zero_gt=False)
    second = _evaluation("2", scenario_score_pct=0, f1=0, specificity=None, zero_gt=False)
    second.comparability_identity["model"] = "different-model"
    aggregate = _aggregate_batch_results([first, second], [], ["1", "2"])
    assert aggregate["macro_scenario_score_pct"] is None
    assert aggregate["comparability_status"] == "not_comparable"
    assert set(aggregate["per_scenario"]) == {"1", "2"}


def test_batch_runner_preserves_test_group_through_evaluation(tmp_path, monkeypatch):
    import json
    from src.agent import batch

    provider = SimpleNamespace(model="test")
    pipeline_instance = Mock(run_dir=tmp_path / "run")
    pipeline_instance.tracker.total_cost.return_value = 0
    pipeline_instance.run.return_value = {}
    pipeline = Mock(return_value=pipeline_instance)
    result = _evaluation("20", scenario_score_pct=50, f1=0.5, specificity=None, zero_gt=False)
    result.split = None
    monkeypatch.setattr("src.agent.pipeline.Pipeline", pipeline)
    monkeypatch.setattr("src.benchmark.evaluator.evaluate", Mock(return_value=result))
    monkeypatch.setattr(batch, "OUTPUT_DIR", tmp_path)

    path = batch.run_batch("20", provider)
    summary = json.loads(path.read_text())
    assert pipeline.call_args.kwargs["benchmark_split"] == "test-public"
    assert result.split == "test-public"
    assert summary["aggregate"]["per_split"]["test-public"]["macro_scenario_score_pct"] == 50


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
