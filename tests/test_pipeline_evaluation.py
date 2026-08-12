"""Regression tests for automatic post-run benchmark evaluation."""
from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import src.agent.batch as batch
from src.api.routes import pipeline as pipeline_route
from src.api.routes.pipeline import StartRequest, _evaluate_single_run
from src.api.routes.runs import _visible_files


class _PipelineStub:
    def __init__(self, run_dir):
        self.run_dir = run_dir
        self.benchmark_split = "lab-export"
        self.meta_updates = []

    def _update_run_meta(self, updates):
        self.meta_updates.append(updates)


def test_missing_generated_ground_truth_is_reported(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    missing = tmp_path / "missing-ground-truth.yaml"
    monkeypatch.setattr(
        pipeline_route,
        "resolve_ground_truth_path",
        lambda _scenario_id: missing,
    )

    event = _evaluate_single_run(
        _PipelineStub(run_dir),
        StartRequest(scenario_id="gen-api-deadbeef00"),
    )

    assert event["status"] == "skipped"
    assert event["metrics"] is None
    summary = json.loads((run_dir / "evaluation_summary.json").read_text())
    assert summary["status"] == "skipped"
    assert "Ground truth not found" in summary["reason"]


def test_generated_run_is_evaluated_and_persisted(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    ground_truth = tmp_path / "ground_truth.yaml"
    ground_truth.write_text("scenario_id: gen-api-deadbeef00\nvulnerabilities: []\n")
    (run_dir / "03_vuln_analysis.json").write_text('{"vulnerabilities": []}')

    seen = {}

    def fake_evaluate(run, gt, policy):
        seen.update(run=run, gt=gt, policy=policy)
        return SimpleNamespace(split=None)

    monkeypatch.setitem(
        sys.modules,
        "src.benchmark.evaluator",
        SimpleNamespace(evaluate=fake_evaluate),
    )
    metrics = {"recall": 1.0, "precision": 1.0, "f1": 1.0, "score_pct": 100.0}
    monkeypatch.setattr(batch, "_evaluation_metrics", lambda _result: metrics)
    monkeypatch.setattr(
        pipeline_route,
        "resolve_ground_truth_path",
        lambda _scenario_id: ground_truth,
    )
    monkeypatch.setattr(
        pipeline_route,
        "asdict",
        lambda _result: {"scenario_id": "gen-api-deadbeef00"},
    )

    event = _evaluate_single_run(
        _PipelineStub(run_dir),
        StartRequest(scenario_id="gen-api-deadbeef00"),
    )

    assert event["status"] == "completed"
    assert event["metrics"] == metrics
    assert seen == {"run": run_dir, "gt": ground_truth, "policy": "strict-v3"}
    assert json.loads((run_dir / "evaluation.json").read_text())["scenario_id"] == "gen-api-deadbeef00"
    summary = json.loads((run_dir / "evaluation_summary.json").read_text())
    assert summary["status"] == "completed"
    assert summary["metrics"] == metrics


def test_evaluation_artifacts_are_not_public_run_files(tmp_path):
    (tmp_path / "evaluation.json").write_text("{}")
    (tmp_path / "evaluation_summary.json").write_text("{}")
    (tmp_path / "scenario_meta.json").write_text('{"scenario_id": "1"}')

    assert _visible_files(tmp_path) == ["scenario_meta.json"]



def test_single_run_emits_evaluation_before_pipeline_done(tmp_path, monkeypatch):
    import queue
    import threading

    from src.agent import pipeline as agent_pipeline
    from src.agent import provider as agent_provider

    events = queue.Queue()

    class _Loop:
        def call_soon_threadsafe(self, callback, event):
            callback(event)

    class _Provider:
        model = "test-model"

        def __init__(self, **_kwargs):
            pass

    class _Tracker:
        def total_cost(self):
            return 0.0

    class _Pipeline:
        def __init__(self, **_kwargs):
            self.run_dir = tmp_path / "run"
            self.run_dir.mkdir()
            self.tracker = _Tracker()

        def run(self, stream_callback, **_kwargs):
            stream_callback({
                "type": "pipeline_done",
                "results": {"phase": "completed"},
                "total_cost_usd": 0.0,
                "run_dir": str(self.run_dir),
            })
            return {"phase": "completed"}

    state = {
        "queue": events,
        "loop": _Loop(),
        "stop_event": threading.Event(),
        "recent_events": [],
        "running": True,
        "stopping": False,
        "cost": 0.0,
        "run_dir": None,
    }
    monkeypatch.setattr(pipeline_route, "_state", state)
    monkeypatch.setattr(agent_provider, "LLMProvider", _Provider)
    monkeypatch.setattr(agent_pipeline, "Pipeline", _Pipeline)
    monkeypatch.setattr(
        pipeline_route,
        "_evaluate_single_run",
        lambda *_args: {
            "type": "evaluation_done",
            "status": "completed",
            "metrics": {"f1": 1.0},
        },
    )

    pipeline_route._pipeline_thread(StartRequest(scenario_id="1"))

    received = []
    while not events.empty():
        received.append(events.get_nowait())
    types = [event["type"] for event in received]
    assert types[:2] == ["evaluation_done", "pipeline_done"]
    assert received[1]["metrics"] == {"f1": 1.0}

