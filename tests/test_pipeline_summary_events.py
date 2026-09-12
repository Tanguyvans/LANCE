"""Exercise post-run API events through the real dashboard event/log handlers.

No model, lab or browser network calls: only the DOM and pipeline execution are
stubbed. Evaluation serialization and frontend JavaScript remain real.
"""
import json
from pathlib import Path
import queue
import shutil
import subprocess
import threading

import pytest

from src.agent.batch import _evaluation_metrics
from src.api.routes import pipeline as route
from src.benchmark.evaluator import EvaluationResult


def _evaluation(run_dir):
    result = EvaluationResult("1", str(run_dir), "fixture.yaml")
    result.scoring_policy = "strict-v3"
    result.precision, result.recall, result.f1_score = 0.625, 0.833, 0.714
    result.true_positives, result.false_positives, result.false_negatives = 10, 6, 2
    result.scenario_score_pct = 76.9
    result.total_gt_vulns = 12
    result.funnel = {
        "schema_version": "funnel-v1",
        "stages": {"confirmed": {
            "available": True, "predictions": 14,
            "true_positives": 10, "false_positives": 4, "false_negatives": 2,
            "precision": 0.714, "recall": 0.833, "f1": 0.769,
        }},
        "diagnostics": {"verification": {
            "confirmed": 14, "inconclusive": 2, "error": 1, "not_tested": 0,
        }},
    }
    result.phase3_metrics_available = True
    result.phase3_status = "completed_with_device_errors"
    result.phase3_devices_total = 4
    result.phase3_devices_analyzed = 3
    result.phase3_devices_failed = 1
    result.phase5_metrics_available = True
    result.phase5_evidence_available = True
    result.intrusion_paths_available = True
    result.phase5_targets_total = 4
    result.phase5_targets_compromised = 2
    result.total_attack_paths = 4
    result.verified_attack_paths = 1
    result.phase5_verified_hops = 0
    # Attractive declarations must never be used instead of verified results.
    result.phase5_observed_hops = 6
    result.attack_paths_detected = 4
    result.path_coverage = 1.0
    return result


def _api_events(tmp_path, monkeypatch, result, status="completed"):
    from src.agent import pipeline as agent_pipeline
    from src.agent import provider as agent_provider
    from src.benchmark import evaluator

    events = queue.Queue()
    ground_truth = tmp_path / "fixture.yaml"
    ground_truth.write_text("vulnerabilities: []\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "03_vuln_analysis.json").write_text('{"vulnerabilities": []}')

    class Loop:
        def call_soon_threadsafe(self, callback, event):
            callback(event)

    class Provider:
        model = "fixture"

        def __init__(self, **kwargs):
            pass

    class Tracker:
        def total_cost(self):
            return 1.207836

    class Pipeline:
        benchmark_split = "dev-public"

        def __init__(self, **kwargs):
            self.run_dir = run_dir
            self.tracker = Tracker()

        def _update_run_meta(self, updates):
            pass

        def run(self, stream_callback, **kwargs):
            results = {"intrusion": status, "report": "completed"}
            stream_callback({
                "type": "pipeline_done", "status": status,
                "results": results, "run_dir": str(run_dir),
                "cleanup_status": "completed", "usage_status": "completed",
                "total_cost_usd": 1.2078,
            })
            return results

    monkeypatch.setattr(route, "_state", {
        "queue": events, "loop": Loop(), "stop_event": threading.Event(),
        "recent_events": [], "running": True, "stopping": False,
        "cost": 0.0, "run_dir": None,
    })
    monkeypatch.setattr(agent_pipeline, "Pipeline", Pipeline)
    monkeypatch.setattr(agent_provider, "LLMProvider", Provider)
    monkeypatch.setattr(route, "resolve_ground_truth_path", lambda _: ground_truth)
    monkeypatch.setattr(evaluator, "evaluate", lambda *args, **kwargs: result)
    route._pipeline_thread(route.StartRequest(scenario_id="1"))
    received = []
    while not events.empty():
        received.append(events.get_nowait())
    return received


def _render_events(events):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for dashboard event integration")
    source_path = Path(__file__).resolve().parents[1] / "src/static/app.js"
    script = r"""
const vm = require('node:vm');
const fs = require('node:fs');
class Element {
  constructor() { this.children = []; this.style = {}; this.textContent = ''; }
  appendChild(child) { this.children.push(child); }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  setAttribute() {}
}
const elements = new Map();
const document = {
  documentElement: new Element(),
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  },
  createElement: () => new Element(),
  addEventListener() {},
};
const context = vm.createContext({
  document, console, getComputedStyle: () => ({getPropertyValue: () => ''}),
});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
vm.runInContext('loadRuns = () => {}; setCost = () => {};', context);
context.events = JSON.parse(fs.readFileSync(0, 'utf8'));
vm.runInContext('events.forEach(handleEvent);', context);
console.log(JSON.stringify(document.getElementById('log').children.map(line => ({
  text: line.children[0].textContent, className: line.className,
}))));
"""
    result = subprocess.run(
        [node, "-e", script, str(source_path)], input=json.dumps(events),
        capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)


def test_api_to_dashboard_uses_final_audit_and_separate_verified_intrusion(tmp_path, monkeypatch):
    result = _evaluation(tmp_path / "run")
    before = json.dumps(_evaluation_metrics(result), sort_keys=True)
    events = _api_events(tmp_path, monkeypatch, result)
    assert [ev["type"] for ev in events[:2]] == ["evaluation_done", "pipeline_done"]
    assert events[1]["status"] == "completed"
    assert events[1]["metrics"] == events[0]["metrics"]
    lines = _render_events(events)
    audit = next(line["text"] for line in lines if "Audit final" in line["text"])
    intrusion = next(line["text"] for line in lines if "Intrusion" in line["text"])
    terminal = lines[-1]["text"]
    assert "76,9" in audit or "76.9" in audit
    assert "62,5" not in audit and "62.5" not in audit
    assert "Score=" not in audit
    assert "2/4" in intrusion and "1/4" in intrusion
    assert "0" in intrusion and "6" not in intrusion
    assert "terminée avec réserves" in terminal
    assert "1.2078" in terminal
    assert "réussi" not in terminal
    # Rendering is not allowed to rewrite saved legacy fields or the funnel.
    assert json.dumps(_evaluation_metrics(result), sort_keys=True) == before


@pytest.mark.parametrize("status,word", [
    ("failed", "échec"), ("stopped", "arrêt"),
    ("budget_exceeded", "budget"), ("blocked", "bloqu"),
])
def test_successful_evaluation_never_overrides_terminal_failure(tmp_path, monkeypatch, status, word):
    events = _api_events(tmp_path, monkeypatch, _evaluation(tmp_path / "run"), status)
    assert events[0]["status"] == "completed"
    assert events[1]["status"] == status
    lines = _render_events(events)
    assert word in lines[-1]["text"]
    assert "terminée avec réserves" not in lines[-1]["text"]
    if status == "failed":
        assert "log-failed" in lines[-1]["className"]


def test_zero_intrusion_success_is_not_an_execution_error(tmp_path, monkeypatch):
    result = _evaluation(tmp_path / "run")
    result.phase3_status = "completed"
    result.phase3_devices_analyzed = 4
    result.phase3_devices_failed = 0
    result.funnel["diagnostics"]["verification"].update(inconclusive=0, error=0)
    result.phase5_targets_compromised = 0
    result.verified_attack_paths = 0
    lines = _render_events(_api_events(tmp_path, monkeypatch, result))
    intrusion = next(line["text"] for line in lines if "Intrusion" in line["text"])
    assert "0/4" in intrusion
    assert "Exécution terminée" in lines[-1]["text"]
    assert "avec réserves" not in lines[-1]["text"]


def test_incompatible_evidence_never_displays_verified_claims(tmp_path, monkeypatch):
    result = _evaluation(tmp_path / "run")
    result.evidence_contract_compatible = False
    result.metrics_compatibility_reason = "fixture: incompatible evidence contract"
    result.funnel["stages"]["confirmed"]["available"] = False
    lines = _render_events(_api_events(tmp_path, monkeypatch, result))
    audit = next(line["text"] for line in lines if "Audit final" in line["text"])
    intrusion = next(line["text"] for line in lines if "Intrusion" in line["text"])
    assert "indisponible" in audit
    assert "indisponible" in intrusion
    assert "2/4" not in intrusion
    assert "1/4" not in intrusion
    assert "0.714" not in audit and "76.9" not in audit and "76,9" not in audit
    assert "avec réserves" in lines[-1]["text"]
