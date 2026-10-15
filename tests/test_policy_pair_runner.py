"""Controlled pair orchestration with simulated deployment/tools/models only."""
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from src.benchmark import policy_pair_runner as pairs


CONFIG = {"scenario_id": "1", "provider": "minimax", "model": "test-model",
          "max_tool_calls": 20, "max_duration_s": None, "max_cost_usd": None,
          "comparison_order": "rules-first"}


@pytest.fixture
def simulation(tmp_path, monkeypatch):
    from src.agent import pipeline, provider
    from src.benchmark import compare_policies, scenario_exports, lab_lock
    monkeypatch.setenv("LANCE_LAB_LOCK", str(tmp_path / "lab.lock"))
    monkeypatch.setattr(pairs, "verify_nato", lambda: None)
    events, calls, constructors = [], [], []
    control = {"mismatch": False, "stop": False, "cleanup": True, "fail": None}
    stop = threading.Event()

    def prepare(self, policy, signal):
        assert lab_lock._held.active
        calls.append(f"prepare-{policy}")
        directory = self.path / f"preparation-{policy}" / "deployment"
        directory.mkdir(parents=True)
        def cleanup(callback):
            assert lab_lock._held.active
            # Public completion must wait for cleanup AND post-run evaluation.
            assert json.loads((self.path / "pair.json").read_text())["status"] == "running"
            calls.append("cleanup")
            return control["cleanup"]
        self.deployments.append(SimpleNamespace(run_dir=directory, _run_teardown=cleanup))

    def observe(self, policy, signal):
        calls.append(f"preflight-{policy}")
        devices = json.loads(json.dumps(self.spec["devices"]))
        if control["mismatch"] and policy == "llm":
            devices[0]["services"] = devices[0]["services"][:1]
        return devices

    class Worker:
        def __init__(self, **kwargs):
            constructors.append(kwargs)
            self.policy = kwargs["decision_policy"]
            self.run_dir = tmp_path / "agent" / self.policy
            self.run_dir.mkdir(parents=True)
        def run(self, stream_callback, stop_event):
            assert lab_lock._held.active
            calls.append(f"audit-{self.policy}")
            (self.run_dir / "run_meta.json").write_text(json.dumps({"status": "completed"}))
            stream_callback({"type": "pipeline_done", "status": "completed"})
            if control["stop"]:
                stop_event.set()
            if control["fail"] == self.policy:
                (self.run_dir / "run_meta.json").write_text('{"status":"failed"}')
                raise ValueError("Simulated worker failure")
        def _update_run_meta(self, updates):
            path = self.run_dir / "run_meta.json"
            data = json.loads(path.read_text())
            path.write_text(json.dumps(data | updates))

    def oracle(scenario_id):
        calls.append("oracle")
        return tmp_path / "private-ground-truth.yaml"

    def compare(left, right, truth):
        assert lab_lock._held.active
        calls.append("compare")
        comparable = bool(left and right) and all(json.loads((p / "run_meta.json").read_text())["status"] == "completed" for p in (left, right))
        return {"comparable": comparable, "incomparability_reasons": [] if comparable else ["missing or incomplete arm"],
                "delta_llm_minus_rules": {} if comparable else None}

    monkeypatch.setattr(pairs.PairRunner, "_prepare", prepare)
    monkeypatch.setattr(pairs.PairRunner, "_observe", observe)
    monkeypatch.setattr(pipeline, "Pipeline", Worker)
    monkeypatch.setattr(pipeline, "OUTPUT_DIR", tmp_path / "agent")
    monkeypatch.setattr(provider, "LLMProvider", lambda **kwargs: calls.append("provider-llm") or SimpleNamespace(**kwargs))
    monkeypatch.setattr(scenario_exports, "resolve_ground_truth_path", oracle)
    monkeypatch.setattr(compare_policies, "compare_runs", compare)
    runner = pairs.PairRunner(dict(CONFIG), root=tmp_path / "pairs")
    return runner, control, calls, constructors, events, stop


def test_both_arms_share_public_inventory_and_limits_and_oracle_is_post_run(simulation):
    runner, control, calls, constructors, events, stop = simulation
    from src.benchmark import lab_lock
    def callback(event):
        if event["type"] == "comparison_done":
            assert lab_lock._held.active
            record = json.loads((runner.path / "pair.json").read_text())
            assert record["finished_at"] and record["status"] == "completed"
        events.append(event)
    data = runner.run(callback=callback, stop_event=stop)
    assert not lab_lock._held.active
    assert data["status"] == "completed" and data["comparison"]["comparable"] is True
    assert calls == ["prepare-rules", "preflight-rules", "audit-rules", "prepare-llm", "preflight-llm",
                     "provider-llm", "audit-llm", "cleanup", "oracle", "compare"]
    left, right = constructors
    assert left["provider"] is None and right["provider"].model == "test-model"
    assert left["comparison_unlimited"] is True and right["comparison_unlimited"] is True
    assert left["max_duration_s"] is None and left["max_cost_usd"] is None
    for field in ("audit_inventory", "max_tool_calls", "max_duration_s", "max_cost_usd", "execution_profile", "phases"):
        assert left[field] == right[field]
    assert left["phases"] == [3, 4] and left["execution_profile"] == "full"
    assert "scenario_id" not in left
    assert all(event["type"] != "pipeline_done" for event in events)
    assert (runner.path / "preflight-rules.json").is_file()
    assert json.loads((runner.path / "pair.json").read_text())["finished_at"]


def test_changed_surface_prevents_second_audit_and_preserves_first_attempt(simulation):
    runner, control, calls, _, events, stop = simulation
    control["mismatch"] = True
    data = runner.run(callback=events.append, stop_event=stop)
    assert data["status"] == "failed" and "surface TCP" in data["error"]
    assert "audit-llm" not in calls and "cleanup" in calls
    assert data["preflights"]["llm"]["status"] == "invalid"
    assert data["arms"]["rules"] and data["arms"]["llm"] is None
    assert data["comparison"]["comparable"] is False


@pytest.mark.parametrize("condition,expected", [("stop", "stopped"), ("fail", "failed")])
def test_stop_or_failed_worker_keeps_cost_artifacts_and_cleans_before_unlock(simulation, condition, expected):
    runner, control, calls, _, events, stop = simulation
    control[condition] = True if condition == "stop" else "rules"
    data = runner.run(callback=events.append, stop_event=stop)
    assert data["status"] == expected and data["arms"]["rules"] == "rules"
    assert "prepare-llm" not in calls and "cleanup" in calls
    assert data["comparison"]["comparable"] is False


def test_failed_cleanup_is_visible_even_for_a_comparable_pair(simulation):
    runner, control, _, _, events, stop = simulation
    control["cleanup"] = False
    data = runner.run(callback=events.append, stop_event=stop)
    assert data["status"] == "partial" and data["cleanup"] is False
    assert data["comparison"]["comparable"] is True


def test_reverse_order_is_respected(simulation):
    runner, _, calls, _, events, stop = simulation
    runner.data["order"] = ["llm", "rules"]
    runner.run(callback=events.append, stop_event=stop)
    assert calls.index("audit-llm") < calls.index("prepare-rules")


def test_public_spec_does_not_pass_vulnerabilities_or_attack_paths_to_workers():
    spec = pairs.public_spec("1")
    assert len(spec["devices"]) == 4 and spec["target_network"] == "192.168.100.0/24"
    assert all(set(d) == {"id", "ip", "role", "services"} for d in spec["devices"])
    assert "attack_paths" not in json.dumps(spec) and "vulnerabilities" not in json.dumps(spec)


def test_personal_pve_is_refused_before_any_deployment(tmp_path, monkeypatch):
    monkeypatch.setattr(pairs, "ROOT", tmp_path)
    monkeypatch.setattr(pairs, "runtime_readiness", lambda: {"available": True})
    file = tmp_path / "benchmarks/ansible/inventory.yml"
    file.parent.mkdir(parents=True)
    file.write_text('all:\n  hosts:\n    proxmox:\n      ansible_host: 192.0.2.10\n')
    monkeypatch.setattr(pairs.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="pve\n"))
    with pytest.raises(pairs.PairPreparationError, match="identité"):
        pairs.verify_nato()


def test_each_preparation_explicitly_removes_before_idempotent_deployment(tmp_path, monkeypatch):
    from src.agent import pipeline
    calls = []
    def deployment(**kwargs):
        return SimpleNamespace(_run_teardown=lambda callback: calls.append("remove") or True,
                               _run_scenario_deploy=lambda callback: calls.append("deploy") or True)
    monkeypatch.setattr(pipeline, "Pipeline", deployment)
    runner = pairs.PairRunner(dict(CONFIG), root=tmp_path)
    runner._prepare("rules", threading.Event())
    runner._prepare("llm", threading.Event())
    assert calls == ["remove", "deploy", "remove", "deploy"]
