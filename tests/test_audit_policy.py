"""Offline experiment tests: real orchestration/scanner/evidence, simulated I/O."""
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from src.agent.audit_experiment import validate_inventory
from src.agent.core import runtime
from src.agent.core.executor import EvidenceWriteError, RunStopped
from src.agent.cost_tracker import BudgetExceeded
from src.agent.pipeline import Pipeline
from src.agent.provider import LLMProvider
from src.agent.registry import AGENTS
from src.benchmark.compare_policies import compare_runs
from src.benchmark.evaluator import evaluate


@pytest.fixture
def inventory():
    return {
        "schema_version": 1, "provenance": "Public inventory for simulated unit tests",
        "target_network": "192.0.2.0/24",
        "devices": [{"id": "web", "ip": "192.0.2.10", "services": [{"name": "http", "port": 80}]}],
        "experiment": {"id": "offline", "family_id": "http", "instance_id": "fixture",
                       "trial_id": "1", "environment_sha256": "a" * 64},
    }


@pytest.fixture
def offline_tools(monkeypatch):
    calls = []
    behavior = {"positive": False, "error": False}

    def probe(**kwargs):
        calls.append(kwargs)
        if behavior["error"]:
            raise TimeoutError("simulated tool failure")
        if behavior["positive"] and kwargs["url"].endswith("/backup/"):
            stdout = 'HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<h1>Index of /backup/</h1><a href="credentials.txt">credentials.txt</a>'
        elif behavior["positive"] and kwargs["url"].endswith("credentials.txt"):
            stdout = "HTTP/1.1 200 OK\r\n\r\nusername=admin\npassword=demo-test-password"
        else:
            stdout = "HTTP/1.1 403 Forbidden\r\n\r\nAccess denied"
        return json.dumps({"stdout": stdout, "return_code": 0})

    recon = [{"name": name, "description": "Simulated HTTP tool", "input_schema": {"type": "object", "properties": {}}, "function": probe}
             for name in ("curl_headers", "http_get")]
    monkeypatch.setattr(runtime, "RECON_TOOLS", recon)
    monkeypatch.setattr(runtime, "TOOL_GROUPS", {**runtime.TOOL_GROUPS, "recon": recon})
    monkeypatch.setattr(runtime, "filter_unavailable_tools", lambda tools: (tools, []))
    monkeypatch.setattr("src.agent.tools.tool_loader.filter_unavailable_tools", lambda tools: (tools, []))
    monkeypatch.setattr(Pipeline, "_persist_run", lambda *_: None)
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", lambda *_: None)
    yield calls, behavior
    from src.agent.tools.graph_tools import _reset_graph_context
    _reset_graph_context()
    runtime.set_cve_cache_only(False)


def make_run(tmp_path, inventory, policy="rules", **overrides):
    settings = dict(decision_policy=policy, experiment_scope="analysis-verification",
                    audit_inventory=inventory, execution_profile="full", max_tool_calls=200,
                    max_duration_s=60, output_dir=tmp_path)
    settings.update(overrides)
    return Pipeline(**settings)


def simulated_llm(run):
    """Protocol double, not an experimental LLM treatment or a measured result."""
    def chat(**kwargs):
        kwargs["cost_tracker"].record_turn(10, 5, 1)
        tools = {tool["name"]: tool["function"] for tool in kwargs["tools"]}
        if kwargs["user_message"].startswith("Review scan"):
            content = (run.run_dir / "03_device_web.json").read_text()
            receipt = json.loads(tools["save_deliverable"](filename="03_device_web.json", content=content))
            assert receipt["validated"] and receipt["status"] == "saved"
        else:
            from src.agent.phases.verification.contract import _phase4_verification_plan
            claim = run._exploit_tool_context.vulnerability
            vuln = next(v for v in json.loads((run.run_dir / "03_vuln_analysis.json").read_text())["vulnerabilities"] if v["id"] == claim["vuln_id"])
            plan = _phase4_verification_plan(vuln, compact=False)
            tools[plan["tool"]](**plan["args_hint"])
        return "Simulated completion"
    run.provider.chat_with_tools = chat


def truth_file(tmp_path, *, positive=False):
    path = tmp_path / "ground_truth.yaml"
    path.write_text(yaml.safe_dump({"scenario_id": "fixture", "vulnerabilities": [{
        "id": "GT1", "title": "Public directory listing", "ip": "192.0.2.10",
        "accepted_types": ["directory_listing"], "severity": "low",
        "services": ["http"], "ports": [80], "protocols": ["tcp"], "endpoints": ["/backup/"],
    }] if positive else []}))
    return path


@pytest.mark.parametrize("positive", [False, True])
def test_real_pipeline_rules_then_llm_pair(tmp_path, inventory, offline_tools, monkeypatch, positive):
    calls, behavior = offline_tools
    behavior["positive"] = positive
    # Even price discovery is forbidden on the no-model path.
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", lambda *_: pytest.fail("rules accessed pricing"))
    run = make_run(tmp_path, inventory)
    result = run.run()
    assert result == {"vuln_analysis": "completed", "exploitation": "completed"}
    assert not (run.run_dir / "02_recon.md").exists()
    assert not (run.run_dir / "05_intrusion.json").exists()
    records = [json.loads(line) for line in (run.run_dir / "tool_calls.jsonl").read_text().splitlines()]
    assert {r["decision_source"] for r in records} == {"rules"}
    assert len({r["evidence_ref"] for r in records}) == len(records) == len(calls)
    summary = json.loads((run.run_dir / "cost_summary.json").read_text())
    assert summary["total_tool_calls"] == len(records)
    assert summary["total_turns"] == summary["total_input_tokens"] == summary["total_cost_usd"] == 0
    assert summary["metrics_schema_version"] == 3
    scans = json.loads((run.run_dir / "03_scans/web.json").read_text())
    assert all(item["evidence_ref"] in {r["evidence_ref"] for r in records} for entries in scans.values() for item in entries)
    if positive:
        assert any(c["url"].endswith("credentials.txt") for c in calls)  # conditional follow-up
        assert any(r["phase"] == 4 for r in records)
    truth = truth_file(tmp_path, positive=positive)
    evaluated = evaluate(run.run_dir, truth)
    assert evaluated.comparability_reason is None
    assert evaluated.funnel["stages"]["confirmed"]["available"]
    if positive:
        assert evaluated.funnel["stages"]["confirmed"]["true_positives"] == 1
    if not positive:
        assert evaluated.specificity == 1
        assert evaluated.verified_f1 is None
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", lambda *_: None)
    provider = SimpleNamespace(model="offline-model", provider="offline-test")
    llm = make_run(tmp_path, inventory, "llm", provider=provider)
    simulated_llm(llm)
    assert llm.run() == {"vuln_analysis": "completed", "exploitation": "completed"}
    pair = compare_runs(run.run_dir, llm.run_dir, truth)
    assert pair["comparable"], pair["incomparability_reasons"]
    assert pair["delta_llm_minus_rules"]["filtered.false_positives"] == 0
    assert pair["delta_llm_minus_rules"]["confirmed.true_positives"] == 0
    assert pair["delta_llm_minus_rules"]["total_turns"] > 0
    if not positive:
        assert pair["delta_llm_minus_rules"]["confirmed.f1"] is None
        assert pair["arms"]["rules"]["metrics"]["llm_cost_per_confirmed_tp"] is None
    meta = json.loads((llm.run_dir / "run_meta.json").read_text())
    meta["max_tool_calls"] += 1
    (llm.run_dir / "run_meta.json").write_text(json.dumps(meta))
    mismatch = compare_runs(run.run_dir, llm.run_dir, truth)
    assert not mismatch["comparable"] and mismatch["delta_llm_minus_rules"] is None
    assert "pair: incompatible max_tool_calls" in mismatch["incomparability_reasons"]
    assert not compare_runs(run.run_dir, None, truth)["comparable"]
    meta["max_tool_calls"] -= 1
    (llm.run_dir / "run_meta.json").write_text(json.dumps(meta))
    (llm.run_dir / "tool_calls.jsonl").unlink()
    missing_proof = compare_runs(run.run_dir, llm.run_dir, truth)
    assert not missing_proof["comparable"]
    assert "llm: missing evaluable stage artifacts" in missing_proof["incomparability_reasons"]


def test_rules_budget_stops_scanner_and_persists_terminal_state(tmp_path, inventory, offline_tools):
    run = make_run(tmp_path, inventory, max_tool_calls=2)
    with pytest.raises(BudgetExceeded):
        run.run()
    assert len(offline_tools[0]) == 2
    meta = json.loads((run.run_dir / "run_meta.json").read_text())
    assert meta["status"] == "budget_exceeded"
    assert json.loads((run.run_dir / "cost_summary.json").read_text())["total_tool_calls"] == 2


def test_tool_errors_do_not_certify_clean_control(tmp_path, inventory, offline_tools):
    offline_tools[1]["error"] = True
    run = make_run(tmp_path, inventory)
    run.run()
    result = evaluate(run.run_dir, truth_file(tmp_path))
    assert result.specificity is None
    assert result.phase3_status == "completed_with_device_errors"
    assert result.total_tool_errors == result.total_tool_calls > 0


@pytest.mark.parametrize("error_type", [BudgetExceeded, EvidenceWriteError])
def test_provider_cannot_swallow_executor_terminal_errors(error_type):
    def fail():
        raise error_type("terminal")
    with pytest.raises(error_type):
        LLMProvider._execute_tool("probe", {}, {"probe": fail})


def test_common_executor_stop_deadline_and_archive_failure(tmp_path, inventory, offline_tools):
    run = make_run(tmp_path, inventory)
    tool = run._wrap_tool({"name": "probe", "function": lambda: "ok"}, phase=3)["function"]
    run._stop_event = threading.Event()
    run._stop_event.set()
    with pytest.raises(RunStopped):
        tool()
    run._stop_event.clear()
    run._run_started = time.monotonic() - 100
    with pytest.raises(BudgetExceeded):
        tool()
    run._run_started = time.monotonic()
    run._execution_limit_reason = None
    (run.run_dir / "tool_calls.jsonl").mkdir()
    with pytest.raises(EvidenceWriteError):
        tool()
    assert run.tracker.summary()["total_tool_calls"] == 1
    with pytest.raises(EvidenceWriteError):
        tool()
    assert run.tracker.summary()["total_tool_calls"] == 1


@pytest.mark.parametrize("change", [
    {"experiment_scope": None}, {"execution_profile": "auto"}, {"phases": [4]},
    {"max_tool_calls": None}, {"max_duration_s": float("nan")}, {"scenario_id": "1"},
    {"dry_run": True}, {"phase_models": {3: "model"}},
])
def test_invalid_experiment_rejected_before_run_directory(tmp_path, inventory, change):
    with pytest.raises(ValueError):
        make_run(tmp_path, inventory, **change)
    assert not list(tmp_path.iterdir())


def test_inventory_rejects_oracle_fields_and_unsafe_target(inventory):
    inventory["ground_truth"] = []
    with pytest.raises(ValueError):
        validate_inventory(inventory)
    del inventory["ground_truth"]
    inventory["devices"][0]["ip"] = "198.51.100.10"
    with pytest.raises(ValueError):
        validate_inventory(inventory)


def test_rules_cli_does_not_construct_provider(tmp_path, inventory, offline_tools, monkeypatch):
    from src.agent import __main__ as cli
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(inventory))
    monkeypatch.setattr(cli, "LLMProvider", lambda **_: pytest.fail("rules constructed provider"))
    monkeypatch.setattr("src.agent.pipeline.OUTPUT_DIR", tmp_path)
    monkeypatch.setattr("sys.argv", ["lance", "--decision-policy", "rules", "--experiment-scope", "analysis-verification", "--audit-inventory", str(path), "--execution-profile", "full", "--max-tool-calls", "100", "--max-duration-s", "60"])
    cli.main()


def test_api_rejects_experiment_instead_of_ignoring_it():
    from pydantic import ValidationError
    from src.api.routes.pipeline import StartRequest
    with pytest.raises(ValidationError, match="CLI-only"):
        StartRequest(model="test", provider="openrouter", decision_policy="rules")


@pytest.mark.parametrize("bad_url", ["http://192.0.2.99/backup/", "http://192.0.2.10/unrelated/"])
def test_rules_cannot_confirm_wrong_target_or_endpoint(tmp_path, inventory, offline_tools, monkeypatch, bad_url):
    from src.agent.phases.verification import rules
    run = make_run(tmp_path, inventory)
    run.context["target_subnet"] = inventory["target_network"]
    finding = {"id": "V1", "device_id": "web", "device_ip": "192.0.2.10", "type": "directory_listing",
               "service": "http", "port": 80, "protocol": "tcp", "endpoint": "/backup/", "severity": "LOW"}
    (run.run_dir / "03_vuln_analysis.json").write_text(json.dumps({"vulnerabilities": [finding]}))
    monkeypatch.setattr(rules, "_phase4_verification_plan", lambda *_args, **_kwargs: {"tool": "curl_headers", "args_hint": {"url": bad_url}})
    result = json.dumps({"return_code": 0, "stdout": "HTTP/1.1 200 OK\r\n\r\n<h1>Index of /backup/</h1>"})
    probe = run._wrap_tool({"name": "curl_headers", "function": lambda **_: result}, phase=4)
    monkeypatch.setattr(run, "_resolve_tools", lambda _: [probe])
    rules.verify(run, AGENTS["exploitation"])
    tests = json.loads((run.run_dir / "04_exploitation.json").read_text())["tests"]
    assert tests[0]["status"] != "CONFIRMED"
    assert tests[0]["evidence_level"] < 2


def test_unavailable_scanner_rule_cannot_certify_control(tmp_path, inventory, offline_tools):
    inventory["devices"][0]["services"] = [{"name": "unrecognized-protocol", "port": 12345}]
    run = make_run(tmp_path, inventory)
    run.run()
    assert evaluate(run.run_dir, truth_file(tmp_path)).specificity is None
