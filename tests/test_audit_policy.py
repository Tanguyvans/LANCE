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


@pytest.mark.parametrize("case, expected_calls, confirmed", [
    ("retry", 2, True), ("adapter_timeout", 2, True), ("process_timeout", 2, True),
    ("structured_fallback", 2, True), ("retry_and_fallback", 3, True),
    ("denied", 1, False), ("permanent_error", 1, False),
    ("exhausted", 2, False), ("post_timeout", 1, False),
    ("budget", 1, False), ("archive_failure", 1, False),
])
def test_bounded_rules_recovery_preserves_evidence_and_limits(
    tmp_path, inventory, offline_tools, monkeypatch, case, expected_calls, confirmed,
):
    from src.agent.phases.verification import rules
    run = make_run(tmp_path, inventory, max_tool_calls=1 if case == "budget" else 10)
    run.context["target_subnet"] = inventory["target_network"]
    finding = {"id": "V1", "device_id": "web", "device_ip": "192.0.2.10", "type": "directory_listing",
               "service": "http", "port": 80, "protocol": "tcp", "endpoint": "/backup/", "severity": "LOW"}
    (run.run_dir / "03_vuln_analysis.json").write_text(json.dumps({"vulnerabilities": [finding]}))
    url = "http://192.0.2.10/backup/"
    if case == "post_timeout":
        monkeypatch.setattr(rules, "_phase4_verification_plan", lambda *_, **__: {
            "tool": "http_request", "args_hint": {"url": url, "method": "POST", "body": "test"},
        })
    calls = []

    def probe(name, **args):
        calls.append((name, args))
        if case in {"exhausted", "budget", "post_timeout"} or (
                case in {"retry", "retry_and_fallback"} and len(calls) == 1):
            raise TimeoutError("simulated timeout")
        if case == "adapter_timeout" and len(calls) == 1:
            return json.dumps({"return_code": 28, "stderr": "curl timeout"})
        if case == "process_timeout" and len(calls) == 1:
            return json.dumps({"return_code": -1, "stderr": "Command timed out after 10s: curl"})
        if case == "denied":
            return json.dumps({"return_code": 0, "stdout": "HTTP/1.1 403 Forbidden\r\n\r\nAccess denied"})
        if case == "permanent_error":
            raise ValueError("invalid tool argument")
        if case in {"structured_fallback", "retry_and_fallback"} and name == "http_get":
            return json.dumps({"return_code": 0, "stdout": "Ambiguous short body"})
        body = '<h1>Index of /backup/</h1><a href="credentials.txt">credentials.txt</a>'
        return json.dumps({"status_code": 200, "body": body} if name == "http_request"
                          else {"return_code": 0, "stdout": "HTTP/1.1 200 OK\r\n\r\n" + body})

    probes = [run._wrap_tool({"name": name, "function": lambda _name=name, **args: probe(_name, **args)}, phase=4)
              for name in ("http_get", "http_request")]
    monkeypatch.setattr(run, "_resolve_tools", lambda _: probes)
    if case == "archive_failure":
        (run.run_dir / "04_rules_decisions.jsonl").mkdir()
    terminal = {"budget": BudgetExceeded, "archive_failure": EvidenceWriteError}.get(case)
    if terminal:
        with pytest.raises(terminal):
            rules.verify(run, AGENTS["exploitation"])
        assert not (run.run_dir / "04_exploitation.json").exists()
    else:
        rules.verify(run, AGENTS["exploitation"])
        result = json.loads((run.run_dir / "04_exploitation.json").read_text())["tests"][0]
        assert (result["status"] == "CONFIRMED") is confirmed
        assert (result["evidence_level"] >= 2) is confirmed
        if case in {"exhausted", "post_timeout", "permanent_error"}:
            assert "V1" in run._phase4_execution_errors
    records = [json.loads(line) for line in (run.run_dir / "tool_calls.jsonl").read_text().splitlines()]
    assert len(calls) == len(records) == expected_calls == run.tracker.summary()["total_tool_calls"]
    assert all(args["url"] == url for _, args in calls)
    if "fallback" in case:
        assert calls[-1] == ("http_request", {"url": url, "method": "GET", "follow_redirects": False})
    if case != "archive_failure":
        decisions = [json.loads(line) for line in (run.run_dir / "04_rules_decisions.jsonl").read_text().splitlines()]
        assert [d["evidence_ref"] for d in decisions] == [r["evidence_ref"] for r in records]
        assert len(decisions) == expected_calls


@pytest.fixture
def campaign_pair(tmp_path, inventory, offline_tools):
    """Real paired artifacts; every network/model operation is a test double."""
    from src.benchmark.policy_campaign import CONFIG_FIELDS
    rules = make_run(tmp_path, inventory)
    rules.run()
    llm = make_run(tmp_path, inventory, "llm", provider=SimpleNamespace(model="offline-model", provider="offline-test"))
    simulated_llm(llm)
    llm.run()
    meta = json.loads((llm.run_dir / "run_meta.json").read_text())
    preflight = tmp_path / "preflight.txt"
    preflight.write_text("Independent environment check fixture; no actual laboratory")
    trial = {key: inventory["experiment"][key] for key in ("trial_id", "family_id", "instance_id")}
    trial.update(order=["rules", "llm"], ground_truth=truth_file(tmp_path).name, arms={
        policy: {"run_dir": str(run.run_dir), "preflight": {"status": "valid", "evidence_ref": preflight.name}}
        for policy, run in (("rules", rules), ("llm", llm))
    })
    manifest = {"schema_version": 1, "campaign_id": inventory["experiment"]["id"],
                "configuration": {key: meta[key] for key in CONFIG_FIELDS}, "trials": [trial]}
    return manifest, tmp_path / "campaign.json"


def test_campaign_retains_all_planned_trials_and_failed_costs(campaign_pair, tmp_path, monkeypatch):
    from src.benchmark.policy_campaign import main, summarize_campaign
    manifest, path = campaign_pair
    trial = json.loads(json.dumps(manifest["trials"][0]))
    trial["trial_id"] = "failed"
    failed_dir = tmp_path / "failed"
    failed_dir.mkdir()
    original = Path(trial["arms"]["llm"]["run_dir"])
    meta = json.loads((original / "run_meta.json").read_text())
    meta.update(status="failed", usage_status="incomplete")
    meta["experiment"]["trial_id"] = "failed"
    (failed_dir / "run_meta.json").write_text(json.dumps(meta))
    (failed_dir / "cost_summary.json").write_text(json.dumps({"total_cost_usd": 0.4, "total_tool_calls": 3}))
    trial["arms"]["llm"]["run_dir"] = str(failed_dir)
    trial["arms"]["rules"]["run_dir"] = None
    manifest["trials"].append(trial)
    absent = json.loads(json.dumps(trial))
    absent["trial_id"] = "not-ready"
    absent["ground_truth"] = None
    for arm in absent["arms"].values():
        arm["run_dir"] = None
        arm["preflight"]["status"] = "invalid"
    manifest["trials"].append(absent)
    path.write_text(json.dumps(manifest))
    report = summarize_campaign(path)
    assert report["planned_pairs"] == 3 and report["eligible_pairs"] == 1
    assert len(report["trials"]) == 6
    assert report["operational"]["rules"]["outcomes"] == {"usable": 1, "not_run": 1, "environment_invalid": 1}
    assert report["operational"]["llm"]["outcomes"] == {"usable": 1, "failed": 1, "environment_invalid": 1}
    for policy in ("rules", "llm"):
        assert report["operational"][policy]["usable_fraction_of_planned"] == 1 / 3
        assert report["operational"][policy]["resources"]["total_cost_usd"]["complete_total"] is None
    costs = report["operational"]["llm"]["resources"]["total_cost_usd"]
    first_cost = json.loads((original / "cost_summary.json").read_text())["total_cost_usd"]
    assert costs["sum_observed"] == pytest.approx(first_cost + 0.4)
    assert costs["observed_runs"] == 2
    assert not report["uncertainty"]["available"]
    assert report["unfixed_configuration_fields"] == []
    assert report["technical_on_eligible_pairs"][0]["families"][0]["delta_means"]["confirmed.f1"]["mean"] is None
    assert all(row["quality"]["confirmed.f1"] is None for row in report["trials"])
    assert all(row["quality"]["specificity"] == 1 for row in report["trials"][:2])
    output, csv_path = tmp_path / "report.json", tmp_path / "report.csv"
    monkeypatch.setattr("sys.argv", ["campaign", "--manifest", str(path), "--output", str(output), "--csv", str(csv_path)])
    assert main() == 0
    assert json.loads(output.read_text())["eligible_pairs"] == 1
    import csv
    with csv_path.open() as handle:
        assert len(list(csv.DictReader(handle))) == 6


@pytest.mark.parametrize("change, outcome, eligible", [
    ("missing_partner", "not_run", 0), ("wrong_model", "configuration_mismatch", 0),
    ("wrong_trial", "configuration_mismatch", 0), ("missing_preflight", "environment_unverified", 0),
    ("invalid_preflight", "protocol_violation", 0), ("over_budget", "budget_exceeded", 0),
    ("missing_truth", "completed_unusable", 0), ("bad_truth", "completed_unusable", 0),
    ("empty_truth", "completed_unusable", 0), ("corrupt_cost", "completed_unusable", 0),
])
def test_campaign_excludes_ineligible_pairs_without_losing_arms(campaign_pair, change, outcome, eligible):
    from src.benchmark.policy_campaign import summarize_campaign
    manifest, path = campaign_pair
    trial = manifest["trials"][0]
    arm = trial["arms"]["llm"]
    if change == "missing_partner":
        arm["run_dir"] = None
    elif change == "wrong_model":
        manifest["configuration"]["model"] = "different-model"
    elif change == "wrong_trial":
        trial["trial_id"] = "wrong"
    elif change == "missing_preflight":
        arm["preflight"]["evidence_ref"] = "absent.txt"
    elif change == "invalid_preflight":
        arm["preflight"]["status"] = "invalid"
    elif change == "over_budget":
        cost_path = Path(arm["run_dir"]) / "cost_summary.json"
        cost = json.loads(cost_path.read_text())
        cost["total_tool_calls"] = manifest["configuration"]["max_tool_calls"] + 1
        cost_path.write_text(json.dumps(cost))
    elif change == "missing_truth":
        trial["ground_truth"] = None
    elif change == "empty_truth":
        (path.parent / trial["ground_truth"]).write_text("")
    elif change == "corrupt_cost":
        (Path(arm["run_dir"]) / "cost_summary.json").write_text("[]")
    else:
        (path.parent / trial["ground_truth"]).write_text("vulnerabilities: [unterminated")
    path.write_text(json.dumps(manifest))
    report = summarize_campaign(path)
    assert report["eligible_pairs"] == eligible
    assert len(report["trials"]) == 2 and report["technical_on_eligible_pairs"] == []
    assert report["operational"]["llm"]["outcomes"] == {outcome: 1}
    if change == "missing_partner":
        assert report["operational"]["rules"]["outcomes"] == {"usable": 1}
    assert all(summary["planned"] == 1 for summary in report["operational"].values())


@pytest.mark.parametrize("change", ["duplicate_trial", "reused_run", "invalid_order", "bad_preflight", "invalid_budget"])
def test_campaign_rejects_ambiguous_manifest(tmp_path, change):
    from src.benchmark.policy_campaign import load_manifest
    template = Path(__file__).parents[1] / "benchmarks/experiments/policy-comparison/pilot.example.json"
    manifest = json.loads(template.read_text())
    trial = manifest["trials"][0]
    if change == "duplicate_trial":
        manifest["trials"].append(trial)
    elif change == "reused_run":
        trial["arms"]["rules"]["run_dir"] = "same-run"
        trial["arms"]["llm"]["run_dir"] = "same-run"
    elif change == "invalid_order":
        trial["order"] = ["rules", "rules"]
    elif change == "invalid_budget":
        manifest["configuration"] = {"max_tool_calls": True}
    else:
        trial["arms"]["llm"]["preflight"]["evidence_ref"] = []
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        load_manifest(path)


@pytest.mark.parametrize("different_model", [False, True], ids=["same-configuration", "separate-models"])
def test_campaign_groups_only_compatible_pairs(campaign_pair, tmp_path, inventory, different_model):
    from src.benchmark.policy_campaign import summarize_campaign
    manifest, path = campaign_pair
    # An exploratory manifest can contain several configurations, but their
    # technical deltas must stay separate. This is not a frozen single-model plan.
    manifest["configuration"].pop("model")
    inventory = json.loads(json.dumps(inventory))
    inventory["experiment"]["trial_id"] = "second-pair"
    trial = json.loads(json.dumps(manifest["trials"][0]))
    trial["trial_id"] = "second-pair"
    for policy in ("rules", "llm"):
        settings = {} if policy == "rules" else {
            "provider": SimpleNamespace(model="another-model" if different_model else "offline-model", provider="offline-test"),
        }
        run = make_run(tmp_path, inventory, policy, **settings)
        if policy == "llm":
            simulated_llm(run)
        run.run()
        trial["arms"][policy]["run_dir"] = str(run.run_dir)
    manifest["trials"].append(trial)
    path.write_text(json.dumps(manifest))
    report = summarize_campaign(path)
    assert report["eligible_pairs"] == 2
    groups = report["technical_on_eligible_pairs"]
    assert len(groups) == (2 if different_model else 1)
    assert [group["families"][0]["evaluable_pairs"] for group in groups] == ([1, 1] if different_model else [2])
    assert report["unfixed_configuration_fields"] == ["model"]
