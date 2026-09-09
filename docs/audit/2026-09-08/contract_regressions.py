"""Offline adversarial examples of desired contracts (no tools or LLM run)."""
import asyncio
import json
import runpy
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.agent.cost_tracker import CostTracker
from src.agent.exploit_evidence import synthesize_exploit_result
from src.benchmark.evaluator import _compute_phase5_metrics, _phase5_access_success, evaluate
from src.benchmark.aggregate import aggregate_evaluations

_helpers = runpy.run_path(str(Path(__file__).resolve().parents[3] / "tests/test_evaluation_funnel.py"))
finding, write_run, confirmation, proof = [_helpers[k] for k in (
    "finding", "write_run", "confirmation", "proof",
)]


@pytest.mark.parametrize("url", [
    "http://192.0.2.99/backup.sql", "http://192.0.2.1:8080/backup.sql",
    "http://192.0.2.1/login",
])
def test_actual_probe_target_wins_over_claim_metadata(tmp_path, url):
    f = finding("a", "192.0.2.1")
    record = proof(f, args={"url": url}, device_ip=f["device_ip"], port=80, endpoint="/backup.sql")
    run, gt = write_run(tmp_path, [f], [f], [confirmation(f)], truth=[f], records=[record])
    actual = evaluate(run, gt, policy="strict-v3").funnel["stages"]["confirmed"]
    assert actual["true_positives"] == 0, actual


def test_ip_in_response_is_not_target_provenance(tmp_path):
    f = finding("a", "192.0.2.1")
    record = proof(f, args={"url": "http://192.0.2.99/backup.sql"},
                   result={"status_code": 200, "body": "password=secret source=192.0.2.1"})
    run, gt = write_run(tmp_path, [f], [f], [confirmation(f)], truth=[f], records=[record])
    actual = evaluate(run, gt, policy="strict-v3").funnel["stages"]["confirmed"]
    assert actual["true_positives"] == 0, actual


def test_duplicate_reference_cannot_transfer_a_different_targets_proof(tmp_path):
    f = finding("a", "192.0.2.1")
    records = [proof(f, result={"status_code": 200, "body": "Welcome"}),
               proof(f, args={"url": "http://192.0.2.99/backup.sql"})]
    run, gt = write_run(tmp_path, [f], [f], [confirmation(f)], truth=[f], records=records)
    actual = evaluate(run, gt, policy="strict-v3").funnel["stages"]["confirmed"]
    assert actual["true_positives"] == 0, actual


@pytest.mark.parametrize("record", [
    {"tool": "http_request", "result": {"status_code": 200, "body": "Welcome"}},
    {"tool": "tcp_send", "result": {"received_bytes": 2, "received_ascii": "OK"}},
    {"tool": "ssh_exec", "result": {"success": True, "return_code": 1, "stdout": ""}},
])
def test_service_contact_or_contradictory_flag_does_not_prove_control(record):
    assert not _phase5_access_success(record, full_profile=True)


@pytest.mark.parametrize("reverse_order", [False, True])
def test_two_direct_logins_do_not_prove_network_pivot(tmp_path, reverse_order):
    a, b = "192.0.2.1", "192.0.2.2"
    (tmp_path / "05_intrusion.json").write_text(json.dumps({"chains": [{"hops": [
        {"device_ip": a, "pivot_to": b}, {"device_ip": b},
    ]}]}))
    records = [{"phase": 5, "tool": "ssh_exec", "args": {"ip": ip, "command": "id"},
                "result": {"return_code": 0, "stdout": "uid=1000(user)"}}
               for ip in ([b, a] if reverse_order else [a, b])]
    metrics = _compute_phase5_metrics(tmp_path,
        [{"ip": a, "hop_depth": 0}, {"ip": b, "hop_depth": 1}],
        [{"chain": [{"device": a}, {"device": b}]}], records)
    assert metrics["phase5_verified_hops"] == 0, metrics
    assert metrics["verified_expected_paths"] == [False], metrics


@pytest.mark.parametrize("vuln_type,tool,args,result", [
    ("data_exposure", "ssh_exec", {}, {"return_code": 0, "stdout": "uid=1000(user)"}),
    ("no_auth", "mysql_query", {"password": "legitimate-password"}, {"return_code": 0, "stdout": "version\n8.0"}),
    ("data_exposure", "telnet_connect", {}, {"return_code": 0, "stdout": "Welcome to device"}),
    ("data_exposure", "tcp_send", {}, {"received_bytes": 2, "received_ascii": "OK"}),
    ("no_auth", "http_request", {"headers": {"Authorization": "Bearer legitimate-token"}},
     {"status_code": 200, "body": "admin dashboard configuration"}),
])
def test_proof_must_establish_claimed_property(vuln_type, tool, args, result):
    verdict = synthesize_exploit_result({"id": "a", "type": vuln_type}, [
        {"tool": tool, "args": args, "result": result},
    ])
    assert verdict["status"] != "EXPLOITED", verdict


def test_running_phase_usage_is_visible_before_completion():
    with patch("src.agent.cost_tracker._resolve_pricing", return_value=({"input": 1.0, "output": 3.0}, "test", False)):
        tracker = CostTracker(model="offline-fixture")
        tracker.start_phase("verification")
        tracker.record_turn(1000, 100)
        assert tracker.total_tokens() == (1000, 100)
        assert tracker.total_cost() == pytest.approx(.0013)


def test_two_sse_subscribers_each_receive_the_same_event():
    from src.api.routes import pipeline

    async def exercise():
        queue = asyncio.Queue()
        queue.put_nowait({"type": "phase_start", "phase": 1})
        queue.put_nowait({"type": "__done__"})
        with patch.dict(pipeline._state, {"queue": queue}):
            responses = [await pipeline.stream_events() for _ in range(2)]
            received = []
            for response in responses:
                try:
                    received.append(await anext(response.body_iterator))
                except StopAsyncIteration:
                    received.append(None)
                await response.body_iterator.aclose()
            assert received[0] == received[1], received

    asyncio.run(exercise())


def runner_stub(tmp_path, *, compact=False):
    return SimpleNamespace(
        run_dir=tmp_path, _artifact_log_lock=threading.Lock(), max_tool_calls=None,
        _tool_call_count=0, benchmark_split="dev", _uses_compact_local_moe=lambda: compact,
        context={"target_subnet": "192.0.2.0/24"},
    )


def test_structured_result_survives_tool_logging(tmp_path):
    from src.agent.core.runner import AgentRunner
    result = {"return_code": 0, "body": "offline fixture"}
    wrapped = AgentRunner._wrap_tool(runner_stub(tmp_path),
        {"name": "fixture", "function": lambda **kw: result}, phase=4)
    wrapped["function"]()
    record = json.loads((tmp_path / "tool_calls.jsonl").read_text())
    decoded = record["result"]
    if isinstance(decoded, str):
        decoded = json.loads(decoded)
    assert decoded == result


@pytest.mark.parametrize("phase,compact", [(2, True), (4, True), (5, False)])
def test_scope_boundary_applies_to_every_execution_profile_and_phase(tmp_path, phase, compact):
    from src.agent.core.runner import AgentRunner
    executed = []
    wrapped = AgentRunner._wrap_tool(runner_stub(tmp_path, compact=compact),
        {"name": "http_get", "function": lambda **kw: executed.append(kw) or "{}"}, phase=phase)
    wrapped["function"](url="http://198.51.100.1/")
    assert not executed, "Out-of-scope call reached the mocked executor"


def test_failed_evidence_write_is_not_silently_successful(tmp_path):
    from src.agent.core.runner import AgentRunner
    stub = runner_stub(tmp_path / "nonexistent-run-dir")
    wrapped = AgentRunner._wrap_tool(stub,
        {"name": "fixture", "function": lambda **kw: '{"success":true}'}, phase=4)
    with pytest.raises((OSError, RuntimeError)):
        wrapped["function"]()


def test_incompatible_experiment_settings_cannot_form_one_model_score():
    rows = [{"scenario_id": "demo", "total_gt_vulns": 1,
             "model": model, "execution_profile": profile, "blind": blind,
             "scoring_policy": "strict-v3", "scenario_score_pct": score,
             "metric_contract_version": "strict-v3.6", "evidence_contract_version": "evidence-v4"}
            for model, profile, blind, score in [
                ("model-A", "compact", True, 0), ("model-B", "full", False, 100)]]
    with pytest.raises(ValueError):
        aggregate_evaluations(rows)


def test_optional_legacy_verified_metric_keeps_missing_trial_visible(tmp_path):
    f = finding("a", "192.0.2.1")
    run, gt = write_run(tmp_path, [f], [f], [confirmation(f)], truth=[f], records=[proof(f)])
    complete = evaluate(run, gt, policy="strict-v3")
    (run / "04_exploitation.json").unlink()
    incomplete = evaluate(run, gt, policy="strict-v3")
    aggregate = aggregate_evaluations([complete, incomplete])
    assert aggregate["macro_verified_f1"] is None, aggregate["macro_verified_f1"]


def test_artifact_presence_does_not_override_failed_run_status(tmp_path):
    from src.api.routes.runs import _run_status
    (tmp_path / "06_report.md").write_text("Partial report generated before failure")
    (tmp_path / "run_meta.json").write_text(json.dumps({"status": "failed"}))
    assert _run_status(tmp_path) != "done"


def test_valid_proof_is_still_credited(tmp_path):
    f = finding("a", "192.0.2.1")
    run, gt = write_run(tmp_path, [f], [f], [confirmation(f)], truth=[f], records=[proof(f)])
    assert evaluate(run, gt, policy="strict-v3").funnel["stages"]["confirmed"]["true_positives"] == 1


def test_missing_proof_is_not_credited(tmp_path):
    f = finding("a", "192.0.2.1")
    run, gt = write_run(tmp_path, [f], [f], [confirmation(f)], truth=[f], records=[])
    assert evaluate(run, gt, policy="strict-v3").funnel["stages"]["confirmed"]["true_positives"] == 0


def test_scope_guard_already_blocks_compact_phase5(tmp_path):
    from src.agent.core.runner import AgentRunner
    executed = []
    wrapped = AgentRunner._wrap_tool(runner_stub(tmp_path, compact=True),
        {"name": "http_get", "function": lambda **kw: executed.append(kw) or "{}"}, phase=5)
    wrapped["function"](url="http://198.51.100.1/")
    assert not executed


def test_phase_usage_is_retained_after_completion():
    with patch("src.agent.cost_tracker._resolve_pricing", return_value=({"input": 1.0, "output": 3.0}, "test", False)):
        tracker = CostTracker(model="offline-fixture")
        tracker.start_phase("verification")
        tracker.record_turn(1000, 100)
        tracker.end_phase()
        assert tracker.total_tokens() == (1000, 100)
        assert tracker.total_cost() == pytest.approx(.0013)


def test_failed_authentication_is_not_control():
    assert not _phase5_access_success({"tool": "ssh_exec", "result": {"authenticated": False, "success": True}}, full_profile=True)


def test_fresh_mqtt_payload_is_not_replaced_by_previous_values():
    from src.agent.tools.tool_loader import DEFINITIONS_DIR, build_subprocess_function, load_tool_yaml
    first = 'sensors/state {"status":"locked","value":1}'
    second = 'sensors/state {"status":"unlocked","value":2}'
    with patch(
        "src.agent.tools.recon_tools._run", side_effect=[
            {"return_code": 0, "stdout": first}, {"return_code": 0, "stdout": second},
        ]
    ):
        fn = build_subprocess_function(load_tool_yaml(DEFINITIONS_DIR / "mqtt_listen.yaml"))
        assert json.loads(fn(broker="192.0.2.1", topic="#"))["stdout"] == first
        assert json.loads(fn(broker="192.0.2.1", topic="#"))["stdout"] == second


def test_api_cannot_modify_provider_without_authentication():
    from fastapi.testclient import TestClient
    from src.api.main import app
    saved = {}
    fake_db = SimpleNamespace(
        upsert_provider=lambda **kw: saved.update(kw),
        get_provider=lambda name: dict(saved),
    )
    with patch("src.api.routes.providers._require_db", return_value=fake_db):
        response = TestClient(app).post("/api/providers", json={
            "name": "offline-fixture", "base_url": "https://example.invalid/v1",
            "api_key_env": "OFFLINE_FIXTURE_KEY",
        })
    assert response.status_code in {401, 403}, response.status_code


def test_available_tokens_do_not_require_format_validation_counters():
    import shutil
    import subprocess
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the offline dashboard renderer check")
    script = '''
        const fs = require('fs'), vm = require('vm');
        const s = fs.readFileSync('src/static/app.js', 'utf8');
        const ctx = {escapeHtml: x => String(x ?? '')};
        vm.createContext(ctx);
        vm.runInContext(s.slice(s.indexOf('function bmNumber('), s.indexOf('function renderBenchmarkTable(')), ctx);
        const html = ctx.renderFunnelDiagnostics({}, {total_tokens: 1234, process_metrics_available: false});
        if (!html.includes('Tokens')) process.exit(1);
    '''
    assert subprocess.run([node, "-e", script], check=False).returncode == 0
