"""MQTT V2 software calibration: real executor/tool adapter, simulated broker I/O."""
import hashlib
import json
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from src.agent.audit_experiment import digest
from src.agent.tools import recon_tools
from benchmarks.experiments.mqtt_reference import (
    CONTRACT, bind_mqtt_tool, evaluate_trial, run_rules, validate_briefing,
)

PUBLIC_PAYLOAD = "fresh-public-canary"
PRIVATE_PAYLOAD = "fresh-private-canary"


@pytest.fixture
def briefing():
    return {
        "schema_version": 1, "scenario_id": "s_mqtt_lecture", "instance_id": "development-01",
        "target_network": "192.0.2.0/24",
        "target": {"asset_id": "broker", "ip": "192.0.2.18", "port": 1883},
        "public_topic": "lance/public/status",
        "private_topic": "lance/private/telemetry",
        "control_credential": {"username": "auditor", "password": "development-control-only"},
        "listen": {"count": 2, "timeout_s": 5},
    }


def oracle_for(briefing, positive):
    return {"schema_version": 1, "briefing_sha256": digest(briefing),
            "intentional_flaws": int(positive),
            "private_canary_sha256": hashlib.sha256(PRIVATE_PAYLOAD.encode()).hexdigest(),
            "public_canary_sha256": hashlib.sha256(PUBLIC_PAYLOAD.encode()).hexdigest()}


def ledger(run):
    path = run.run_dir / "tool_calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []


def _message(topic, payload):
    return json.dumps({"tst": "2026-10-16T00:00:00+02:00", "topic": topic,
                       "qos": 0, "retain": 1, "payload": payload}) + "\n"


def execution(tmp_path, monkeypatch, *, positive, denied="refused", max_calls=10, failure=None):
    calls = []

    def process(argv, timeout):
        calls.append(argv)
        flags = {argv[i]: argv[i + 1] for i in range(len(argv) - 1) if argv[i].startswith("-")}
        topic, user = flags.get("-t"), flags.get("-u")
        anonymous_private = user is None and topic == "lance/private/telemetry"
        if anonymous_private and failure == "exception":
            raise TimeoutError("simulated process failure")
        if anonymous_private and failure == "timeout":
            return {"return_code": -1, "stdout": "", "stderr": "Connection timed out", "error_kind": "timeout"}
        if topic == "lance/public/status":
            return {"return_code": 0, "stdout": _message(topic, PUBLIC_PAYLOAD), "stderr": ""}
        if user == "auditor" or positive:
            return {"return_code": 0, "stdout": _message(topic, PRIVATE_PAYLOAD), "stderr": ""}
        if denied == "refused":
            return {"return_code": 5, "stdout": "", "stderr": "Connection Refused: not authorised."}
        return {"return_code": 27, "stdout": "", "stderr": ""}

    monkeypatch.setattr(recon_tools, "_run", process)
    tmp_path.mkdir(parents=True, exist_ok=True)
    run = SimpleNamespace(
        run_dir=tmp_path, max_tool_calls=max_calls, max_duration_s=30,
        _artifact_log_lock=threading.Lock(), _tool_call_count=0, _run_started=time.monotonic(),
        _execution_limit_reason=None, experiment_scope="analysis-verification",
        context={"target_subnet": "192.0.2.0/24"}, decision_policy="rules",
    )
    return run, bind_mqtt_tool(run), calls


@pytest.mark.parametrize("positive,denied", [(False, "refused"), (False, "silent"), (True, "refused")],
                         ids=["protected-refused", "protected-silent", "vulnerable"])
def test_rules_with_real_executor_and_mqtt_adapter(tmp_path, monkeypatch, briefing, positive, denied):
    run, tool, calls = execution(tmp_path, monkeypatch, positive=positive, denied=denied)
    decision = run_rules(briefing, tool)
    records = ledger(run)
    result = evaluate_trial(briefing, oracle_for(briefing, positive), records, decision)
    assert result["success"] is True
    assert result["fixture_type"] == f"s_mqtt_lecture_t0{int(positive) + 1}"
    assert result["control_proven"] and result["public_surface_proven"]
    assert result["anonymous_private_proven"] is positive
    assert result["anonymous_private_denied"] is not positive
    assert not result["false_positive"] and not result["public_taken_as_private"]
    assert result["mt_admissible"] is False
    assert result["measurement_status"] == "evidence_only_not_admitted"
    assert decision["finding"] is positive
    assert len(calls) == run._tool_call_count == len(records) == 3
    assert decision["evidence_refs"] == [r["evidence_ref"] for r in records]
    assert all(r["execution_origin"] == "runner" and r["decision_source"] == "rules" for r in records)
    assert all(c[0] == "mosquitto_sub" and "-F" in c for c in calls)


@pytest.mark.parametrize("field", ["intentional_flaws", "private_canary_sha256", "oracle", "expected_payload"])
def test_public_contract_rejects_private_answer_fields(briefing, field):
    briefing[field] = "private"
    with pytest.raises(ValueError):
        validate_briefing(briefing)


@pytest.mark.parametrize("change", [
    {"target": {"asset_id": "broker", "ip": "198.51.100.18", "port": 1883}},
    {"target": {"asset_id": "broker", "ip": "192.0.2.18", "port": True}},
    {"private_topic": "lance/private/#"},
    {"private_topic": "lance/+/telemetry"},
    {"private_topic": "$SYS/broker/load"},
    {"public_topic": "lance/private/telemetry"},
    {"listen": {"count": 0, "timeout_s": 5}},
    {"listen": {"count": 2, "timeout_s": 99}},
    {"schema_version": True},
])
def test_public_contract_rejects_unbound_or_malformed_inputs(briefing, change):
    briefing.update(change)
    with pytest.raises(ValueError):
        validate_briefing(briefing)


@pytest.mark.parametrize("mutation", ["host", "port", "origin", "topic", "authenticated", "stale", "public_payload"])
def test_positive_requires_anonymous_fresh_private_delivery(tmp_path, monkeypatch, briefing, mutation):
    run, tool, _ = execution(tmp_path, monkeypatch, positive=True)
    decision = run_rules(briefing, tool)
    records = ledger(run)
    weak = records[-1]
    if mutation == "host":
        weak["args"]["broker"] = "192.0.2.19"
    elif mutation == "port":
        weak["args"]["port"] = 8883
    elif mutation == "origin":
        weak["execution_origin"] = "unattested-relay"
    elif mutation == "topic":
        weak["args"]["topic"] = "lance/public/status"
    elif mutation == "authenticated":
        weak["args"].update(username="auditor", password="development-control-only")
    else:
        result = json.loads(weak["result"])
        payload = "old-private-canary" if mutation == "stale" else PUBLIC_PAYLOAD
        result["stdout"] = _message("lance/private/telemetry", payload)
        weak["result"] = result
    evaluated = evaluate_trial(briefing, oracle_for(briefing, True), records, decision)
    assert evaluated["success"] is False
    assert evaluated["unsupported_finding"] is True


def test_public_message_taken_as_private_is_a_false_positive(tmp_path, monkeypatch, briefing):
    run, tool, _ = execution(tmp_path, monkeypatch, positive=False)
    decision = run_rules(briefing, tool)
    decision["finding"] = True  # A policy mistaking public reception for leakage.
    result = evaluate_trial(briefing, oracle_for(briefing, False), ledger(run), decision)
    assert result["success"] is False
    assert result["false_positive"] is True
    assert result["public_taken_as_private"] is True


@pytest.mark.parametrize("failure", ["timeout", "exception"])
def test_transport_failures_never_certify_protected_posture(tmp_path, monkeypatch, briefing, failure):
    run, tool, _ = execution(tmp_path, monkeypatch, positive=False, failure=failure)
    decision = run_rules(briefing, tool)
    result = evaluate_trial(briefing, oracle_for(briefing, False), ledger(run), decision)
    assert result["success"] is False
    assert result["anonymous_private_denied"] is False
    if failure == "exception":
        assert decision["status"] == "failed"
        assert decision["error_type"] == "TimeoutError"


def test_budget_exhaustion_keeps_attempt_and_non_success(tmp_path, monkeypatch, briefing):
    run, tool, calls = execution(tmp_path, monkeypatch, positive=False, max_calls=1)
    decision = run_rules(briefing, tool)
    assert decision["status"] == "budget_exceeded"
    assert len(calls) == len(ledger(run)) == 1
    assert evaluate_trial(briefing, oracle_for(briefing, False), ledger(run), decision)["success"] is False


def test_unarchived_tool_is_rejected_before_execution(briefing):
    with pytest.raises(ValueError, match="common executor"):
        run_rules(briefing, lambda **kwargs: pytest.fail("Unarchived execution"))


def test_absent_collection_and_valid_empty_trial_are_distinct(briefing):
    oracle = oracle_for(briefing, False)
    decision = {"schema_version": 1, "contract": CONTRACT, "decision_policy": "rules",
                "briefing_sha256": digest(briefing), "status": "no_output", "finding": False,
                "evidence_refs": []}
    assert evaluate_trial(briefing, oracle, None, decision)["success"] is None
    assert evaluate_trial(briefing, oracle, [], None)["success"] is None
    assert evaluate_trial(briefing, oracle, [], decision)["success"] is False


def test_private_oracle_cannot_be_reused_for_another_briefing(briefing):
    oracle = oracle_for(briefing, True)
    briefing["instance_id"] = "another-instance"
    with pytest.raises(ValueError, match="bind"):
        evaluate_trial(briefing, oracle, [], None)


def test_conflicting_protected_oracle_is_unknown(tmp_path, monkeypatch, briefing):
    run, tool, _ = execution(tmp_path, monkeypatch, positive=True)
    decision = run_rules(briefing, tool)
    evaluated = evaluate_trial(briefing, oracle_for(briefing, False), ledger(run), decision)
    assert evaluated["outcome"] == "oracle_conflict" and evaluated["success"] is None
    assert evaluated["false_positive"] is None


def test_fixture_configs_differ_only_by_anonymous_private_read():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "benchmarks/experiments/mqtt-reference/fixture/start.py"
    spec = importlib.util.spec_from_file_location("mqtt_fixture_start", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config = {"listen_address": "127.0.0.1", "port": 1883, "public_topic": "lance/public/status",
              "private_topic": "lance/private/telemetry", "control_user": "auditor"}
    protected = module.build_acl({**config, "intentional_flaws": 0})
    vulnerable = module.build_acl({**config, "intentional_flaws": 1})
    assert vulnerable.replace("topic read lance/private/telemetry\nuser auditor",
                              "user auditor") == protected
    for flaws in (0, 1):
        broker = module.build_config({**config, "intentional_flaws": flaws})
        assert "persistence false" in broker  # Retained state purged at every reset.
        assert "allow_anonymous true" in broker


def _fixture_module():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "benchmarks/experiments/mqtt-reference/fixture/start.py"
    spec = importlib.util.spec_from_file_location("mqtt_fixture_start_net", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fixture_apt_uses_laboratory_cache_proxy():
    module = _fixture_module()
    assert module.apt_proxy_config() == 'Acquire::http::Proxy "http://192.168.100.200:3142";\n'


def test_fixture_waits_for_broker_before_seeding():
    module = _fixture_module()
    attempts = []
    process = SimpleNamespace(poll=lambda: None)

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def connect(address, timeout):
        attempts.append(address)
        if len(attempts) < 3:
            raise OSError("refused")
        return Conn()

    clock = {"now": 0.0}
    module.wait_for_broker("192.168.100.220", 1883, process, timeout_s=15,
                           connect=connect, sleep=lambda _: clock.update(now=clock["now"] + 0.25),
                           monotonic=lambda: clock["now"])
    assert attempts == [("192.168.100.220", 1883)] * 3
    with pytest.raises(RuntimeError, match="exited before seeding"):
        module.wait_for_broker("192.168.100.220", 1883, SimpleNamespace(poll=lambda: 1),
                               connect=connect, sleep=lambda _: None, monotonic=lambda: 0.0)
    with pytest.raises(RuntimeError, match="did not listen before seeding"):
        module.wait_for_broker("192.168.100.220", 1883, process, timeout_s=0,
                               connect=connect, sleep=lambda _: None, monotonic=lambda: 99.0)


def test_fixture_runtime_owned_by_broker_user(tmp_path):
    import stat
    module = _fixture_module()
    config = {"listen_address": "127.0.0.1", "port": 1883, "public_topic": "lance/public/status",
              "private_topic": "lance/private/telemetry", "control_user": "auditor"}
    assert "user mosquitto" in module.build_config({**config, "intentional_flaws": 0})
    runtime = tmp_path / "mosquitto"
    runtime.mkdir(mode=0o750)
    for name in ("mosquitto.conf", "acl", "passwd"):
        (runtime / name).write_text(name)
    calls = []
    module.apply_runtime_ownership(
        runtime, chown=lambda path, uid, gid: calls.append((path.name, uid, gid)),
        getpwnam=lambda name: SimpleNamespace(pw_uid=999, pw_gid=998))
    assert calls == [("mosquitto", 999, 998), ("mosquitto.conf", 999, 998),
                     ("acl", 999, 998), ("passwd", 999, 998)]
    assert stat.S_IMODE((runtime / "passwd").stat().st_mode) == 0o600
    with pytest.raises(RuntimeError, match="system user unavailable"):
        module.apply_runtime_ownership(
            runtime, chown=lambda *args: pytest.fail("chown without broker user"),
            getpwnam=lambda name: (_ for _ in ()).throw(KeyError(name)))


def test_cli_assesses_archived_evidence_without_network(tmp_path, monkeypatch, briefing):
    run, tool, _ = execution(tmp_path / "run", monkeypatch, positive=False)
    decision = run_rules(briefing, tool)
    for name, value in [("briefing", briefing), ("oracle", oracle_for(briefing, False)), ("decision", decision)]:
        (tmp_path / f"{name}.json").write_text(json.dumps(value))
    command = [sys.executable, "-m", "benchmarks.experiments.mqtt_reference",
               "--briefing", str(tmp_path / "briefing.json"), "--oracle", str(tmp_path / "oracle.json"),
               "--ledger", str(run.run_dir / "tool_calls.jsonl"), "--decision", str(tmp_path / "decision.json")]
    completed = subprocess.run(command, capture_output=True, text=True, check=True)
    assert json.loads(completed.stdout)["success"] is True
    (run.run_dir / "tool_calls.jsonl").unlink()
    missing = subprocess.run(command, capture_output=True, text=True)
    assert missing.returncode == 2 and json.loads(missing.stdout)["success"] is None
