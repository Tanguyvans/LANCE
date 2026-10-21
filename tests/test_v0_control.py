"""V0 control: a public procedure executed by both arms, measured from the ledger."""
import json
import subprocess
import sys
import threading
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

from openai.types.chat import ChatCompletion
import pytest
import yaml

from src.agent.audit_experiment import digest
from src.agent.provider import LLMProvider
from src.agent.tools import recon_tools
from benchmarks.experiments import mqtt_reference_live as live
from benchmarks.experiments.mqtt_reference import bind_mqtt_tool
from benchmarks.experiments.ssh_reference_llm import RecordingClient, _message
from benchmarks.experiments.v0_control import (
    CONTRACT, evaluate_trial, oracle_for, run_rules, validate_briefing,
)
from benchmarks.experiments.v0_control_llm import run_llm

ROOT = Path(__file__).resolve().parents[1]
PAYLOADS = {"v0/maintenance": "v0-payload-maintenance", "v0/status": "v0-payload-status",
            "v0/telemetry": "v0-payload-telemetry", "v0/energy": "v0-payload-energy"}
CREDENTIALS = {"v0/maintenance": ("auditor", "control-only"),
               "v0/telemetry": ("operator", "operator-only")}


@pytest.fixture
def briefing():
    return {
        "schema_version": 1, "scenario_id": "v0_fidelite_mqtt", "instance_id": "control-01",
        "target_network": "192.0.2.0/24",
        "target": {"asset_id": "broker", "ip": "192.0.2.18", "port": 1883},
        "steps": [
            {"topic": "v0/maintenance", "count": 1, "timeout_s": 5,
             "credential": {"username": "auditor", "password": "control-only"}},
            {"topic": "v0/status", "credential": None, "count": 1, "timeout_s": 5},
            {"topic": "v0/telemetry", "count": 2, "timeout_s": 5,
             "credential": {"username": "operator", "password": "operator-only"}},
            {"topic": "v0/energy", "credential": None, "count": 1, "timeout_s": 10},
        ],
    }


def oracle(briefing):
    return oracle_for(briefing, [PAYLOADS[step["topic"]] for step in briefing["steps"]])


def _msg(topic, payload):
    return json.dumps({"tst": "2026-10-21T00:00:00+02:00", "topic": topic,
                       "qos": 0, "retain": 1, "payload": payload}) + "\n"


def broker(denied=()):
    """Serve each declared topic to the credential its step names."""
    def process(argv, timeout):
        flags = {argv[i]: argv[i + 1] for i in range(len(argv) - 1) if argv[i].startswith("-")}
        topic, user = flags.get("-t"), flags.get("-u")
        if topic not in PAYLOADS:
            return {"return_code": 5, "stdout": "", "stderr": "Connection Refused: not authorised."}
        expected = CREDENTIALS.get(topic)
        if topic in denied or (expected is not None and user != expected[0]):
            return {"return_code": 5, "stdout": "", "stderr": "Connection Refused: not authorised."}
        return {"return_code": 0, "stdout": _msg(topic, PAYLOADS[topic]), "stderr": ""}
    return process


def ledger(run):
    path = run.run_dir / "tool_calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []


def execute_for(tmp_path, monkeypatch, max_calls=10, denied=()):
    monkeypatch.setattr(recon_tools, "_run", broker(denied))
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "tool_calls.jsonl").touch()
    run = SimpleNamespace(
        run_dir=tmp_path, max_tool_calls=max_calls, max_duration_s=30,
        _artifact_log_lock=threading.Lock(), _tool_call_count=0, _run_started=time.monotonic(),
        _execution_limit_reason=None, experiment_scope="v0-control-calibration",
        context={"target_subnet": "192.0.2.0/24"}, decision_policy="rules",
    )
    return run, bind_mqtt_tool(run)


def test_rules_execute_every_declared_step_in_order(tmp_path, monkeypatch, briefing):
    run, tool = execute_for(tmp_path, monkeypatch)
    decision = run_rules(briefing, tool)
    records = ledger(run)
    result = evaluate_trial(briefing, oracle(briefing), records, decision)
    assert decision["status"] == "completed"
    assert [r["args"]["topic"] for r in records] == [s["topic"] for s in briefing["steps"]]
    assert [r["args"]["timeout"] for r in records] == [s["timeout_s"] for s in briefing["steps"]]
    assert decision["executed"] == [r["evidence_ref"] for r in records]
    assert result["success"] is True and result["outcome"] == "valid"
    assert result["executed_steps"] == len(briefing["steps"])
    assert result["skipped_steps"] == 0
    assert result["payload_mismatches"] == result["unexpected_refs"] == 0
    assert result["fixture_type"] == "v0_fidelite_mqtt_4etapes"
    assert result["mt_admissible"] is False
    assert result["measurement_status"] == "evidence_only_not_admitted"
    assert run._tool_call_count == len(records) == len(briefing["steps"])


def test_anonymous_step_is_never_executed_with_a_credential(tmp_path, monkeypatch, briefing):
    run, tool = execute_for(tmp_path, monkeypatch)
    decision = run_rules(briefing, tool)
    anonymous = [r for r in ledger(run) if r["args"]["topic"] in {"v0/status", "v0/energy"}]
    assert anonymous and all(not r["args"].get("username") for r in anonymous)
    assert evaluate_trial(briefing, oracle(briefing), ledger(run), decision)["success"] is True


def test_skipped_step_is_measured_from_the_cited_sequence(tmp_path, monkeypatch, briefing):
    run, tool = execute_for(tmp_path, monkeypatch)
    decision = run_rules(briefing, tool)
    decision["executed"] = decision["executed"][1:]
    result = evaluate_trial(briefing, oracle(briefing), ledger(run), decision)
    assert result["success"] is False and result["outcome"] == "incomplete"
    assert result["executed_steps"] == 0 and result["skipped_steps"] == len(briefing["steps"])


def test_unexpected_reference_breaks_fidelity(tmp_path, monkeypatch, briefing):
    run, tool = execute_for(tmp_path, monkeypatch)
    decision = run_rules(briefing, tool)
    records = ledger(run)
    extra = deepcopy(records[-1])
    extra["evidence_ref"] = "invented-observation"
    records.append(extra)
    decision["executed"].append(extra["evidence_ref"])
    result = evaluate_trial(briefing, oracle(briefing), records, decision)
    assert result["success"] is False and result["unexpected_refs"] == 1
    assert result["executed_steps"] == len(briefing["steps"])


def test_invented_reference_is_unknown_not_success(tmp_path, monkeypatch, briefing):
    run, tool = execute_for(tmp_path, monkeypatch)
    decision = run_rules(briefing, tool)
    decision["executed"][-1] = "invented-observation"
    result = evaluate_trial(briefing, oracle(briefing), ledger(run), decision)
    assert result["success"] is None and result["reason"] == "cited_observation_missing"


def test_duplicate_reference_is_rejected(tmp_path, monkeypatch, briefing):
    run, tool = execute_for(tmp_path, monkeypatch)
    decision = run_rules(briefing, tool)
    decision["executed"][-1] = decision["executed"][0]
    with pytest.raises(ValueError, match="more than once"):
        evaluate_trial(briefing, oracle(briefing), ledger(run), decision)


def test_stale_payload_is_a_fidelity_mismatch(tmp_path, monkeypatch, briefing):
    run, tool = execute_for(tmp_path, monkeypatch)
    decision = run_rules(briefing, tool)
    records = ledger(run)
    result = json.loads(records[1]["result"]) if isinstance(records[1]["result"], str) else records[1]["result"]
    result["stdout"] = _msg("v0/status", "v0-payload-from-a-previous-trial")
    records[1]["result"] = result
    evaluated = evaluate_trial(briefing, oracle(briefing), records, decision)
    assert evaluated["success"] is False and evaluated["payload_mismatches"] == 1
    assert evaluated["executed_steps"] == len(briefing["steps"])


def test_budget_exhaustion_is_recorded_not_certified(tmp_path, monkeypatch, briefing):
    run, tool = execute_for(tmp_path, monkeypatch, max_calls=2)
    decision = run_rules(briefing, tool)
    assert decision["status"] == "budget_exceeded"
    assert len(decision["executed"]) == len(ledger(run)) == 2
    result = evaluate_trial(briefing, oracle(briefing), ledger(run), decision)
    assert result["success"] is False and result["outcome"] == "budget"
    assert result["executed_steps"] == 2 and result["skipped_steps"] == 2


def test_denied_step_fails_the_control_without_crashing(tmp_path, monkeypatch, briefing):
    run, tool = execute_for(tmp_path, monkeypatch, denied={"v0/telemetry"})
    decision = run_rules(briefing, tool)
    result = evaluate_trial(briefing, oracle(briefing), ledger(run), decision)
    assert decision["status"] == "completed"
    assert result["success"] is False and result["payload_mismatches"] == 1


def test_absent_collection_and_terminal_decision_are_distinct(briefing):
    decision = {"schema_version": 1, "contract": CONTRACT, "decision_policy": "rules",
                "briefing_sha256": digest(briefing), "status": "no_output", "executed": []}
    assert evaluate_trial(briefing, oracle(briefing), None, decision)["success"] is None
    assert evaluate_trial(briefing, oracle(briefing), [], None)["success"] is None
    assert evaluate_trial(briefing, oracle(briefing), [], decision)["success"] is False


@pytest.mark.parametrize("field", ["expected_sha256", "payloads", "oracle"])
def test_public_briefing_rejects_private_answer_fields(briefing, field):
    briefing[field] = "private"
    with pytest.raises(ValueError):
        validate_briefing(briefing)


@pytest.mark.parametrize("change", [
    {"steps": []},
    {"steps": [{"topic": "v0/status", "credential": None, "count": 1, "timeout_s": 5}] * 25},
    {"steps": [{"topic": "v0/#", "credential": None, "count": 1, "timeout_s": 5}]},
    {"steps": [{"topic": "v0/+", "credential": None, "count": 1, "timeout_s": 5}]},
    {"steps": [{"topic": "$SYS/broker/load", "credential": None, "count": 1, "timeout_s": 5}]},
    {"steps": [{"topic": "v0/status", "credential": None, "count": 0, "timeout_s": 5}]},
    {"steps": [{"topic": "v0/status", "credential": None, "count": 11, "timeout_s": 5}]},
    {"steps": [{"topic": "v0/status", "credential": None, "count": 1, "timeout_s": 0}]},
    {"steps": [{"topic": "v0/status", "credential": None, "count": 1, "timeout_s": 61}]},
    {"steps": [{"topic": "v0/status", "credential": {"username": "operator"}, "count": 1, "timeout_s": 5}]},
    {"steps": [{"topic": "v0/status", "credential": None, "count": True, "timeout_s": 5}]},
    {"schema_version": True},
    {"target": {"asset_id": "broker", "ip": "198.51.100.18", "port": 1883}},
])
def test_public_briefing_rejects_unbound_or_malformed_steps(briefing, change):
    briefing.update(change)
    with pytest.raises(ValueError):
        validate_briefing(briefing)


def test_oracle_requires_one_payload_per_step_and_allows_repeated_subscriptions(briefing):
    payloads = [PAYLOADS[step["topic"]] for step in briefing["steps"]]
    bound = oracle_for(briefing, payloads)
    assert bound["expected_sha256"][0] != bound["expected_sha256"][1]
    # Two steps may name the same subscription; a single record still cannot
    # answer both, because the decision must cite distinct bound references.
    repeated = oracle_for(briefing, [payloads[0]] * len(payloads))
    assert len(set(repeated["expected_sha256"])) == 1
    with pytest.raises(ValueError):
        oracle_for(briefing, payloads[:-1])
    with pytest.raises(ValueError):
        oracle_for(briefing, [""] + payloads[1:])


def test_oracle_cannot_be_reused_for_another_instance(briefing):
    bound = oracle(briefing)
    briefing["instance_id"] = "control-02"
    with pytest.raises(ValueError, match="bind"):
        evaluate_trial(briefing, bound, [], None)


def test_unarchived_tool_is_rejected_before_execution(briefing):
    with pytest.raises(ValueError, match="common executor"):
        run_rules(briefing, lambda **kwargs: pytest.fail("Unarchived execution"))


class FakeClient:
    base_url = "http://development.invalid/v1"

    def __init__(self, steps):
        self.steps, self.requests = steps, []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def with_options(self, **kwargs):
        return self

    def create(self, **kwargs):
        self.requests.append(deepcopy({**kwargs, "messages": [_message(item) for item in kwargs["messages"]]}))
        index = len(self.requests) - 1
        if index < self.steps:
            name, arguments = "run_step", {"index": index}
        else:
            refs = [json.loads(item["content"])["evidence_ref"] for item in self.requests[-1]["messages"]
                    if item["role"] == "tool" and "evidence_ref" in json.loads(item["content"])]
            name, arguments = "finish_control", {"evidence_refs": refs[:self.steps]}
        return self.reply(name, arguments, index)

    @staticmethod
    def reply(name, arguments, index):
        return ChatCompletion.model_validate({
            "id": f"completion-{index}", "object": "chat.completion", "created": 1, "model": "development-model",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None, "reasoning_content": "DO_NOT_ARCHIVE_PRIVATE_REASONING",
                "tool_calls": [{"id": f"tool-{index}", "type": "function",
                                "function": {"name": name, "arguments": json.dumps(arguments)}}]}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
        })


class ScriptedClient(FakeClient):
    """Follow a fixed tool schedule; `finish:k` cites the first k references."""

    def __init__(self, schedule):
        self.schedule, self.requests = schedule, []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.requests.append(deepcopy({**kwargs,
                                       "messages": [_message(item) for item in kwargs["messages"]]}))
        index = len(self.requests) - 1
        action = self.schedule[min(index, len(self.schedule) - 1)]
        if action.startswith("run_step"):
            name, arguments = "run_step", {"index": int(action.split(":")[1])}
        else:
            refs = [json.loads(item["content"])["evidence_ref"]
                    for item in self.requests[-1]["messages"]
                    if item["role"] == "tool" and "evidence_ref" in json.loads(item["content"])]
            name, arguments = "finish_control", {"evidence_refs": refs[:int(action.split(":")[1])]}
        return self.reply(name, arguments, index)


def llm_setup(tmp_path, monkeypatch, briefing, max_calls=32, max_turns=32, duration=60, client=None):
    monkeypatch.setattr(recon_tools, "_run", broker())
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", lambda _: None)
    args = SimpleNamespace(max_tool_calls=max_calls, max_duration_s=duration, max_turns=max_turns,
                           max_cost_usd=1, model="development-model", provider="ollama-umons")
    run = live.new_run(tmp_path, "llm", args, network=briefing["target_network"])
    provider = object.__new__(LLMProvider)
    provider.provider, provider.model = "ollama-umons", "development-model"
    provider.client = RecordingClient(client or FakeClient(len(briefing["steps"])), tmp_path)
    return run, provider


def test_llm_arm_executes_the_same_public_procedure(tmp_path, monkeypatch, briefing):
    run, provider = llm_setup(tmp_path, monkeypatch, briefing)
    decision = run_llm(briefing, bind_mqtt_tool(run), run, provider)
    records = ledger(run)
    assert decision["status"] == "completed" and decision["decision_policy"] == "llm"
    assert [r["args"]["topic"] for r in records] == [s["topic"] for s in briefing["steps"]]
    result = evaluate_trial(briefing, oracle(briefing), records, decision)
    assert result["success"] is True and result["executed_steps"] == len(briefing["steps"])
    prompt = json.loads((tmp_path / "prompt.json").read_text())
    assert set(prompt) == {"system", "user", "tools"}
    assert [tool["name"] for tool in prompt["tools"]] == ["run_step", "finish_control"]
    assert "expected_sha256" not in prompt["user"]["briefing"]
    wire = (tmp_path / "provider-wire.jsonl").read_text()
    assert "DO_NOT_ARCHIVE_PRIVATE_REASONING" not in wire
    assert "expected_sha256" not in wire


def test_llm_arm_refuses_a_truncated_completion(tmp_path, monkeypatch, briefing):
    # The model tries to close after two of four steps: the tool refuses, the
    # arm keeps running, and the control still ends complete.
    schedule = ["run_step:0", "run_step:1", "finish:2",
                "run_step:2", "run_step:3", "finish:4"]
    run, provider = llm_setup(tmp_path, monkeypatch, briefing, client=ScriptedClient(schedule))
    decision = run_llm(briefing, bind_mqtt_tool(run), run, provider)
    assert len(decision["executed"]) == len(briefing["steps"])
    result = evaluate_trial(briefing, oracle(briefing), ledger(run), decision)
    assert result["success"] is True and result["skipped_steps"] == 0


def test_llm_arm_is_budgeted_like_the_rules_arm(tmp_path, monkeypatch, briefing):
    run, provider = llm_setup(tmp_path, monkeypatch, briefing, max_calls=2)
    decision = run_llm(briefing, bind_mqtt_tool(run), run, provider)
    assert decision["status"] == "budget_exceeded"
    result = evaluate_trial(briefing, oracle(briefing), ledger(run), decision)
    assert result["success"] is False and result["outcome"] == "budget"


def test_cli_evaluates_an_archived_trial_without_network(tmp_path, monkeypatch, briefing):
    run, tool = execute_for(tmp_path / "run", monkeypatch)
    decision = run_rules(briefing, tool)
    for name, value in [("briefing", briefing), ("oracle", oracle(briefing)), ("decision", decision)]:
        (tmp_path / f"{name}.json").write_text(json.dumps(value))
    command = [sys.executable, "-m", "benchmarks.experiments.v0_control", str(tmp_path)]
    (tmp_path / "tool_calls.jsonl").write_text((run.run_dir / "tool_calls.jsonl").read_text())
    completed = subprocess.run(command, capture_output=True, text=True, check=True, cwd=ROOT)
    assert json.loads(completed.stdout)["success"] is True
    (tmp_path / "tool_calls.jsonl").unlink()
    missing = subprocess.run(command, capture_output=True, text=True, cwd=ROOT)
    assert json.loads(missing.stdout)["success"] is None


def live_config():
    return {"port": 1883, "control_user": "auditor", "control_password": "control-secret",
            "private_topic": "lance/private/telemetry", "public_topic": "lance/public/status",
            "private_canary": "private-canary", "public_canary": "public-canary",
            "seeder_password": "fixture-only", "intentional_flaws": 0}


def live_broker(config):
    """Serve the fixture's two subscriptions with the trial's fresh canaries."""
    def process(argv, timeout):
        flags = {argv[i]: argv[i + 1] for i in range(len(argv) - 1) if argv[i].startswith("-")}
        topic, user = flags.get("-t"), flags.get("-u")
        if topic == config["private_topic"] and user == config["control_user"]:
            return {"return_code": 0, "stdout": _msg(topic, config["private_canary"]), "stderr": ""}
        if topic == config["public_topic"]:
            return {"return_code": 0, "stdout": _msg(topic, config["public_canary"]), "stderr": ""}
        return {"return_code": 5, "stdout": "", "stderr": "Connection Refused: not authorised."}
    return process


def test_control_steps_leave_the_completion_and_routing_turns_inside_the_maximum():
    from benchmarks.experiments import v0_control as control
    from benchmarks.experiments import v0_control_live as v0live
    # 32 calls and 32 turns are the harness maxima; the provider keeps two
    # turns for the terminal call, and a turn that produces no data call must
    # not cost the declared procedure. The first 30-step passage spent four
    # routing turns and closed without a decision.
    assert control.MAX_STEPS == v0live.MAX_STEPS == v0live.DEFAULT_STEPS == 24
    assert control.TURN_RESERVE == v0live.TURN_RESERVE == 2
    assert control.ROUTING_SLACK == v0live.ROUTING_SLACK == 6
    assert v0live.MAX_STEPS + 8 == v0live.MAX_TURNS == 32
    workflow = (ROOT / '.github/workflows/v0-control.yml').read_text()
    assert 'case "$V0_STEPS" in 8|16|24)' in workflow
    assert '--max-turns "$((V0_STEPS + 8))"' in workflow


@pytest.mark.parametrize("steps, calls, turns", [
    (24, 24, 32), (8, 8, 16),
])
def test_a_control_budget_admits_the_reserve_and_the_routing_slack(steps, calls, turns):
    from benchmarks.experiments import v0_control_live as v0live
    v0live.check_budget(steps, calls, turns)


@pytest.mark.parametrize("steps, calls, turns", [
    (25, 25, 33),      # beyond the harness maximum for steps
    (30, 30, 32),      # zero routing slack: the first passage's defect
    (24, 24, 31),      # one routing turn short
    (24, 20, 32),      # the data-call ceiling cannot cover the procedure
])
def test_a_control_budget_refuses_an_instrument_that_cannot_finish(steps, calls, turns):
    from benchmarks.experiments import v0_control_live as v0live
    with pytest.raises(ValueError):
        v0live.check_budget(steps, calls, turns)


def test_a_frozen_threshold_travels_with_its_calibration(tmp_path):
    from benchmarks.experiments import v0_control_live as v0live
    manifest = tmp_path / "manifest.json"
    unfrozen = v0live.frozen_threshold(manifest, steps=24)
    assert unfrozen == {"threshold": None, "threshold_frozen": False,
                        "threshold_rule": v0live.THRESHOLD_RULE}
    manifest.write_text(json.dumps({
        "schema_version": 1, "contract": CONTRACT, "scenario_id": "v0_fidelite_mqtt",
        "steps": 24, "threshold": 2 / 3, "threshold_frozen": True, "saturating": False,
        "evidence": {"run_id": "39592971744", "git_commit": "ae32dd7"}}))
    frozen = v0live.frozen_threshold(manifest, steps=24)
    assert frozen["threshold"] == pytest.approx(2 / 3)
    assert frozen["threshold_frozen"] is True
    assert frozen["threshold_evidence"] == {"run_id": "39592971744", "git_commit": "ae32dd7"}
    assert frozen["saturating"] is False
    with pytest.raises(ValueError):
        v0live.frozen_threshold(manifest, steps=8)


@pytest.mark.parametrize("change", [
    {"threshold_frozen": False},
    {"threshold": None},
    {"threshold": 1.5},
    {"threshold": True},
    {"contract": "v0-control-other-v1"},
    {"scenario_id": "other"},
])
def test_a_manifest_that_does_not_freeze_a_rate_is_refused(tmp_path, change):
    from benchmarks.experiments import v0_control_live as v0live
    manifest = tmp_path / "manifest.json"
    record = {"schema_version": 1, "contract": CONTRACT, "scenario_id": "v0_fidelite_mqtt",
              "steps": 24, "threshold": 0.5, "threshold_frozen": True}
    record.update(change)
    manifest.write_text(json.dumps(record))
    with pytest.raises(ValueError):
        v0live.frozen_threshold(manifest, steps=24)


def test_the_campaign_manifest_freezes_the_rate_of_this_control():
    from benchmarks.experiments import v0_control_live as v0live
    frozen = v0live.frozen_threshold(steps=v0live.MAX_STEPS)
    assert frozen["threshold_frozen"] is True
    assert 0.0 < frozen["threshold"] < 1.0
    assert frozen["saturating"] is True
    evidence = frozen["threshold_evidence"]
    assert evidence["run_id"] and evidence["git_commit"]
    assert evidence["arms"] == {"rules": [True] * 3, "llm": [True] * 3}
    # X is the floor the first passage froze: three successes in three
    # repetitions clear it, and the defect that passage exposed — one failure
    # in three — does not.
    x = frozen["threshold"]
    assert v0live.threshold_met({"rules": [True] * 3, "llm": [True] * 3}, x) \
        == {"rules": True, "llm": True}
    assert v0live.threshold_met({"rules": [True] * 3, "llm": [True, True, False]}, x) \
        == {"rules": True, "llm": False}
    assert v0live.threshold_met({}, None) == {"rules": None, "llm": None}


def test_routing_is_published_as_counts_and_never_as_content():
    from benchmarks.experiments.v0_control_llm import routing
    events = [
        {"type": "provider_diagnostic", "event": "request", "turn": 1},
        {"type": "provider_diagnostic", "event": "tool", "reason": "malformed_args",
         "arguments": "control-secret"},
        {"type": "provider_diagnostic", "event": "terminal", "cause": "max_turns_exhausted"},
        {"type": "tool_result", "name": "run_step", "result": "private-canary"},
    ]
    assert routing(events) == {"cause=max_turns_exhausted": 1, "event=request": 1,
                               "event=terminal": 1, "event=tool": 1,
                               "reason=malformed_args": 1}


def test_live_summary_publishes_counts_without_fixture_values(tmp_path):
    from benchmarks.experiments import v0_control_live as v0live
    config = live_config()
    results = {"schema_version": 1, "contract": CONTRACT, "scenario_id": "v0_fidelite_mqtt",
               "steps": 2, "repetitions": 1, "arms": ["rules", "llm"],
               "threshold": None, "threshold_frozen": False,
               "cases": [{"repetition": 1, "policy": "llm", "spend": {"cost_usd": None},
                          "evaluation": {"success": False, "outcome": "budget",
                                         "executed_steps": 1, "skipped_steps": 1,
                                         "payload_mismatches": 0, "unexpected_refs": 0,
                                         "evidence_refs": ["ev-1"], "reason": "budget"}}],
               "failures": [], "summary": {"outcome": "instrument_defect"}}
    (tmp_path / "results.json").write_text(json.dumps(results))
    summary = v0live.public_summary(tmp_path)
    assert summary["summary"] == {"outcome": "instrument_defect"}
    assert summary["threshold"] is None and summary["threshold_frozen"] is False
    assert summary["cases"] == [{"repetition": 1, "policy": "llm",
                                 "spend": {"cost_usd": None}, "routing": None,
                                 "success": False, "outcome": "budget", "executed_steps": 1,
                                 "skipped_steps": 1, "payload_mismatches": 0,
                                 "unexpected_refs": 0}]
    published = json.dumps(summary)
    for secret in ("private-canary", "control-secret", "fixture-only",
                   config["private_topic"], "evidence_refs"):
        assert secret not in published


def test_live_briefing_alternates_the_declared_subscriptions():
    from benchmarks.experiments import v0_control_live as v0live
    public = v0live.build_briefing("v0-control", "192.168.100.220", live_config(), 24)
    assert len(public["steps"]) == 24
    assert [step["credential"] is not None for step in public["steps"]] == [True, False] * 12
    assert {step["topic"] for step in public["steps"]} == {"lance/private/telemetry",
                                                          "lance/public/status"}
    payloads = v0live.payloads_for(public, live_config())
    assert payloads[0] == "private-canary" and payloads[1] == "public-canary"
    oracle_for(public, payloads)


def test_live_preflight_requires_every_declared_read(tmp_path, monkeypatch):
    from benchmarks.experiments import v0_control_live as v0live
    config = live_config()
    public = v0live.build_briefing("v0-control", "192.168.100.220", config, 4)
    oracle = oracle_for(public, v0live.payloads_for(public, config))
    monkeypatch.setattr(recon_tools, "_run", live_broker(config))
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", lambda _: None)
    args = SimpleNamespace(max_tool_calls=32, max_duration_s=60, max_turns=32,
                           max_cost_usd=1, model="development-model", provider="ollama-umons")
    v0live.preflight(public, oracle, tmp_path, args)
    attestation = json.loads((tmp_path / "attestation.json").read_text())
    assert attestation["status"] == "valid" and len(attestation["checks"]) == 2
    assert all(check["read_proven"] for check in attestation["checks"])


def test_live_preflight_fails_when_a_declared_canary_is_absent(tmp_path, monkeypatch):
    from benchmarks.experiments import v0_control_live as v0live
    config = live_config()
    public = v0live.build_briefing("v0-control", "192.168.100.220", config, 2)
    oracle = oracle_for(public, v0live.payloads_for(public, config))

    def process(argv, timeout):
        flags = {argv[i]: argv[i + 1] for i in range(len(argv) - 1) if argv[i].startswith("-")}
        return {"return_code": 0, "stdout": _msg(flags.get("-t"), "stale-canary"), "stderr": ""}

    monkeypatch.setattr(recon_tools, "_run", process)
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", lambda _: None)
    args = SimpleNamespace(max_tool_calls=32, max_duration_s=60, max_turns=32,
                           max_cost_usd=1, model="development-model", provider="ollama-umons")
    with pytest.raises(RuntimeError, match="preflight"):
        v0live.preflight(public, oracle, tmp_path, args)
    assert json.loads((tmp_path / "attestation.json").read_text())["status"] == "invalid"


def test_live_rules_arm_is_measured_against_the_archived_ledger(tmp_path, monkeypatch):
    from benchmarks.experiments import v0_control_live as v0live
    config = live_config()
    public = v0live.build_briefing("v0-control", "192.168.100.220", config, 6)
    oracle = oracle_for(public, v0live.payloads_for(public, config))
    monkeypatch.setattr(recon_tools, "_run", live_broker(config))
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", lambda _: None)
    args = SimpleNamespace(max_tool_calls=32, max_duration_s=60, max_turns=32,
                           max_cost_usd=1, model="development-model", provider="ollama-umons")
    evaluation = v0live.run_arm(public, oracle, "rules", tmp_path, args, {"trial_id": "v0-control"})
    assert evaluation["success"] is True and evaluation["executed_steps"] == 6
    assert json.loads((tmp_path / "evaluation.json").read_text())["success"] is True
    assert json.loads((tmp_path / "run_meta.json").read_text())["status"] == "completed"


def test_live_gate_reads_the_documented_four_outcomes():
    from benchmarks.experiments.v0_control_live import gate

    def arms(rules, llm):
        return {"rules": [{"evaluation": {"success": value}} for value in rules],
                "llm": [{"evaluation": {"success": value}} for value in llm]}

    assert gate(arms([True, True], [True, True])) == "valid_control"
    assert gate(arms([True, True], [False, True])) == "instrument_defect"
    assert gate(arms([False], [True, True])) == "competence_or_omitted_coverage"
    assert gate(arms([False], [False])) == "out_of_scope"
    assert gate({"rules": [], "llm": []}) == "out_of_scope"


def test_workflow_is_manual_dev2_only_and_declares_the_lock_held():
    text = (ROOT / '.github/workflows/v0-control.yml').read_text()
    document = yaml.safe_load(text)
    assert 'workflow_dispatch' in document[True]  # YAML parses the `on` key as True.
    assert document['concurrency']['group'] == 'lance-lab-dev2'
    job = document['jobs']['v0-control']
    assert job['runs-on'] == ['self-hosted', 'nato-master']
    # The controller refuses to run without the marker the shell sets once it
    # owns the shared lock, so the job env must carry it.
    assert job['env']['LANCE_MQTT_LOCK_HELD'] == '1'
    assert 'refs/heads/dev/2' in text
    assert '--max-cost-usd' not in text and '--max-duration-s' not in text
    assert 'upload-artifact' not in text
    assert 'v0_control_live run' in text and 'v0_control_live cleanup' in text
    assert 'v0_control_live summary' in text
    assert '$((600 + 3600 * V0_REPETITIONS))' in text
    # The declared steps bound the data calls; the turns add the completion
    # reserve the provider loop keeps for itself and the routing turns that
    # produce no data call.
    assert '--max-tool-calls "$V0_STEPS" --max-turns "$((V0_STEPS + 8))"' in text
