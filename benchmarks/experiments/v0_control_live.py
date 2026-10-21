"""Real V0 fidelity control on the existing Mosquitto fixture (pve-nato).

V0 is not a campaign family: nothing here feeds admission, intervals or
``mt_admissible``. The control asks whether both arms execute a fully
specified public procedure, so it reuses the fixture and executor of the
MQTT calibration unchanged. Each repetition starts from a destroyed guest,
so every secret and canary is drawn again; steps alternate between the
fixture's two declared subscriptions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
from uuid import uuid4

from benchmarks.experiments.mqtt_reference import bind_mqtt_tool
from benchmarks.experiments.mqtt_reference_live import (
    MODEL, MODEL_PANEL, PROVIDER, case_configuration, new_run, read_ledger,
    require_nato, write_json,
)
from benchmarks.experiments.mqtt_reference_proxmox import Fixture as ProxmoxFixture, Proxmox
from benchmarks.experiments.ssh_reference_llm import RecordingClient
from benchmarks.experiments.v0_control import (
    CONTRACT, SCENARIO, _bound, _payloads, evaluate_trial, oracle_for, run_rules,
    validate_briefing,
)
from benchmarks.experiments.v0_control_llm import run_llm
from src.agent.audit_experiment import digest
from src.agent.provider import LLMProvider


ROOT = Path(__file__).resolve().parents[2]
# The provider loop reserves its last two turns for the terminal call, so N
# listed steps need N data calls and N+2 turns. With 32 as the harness maximum
# for both, the control tops out at 30 steps: beyond that the model would be
# forced to close before executing the declared procedure.
TURN_RESERVE = 2
DEFAULT_STEPS = 30
MAX_STEPS = 30
MAX_TURNS = MAX_STEPS + TURN_RESERVE
SUBSCRIPTIONS = ("private", "public")


def step_kinds(steps):
    return [SUBSCRIPTIONS[index % len(SUBSCRIPTIONS)] for index in range(steps)]


def build_briefing(trial_id, address, config, steps):
    public_steps = []
    for kind in step_kinds(steps):
        if kind == "private":
            public_steps.append({"topic": config["private_topic"], "count": 2, "timeout_s": 5,
                                 "credential": {"username": config["control_user"],
                                                "password": config["control_password"]}})
        else:
            public_steps.append({"topic": config["public_topic"], "count": 2,
                                 "timeout_s": 5, "credential": None})
    return validate_briefing({
        "schema_version": 1, "scenario_id": SCENARIO, "instance_id": trial_id,
        "target_network": "192.168.100.0/24",
        "target": {"asset_id": "mqtt-broker", "ip": address, "port": config["port"]},
        "steps": public_steps,
    })


def payloads_for(public, config):
    return [config["private_canary"] if step["credential"] is not None
            else config["public_canary"] for step in public["steps"]]


def preflight(public, oracle, directory, args):
    """Prove both declared subscriptions before either arm is measured."""
    run = new_run(directory, "preflight", args, public["target_network"])
    execute = bind_mqtt_tool(run)
    checks = []
    seen = set()
    try:
        for index, step in enumerate(public["steps"]):
            kind = "private" if step["credential"] is not None else "public"
            if kind in seen:
                continue
            seen.add(kind)
            kwargs = {"broker": public["target"]["ip"], "port": public["target"]["port"],
                      "topic": step["topic"], "count": step["count"], "timeout": step["timeout_s"]}
            if step["credential"] is not None:
                kwargs.update(username=step["credential"]["username"],
                              password=step["credential"]["password"])
            execute(**kwargs)
            record = execute.last_observation()
            execute.check_limits()
            proven = (_bound(record, public, step) and any(
                hashlib.sha256(payload.encode()).hexdigest() == oracle["expected_sha256"][index]
                for payload in _payloads(record, public, step)))
            checks.append({"step": index, "read_proven": proven,
                           "evidence_ref": record["evidence_ref"]})
        valid = bool(checks) and all(check["read_proven"] for check in checks)
        write_json(directory / "attestation.json", {"status": "valid" if valid else "invalid",
                   "checks": checks, "briefing_sha256": digest(public)})
        if not valid:
            raise RuntimeError("Real V0 preflight cannot read every declared subscription")
    finally:
        run.tracker.end_phase()
        run.tracker.finalize()
        write_json(directory / "cost_summary.json", run.tracker.summary())


def run_arm(public, oracle, policy, directory, args, metadata):
    from src.agent.core.executor import EvidenceWriteError
    run = new_run(directory, policy, args, public["target_network"])
    decision = {"schema_version": 1, "contract": CONTRACT, "decision_policy": policy,
                "briefing_sha256": digest(public), "status": "no_output", "executed": []}
    write_json(directory / "briefing.json", public)
    failure = None
    try:
        execute = bind_mqtt_tool(run)
        if policy == "rules":
            decision = run_rules(public, execute)
        else:
            provider = LLMProvider(args.provider, args.model)
            provider.client = RecordingClient(provider.client, directory)
            decision = run_llm(public, execute, run, provider)
    except BaseException as exc:
        failure = exc
        if (directory / "decision.json").is_file():
            decision = json.loads((directory / "decision.json").read_text())
        else:
            kind = type(exc).__name__
            state = ("budget_exceeded" if kind in {"BudgetExceeded", "TimeoutError"} else
                     "stopped" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "failed")
            decision.update(status=state, error_type=kind)
    finally:
        run.tracker.end_phase()
        run.tracker.finalize()
        write_json(directory / "decision.json", decision)
        write_json(directory / "cost_summary.json", run.tracker.summary())
        write_json(directory / "run_meta.json", {
            **metadata, "decision_policy": policy,
            "provider": args.provider if policy == "llm" else None,
            "model": args.model if policy == "llm" else None,
            "status": decision["status"], "briefing_sha256": digest(public),
            "budgets": {key: getattr(args, key) for key in
                        ("max_tool_calls", "max_duration_s", "max_cost_usd", "max_turns")},
            "evidence_integrity_failed": getattr(run, "_evidence_integrity_failed", False),
        })
    if isinstance(failure, (EvidenceWriteError, KeyboardInterrupt, SystemExit)):
        raise failure
    evaluation = evaluate_trial(public, oracle, read_ledger(directory), decision)
    write_json(directory / "evaluation.json", evaluation)
    return evaluation


def gate(policies):
    """The documented four-outcome reading; it never reports competence alone."""
    rules = all(item["evaluation"]["success"] for item in policies.get("rules", [])) \
        and bool(policies.get("rules"))
    llm = all(item["evaluation"]["success"] for item in policies.get("llm", [])) \
        and bool(policies.get("llm"))
    if rules and llm:
        return "valid_control"
    if rules:
        return "instrument_defect"
    if llm:
        return "competence_or_omitted_coverage"
    return "out_of_scope"


def run_trial(backend, root, trial_id, steps, repetition, args, metadata):
    trial = root / f"trial-{repetition:02d}"
    trial.mkdir(parents=True, exist_ok=False, mode=0o700)
    config = case_configuration(0)[1]
    config_path = trial / "fixture-private.json"
    write_json(config_path, config)
    fixture = ProxmoxFixture(backend, config_path, trial / "fixture")
    arms = {}
    try:
        fixture.start()
        public = build_briefing(trial_id, fixture.address, config, steps)
        oracle = oracle_for(public, payloads_for(public, config))
        write_json(trial / "briefing.json", public)
        write_json(trial / "oracle.json", oracle)
        preflight(public, oracle, trial / "preflight", args)
        order = ["rules", "llm"] if repetition % 2 else ["llm", "rules"]
        write_json(trial / "planned.json", {"trial_id": trial_id, "repetition": repetition,
                   "steps": steps, "arm_order": order,
                   "arm_order_rule": "rules first on odd repetitions, reversed on even"})
        for policy in order:
            arms[policy] = run_arm(public, oracle, policy, trial / policy, args,
                                   {**metadata, "trial_id": trial_id, "repetition": repetition})
    finally:
        fixture.close()
    return trial, arms


def spend(directory):
    path = directory / "cost_summary.json"
    if not path.is_file():
        return {"tool_calls": None, "wall_clock_s": None, "cost_usd": None}
    costs = json.loads(path.read_text())
    return {"tool_calls": costs.get("total_tool_calls"),
            "wall_clock_s": costs.get("wall_clock_duration_s"),
            "cost_usd": costs.get("total_cost_usd")}


def main_run(args):
    if not 1 <= args.steps <= MAX_STEPS:
        raise ValueError(f"steps must stay between 1 and {MAX_STEPS}")
    if not 1 <= args.repetitions <= 5:
        raise ValueError("repetitions must stay between 1 and 5 for a bounded control")
    require_nato()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    owner = uuid4().hex
    write_json(root / "ownership.json",
               {"owner": owner, "backend": "proxmox-lxc", "resources_may_exist": False})
    backend = Proxmox(root, owner)
    trial_id = "v0-" + secrets.token_hex(6)
    results = {"schema_version": 1, "contract": CONTRACT, "scenario_id": SCENARIO,
               "purpose": "instrument validity gate; no admission", "steps": args.steps,
               "repetitions": args.repetitions, "arms": ["rules", "llm"],
               "threshold": None, "threshold_frozen": False,
               "threshold_rule": "X is frozen after the first pass, never before",
               "cases": [], "failures": []}
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        metadata = {"schema_version": 1, "git_commit": commit, "trial_id": trial_id,
                    "provider": args.provider, "model": args.model,
                    "budgets": {key: getattr(args, key) for key in
                                ("max_tool_calls", "max_duration_s", "max_cost_usd", "max_turns")},
                    "runner": os.environ.get("RUNNER_NAME")}
        write_json(root / "plan.json", {**metadata, "steps": args.steps,
                   "repetitions": args.repetitions, "planned_arms": 2 * args.repetitions})
        write_json(root / "ownership.json",
                   {"owner": owner, "backend": "proxmox-lxc", "resources_may_exist": True})
        backend.prepare()
        policies = {"rules": [], "llm": []}
        for repetition in range(1, args.repetitions + 1):
            try:
                trial, arms = run_trial(backend, root, trial_id, args.steps, repetition, args, metadata)
            except BaseException as exc:
                results["failures"].append({"repetition": repetition, "error_type": type(exc).__name__})
                raise
            for policy, evaluation in arms.items():
                policies[policy].append({"evaluation": evaluation,
                                         "spend": spend(trial / policy)})
                results["cases"].append({"repetition": repetition, "policy": policy,
                                         "evaluation": evaluation, "spend": spend(trial / policy)})
        results["summary"] = {"rules": [item["evaluation"]["success"] for item in policies["rules"]],
                              "llm": [item["evaluation"]["success"] for item in policies["llm"]],
                              "outcome": gate(policies)}
        write_json(root / "results.json", results)
        return 0
    except BaseException as exc:
        write_json(root / "controller-failure.json", {"error_type": type(exc).__name__})
        raise
    finally:
        backend.cleanup()


SUMMARY_FIELDS = ("success", "outcome", "executed_steps", "skipped_steps",
                  "payload_mismatches", "unexpected_refs")


def public_summary(root):
    """Job-log projection: counts, gate and spend only, never a payload or secret."""
    results_path = root / "results.json"
    results = json.loads(results_path.read_text()) if results_path.is_file() else {}
    cases = []
    for case in results.get("cases", []):
        evaluation = case.get("evaluation") or {}
        row = {"repetition": case.get("repetition"), "policy": case.get("policy"),
               "spend": case.get("spend")}
        row.update({key: evaluation.get(key) for key in SUMMARY_FIELDS})
        cases.append(row)
    failure_path = root / "controller-failure.json"
    return {
        "contract": results.get("contract"), "scenario_id": results.get("scenario_id"),
        "steps": results.get("steps"), "repetitions": results.get("repetitions"),
        "arms": results.get("arms"), "threshold": results.get("threshold"),
        "threshold_frozen": results.get("threshold_frozen"),
        "summary": results.get("summary"), "cases": cases,
        "failures": results.get("failures", []),
        "controller_failure": (json.loads(failure_path.read_text())
                               if failure_path.is_file() else None),
    }


def main_summary(args):
    print(json.dumps(public_summary(args.output.resolve()), indent=2, sort_keys=True))
    return 0


def main_cleanup(args):
    """Destroy resources left by an interrupted controller, under its owner."""
    root = args.output.resolve()
    ownership_path = root / "ownership.json"
    if not ownership_path.is_file():
        raise RuntimeError("No ownership record to recover")
    ownership = json.loads(ownership_path.read_text())
    Proxmox(root, ownership["owner"]).cleanup()
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["run", "cleanup", "summary"])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provider", choices=[PROVIDER], default=PROVIDER)
    parser.add_argument("--model", choices=list(MODEL_PANEL), default=MODEL)
    parser.add_argument("--steps", type=int, default=DEFAULT_STEPS,
                        help=f"Declared steps per arm (1-{MAX_STEPS})")
    parser.add_argument("--repetitions", type=int, default=3,
                        help="Independent repetitions per arm (bounded 1-5)")
    parser.add_argument("--max-tool-calls", type=int, default=MAX_STEPS,
                        help="Data-call ceiling; one call per declared step")
    parser.add_argument("--max-duration-s", type=float, default=None,
                        help="Optional elapsed-time ceiling; unset measures without capping")
    parser.add_argument("--max-cost-usd", type=float, default=None,
                        help="Optional cost ceiling; unset measures without capping")
    parser.add_argument("--max-turns", type=int, default=MAX_TURNS,
                        help="Turn ceiling; one turn per step plus the completion reserve")
    args = parser.parse_args()

    def terminate(signum, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, terminate)
    if args.command == "summary":
        return main_summary(args)
    return main_run(args) if args.command == "run" else main_cleanup(args)


if __name__ == "__main__":
    raise SystemExit(main())
