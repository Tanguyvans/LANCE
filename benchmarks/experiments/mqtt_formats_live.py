"""H2 runner on nato: the frozen dossier corpus, both arms, no fixture.

No broker is started and no network transition is attempted: the dossier is
frozen, so the only remote call is the provider of the LLM arm. Each arm is
recounted from its journal; the private oracle never reaches the prompt and
never appears in the public summary.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from types import SimpleNamespace

from benchmarks.experiments.mqtt_formats import (
    CONTRACT, METRIC, SCENARIO, Journal, aggregate, evaluate, run_rules,
    validate_dossier,
)
from benchmarks.experiments.mqtt_formats_llm import (
    MAX_TURNS, check_budget, run_llm,
)
from benchmarks.experiments.mqtt_reference_live import (
    MODEL, MODEL_PANEL, PROVIDER, require_nato, write_json,
)
from benchmarks.experiments.ssh_reference_llm import RecordingClient
from src.agent.audit_experiment import digest
from src.agent.cost_tracker import CostTracker
from src.agent.provider import LLMProvider

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "benchmarks" / "experiments" / "mqtt-formats-corpus.json"
SCOPE = "mqtt-formats-interpretation"
PREDICTION = "llm beats the declared parsers on variant/raw and equals them elsewhere"


def load_corpus(path=CORPUS):
    """Load and re-prove the frozen corpus: every oracle must bind its dossier."""
    corpus = json.loads(Path(path).read_text(encoding="utf-8"))
    if corpus.get("contract") != CONTRACT or corpus.get("scenario_id") != SCENARIO:
        raise ValueError("Corpus does not describe this family")
    fixtures = corpus.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError("Corpus carries no fixture")
    seen, loaded = set(), []
    for item in fixtures:
        public = validate_dossier(item["dossier"])
        if public["fixture_type"] in seen:
            raise ValueError("Corpus repeats a fixture type")
        if public["question"] != corpus["question"]:
            raise ValueError("Every fixture must ask the same question")
        oracle = item["oracle"]
        if oracle.get("dossier_sha256") != digest(public) or oracle.get("contract") != CONTRACT:
            raise ValueError(f"Oracle of {public['fixture_type']} does not bind its dossier")
        seen.add(public["fixture_type"])
        loaded.append({"dossier": public, "oracle": oracle})
    return loaded


def new_run(directory, policy, args):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "tool_calls.jsonl").touch(exist_ok=False)
    run = SimpleNamespace(
        run_dir=directory, max_tool_calls=args.max_tool_calls,
        max_duration_s=args.max_duration_s, max_turns=args.max_turns,
        _artifact_log_lock=threading.Lock(), _tool_call_count=0,
        _run_started=time.monotonic(), _execution_limit_reason=None,
        experiment_scope=SCOPE, context={"target_subnet": "127.0.0.1/32"},
        decision_policy=policy,
        tracker=CostTracker(model=args.model if policy == "llm" else "",
                            provider=args.provider if policy == "llm" else "",
                            max_cost_usd=args.max_cost_usd, execution_metrics=True),
    )
    run.tracker.start_run()
    run.tracker.start_phase(SCOPE)
    return run


def _write_journal(directory, journal):
    (directory / "journal.jsonl").write_text(
        "".join(json.dumps(record) + "\n" for record in journal.records), encoding="utf-8")


def failed_evaluation(public, status):
    return {"schema_version": 1, "contract": CONTRACT, "scenario_id": SCENARIO,
            "metric": METRIC, "fixture_type": public["fixture_type"], "view": public["view"],
            "schema": public["schema"], "success": False, "status": status,
            "conclusion_correct": False, "contradiction": False,
            "messages": len(public["messages"]), "correct": 0, "abstained": 0,
            "coverage": 0.0, "wrong": [message["message_id"] for message in public["messages"]],
            "mt_admissible": False, "measurement_status": "evidence_only_not_admitted"}


def run_arm(public, oracle, policy, directory, args, metadata):
    run = new_run(directory, policy, args)
    decision = {"schema_version": 1, "contract": CONTRACT, "decision_policy": policy,
                "dossier_sha256": digest(public), "status": "no_output",
                "conclusion": None, "verdicts": {}}
    write_json(directory / "dossier.json", public)
    write_json(directory / "oracle.json", oracle)
    journal = Journal(public, public["view"])
    failure = None
    try:
        if policy == "rules":
            answer = run_rules(public, journal)
            decision.update(status="completed", conclusion=answer["conclusion"],
                            verdicts=answer["verdicts"])
            # Both arms leave the same answer artefact: the recount reads the
            # file, not the arm's own claim.
            write_json(directory / "answer.json", answer)
        else:
            provider = LLMProvider(args.provider, args.model)
            provider.client = RecordingClient(provider.client, directory)
            decision = run_llm(public, run, provider, journal)
            answer = {"schema_version": 1, "contract": CONTRACT, "decision_policy": "llm",
                      "dossier_sha256": journal.dossier_sha256,
                      "verdicts": decision["verdicts"], "conclusion": decision["conclusion"]}
            if decision["status"] == "completed":
                write_json(directory / "answer.json", answer)
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
        if policy == "rules":
            _write_journal(directory, journal)
        run.tracker.end_phase()
        run.tracker.finalize()
        write_json(directory / "decision.json", decision)
        write_json(directory / "cost_summary.json", run.tracker.summary())
        write_json(directory / "run_meta.json", {
            **metadata, "decision_policy": policy,
            "provider": args.provider if policy == "llm" else None,
            "model": args.model if policy == "llm" else None,
            "status": decision["status"], "dossier_sha256": digest(public),
            "budgets": {key: getattr(args, key) for key in
                        ("max_tool_calls", "max_duration_s", "max_cost_usd", "max_turns")},
            "evidence_integrity_failed": getattr(run, "_evidence_integrity_failed", False),
        })
    if isinstance(failure, (KeyboardInterrupt, SystemExit)):
        raise failure
    if decision["status"] != "completed" or not (directory / "answer.json").is_file():
        evaluation = failed_evaluation(public, decision["status"])
    else:
        evaluation = evaluate(public, oracle, json.loads(
            (directory / "answer.json").read_text()), journal)
    write_json(directory / "evaluation.json", evaluation)
    return evaluation


def spend(directory):
    path = directory / "cost_summary.json"
    if not path.is_file():
        return {"tool_calls": None, "wall_clock_s": None, "cost_usd": None}
    costs = json.loads(path.read_text())
    return {"tool_calls": costs.get("total_tool_calls"),
            "wall_clock_s": costs.get("wall_clock_duration_s"),
            "cost_usd": costs.get("total_cost_usd")}


def prediction_check(cases):
    """Whether the declared prediction held, read from the per-group rates.

    H2 predicts a strict gain on variant/raw and equality on the three other
    groups. Anything else is a refutation, and the protocol says which
    hypothesis a normalized-view gain belongs to (H4).
    """
    rules, llm = {}, {}
    for case in cases:
        rate = case["evaluation"]
        if not rate:
            continue
        key = f"{rate['schema']}/{rate['view']}"
        target = llm if case["policy"] == "llm" else rules
        entry = target.setdefault(key, [0, 0])
        entry[0] += 1 if rate["success"] else 0
        entry[1] += 1
    rates = {arm: {key: (value[0] / value[1] if value[1] else None)
                   for key, value in table.items()}
             for arm, table in (("rules", rules), ("llm", llm))}
    groups_seen = set(rates["rules"]) | set(rates["llm"])
    gain = ("variant/raw" in groups_seen
            and rates["rules"].get("variant/raw") is not None
            and rates["llm"].get("variant/raw") is not None
            and rates["llm"]["variant/raw"] > rates["rules"]["variant/raw"])
    normalised = [key for key in groups_seen if key.endswith("/normalized")]
    normalised_equal = all(rates["rules"].get(key) == rates["llm"].get(key)
                           for key in normalised) if normalised else None
    return {"prediction": PREDICTION, "rates": rates,
            "raw_gain": gain, "normalized_equal": normalised_equal,
            "holds": bool(gain) and normalised_equal is not False,
            "reading": ("a gain in the normalized view would be H4, not H2"
                        if normalised_equal is False else
                        "equality in the raw view refutes H2" if not gain else
                        "prediction holds on this corpus")}


def main_run(args):
    fixtures = load_corpus()
    messages = {len(item["dossier"]["messages"]) for item in fixtures}
    check_budget(max(messages), args.max_tool_calls, args.max_turns)
    if not 1 <= args.repetitions <= 5:
        raise ValueError("repetitions must stay between 1 and 5")
    require_nato()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    metadata = {"schema_version": 1, "git_commit": commit, "provider": args.provider,
                "model": args.model, "runner": os.environ.get("RUNNER_NAME"),
                "corpus_sha256": hashlib_digest(CORPUS)}
    write_json(root / "plan.json", {
        **metadata, "repetitions": args.repetitions,
        "fixtures": [item["dossier"]["fixture_type"] for item in fixtures],
        "planned_arms": 2 * len(fixtures) * args.repetitions,
        "budgets": {key: getattr(args, key) for key in
                    ("max_tool_calls", "max_duration_s", "max_cost_usd", "max_turns")}})
    results = {"schema_version": 1, "contract": CONTRACT, "scenario_id": SCENARIO,
               "metric": METRIC, "purpose": "hypothesis family; no admission",
               "repetitions": args.repetitions, "arms": ["rules", "llm"],
               "corpus_sha256": metadata["corpus_sha256"], "cases": [], "failures": []}
    try:
        for repetition in range(1, args.repetitions + 1):
            for index, item in enumerate(fixtures):
                trial = root / f"trial-{repetition:02d}" / item["dossier"]["fixture_type"]
                trial.mkdir(parents=True, exist_ok=False, mode=0o700)
                order = ["rules", "llm"] if (repetition + index) % 2 else ["llm", "rules"]
                try:
                    for policy in order:
                        evaluation = run_arm(item["dossier"], item["oracle"], policy,
                                             trial / policy, args,
                                             {**metadata, "repetition": repetition})
                        results["cases"].append({
                            "repetition": repetition, "policy": policy,
                            "fixture_type": item["dossier"]["fixture_type"],
                            "evaluation": evaluation,
                            "spend": spend(trial / policy),
                            "routing": routing(trial / policy)})
                except BaseException as exc:
                    results["failures"].append({
                        "repetition": repetition,
                        "fixture_type": item["dossier"]["fixture_type"],
                        **failure_detail(exc)})
                    write_json(root / "results.json", results)
                    raise
        results["summary"] = aggregate([case["evaluation"] for case in results["cases"]])
        results["prediction"] = prediction_check(results["cases"])
        write_json(root / "results.json", results)
        return 0
    except BaseException as exc:
        write_json(root / "controller-failure.json", failure_detail(exc))
        raise


def routing(directory):
    """Turn routing of the LLM arm, or None for the arm that has no turns.

    ``v0_control_llm.routing`` counts events in memory; here the record is read
    back from the trial directory, so the recount stays outside the arm.
    """
    path = directory / "routing.json"
    return json.loads(path.read_text()) if path.is_file() else None


def failure_detail(exc):
    """Error class and code frames only.

    A controller defect has to be diagnosable from the job log, but a traceback
    can quote a message or a dossier value. Frames name code, not data, so the
    publishing surface stays the same as the summary's.
    """
    import traceback
    frames = [{"file": Path(frame.filename).name, "line": frame.lineno,
               "function": frame.name}
              for frame in traceback.extract_tb(exc.__traceback__)][-6:]
    return {"error_type": type(exc).__name__, "frames": frames}


def hashlib_digest(path):
    import hashlib
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


SUMMARY_FIELDS = ("success", "status", "conclusion", "expected_conclusion",
                  "conclusion_correct", "contradiction", "messages", "correct",
                  "abstained", "coverage")


def public_summary(root):
    """Job-log projection: counts and outcomes only, never a payload or an oracle."""
    results_path = root / "results.json"
    results = json.loads(results_path.read_text()) if results_path.is_file() else {}
    cases = []
    for case in results.get("cases", []):
        row = {"repetition": case.get("repetition"), "policy": case.get("policy"),
               "fixture_type": case.get("fixture_type"), "spend": case.get("spend"),
               "routing": case.get("routing")}
        if case.get("evaluation"):
            row.update({key: case["evaluation"].get(key) for key in SUMMARY_FIELDS})
        cases.append(row)
    failure_path = root / "controller-failure.json"
    return {"contract": results.get("contract"), "scenario_id": results.get("scenario_id"),
            "metric": results.get("metric"), "repetitions": results.get("repetitions"),
            "arms": results.get("arms"), "corpus_sha256": results.get("corpus_sha256"),
            "summary": results.get("summary"), "prediction": results.get("prediction"),
            "cases": cases, "failures": results.get("failures", []),
            "controller_failure": (json.loads(failure_path.read_text())
                                   if failure_path.is_file() else None)}


def main_summary(args):
    print(json.dumps(public_summary(args.output.resolve()), indent=2, sort_keys=True))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["run", "summary"])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provider", choices=[PROVIDER], default=PROVIDER)
    parser.add_argument("--model", choices=list(MODEL_PANEL), default=MODEL)
    parser.add_argument("--repetitions", type=int, default=3,
                        help="Independent repetitions per fixture and arm (1-5)")
    parser.add_argument("--max-tool-calls", type=int, default=13,
                        help="Tool-call ceiling; one read per message plus the close")
    parser.add_argument("--max-duration-s", type=float, default=None,
                        help="Optional elapsed-time ceiling; unset measures without capping")
    parser.add_argument("--max-cost-usd", type=float, default=None,
                        help="Optional cost ceiling; unset measures without capping")
    parser.add_argument("--max-turns", type=int, default=MAX_TURNS,
                        help="Turn ceiling; calls plus the completion reserve and routing slack")
    args = parser.parse_args()

    def terminate(signum, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, terminate)
    if args.command == "summary":
        return main_summary(args)
    return main_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
