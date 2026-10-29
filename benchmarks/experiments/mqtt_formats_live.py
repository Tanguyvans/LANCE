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
    CONTRACT, METRIC, SCENARIO, Journal, aggregate, evaluate, run_attempting_rules,
    run_rules, validate_dossier,
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
# The declared parsers, the model, and the script that tries by convention.
# The third is a baseline, not a contender: it exists to say whether the gain
# over the declaration belongs to the model or to the declaration.
ARMS = ("rules", "rules_attempt", "llm")
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
    """Build one H2 arm through the shared harness core."""
    from benchmarks.experiments.harness import build_run

    return build_run(directory=directory, scope=SCOPE, phase=SCOPE,
                     policy=policy, args=args)


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
        if policy in ("rules", "rules_attempt"):
            answer = (run_rules(public, journal) if policy == "rules"
                      else run_attempting_rules(public, journal))
            decision.update(status="completed", conclusion=answer["conclusion"],
                            verdicts=answer["verdicts"])
            # Every arm leaves the same answer artefact: the recount reads the
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
        if policy != "llm":
            # The LLM arm writes its own journal, because its evidence log is
            # the record the arm must be recounted against.
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


def summaries(cases):
    """One aggregate per arm, never a pool of the arms.

    A pooled rate mixes the declared parsers with the model, so a group where
    they disagree reads as a single middling number and hides exactly the
    difference H2 measures.
    """
    return {policy: aggregate([case["evaluation"] for case in cases
                               if case.get("policy") == policy
                               and case.get("evaluation")])
            for policy in ARMS}


def prediction_check(cases):
    """Whether the declared prediction held, read from the per-group rates.

    H2 predicts a strict gain on variant/raw and equality on the three other
    groups. Anything else is a refutation, and the protocol says which
    hypothesis a normalized-view gain belongs to (H4).
    """
    tables = {arm: {} for arm in ARMS}
    for case in cases:
        rate = case["evaluation"]
        if not rate or case.get("policy") not in tables:
            continue
        key = f"{rate['schema']}/{rate['view']}"
        entry = tables[case["policy"]].setdefault(key, [0, 0])
        entry[0] += 1 if rate["success"] else 0
        entry[1] += 1
    rates = {arm: {key: (value[0] / value[1] if value[1] else None)
                   for key, value in table.items()}
             for arm, table in tables.items()}
    groups_seen = set().union(*(set(table) for table in rates.values()))
    gain = ("variant/raw" in groups_seen
            and rates["rules"].get("variant/raw") is not None
            and rates["llm"].get("variant/raw") is not None
            and rates["llm"]["variant/raw"] > rates["rules"]["variant/raw"])
    normalised = [key for key in groups_seen if key.endswith("/normalized")]
    normalised_equal = all(rates["rules"].get(key) == rates["llm"].get(key)
                           for key in normalised) if normalised else None
    # The baseline that tries exists for one question: does the model's gain
    # over the declared parser survive a script that reads by convention?
    attempt = rates["rules_attempt"].get("variant/raw")
    absorbed = (attempt is not None and rates["llm"].get("variant/raw") is not None
                and gain and attempt >= rates["llm"]["variant/raw"])
    return {"prediction": PREDICTION, "rates": rates,
            "raw_gain": gain, "normalized_equal": normalised_equal,
            "convention_gain_absorbed": absorbed,
            "holds": bool(gain) and normalised_equal is not False,
            "reading": ("a gain in the normalized view would be H4, not H2"
                        if normalised_equal is False else
                        "equality in the raw view refutes H2" if not gain else
                        "the convention baseline covers the raw variant: the gain "
                        "over the declared parser is not specific to the model"
                        if absorbed else
                        "prediction holds on this corpus, against a convention "
                        "baseline that does not cover the group")}


def provider_preflight(args, root):
    """Reachability and model presence, before the first dossier arm runs.

    Three failures produce the same zero: the endpoint is unreachable, the
    model is absent from it, or the model answers nothing usable. Only the
    third is a measurement, so the runner names the first two first. The
    catalogue call generates nothing and carries no dossier content.
    """
    from src.agent.provider import _is_network_error

    try:
        provider = LLMProvider(args.provider, args.model)
        catalogue = provider.client.with_options(timeout=15, max_retries=0).models.list()
        available = any(item.id == args.model for item in catalogue.data)
        write_json(root / "provider-preflight.json", {
            "provider": args.provider, "model": args.model, "available": available,
            "models_listed": len(catalogue.data),
            "purpose": "catalogue only; no model generation"})
        return available
    except Exception as exc:
        write_json(root / "provider-preflight-error.json", {
            "provider": args.provider, "model": args.model,
            "error_type": type(exc).__name__,
            "error_kind": "network" if _is_network_error(exc) else "protocol",
            "status_code": getattr(exc, "status_code", None)})
        return None


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
    # An unreachable endpoint or an absent model would spend every arm to
    # produce the same zero as a model that cannot read the corpus. Stop here,
    # with a named cause, rather than report 24 arms of nothing.
    reachable = provider_preflight(args, root)
    if reachable is not True:
        raise RuntimeError(
            "Provider preflight failed: the endpoint is unreachable"
            if reachable is None else
            f"Provider preflight failed: model {args.model} is not served")
    results = {"schema_version": 1, "contract": CONTRACT, "scenario_id": SCENARIO,
               "metric": METRIC, "purpose": "hypothesis family; no admission",
               "repetitions": args.repetitions, "arms": list(ARMS),
               "corpus_sha256": metadata["corpus_sha256"], "cases": [], "failures": []}
    try:
        for repetition in range(1, args.repetitions + 1):
            for index, item in enumerate(fixtures):
                trial = root / f"trial-{repetition:02d}" / item["dossier"]["fixture_type"]
                trial.mkdir(parents=True, exist_ok=False, mode=0o700)
                # Rotate the arm order so no arm always runs first on a dossier.
                shift = (repetition + index) % len(ARMS)
                order = list(ARMS[shift:]) + list(ARMS[:shift])
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
        results["summary"] = summaries(results["cases"])
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
    preflight, preflight_error = root / "provider-preflight.json", root / "provider-preflight-error.json"
    return {"contract": results.get("contract"), "scenario_id": results.get("scenario_id"),
            "provider_preflight": (json.loads(preflight.read_text())
                                   if preflight.is_file() else None),
            "provider_preflight_error": (json.loads(preflight_error.read_text())
                                         if preflight_error.is_file() else None),
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
