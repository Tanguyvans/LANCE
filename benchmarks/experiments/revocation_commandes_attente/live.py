"""Revocation challenge runner on the mini-PC: the three scripts and the model.

Every approach reads the same documentation and the same journal; the answer
key never reaches the prompt and never appears in the public summary. The only
remote call is the provider of the LLM approach.

    venv/bin/python -m benchmarks.experiments.revocation_commandes_attente.live run --output DIR
    venv/bin/python -m benchmarks.experiments.revocation_commandes_attente.live summary --output DIR
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess

from benchmarks.experiments.mqtt_formats_live import (
    failure_detail, provider_preflight, routing, spend,
)
from benchmarks.experiments.mqtt_reference_live import (
    MODEL, MODEL_PANEL, PROVIDER, require_nato, write_json,
)
from benchmarks.experiments.revocation_commandes_attente.llm import (
    MAX_TOOL_CALLS, MAX_TURNS, check_budget, run_llm,
)
from benchmarks.experiments.revocation_commandes_attente.sonde import (
    JOURNALS, LOTS, SCRIPTS, expected_verdict, frozen_sha256, frozen_v3_sha256, journal_facts,
    scripts_sha256,
)
from benchmarks.experiments.ssh_reference_llm import RecordingClient
from src.agent.provider import LLMProvider

ROOT = Path(__file__).resolve().parents[3]
SCOPE = "revocation-queued-commands"
APPROACHES = (*SCRIPTS, "llm")


def load_corpus(lot: str = "connu") -> list[dict]:
    """Every documentation on every journal, with its expected verdict.

    An incomplete answer key or an empty lot is refused before any run starts.
    """
    docs_dir, answer_key = LOTS[lot]
    if not answer_key.is_file():
        raise ValueError(f"The lot {lot} has no answer key yet")
    key = json.loads(answer_key.read_text(encoding="utf-8"))
    corpus = []
    for path in sorted(docs_dir.glob("*.md")):
        if path.name not in key:
            raise ValueError(f"No answer for {path.name}")
        entry = key[path.name]
        text = path.read_text(encoding="utf-8")
        for journal in JOURNALS:
            facts = journal_facts(JOURNALS[journal])
            corpus.append({"doc": path.name, "journal": journal, "text": text,
                           "behaviour": entry["behaviour"],
                           "expected": expected_verdict(entry["behaviour"],
                                                        entry.get("period_s"), facts)})
    if not corpus:
        raise ValueError(f"The lot {lot} holds no documentation")
    return corpus


def corpus_sha256(lot: str = "connu") -> str:
    docs_dir, answer_key = LOTS[lot]
    digest = hashlib.sha256()
    for path in [*sorted(docs_dir.glob("*.md")), answer_key]:
        digest.update(path.name.encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def new_run(directory, policy, args):
    from benchmarks.experiments.harness import build_run

    return build_run(directory=directory, scope=SCOPE, phase=SCOPE, policy=policy, args=args)


def run_approach(case: dict, policy: str, directory: Path, args, metadata: dict) -> dict:
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    run = new_run(directory, policy, args)
    decision = {"schema_version": 1, "decision_policy": policy, "status": "no_output",
                "verdict": None}
    failure = None
    try:
        journal = JOURNALS[case["journal"]]
        if policy in SCRIPTS:
            decision.update(status="completed", verdict=SCRIPTS[policy](case["text"], journal))
        else:
            provider = LLMProvider(args.provider, args.model)
            provider.client = RecordingClient(provider.client, directory)
            decision = run_llm(case["text"], journal, run, provider)
    except BaseException as exc:
        failure = exc
        if (directory / "decision.json").is_file():
            decision = json.loads((directory / "decision.json").read_text())
        else:
            decision.update(status="failed", error_type=type(exc).__name__)
    finally:
        run.tracker.end_phase()
        run.tracker.finalize()
        write_json(directory / "decision.json", decision)
        write_json(directory / "cost_summary.json", run.tracker.summary())
        write_json(directory / "run_meta.json", {
            **metadata, "decision_policy": policy, "doc": case["doc"],
            "journal": case["journal"],
            "provider": args.provider if policy == "llm" else None,
            "model": args.model if policy == "llm" else None,
            "status": decision["status"],
            "budgets": {"max_tool_calls": args.max_tool_calls, "max_turns": args.max_turns,
                        "max_duration_s": args.max_duration_s,
                        "max_cost_usd": args.max_cost_usd},
        })
    if isinstance(failure, (KeyboardInterrupt, SystemExit)):
        raise failure
    evaluation = {"doc": case["doc"], "journal": case["journal"],
                  "behaviour": case["behaviour"], "policy": policy,
                  "status": decision["status"], "expected": case["expected"],
                  "verdict": decision.get("verdict"),
                  "correct": decision["status"] == "completed"
                  and decision.get("verdict") == case["expected"]}
    write_json(directory / "evaluation.json", evaluation)
    return evaluation


def summarise(cases: list[dict]) -> dict:
    """Correct verdicts per approach, per behaviour and per journal, never pooled
    across approaches."""
    table = {}
    for case in cases:
        row = table.setdefault(case["policy"], {"correct": 0, "total": 0,
                                                "by_behaviour": {}, "by_journal": {}})
        row["correct"] += case["correct"]
        row["total"] += 1
        for axis, value in (("by_behaviour", str(case["behaviour"])),
                            ("by_journal", case["journal"])):
            cell = row[axis].setdefault(value, [0, 0])
            cell[0] += case["correct"]
            cell[1] += 1
    return table


def main_run(args) -> int:
    check_budget(args.max_tool_calls, args.max_turns)
    if not 1 <= args.repetitions <= 5:
        raise ValueError("repetitions must stay between 1 and 5")
    corpus = load_corpus(args.lot)
    require_nato()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    metadata = {"schema_version": 1, "git_commit": commit, "provider": args.provider,
                "model": args.model, "runner": os.environ.get("RUNNER_NAME"),
                "lot": args.lot, "corpus_sha256": corpus_sha256(args.lot),
                "scripts_sha256": scripts_sha256(), "frozen_sha256": frozen_sha256(),
                "frozen_v3_sha256": frozen_v3_sha256()}
    write_json(root / "plan.json", {**metadata, "repetitions": args.repetitions,
                                    "documentations": sorted({case["doc"] for case in corpus}),
                                    "journals": list(JOURNALS),
                                    "approaches": list(APPROACHES)})
    reachable = provider_preflight(args, root)
    if reachable is not True:
        raise RuntimeError("Provider preflight failed: the endpoint is unreachable"
                           if reachable is None else
                           f"Provider preflight failed: model {args.model} is not served")
    results = {"schema_version": 1, "scope": SCOPE, **metadata,
               "repetitions": args.repetitions, "approaches": list(APPROACHES), "cases": []}
    try:
        for repetition in range(1, args.repetitions + 1):
            for index, case in enumerate(corpus):
                # Rotate the order so no approach always runs first on a documentation.
                shift = (repetition + index) % len(APPROACHES)
                for policy in APPROACHES[shift:] + APPROACHES[:shift]:
                    directory = (root / f"trial-{repetition:02d}" / case["doc"].removesuffix(".md")
                                 / case["journal"] / policy)
                    evaluation = run_approach(case, policy, directory, args,
                                              {**metadata, "repetition": repetition})
                    results["cases"].append({**evaluation, "repetition": repetition,
                                             "spend": spend(directory),
                                             "routing": routing(directory)})
        results["summary"] = summarise(results["cases"])
        write_json(root / "results.json", results)
        return 0
    except BaseException as exc:
        write_json(root / "results.json", results)
        write_json(root / "controller-failure.json", failure_detail(exc))
        raise


def public_summary(root: Path) -> dict:
    """Job-log projection: counts and statuses only, no documentation text."""
    path = root / "results.json"
    results = json.loads(path.read_text()) if path.is_file() else {}
    failure = root / "controller-failure.json"
    preflight, preflight_error = root / "provider-preflight.json", root / "provider-preflight-error.json"
    return {
        "scope": results.get("scope"), "git_commit": results.get("git_commit"),
        "model": results.get("model"), "repetitions": results.get("repetitions"),
        "lot": results.get("lot"), "scripts_sha256": results.get("scripts_sha256"),
        "frozen_sha256": results.get("frozen_sha256"),
        "frozen_v3_sha256": results.get("frozen_v3_sha256"),
        "corpus_sha256": results.get("corpus_sha256"),
        "provider_preflight": json.loads(preflight.read_text()) if preflight.is_file() else None,
        "provider_preflight_error": (json.loads(preflight_error.read_text())
                                     if preflight_error.is_file() else None),
        "summary": results.get("summary"),
        "cases": [{key: case.get(key) for key in ("repetition", "doc", "journal", "behaviour",
                                                  "policy",
                                                  "status", "expected", "verdict", "correct",
                                                  "spend")}
                  for case in results.get("cases", [])],
        "controller_failure": json.loads(failure.read_text()) if failure.is_file() else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["run", "summary"])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provider", choices=[PROVIDER], default=PROVIDER)
    parser.add_argument("--model", choices=list(MODEL_PANEL), default=MODEL)
    parser.add_argument("--lot", choices=list(LOTS), default="connu",
                        help="connu: the nine documentations the strongest script was written "
                             "against; inedit: documentations written after it was frozen; "
                             "v3: documentations written after the mechanism script was frozen")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--max-tool-calls", type=int, default=MAX_TOOL_CALLS)
    parser.add_argument("--max-turns", type=int, default=MAX_TURNS)
    parser.add_argument("--max-duration-s", type=float, default=None,
                        help="Optional elapsed-time ceiling; unset measures without capping")
    parser.add_argument("--max-cost-usd", type=float, default=None,
                        help="Optional cost ceiling; unset measures without capping")
    args = parser.parse_args()

    def terminate(signum, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, terminate)
    if args.command == "summary":
        print(json.dumps(public_summary(args.output.resolve()), indent=2, sort_keys=True))
        return 0
    return main_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
