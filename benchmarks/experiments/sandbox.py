"""Hermetic sandbox for one deterministic H2 arm, outside the laboratory.

The sandbox exists to prove, on a developer machine or in CI, that a harness
runs without a broker, without a model and without the laboratory. It runs the
deterministic ``rules`` arm of ``s_mqtt_formats`` against the frozen corpus,
writes the trial files, presents them to the existing offline recount, and
asserts that no network, process or write outside the trial directory occurred
while it ran.

What it does not do, and never claims:

- no LLM arm: this is not a measurement of a model;
- no preflight attestation: it never yields ``pair_admissible`` or
  ``mt_admissible``, which stay laboratory duties;
- no fixture: the corpus is frozen, so nothing is deployed or reset.

Usage::

    python -m benchmarks.experiments.sandbox --output DIR
"""
from __future__ import annotations

import argparse
import json
from contextlib import contextmanager
from pathlib import Path
import sys
from typing import Any, Callable

from benchmarks.experiments.mqtt_formats import (
    Journal, evaluate, run_attempting_rules, run_rules, validate_dossier,
)

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "benchmarks" / "experiments" / "mqtt-formats-corpus.json"

# Events the audit hook treats as a breach of the sandbox contract. ``open``
# is handled separately because reading is legitimate and writing is not.
BLOCKED_EVENTS = frozenset({
    "socket.connect", "socket.connect_ex", "socket.getaddrinfo", "socket.sendto",
    "subprocess.Popen", "os.system", "os.exec", "os.fork",
})
WRITE_FLAGS = 1 | 2 | 64 | 512 | 1024  # O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND


class SandboxBreach(RuntimeError):
    """The deterministic arm touched something the sandbox forbids."""


def _within(path: str, allowed: Path) -> bool:
    try:
        Path(path).resolve().relative_to(allowed)
    except (OSError, ValueError):
        return False
    return True


class Guard:
    """Armable audit gate.

    An audit hook cannot be removed from a running interpreter, and the test
    process must still be able to clean up its own temporary directories. The
    guard therefore stays installed and only inspects events while armed, so
    ``with guard.active():`` scopes the enforcement to the sandbox run.
    """

    def __init__(self, allowed_output: Path, breaches: list[str]) -> None:
        # Symlinked temporary directories (macOS /tmp -> /private/tmp) must
        # compare on the same resolved form as the paths actually opened.
        self.allowed = allowed_output.resolve()
        self.breaches = breaches
        self.armed = False

    @contextmanager
    def active(self):
        self.armed = True
        try:
            yield self
        finally:
            self.armed = False

    def __call__(self, event: str, args: tuple) -> None:
        if not self.armed:
            return
        if event in BLOCKED_EVENTS:
            self.breaches.append(f"{event}:{args[0] if args else ''}")
            raise SandboxBreach(event)
        if event == "open":
            flags = args[2] if len(args) > 2 else None
            target = args[0]
            if isinstance(flags, int) and flags & WRITE_FLAGS and isinstance(target, (str, bytes, Path)):
                if not _within(str(target), self.allowed):
                    self.breaches.append(f"write:{target}")
                    raise SandboxBreach(f"write outside {self.allowed}: {target}")


def audit_hook(allowed_output: Path, breaches: list[str]) -> Guard:
    """Return an armable guard refusing network, processes and foreign writes."""
    return Guard(allowed_output, breaches)


_INSTALLED: list[Guard] = []


def install_guard(allowed_output: Path, breaches: list[str]) -> Guard:
    """Install the process-wide hook once and return the armed guard."""
    if not _INSTALLED:
        guard = Guard(allowed_output, breaches)
        sys.addaudithook(guard.__call__)
        _INSTALLED.append(guard)
    return _INSTALLED[0]


def load_corpus() -> dict[str, Any]:
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
                    encoding="utf-8")


def run_one(fixture: dict[str, Any], directory: Path) -> dict[str, Any]:
    """Run one deterministic arm on one frozen fixture and write the trial."""
    dossier = validate_dossier(fixture["dossier"])
    oracle = fixture["oracle"]
    directory.mkdir(parents=True, exist_ok=True)
    journal = Journal(dossier, dossier["view"])
    arm = fixture.get("arm", "rules")
    answer = (run_attempting_rules if arm == "rules_attempt" else run_rules)(dossier, journal)
    _write_json(directory / "dossier.json", dossier)
    _write_json(directory / "oracle.json", oracle)
    _write_json(directory / "answer.json", answer)
    (directory / "journal.jsonl").write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in journal.records),
        encoding="utf-8")
    evaluation = evaluate(dossier, oracle, answer, journal)
    _write_json(directory / "evaluation.json", evaluation)
    return evaluation


def run_sandbox(output: Path) -> dict[str, Any]:
    """Run every fixture under the audit hook and report what happened."""
    corpus = load_corpus()
    output.mkdir(parents=True, exist_ok=True)
    breaches: list[str] = []
    guard = install_guard(output, breaches)
    guard.allowed = output.resolve()
    trials: list[dict[str, Any]] = []
    with guard.active():
        for index, fixture in enumerate(corpus["fixtures"]):
            directory = output / f"trial-{index:02d}"
            evaluation = run_one(fixture, directory)
            trials.append({
                "trial": directory.name,
                "view": fixture["dossier"]["view"],
                "schema": fixture["dossier"]["schema"],
                "arm": fixture.get("arm", "rules"),
                "success": evaluation["success"],
                "conclusion_correct": evaluation.get("conclusion_correct"),
                "abstained": evaluation.get("abstained"),
            })
    report = {
        "schema_version": 1,
        "sandbox": "deterministic-rules",
        "scenario_id": corpus["scenario_id"],
        "corpus_sha256_contract": corpus.get("contract"),
        "trials": trials,
        "hermetic": not breaches,
        "breaches": breaches,
        "claims_measurement": False,
        "note": ("Deterministic arms only; no LLM, no preflight, no admission. "
                 "Never yields pair_admissible or mt_admissible."),
    }
    _write_json(output / "sandbox-report.json", report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Hermetic deterministic H2 sandbox")
    parser.add_argument("--output", type=Path, required=True,
                        help="Directory receiving the trials and the report")
    args = parser.parse_args(argv)
    report = run_sandbox(args.output)
    print(json.dumps({key: report[key] for key in
                      ("sandbox", "trials", "hermetic", "breaches")}, indent=2, ensure_ascii=False))
    return 0 if report["hermetic"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
