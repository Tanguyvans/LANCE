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
#
# The list is deliberately not just the obvious ones: ``os.posix_spawn`` starts
# a process without going through ``subprocess``, and ``ctypes`` can reach the C
# library without any Python-level process API. Both were measured escaping an
# earlier version of this guard.
BLOCKED_EVENTS = frozenset({
    "socket.connect", "socket.connect_ex", "socket.getaddrinfo", "socket.sendto",
    "socket.bind", "socket.__new__",
    "subprocess.Popen",
    "os.system", "os.exec", "os.fork", "os.execv", "os.execl", "os.execve",
    "os.spawn", "os.posix_spawn", "os.posix_spawnp",
    "ctypes.dlopen", "ctypes.dlsym", "ctypes.call_function",
    "os.rename", "os.remove", "os.rmdir", "os.replace", "os.unlink",
    "shutil.move", "shutil.rmtree", "shutil.copyfile",
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
    """Install the process-wide hook once, rebound to this run's scope.

    An audit hook cannot be removed, so the same guard stays registered for
    the process. Each call must still observe *its own* directory and report
    into *its own* list, otherwise a second run would authorise the first
    run's directory and silence its own breaches.
    """
    if not _INSTALLED:
        guard = Guard(allowed_output, breaches)
        sys.addaudithook(guard.__call__)
        _INSTALLED.append(guard)
    else:
        guard = _INSTALLED[0]
        guard.allowed = allowed_output.resolve()
        guard.breaches = breaches
    return guard


def load_corpus() -> dict[str, Any]:
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
                    encoding="utf-8")


ARMS = {"rules": run_rules, "rules_attempt": run_attempting_rules}


def run_one(fixture: dict[str, Any], directory: Path, arm: str = "rules") -> dict[str, Any]:
    """Run one deterministic arm on one frozen fixture and write the trial.

    The arm is a parameter, never read from the corpus: the frozen corpus
    declares a dossier and its oracle, not the policy under test.
    """
    if arm not in ARMS:
        raise ValueError(f"Unknown deterministic arm: {arm}")
    dossier = validate_dossier(fixture["dossier"])
    oracle = fixture["oracle"]
    directory.mkdir(parents=True, exist_ok=True)
    journal = Journal(dossier, dossier["view"])
    answer = ARMS[arm](dossier, journal)
    _write_json(directory / "dossier.json", dossier)
    _write_json(directory / "oracle.json", oracle)
    _write_json(directory / "answer.json", answer)
    (directory / "journal.jsonl").write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in journal.records),
        encoding="utf-8")
    evaluation = evaluate(dossier, oracle, answer, journal)
    _write_json(directory / "evaluation.json", evaluation)
    return evaluation


def run_sandbox(output: Path, arm: str = "rules") -> dict[str, Any]:
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
            evaluation = run_one(fixture, directory, arm)
            trials.append({
                "trial": directory.name,
                "view": fixture["dossier"]["view"],
                "schema": fixture["dossier"]["schema"],
                "arm": arm,
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
        "arm": arm,
        # Scope of the claim, stated with the result so it cannot be read as
        # more than it is: an audit hook observes Python-level events only.
        "guard": {
            "mechanism": "sys.addaudithook",
            "blocked_events": sorted(BLOCKED_EVENTS),
            "unobserved": [
                "native code reached without ctypes/Popen/posix_spawn",
                "writes through a descriptor opened before arming",
                "kernel-level syscalls issued outside CPython",
            ],
            "scope": "None of the listed events occurred; this is not a "
                     "native-code sandbox and does not prove the process was isolated.",
        },
        "guard_clean": not breaches,
        "breaches": breaches,
        "claims_measurement": False,
        "claims_isolation": False,
        "note": ("Deterministic arms only; no LLM, no preflight, no admission. "
                 "Never yields pair_admissible or mt_admissible."),
    }
    _write_json(output / "sandbox-report.json", report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Hermetic deterministic H2 sandbox")
    parser.add_argument("--output", type=Path, required=True,
                        help="Directory receiving the trials and the report")
    parser.add_argument("--arm", choices=sorted(ARMS), default="rules",
                        help="Deterministic arm to run (default: rules)")
    args = parser.parse_args(argv)
    report = run_sandbox(args.output, args.arm)
    print(json.dumps({key: report[key] for key in
                      ("sandbox", "arm", "trials", "guard_clean", "breaches")},
                     indent=2, ensure_ascii=False))
    return 0 if report["guard_clean"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
