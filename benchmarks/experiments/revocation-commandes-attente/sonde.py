"""Probe: can a script without a model decide the revocation verdict?

A gateway queues a command for a sleeping device; the sender's permissions are
withdrawn before delivery; the command is delivered anyway. Whether that is a
flaw depends on the product's documentation:

- behaviour 1: withdrawing permissions discards undelivered commands -> flaw;
- behaviour 2: permissions are checked at submission only -> expected;
- behaviour 3: undelivered commands are discarded after a period -> flaw only
  if the command waited longer than that period.

Every documentation is read against the same journal. The answer key
(``corrige.json``) is read only to score; no script receives it.

    .venv/bin/python benchmarks/experiments/revocation-commandes-attente/sonde.py
"""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
DOCS_DIR = HERE / "documentations"
ANSWER_KEY = HERE / "corrige.json"

# One journal for every documentation: nothing in it reveals the product.
JOURNAL = (
    "16:39:12  mqtt     publisher=operator_17  topic=site/x/device/y/request  result=accepted",
    "16:39:13  gateway  operation=queued        destination=device_y",
    "16:42:00  iam      principal=operator_17   status=revoked",
    "16:44:51  gateway  operation=dispatched    transport_identity=gateway_service",
)


def _seconds(clock: str) -> int:
    hours, minutes, seconds = (int(part) for part in clock.split(":"))
    return hours * 3600 + minutes * 60 + seconds


def journal_facts(journal) -> dict:
    """Technical facts every approach extracts the same way."""
    times = {}
    for line in journal:
        clock = line.split()[0]
        for event in ("queued", "revoked", "dispatched"):
            if event in line:
                times[event] = _seconds(clock)
    return {
        "dispatched_after_revocation": times["dispatched"] > times["revoked"],
        "waited_s": times["dispatched"] - times["queued"],
    }


def expected_verdict(behaviour: int, period_s: int | None, facts: dict) -> str:
    """Verdict implied by the answer key; used for scoring only."""
    if not facts["dispatched_after_revocation"]:
        return "expected"
    if behaviour == 1:
        return "flaw"
    if behaviour == 2:
        return "expected"
    return "flaw" if facts["waited_s"] > period_s else "expected"


# --------------------------------------------------------------------------
# Adversarial scripts. Each receives the documentation text and the journal
# only, and returns "flaw" or "expected". They are written to win.
# --------------------------------------------------------------------------

UNITS = {"s": 1, "sec": 1, "second": 1, "min": 60, "minute": 60,
         "h": 3600, "hr": 3600, "hour": 3600, "d": 86400, "day": 86400}
DURATION = re.compile(r"(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|hours?|hrs?|h|days?|d)\b",
                      re.IGNORECASE)
QUEUE = r"(queue|queued|pending|undelivered|outstanding|stored|buffer|backlog|waiting|not yet delivered|held)"
DISCARD = r"(discard|drop|purg|cancel|delet|remov|flush|invalidat|void|clear|expire|evict|reject)"
PERMISSION = r"(permission|privilege|right|role|access|credential|authori[sz]|revok|withdr[ae]w|deactivat|disabl|suspend)"
SUBMISSION = r"(at (?:the time of )?submission|when (?:a |the )?command is (?:submitted|sent|accepted|received)|upon (?:submission|acceptance|receipt)|on submission|at (?:enqueue|acceptance))"
ALWAYS = r"(regardless|irrespective|even if|even when|still (?:be )?deliver|guarantee|no matter|remain(?:s)? valid)"
EXPIRY = r"(expire|expiry|expiration|retention|retain|time-to-live|ttl|older than|longer than|discard|purg|drop)"
NEGATION = re.compile(r"\b(not|never|no longer|n't|without|nor)\b", re.IGNORECASE)


def _sentences(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"(?<=[.!?])\s+|\n+", text) if part.strip()]


def _has(pattern: str, sentence: str) -> bool:
    return re.search(pattern, sentence, re.IGNORECASE) is not None


def _negated_discard(sentence: str) -> bool:
    match = re.search(DISCARD, sentence, re.IGNORECASE)
    if match is None:
        return False
    window = sentence[max(0, match.start() - 40):match.start()]
    return NEGATION.search(window) is not None


def _durations(sentence: str) -> list[int]:
    found = []
    for value, unit in DURATION.findall(sentence):
        key = unit.lower().rstrip("s") or "s"
        key = {"sec": "s", "min": "min", "hr": "h"}.get(key, key)
        found.append(int(float(value) * UNITS.get(key, 1)))
    return found


def script_default(documentation: str, journal) -> str:
    """Delivered after revocation is always a flaw."""
    return "flaw" if journal_facts(journal)["dispatched_after_revocation"] else "expected"


def script_duration(documentation: str, journal) -> str:
    """Find an expiry period near queue words and compare it with the wait."""
    facts = journal_facts(journal)
    for sentence in _sentences(documentation):
        if _has(QUEUE, sentence) and _has(EXPIRY, sentence):
            durations = _durations(sentence)
            if durations:
                return "flaw" if facts["waited_s"] > durations[0] else "expected"
    return script_default(documentation, journal)


def script_keywords(documentation: str, journal) -> str:
    """Score behaviours sentence by sentence, with negation, then decide."""
    facts = journal_facts(journal)
    if not facts["dispatched_after_revocation"]:
        return "expected"
    scores = {1: 0, 2: 0, 3: 0}
    period = None
    for sentence in _sentences(documentation):
        queue, permission = _has(QUEUE, sentence), _has(PERMISSION, sentence)
        discard = _has(DISCARD, sentence) and not _negated_discard(sentence)
        durations = _durations(sentence)
        if queue and _has(EXPIRY, sentence) and durations:
            scores[3] += 2
            period = durations[0] if period is None else period
        if queue and permission and discard and not durations:
            scores[1] += 2
        if permission and _has(SUBMISSION, sentence):
            scores[2] += 2
        if (queue or permission) and _has(ALWAYS, sentence):
            scores[2] += 1
        if queue and permission and _negated_discard(sentence):
            scores[2] += 1
    behaviour = max(scores, key=lambda key: (scores[key], key == 1))
    if scores[behaviour] == 0:
        return "flaw"
    if behaviour == 3 and period is not None:
        return "flaw" if facts["waited_s"] > period else "expected"
    return "flaw" if behaviour == 1 else "expected"


SCRIPTS = {"default": script_default, "keywords": script_keywords, "duration": script_duration}


def scripts_sha256() -> str:
    """Fingerprint of everything the scripts run, to show they did not change."""
    parts = [inspect.getsource(function) for function in (
        journal_facts, _sentences, _has, _negated_discard, _durations,
        script_default, script_duration, script_keywords)]
    constants = (UNITS, DURATION.pattern, QUEUE, DISCARD, PERMISSION, SUBMISSION,
                 ALWAYS, EXPIRY, NEGATION.pattern, JOURNAL)
    parts.append(repr(constants))
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def run(docs_dir: Path = DOCS_DIR, answer_key: Path = ANSWER_KEY) -> dict:
    key = json.loads(answer_key.read_text(encoding="utf-8"))
    facts = journal_facts(JOURNAL)
    rows = []
    for path in sorted(docs_dir.glob("*.md")):
        entry = key[path.name]
        expected = expected_verdict(entry["behaviour"], entry.get("period_s"), facts)
        text = path.read_text(encoding="utf-8")
        verdicts = {name: script(text, JOURNAL) for name, script in SCRIPTS.items()}
        rows.append({"doc": path.name, "behaviour": entry["behaviour"],
                     "expected": expected, "verdicts": verdicts})
    totals = {name: sum(row["verdicts"][name] == row["expected"] for row in rows)
              for name in SCRIPTS}
    return {"scripts_sha256": scripts_sha256(), "rows": rows, "totals": totals}


def main() -> int:
    result = run()
    print(f"scripts sha256: {result['scripts_sha256']}")
    header = f"{'documentation':34} beh  expected  " + "  ".join(f"{name:9}" for name in SCRIPTS)
    print(header)
    for row in result["rows"]:
        marks = "  ".join(f"{('ok ' if row['verdicts'][n] == row['expected'] else 'NO ') + row['verdicts'][n]:9}"
                          for n in SCRIPTS)
        print(f"{row['doc']:34} {row['behaviour']:>3}  {row['expected']:8}  {marks}")
    count = len(result["rows"])
    print("correct: " + ", ".join(f"{name} {total}/{count}" for name, total in result["totals"].items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
