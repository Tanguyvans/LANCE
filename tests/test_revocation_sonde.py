"""Offline checks of the revocation probe and its adversarial scripts."""
from __future__ import annotations

import importlib.util
import inspect
import json
from pathlib import Path

import pytest

SONDE = Path(__file__).resolve().parents[1] / "benchmarks/experiments/revocation-commandes-attente/sonde.py"


@pytest.fixture(scope="module")
def sonde():
    spec = importlib.util.spec_from_file_location("revocation_sonde", SONDE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_journal_facts(sonde):
    facts = sonde.journal_facts(sonde.JOURNAL)
    assert facts == {"dispatched_after_revocation": True, "waited_s": 338}


@pytest.mark.parametrize("behaviour, period, verdict", [
    (1, None, "flaw"), (2, None, "expected"), (3, 300, "flaw"), (3, 600, "expected")])
def test_expected_verdict(sonde, behaviour, period, verdict):
    assert sonde.expected_verdict(behaviour, period, sonde.journal_facts(sonde.JOURNAL)) == verdict


def test_scripts_never_read_the_answer_key(sonde):
    for script in sonde.SCRIPTS.values():
        assert list(inspect.signature(script).parameters) == ["documentation", "journal"]
        source = inspect.getsource(script)
        assert "ANSWER_KEY" not in source and "corrige" not in source


def test_every_documentation_gets_the_same_journal(sonde, tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(sonde, "SCRIPTS", {"spy": lambda doc, journal: seen.append(journal) or "flaw"})
    for name in ("a.md", "b.md"):
        (tmp_path / name).write_text("Gateway manual.", encoding="utf-8")
    key = tmp_path / "key.json"
    key.write_text(json.dumps({"a.md": {"behaviour": 1}, "b.md": {"behaviour": 2}}), encoding="utf-8")
    result = sonde.run(tmp_path, key)
    assert seen == [sonde.JOURNAL, sonde.JOURNAL]
    assert [row["expected"] for row in result["rows"]] == ["flaw", "expected"]


@pytest.mark.parametrize("text, verdict", [
    ("When an operator's permissions are revoked, all of their pending commands are discarded.", "flaw"),
    ("Permissions are checked at submission; queued commands are not cancelled afterwards.", "expected"),
    ("Pending commands older than 10 minutes are discarded.", "expected"),
    ("Pending commands older than 2 minutes are discarded.", "flaw"),
])
def test_keyword_script_on_explicit_sentences(sonde, text, verdict):
    assert sonde.script_keywords(text, sonde.JOURNAL) == verdict


def test_duration_script_falls_back_to_the_default_rule(sonde):
    assert sonde.script_duration("Sessions time out after 30 minutes.", sonde.JOURNAL) == "flaw"
    assert sonde.script_duration("Queued messages expire after 1 hour.", sonde.JOURNAL) == "expected"


def test_fingerprint_is_stable(sonde):
    assert sonde.scripts_sha256() == sonde.scripts_sha256()
    assert len(sonde.scripts_sha256()) == 64
