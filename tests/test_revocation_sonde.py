"""Offline checks of the revocation probe and its adversarial scripts."""
from __future__ import annotations

import importlib.util
import inspect
import json
from pathlib import Path

import pytest

SONDE = Path(__file__).resolve().parents[1] / "benchmarks/experiments/revocation_commandes_attente/sonde.py"


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


def test_every_documentation_gets_every_journal(sonde, tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(sonde, "SCRIPTS", {"spy": lambda doc, journal: seen.append(journal) or "flaw"})
    for name in ("a.md", "b.md"):
        (tmp_path / name).write_text("Gateway manual.", encoding="utf-8")
    key = tmp_path / "key.json"
    key.write_text(json.dumps({"a.md": {"behaviour": 1}, "b.md": {"behaviour": 2}}), encoding="utf-8")
    result = sonde.run(tmp_path, key)
    assert seen == [*sonde.JOURNALS.values()] * 2
    assert [row["expected"] for row in result["rows"]] == ["flaw"] * 4 + ["expected"] * 4


def test_the_journals_differ_only_by_the_wait(sonde):
    waits = {name: sonde.journal_facts(journal)["waited_s"]
             for name, journal in sonde.JOURNALS.items()}
    assert waits == {"attente-5min": 338, "attente-10h": 36000,
                     "attente-60h": 216000, "attente-4j": 345600}
    for journal in sonde.JOURNALS.values():
        assert sonde.journal_facts(journal)["dispatched_after_revocation"]
        assert journal[:3] == sonde.JOURNALS["attente-5min"][:3]


def test_version_one_is_untouched(sonde):
    assert sonde.scripts_sha256() == (
        "faaf189ee6057635ec072987e8c059c8660bc04c7ae8f83f9549595db95b257d")


def test_the_strongest_script_wins_on_the_known_lot(sonde):
    result = sonde.run(*sonde.LOTS["connu"])
    assert result["totals"]["best"] == len(result["rows"]) == 36


@pytest.mark.parametrize("text, wait, verdict", [
    # Paraphrases absent from the known lot: the script must not rely on exact sentences.
    ("Once an operator is suspended, the gateway cancels every instruction they left pending.", 338, "flaw"),
    ("Rights are validated upon intake; later account suspension does not block queued work.", 338, "expected"),
    ("Undelivered commands are kept for up to twelve hours, then deleted.", 338, "expected"),
    ("Undelivered commands are kept for up to twelve hours, then deleted.", 36000 * 2, "flaw"),
    ("Operator sessions expire after 10 minutes. Revoking a role removes its pending requests.", 338, "flaw"),
])
def test_the_strongest_script_on_new_wordings(sonde, text, wait, verdict):
    assert sonde.script_best(text, sonde._journal(wait)) == verdict


def test_versions_two_and_three_are_frozen(sonde):
    """Commit ee03270 froze version 2; the v3 freeze adds the mechanism script."""
    assert sonde.frozen_sha256() == (
        "7cb52c29d00b865569f55afa90e0ca448017008d77f39df378fd2d4130550005")
    assert sonde.frozen_v3_sha256() == (
        "ecdeab039ba06c79bdc12dd6ffc1ed9b705b3cd70f302eef8b3d4b73d12269a8")


@pytest.mark.parametrize("lot, count", [("connu", 36), ("inedit", 60)])
def test_the_mechanism_script_keeps_every_known_case(sonde, lot, count):
    result = sonde.run(*sonde.LOTS[lot])
    assert result["totals"]["mechanism"] == len(result["rows"]) == count


# Hand-written before the v3 lot, after its brief: each rule follows from two
# facts, without the v2 words. In-sample for the mechanism script.
MECHANISM_DOCS = {
    "signature checked on wake": (1, None, (
        "1. Each command is signed with the submitting operator's personal key. "
        "2. Operator sessions time out after 15 minutes. "
        "3. When the device wakes, it checks the signature against the operator directory "
        "as it stands at that moment. "
        "4. Directory entries for disabled accounts are marked inactive within seconds.")),
    "account checked before each send": (1, None, (
        "1. The hub keeps commands for sleeping sensors. "
        "2. Before each transmission, the dispatcher confirms that the submitting account "
        "is still enabled. 3. Tokens are valid for 8 hours.")),
    "closing cascades to owned objects": (1, None, (
        "1. Every queued command is an object owned by the operator who created it. "
        "2. Certificates are renewed every 30 days. "
        "3. Closing an account cancels every object owned by that account.")),
    "endpoint refuses invalid tokens": (1, None, (
        "1. Commands carry the issuer's access token to the endpoint. "
        "2. Access tokens of deactivated users are flagged invalid immediately. "
        "3. The endpoint refuses any command whose token is invalid.")),
    "gateway re-signs": (2, None, (
        "1. On submission, the gateway confirms the operator's role. "
        "2. Admin sessions last 20 minutes. "
        "3. The gateway then re-signs the command with its own service key. "
        "4. Devices trust only the gateway's key and never see operator identities.")),
    "role snapshot": (2, None, (
        "1. When a command is accepted, the gateway records a snapshot of the sender's role "
        "in the queue entry. 2. Delivery relies on that recorded snapshot. "
        "3. The dispatcher does not consult the account directory again.")),
    "disabling only blocks new work": (2, None, (
        "1. Commands wait at the relay until the endpoint polls. "
        "2. Disabling an operator only prevents new sign-ins and new submissions. "
        "3. API keys expire after 12 hours.")),
    "deadline stamp": (3, 129600, (
        "1. Each queued item is stamped with a deadline at creation. "
        "2. The deadline is set 36 hours after creation. "
        "3. The dispatcher looks only at the destination and the deadline, not at who "
        "submitted the item. 4. Operator sessions expire after 30 minutes.")),
    "one week then give up": (3, 604800, (
        "1. Pending commands stay in the queue for up to one week, after which the gateway "
        "gives up on them. 2. Tokens last 24 hours. "
        "3. Account changes are handled by the directory service.")),
    "retries for three days": (3, 259200, (
        "1. The relay retries delivery every 10 minutes for up to 3 days and then abandons "
        "the command. 2. Certificates are valid for one year. "
        "3. Delivery uses the relay's own service identity.")),
}


@pytest.mark.parametrize("name", sorted(MECHANISM_DOCS))
def test_the_mechanism_script_reads_two_fact_rules(sonde, name):
    behaviour, period, text = MECHANISM_DOCS[name]
    for journal in sonde.JOURNALS.values():
        expected = sonde.expected_verdict(behaviour, period, sonde.journal_facts(journal))
        assert sonde.script_mechanism(text, journal) == expected


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


# --- the LLM approach, the runner and the workflow -------------------------

from types import SimpleNamespace

from openai.types.chat import ChatCompletion
import yaml

from benchmarks.experiments.revocation_commandes_attente import live
from benchmarks.experiments.revocation_commandes_attente import llm as revocation_llm
from benchmarks.experiments.ssh_reference_llm import RecordingClient, _message
from src.agent.provider import LLMProvider

DOC = ("Permissions are checked when a command is submitted. "
       "Accepted commands stay queued until the device reconnects.")


class ScriptedVerdict:
    """Answer each request with the next scheduled finish_verdict call."""

    base_url = "http://development.invalid/v1"

    def __init__(self, schedule):
        self.schedule = schedule
        self.requests = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def with_options(self, **kwargs):
        return self

    def create(self, **kwargs):
        self.requests.append({**kwargs, "messages": [_message(item) for item in kwargs["messages"]]})
        index = len(self.requests) - 1
        arguments = self.schedule[min(index, len(self.schedule) - 1)]
        return ChatCompletion.model_validate({
            "id": f"completion-{index}", "object": "chat.completion", "created": 1,
            "model": "development-model",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None,
                "tool_calls": [{"id": f"tool-{index}", "type": "function", "function": {
                    "name": "finish_verdict", "arguments": json.dumps(arguments)}}]}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
        })

    def refusals(self):
        found = []
        for request in self.requests:
            for item in request["messages"]:
                if item["role"] == "tool":
                    body = json.loads(item["content"])
                    if isinstance(body, dict) and body.get("ok") is False:
                        found.append(body["error_kind"])
        return found


def _args(**overrides):
    values = dict(max_tool_calls=revocation_llm.MAX_TOOL_CALLS, max_turns=revocation_llm.MAX_TURNS,
                  max_duration_s=60, max_cost_usd=1, model="development-model",
                  provider="ollama-umons", lot="connu")
    values.update(overrides)
    return SimpleNamespace(**values)


def _provider(client, directory):
    provider = object.__new__(LLMProvider)
    provider.provider, provider.model = "ollama-umons", "development-model"
    provider.client = RecordingClient(client, directory)
    return provider


def test_the_llm_closes_with_quotations_from_the_documentation(tmp_path, monkeypatch):
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", lambda _: None)
    run = live.new_run(tmp_path, "llm", _args())
    client = ScriptedVerdict([{"verdict": "expected", "reasoning": "Checked at submission.",
                               "evidence": ["Permissions are checked when a command is submitted."]}])
    decision = revocation_llm.run_llm(DOC, sonde_module().JOURNAL, run, _provider(client, tmp_path))
    assert decision["status"] == "completed" and decision["verdict"] == "expected"
    assert run._tool_call_count == 1
    prompt = json.loads((tmp_path / "prompt.json").read_text())
    assert prompt["user"]["documentation"] == DOC
    # The model's inputs are the journal, the documentation and its budgets: no answer key.
    assert set(prompt["user"]) == {"journal", "documentation", "budgets"}


def test_an_invented_quotation_is_refused_then_corrected(tmp_path, monkeypatch):
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", lambda _: None)
    run = live.new_run(tmp_path, "llm", _args())
    client = ScriptedVerdict([
        {"verdict": "flaw", "reasoning": "x", "evidence": ["Revocation purges the queue."]},
        {"verdict": "expected", "reasoning": "y",
         "evidence": ["Accepted commands stay queued until the device reconnects."]}])
    decision = revocation_llm.run_llm(DOC, sonde_module().JOURNAL, run, _provider(client, tmp_path))
    assert client.refusals() == ["quotation_not_in_documentation"]
    assert decision["status"] == "completed" and decision["verdict"] == "expected"


def test_budget_without_routing_slack_is_refused():
    with pytest.raises(ValueError):
        revocation_llm.check_budget(3, 5)


def test_the_runner_scores_scripts_and_model_on_the_same_case(tmp_path, monkeypatch):
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", lambda _: None)
    client = ScriptedVerdict([{"verdict": "expected", "reasoning": "z",
                               "evidence": ["Permissions are checked when a command is submitted."]}])
    monkeypatch.setattr(live, "LLMProvider",
                        lambda provider, model: SimpleNamespace(
                            client=client, provider=provider, model=model,
                            chat_with_tools=_provider(client, tmp_path).chat_with_tools))
    case = {"doc": "x.md", "journal": "attente-10h", "text": DOC, "behaviour": 2,
            "expected": "expected"}
    script = live.run_approach(case, "default", tmp_path / "default", _args(), {})
    model = live.run_approach(case, "llm", tmp_path / "llm", _args(), {})
    assert script == {"doc": "x.md", "journal": "attente-10h", "behaviour": 2,
                      "policy": "default", "status": "completed",
                      "expected": "expected", "verdict": "flaw", "correct": False}
    assert model["verdict"] == "expected" and model["correct"] is True
    prompt = json.loads((tmp_path / "llm" / "prompt.json").read_text())
    assert prompt["user"]["journal"] == list(sonde_module().JOURNALS["attente-10h"])
    assert live.summarise([script, model]) == {
        "default": {"correct": 0, "total": 1, "by_behaviour": {"2": [0, 1]},
                    "by_journal": {"attente-10h": [0, 1]}},
        "llm": {"correct": 1, "total": 1, "by_behaviour": {"2": [1, 1]},
                "by_journal": {"attente-10h": [1, 1]}}}


def test_the_committed_corpus_loads_with_its_answer_key():
    corpus = live.load_corpus("connu")
    assert len(corpus) == 36
    assert [case["behaviour"] for case in corpus[::4]] == [1, 1, 1, 2, 2, 2, 3, 3, 3]
    # Behaviour 3 now has both answers, depending on the wait.
    assert {case["expected"] for case in corpus if case["behaviour"] == 3} == {"flaw", "expected"}
    assert len(live.corpus_sha256("connu")) == 64


def test_the_v3_lot_skips_the_document_excluded_before_any_score():
    corpus = live.load_corpus("v3")
    docs = {case["doc"] for case in corpus}
    assert len(docs) == 14 and len(corpus) == 56
    assert "05-copperfern-security-guide.md" not in docs
    assert {case["behaviour"] for case in corpus if case["doc"].startswith("0")} == {1, 2, 3}


def test_an_unwritten_lot_is_refused(monkeypatch, tmp_path):
    monkeypatch.setitem(live.LOTS, "inedit", (tmp_path / "docs", tmp_path / "key.json"))
    with pytest.raises(ValueError, match="no answer key"):
        live.load_corpus("inedit")


def test_the_runner_refuses_to_run_outside_nato(tmp_path, monkeypatch):
    monkeypatch.delenv("RUNNER_NAME", raising=False)
    with pytest.raises(RuntimeError, match="nato-master"):
        live.main_run(_args(output=tmp_path / "out", repetitions=1))
    assert not (tmp_path / "out").exists()


def test_the_public_summary_carries_no_documentation_text(tmp_path):
    (tmp_path / "results.json").write_text(json.dumps({"cases": [
        {"doc": "x.md", "policy": "llm", "text": DOC, "verdict": "flaw", "correct": True}]}))
    summary = live.public_summary(tmp_path)
    assert DOC not in json.dumps(summary)
    assert summary["cases"][0]["verdict"] == "flaw"


def test_the_workflow_is_manual_on_dev2_under_the_laboratory_lock():
    workflow = yaml.safe_load((Path(__file__).resolve().parents[1]
                               / ".github/workflows/revocation-commandes.yml").read_text())
    assert list(workflow[True]) == ["workflow_dispatch"]
    job = workflow["jobs"]["revocation"]
    assert job["runs-on"] == ["self-hosted", "nato-master"]
    run = job["steps"][0]["run"]
    assert 'require "${GITHUB_REF:-}" refs/heads/dev/2' in run
    assert "flock -x 9" in run
    assert "-m benchmarks.experiments.revocation_commandes_attente.live run" in run
    assert '--lot "$REV_LOT"' in run
    assert workflow[True]["workflow_dispatch"]["inputs"]["lot"]["options"] == ["connu", "inedit", "v3"]
    assert job["steps"][1]["if"] == "always()"


def test_the_time_limit_follows_the_number_of_cases():
    """Run #4 was cut at 70 min: the limit ignored the four journals."""
    from benchmarks.experiments.revocation_commandes_attente.live import load_corpus

    workflow = yaml.safe_load((Path(__file__).resolve().parents[1]
                               / ".github/workflows/revocation-commandes.yml").read_text())
    job = workflow["jobs"]["revocation"]
    run = job["steps"][0]["run"]
    assert 'load_corpus(os.environ["REV_LOT"])' in run
    assert 'limit="$((600 + 120 * cases * REV_REPETITIONS))"' in run
    assert 'timeout --signal=TERM --kill-after=45s "$limit"' in run
    largest = max(len(load_corpus(lot)) for lot in ("connu", "inedit", "v3"))
    assert job["timeout-minutes"] * 60 >= 600 + 120 * largest * 3


def sonde_module():
    from benchmarks.experiments.revocation_commandes_attente import sonde
    return sonde


@pytest.mark.parametrize("step_index", [0, 1])
def test_each_step_reexecs_through_sudo_with_the_variables_it_reads(tmp_path, step_index):
    """The rebuilt runner is unprivileged: each step must become root first."""
    import os
    import re
    import shutil
    import subprocess

    if os.geteuid() == 0 or shutil.which("bash") is None:
        pytest.skip("Needs an unprivileged shell")
    workflow = yaml.safe_load((Path(__file__).resolve().parents[1]
                               / ".github/workflows/revocation-commandes.yml").read_text())
    job = workflow["jobs"]["revocation"]
    script = tmp_path / "step.sh"
    script.write_text(job["steps"][step_index]["run"], encoding="utf-8")
    fake = tmp_path / "bin"
    fake.mkdir()
    record = tmp_path / "sudo-args"
    (fake / "sudo").write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > {record}\n', encoding="utf-8")
    (fake / "sudo").chmod(0o755)
    env = {**os.environ, "PATH": f"{fake}:{os.environ['PATH']}"}
    subprocess.run(["bash", str(script)], env=env, check=True, timeout=10)
    args = record.read_text().splitlines()
    assert args[0] == "-n" and args[-2:] == ["bash", str(script)]
    preserved = set(args[1].removeprefix("--preserve-env=").split(","))
    # Every job variable and runner variable the step reads must survive sudo.
    read = set(re.findall(r"\$\{?([A-Z][A-Z0-9_]+)", job["steps"][step_index]["run"]))
    needed = read & (set(job["env"]) | {"RUNNER_NAME", "GITHUB_EVENT_NAME", "GITHUB_REF"})
    assert needed <= preserved
