"""Per-card report isolation, completeness and resumption; no live provider."""
import json
from collections import Counter

import pytest

from src.agent.phases.registry import run_phase
from src.agent.registry import AGENTS
from src.agent.phases.report import sections
from tests.test_report_review_regressions import report_run


def manifest(pipeline):
    return json.loads((pipeline.run_dir / sections.MANIFEST).read_text())


def test_summary_never_uses_model_prose_or_invents_traceability_incidents(report_run):
    p = report_run("full", "ok")
    original = p.provider.chat_with_tools.side_effect
    def generate(**kwargs):
        assert prompt_card(kwargs)["kind"] != "summary"
        return original(**kwargs)
    p.provider.chat_with_tools.side_effect = generate
    assert run_phase(p, AGENTS["report"]) == "completed"
    entry = manifest(p)["sections"][-1]
    saved = sections.read_object(p.run_dir, entry["artifact"])
    assert saved["generated_by"] == "pipeline"
    assert saved["attempts"] == []
    text = (p.run_dir / "06_report_analysis.md").read_text()
    assert "1 confirmées" in text and "1 non concluantes" in text
    assert "références non conformes" not in text
    assert "infirmée" not in text and "disparu" not in text
    assert "faits enregistrés" in (p.run_dir / "06_report.md").read_text()


def test_summary_missing_sources_are_unknown_not_zero_or_negative_proof():
    text = sections.render_summary({
        "source_issues": ["missing tests"], "analysis_counts": {},
        "recorded_verification_states": {}, "execution_facts": {"ledger_readable": False},
        "intrusion": {"available": False},
    })
    assert "inconnu/inconnu" in text
    assert "ne sont pas exhaustifs" in text
    assert "0 confirmées" not in text
    assert "journal d’outils est absent" in text
    assert "couverture inconnue" in text


def prompt_card(kwargs):
    return json.loads(kwargs["system_prompt"].split("\n\n", 1)[1])


@pytest.mark.parametrize("profile", ["full", "compact"])
def test_isolated_contexts_include_indeterminate_and_summary_last(report_run, profile):
    p = report_run(profile, "ok")
    originals = {f: (p.run_dir / f).read_bytes() for f in
                 ("03_vuln_analysis.json", "04_exploitation.json", "05_intrusion.json")}
    assert run_phase(p, AGENTS["report"]) == "completed"
    calls = p.provider.chat_with_tools.call_args_list
    cards = [prompt_card(c.kwargs) for c in calls]
    assert [c["key"] for c in cards] == ["finding-0001", "finding-0002", "intrusion-limits"]
    cards.append(sections.read_object(p.run_dir, manifest(p)["sections"][-1]["artifact"])["card"])
    assert cards[0]["facts"]["hypothesis"]["id"] == "V1"
    assert "synthetic finding 2" not in calls[0].kwargs["system_prompt"]
    assert "synthetic finding 1" not in calls[1].kwargs["system_prompt"]
    assert cards[1]["facts"]["recorded_verification_state"] == "inconclusive"
    assert "hypothesis" not in cards[-1]["facts"]
    assert cards[-1]["facts"]["recorded_verification_states"] == {"confirmed": 1, "inconclusive": 1}
    text = (p.run_dir / "06_report.md").read_text()
    assert text.count("— finding-0001") == text.count("— finding-0002") == 1
    assert "inconclusive" in text and "Synthèse exécutive" in text
    for name, content in originals.items():
        assert (p.run_dir / name).read_bytes() == content


def test_truncated_card_does_not_abort_others_and_only_failed_card_is_retried(report_run):
    p = report_run("full", "ok")
    original = p.provider.chat_with_tools.side_effect

    def generate(**kw):
        if prompt_card(kw)["key"] == "finding-0002":
            kw["completion_metadata"]["finish_reason"] = "length"
            return "TRUNCATED-DRAFT"
        return original(**kw)

    p.provider.chat_with_tools.side_effect = generate
    assert run_phase(p, AGENTS["report"]) == "partial:memo_truncated"
    m = manifest(p)
    assert [e["status"] for e in m["sections"]] == ["usable", "unavailable", "usable", "usable"]
    assert "TRUNCATED-DRAFT" not in (p.run_dir / "06_report.md").read_text()
    rejected = sections.read_object(p.run_dir, m["sections"][1]["artifact"])
    assert rejected["draft"] == "TRUNCATED-DRAFT"
    assert [a["cause"] for a in rejected["attempts"]] == ["memo_truncated"] * 2
    assert [a["max_tokens"] for a in rejected["attempts"]] == [2048, 4096]

    p.provider.chat_with_tools.reset_mock()
    p.provider.chat_with_tools.side_effect = original
    assert run_phase(p, AGENTS["report"]) == "completed"
    # Summary is invalidated because writing completeness changed; other cards remain intact.
    assert [prompt_card(c.kwargs)["key"] for c in p.provider.chat_with_tools.call_args_list] == ["finding-0002"]
    assert [e["reused"] for e in manifest(p)["sections"]] == [True, False, True, False]
    p.provider.chat_with_tools.reset_mock()
    assert run_phase(p, AGENTS["report"]) == "completed"
    p.provider.chat_with_tools.assert_not_called()


@pytest.mark.parametrize("profile", ["full", "compact"])
def test_one_truncation_recovers_without_rewriting_other_cards(report_run, profile):
    p = report_run(profile, "ok")
    original = p.provider.chat_with_tools.side_effect
    counts = Counter()
    sources = {name: (p.run_dir / name).read_bytes() for name in
               ("03_vuln_analysis.json", "04_exploitation.json", "05_intrusion.json")}
    def generate(**kw):
        key = prompt_card(kw)["key"]
        counts[key] += 1
        if key == "finding-0001":
            kw["cost_tracker"].record_turn(20, 10)
            kw["completion_metadata"].update(finish_reason="length" if counts[key] == 1 else "stop",
                                               output_tokens=10, reasoning_tokens=None, reasoning_chars=0)
            return "REJECTED-DRAFT" if counts[key] == 1 else "Review the linked evidence."
        return original(**kw)
    p.provider.chat_with_tools.side_effect = generate
    assert run_phase(p, AGENTS["report"]) == "completed"
    assert counts == {"finding-0001": 2, "finding-0002": 1, "intrusion-limits": 1}
    calls = p.provider.chat_with_tools.call_args_list
    assert [c.kwargs["max_tokens"] for c in calls[:2]] == [p.execution_profile.report_max_tokens, p.execution_profile.report_max_tokens * 2]
    assert calls[0].kwargs["system_prompt"] == calls[1].kwargs["system_prompt"]
    assert "REJECTED-DRAFT" not in (p.run_dir / "06_report.md").read_text()
    entry = manifest(p)["sections"][0]
    record = sections.read_object(p.run_dir, entry["artifact"])
    assert entry["attempt_count"] == 2
    assert [a["cause"] for a in record["attempts"]] == ["memo_truncated", "none"]
    assert p.tracker.total_tokens() == (1040, 100)
    assert all((p.run_dir / name).read_bytes() == data for name, data in sources.items())
    p.provider.chat_with_tools.reset_mock()
    assert run_phase(p, AGENTS["report"]) == "completed"
    p.provider.chat_with_tools.assert_not_called()


@pytest.mark.parametrize("guard", ["budget", "stop", "deadline"])
def test_truncation_recovery_respects_run_guards(report_run, monkeypatch, guard):
    import importlib
    from src.agent.cost_tracker import BudgetExceeded
    module = importlib.import_module("src.agent.phases.report.run")
    p = report_run("full", "ok")
    clock = {"now": 1.0}
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["now"])
    def generate(**kw):
        kw["completion_metadata"]["finish_reason"] = "length"
        if guard == "stop":
            p._stop_event.set()
        elif guard == "deadline":
            clock["now"] = 10_000
        else:
            def fail_budget():
                raise BudgetExceeded("test budget exhausted")
            monkeypatch.setattr(p.tracker, "check_budget", fail_budget)
        return "REJECTED-DRAFT"
    p.provider.chat_with_tools.side_effect = generate
    if guard == "budget":
        with pytest.raises(BudgetExceeded):
            run_phase(p, AGENTS["report"])
    else:
        assert run_phase(p, AGENTS["report"]) == ("stopped" if guard == "stop" else "partial:timeout")
    assert p.provider.chat_with_tools.call_count == 1
    assert "REJECTED-DRAFT" not in (p.run_dir / "06_report.md").read_text()


def test_retry_provider_failure_stays_partial_and_keeps_first_attempt(report_run):
    p = report_run("full", "ok")
    original = p.provider.chat_with_tools.side_effect
    count = 0
    def generate(**kw):
        nonlocal count
        if prompt_card(kw)["key"] != "finding-0001":
            return original(**kw)
        count += 1
        if count == 1:
            kw["completion_metadata"]["finish_reason"] = "length"
            return "REJECTED-DRAFT"
        raise RuntimeError("provider unavailable")
    p.provider.chat_with_tools.side_effect = generate
    assert run_phase(p, AGENTS["report"]) == "partial:provider_error"
    entry = manifest(p)["sections"][0]
    record = sections.read_object(p.run_dir, entry["artifact"])
    assert record["attempts"][0]["draft"] == "REJECTED-DRAFT"
    assert record["attempts"][1]["error_kind"] == "RuntimeError"
    assert entry["finish_reason"] is None
    assert count == 2


def test_generation_settings_invalidate_cache(report_run):
    from dataclasses import replace
    p = report_run("full", "ok")
    assert run_phase(p, AGENTS["report"]) == "completed"
    p.execution_profile = replace(p.execution_profile, report_max_tokens=1024)
    p.provider.chat_with_tools.reset_mock()
    assert run_phase(p, AGENTS["report"]) == "completed"
    assert p.provider.chat_with_tools.call_count == 3


def test_changed_source_invalidates_only_its_card(report_run):
    p = report_run("full", "ok")
    assert run_phase(p, AGENTS["report"]) == "completed"
    path = p.run_dir / "03_vuln_analysis.json"
    data = json.loads(path.read_text())
    data["vulnerabilities"][1]["details"] = "CHANGED-FACT"
    path.write_text(json.dumps(data))
    p.provider.chat_with_tools.reset_mock()
    assert run_phase(p, AGENTS["report"]) == "completed"
    assert [prompt_card(c.kwargs)["key"] for c in p.provider.chat_with_tools.call_args_list] == ["finding-0002"]
    assert "CHANGED-FACT" in (p.run_dir / "06_report.md").read_text()


def test_large_inventory_has_no_global_cutoff_and_no_model_call_for_oversize_card(report_run):
    p = report_run("full", "ok")
    findings = [{"id": f"H{i}", "device_ip": f"192.0.2.{i}", "type": "no_auth",
                 "details": "é" * 30_000 if i == 2 else f"fact-{i}"} for i in range(1, 31)]
    (p.run_dir / "03_vuln_analysis.json").write_text(json.dumps({"vulnerabilities": findings}))
    (p.run_dir / "04_exploitation.json").write_text(json.dumps({"tests": []}))
    assert run_phase(p, AGENTS["report"]) == "partial:context_too_large"
    m = manifest(p)
    assert len(m["sections"]) == 32
    assert m["sections"][1]["cause"] == "context_too_large"
    assert all(len(c.kwargs["system_prompt"].encode()) <= sections.CONTEXT_MAX_BYTES
               for c in p.provider.chat_with_tools.call_args_list)
    text = (p.run_dir / "06_report.md").read_text()
    assert "fact-30" in text and "é" * 30_000 in text
    assert text.count("— finding-") == 30


def test_duplicate_ids_and_orphan_tests_are_not_silently_merged(report_run):
    p = report_run("full", "ok")
    path = p.run_dir / "03_vuln_analysis.json"
    data = json.loads(path.read_text())
    data["vulnerabilities"][1]["id"] = "V1"
    path.write_text(json.dumps(data))
    assert run_phase(p, AGENTS["report"]) == "partial:ambiguous_identity"
    entries = manifest(p)["sections"]
    assert Counter(e["kind"] for e in entries) == {"finding": 2, "diagnostic": 1, "intrusion": 1, "summary": 1}
    assert entries[0]["cause"] == entries[1]["cause"] == "ambiguous_identity"


def test_missing_source_is_reported_not_treated_as_empty_success(report_run):
    p = report_run("full", "ok")
    (p.run_dir / "03_vuln_analysis.json").unlink()
    assert run_phase(p, AGENTS["report"]).startswith("partial:")
    assert any(e["cause"] == "source_invalid" for e in manifest(p)["sections"])
    assert "Sources manquantes" in (p.run_dir / "06_report.md").read_text()


def test_malformed_or_tampered_cache_is_not_promoted(report_run):
    p = report_run("full", "ok")
    assert run_phase(p, AGENTS["report"]) == "completed"
    entry = manifest(p)["sections"][0]
    path = p.run_dir / entry["artifact"]
    data = json.loads(path.read_text())
    data["text"] = "TAMPERED-TEXT"
    path.write_text(json.dumps(data))
    p.provider.chat_with_tools.reset_mock()
    assert run_phase(p, AGENTS["report"]) == "completed"
    assert p.provider.chat_with_tools.call_count == 1
    assert "TAMPERED-TEXT" not in (p.run_dir / "06_report.md").read_text()


def test_global_deadline_stops_requests_but_renders_remaining_facts(report_run, monkeypatch):
    import importlib
    module = importlib.import_module("src.agent.phases.report.run")
    p = report_run("full", "ok")
    clock = {"now": 1.0}
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["now"])

    def generate(**kw):
        clock["now"] = 10_000.0
        return "LATE-RESPONSE"

    p.provider.chat_with_tools.side_effect = generate
    assert run_phase(p, AGENTS["report"]) == "partial:timeout"
    assert p.provider.chat_with_tools.call_count == 1
    assert len(manifest(p)["sections"]) == 4
    report = (p.run_dir / "06_report.md").read_text()
    assert "synthetic finding 2" in report and "LATE-RESPONSE" not in report


@pytest.mark.parametrize("changes,expected", [
    ({}, True),
    ({"vuln_id": "V2"}, False),
    ({"args": {"host": "192.0.2.2"}}, False),
])
def test_only_attributed_ledger_excerpts_enter_the_card(report_run, changes, expected):
    from tests.test_report_traceability import record
    p = report_run("full", "ok")
    path = p.run_dir / "04_exploitation.json"
    data = json.loads(path.read_text())
    data["tests"][0]["evidence_refs"] = ["tc-1"]
    path.write_text(json.dumps(data))
    ledger = p.run_dir / "tool_calls.jsonl"
    ledger.write_text(json.dumps(record(**changes)) + "\n")
    cards, _ = sections.build_cards(p.run_dir)
    linked = cards[0]["facts"]["tests"][0]
    assert bool(linked["attributed_observations"]) is expected
    assert "property/proof acceptance is not evaluated" in linked["reference_diagnostic"]


def test_changed_evidence_invalidates_only_its_card(report_run):
    from tests.test_report_traceability import record
    p = report_run("full", "ok")
    path = p.run_dir / "04_exploitation.json"
    data = json.loads(path.read_text())
    data["tests"][0]["evidence_refs"] = ["tc-1"]
    path.write_text(json.dumps(data))
    ledger = p.run_dir / "tool_calls.jsonl"
    ledger.write_text(json.dumps(record()) + "\n")
    assert run_phase(p, AGENTS["report"]) == "completed"
    ledger.write_text(json.dumps(record(result={"stdout": "changed observation"})) + "\n")
    p.provider.chat_with_tools.reset_mock()
    assert run_phase(p, AGENTS["report"]) == "completed"
    assert [prompt_card(c.kwargs)["key"] for c in p.provider.chat_with_tools.call_args_list] == ["finding-0001"]


def test_upstream_failure_reaches_summary_and_invalidates_intrusion_card(report_run):
    p = report_run("full", "ok")
    assert run_phase(p, AGENTS["report"]) == "completed"
    p._run_results["intrusion"] = "failed:phase5_completion_invalid"
    p.provider.chat_with_tools.reset_mock()
    assert run_phase(p, AGENTS["report"]) == "completed"  # report, not whole pipeline
    cards = [prompt_card(c.kwargs) for c in p.provider.chat_with_tools.call_args_list]
    assert [c["key"] for c in cards] == ["intrusion-limits"]
    cards.append(sections.read_object(p.run_dir, manifest(p)["sections"][-1]["artifact"])["card"])
    assert cards[-1]["facts"]["intrusion"]["execution_status"].startswith("failed:")
    assert cards[-1]["facts"]["analysis_counts"]["devices_failed"] == 1
    assert "failed:phase5_completion_invalid" in (p.run_dir / "06_report.md").read_text()


def test_model_change_invalidates_cached_commentary(report_run):
    p = report_run("full", "ok")
    assert run_phase(p, AGENTS["report"]) == "completed"
    p.provider.model = "another-test-model"
    p.provider.chat_with_tools.reset_mock()
    assert run_phase(p, AGENTS["report"]) == "completed"
    assert p.provider.chat_with_tools.call_count == 3
    assert not any(e["reused"] for e in manifest(p)["sections"])


def test_stop_during_resumption_preserves_usable_cards_without_success(report_run):
    p = report_run("full", "ok")
    assert run_phase(p, AGENTS["report"]) == "completed"
    p._stop_event.set()
    p.provider.chat_with_tools.reset_mock()
    assert run_phase(p, AGENTS["report"]) == "stopped"
    p.provider.chat_with_tools.assert_not_called()
    assert all(e["reused"] for e in manifest(p)["sections"])
    assert "synthetic finding 2" in (p.run_dir / "06_report.md").read_text()


def test_assembly_rejects_missing_or_mismatched_snapshots(report_run):
    p = report_run("full", "ok")
    assert run_phase(p, AGENTS["report"]) == "completed"
    m = manifest(p)
    path = p.run_dir / m["sections"][0]["artifact"]
    value = json.loads(path.read_text())
    value["card"]["facts"]["hypothesis"]["device_ip"] = "192.0.2.99"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="mismatch"):
        sections.render_cards(p.run_dir, m)
    path.unlink()
    with pytest.raises(FileNotFoundError):
        sections.render_cards(p.run_dir, m)
