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
    assert [c["key"] for c in cards] == ["finding-0001", "finding-0002", "intrusion-limits", "summary"]
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

    p.provider.chat_with_tools.reset_mock()
    p.provider.chat_with_tools.side_effect = original
    assert run_phase(p, AGENTS["report"]) == "completed"
    # Summary is invalidated because writing completeness changed; other cards remain intact.
    assert [prompt_card(c.kwargs)["key"] for c in p.provider.chat_with_tools.call_args_list] == ["finding-0002", "summary"]
    assert [e["reused"] for e in manifest(p)["sections"]] == [True, False, True, False]
    p.provider.chat_with_tools.reset_mock()
    assert run_phase(p, AGENTS["report"]) == "completed"
    p.provider.chat_with_tools.assert_not_called()


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
    assert [c["key"] for c in cards] == ["intrusion-limits", "summary"]
    assert cards[-1]["facts"]["intrusion"]["execution_status"].startswith("failed:")
    assert cards[-1]["facts"]["analysis_counts"]["devices_failed"] == 1
    assert "failed:phase5_completion_invalid" in (p.run_dir / "06_report.md").read_text()


def test_model_change_invalidates_cached_commentary(report_run):
    p = report_run("full", "ok")
    assert run_phase(p, AGENTS["report"]) == "completed"
    p.provider.model = "another-test-model"
    p.provider.chat_with_tools.reset_mock()
    assert run_phase(p, AGENTS["report"]) == "completed"
    assert p.provider.chat_with_tools.call_count == 4
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
