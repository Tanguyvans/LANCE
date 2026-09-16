import json

import pytest

from src.agent.phases.report.context import build_report_analysis_context, REPORT_CONTEXT_MAX_BYTES


def test_empty_cve_inventory_does_not_hide_recorded_searches(tmp_path):
    ledger = tmp_path / "tool_calls.jsonl"
    ledger.write_text('\n'.join(json.dumps({"tool": "cve_search", "result": []}) for _ in range(13)))
    before = ledger.read_bytes()
    context = build_report_analysis_context(tmp_path)
    assert context["execution_facts"]["cve_search_calls"] == 13
    assert context["execution_facts"]["recorded_calls"] == 13
    assert ledger.read_bytes() == before


@pytest.mark.parametrize("contents", [None, '{bad-json', '[]', '{"result": "ok"}'])
def test_missing_or_malformed_ledger_is_not_zero_searches(tmp_path, contents):
    if contents is not None:
        (tmp_path / "tool_calls.jsonl").write_text(contents)
    facts = build_report_analysis_context(tmp_path)["execution_facts"]
    assert facts["ledger_readable"] is False
    assert facts["cve_search_calls"] is None


def test_indeterminate_targets_and_reasons_are_bounded_context_not_confirmations(tmp_path):
    tests = [{"vuln_id": f"F{i}", "status": "FAILED", "verification_status": "inconclusive",
              "service": "mqtt-ws", "port": 9001, "device_ip": "192.0.2.1",
              "evidence": "No application exchange observed. " * 200} for i in range(20)]
    path = tmp_path / "04_exploitation.json"
    path.write_text(json.dumps({"tests": tests}))
    before = path.read_bytes()
    context = build_report_analysis_context(tmp_path)
    assert len(context["unresolved_tests"]) == 12
    assert context["omissions"]["unresolved_tests"] == 8
    assert context["unresolved_tests"][0]["service"] == "mqtt-ws"
    assert context["phase6"] == {}
    assert context["intrusion"] == {}
    assert path.read_bytes() == before
    size = len(json.dumps(context, ensure_ascii=False, separators=(",", ":")).encode())
    assert context["bounds"]["serialized_bytes"] == size <= REPORT_CONTEXT_MAX_BYTES
