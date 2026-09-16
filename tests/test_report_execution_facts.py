import json

import pytest

from src.agent.phases.report.sections import build_cards, section_prompt, CONTEXT_MAX_BYTES


def test_empty_cve_inventory_does_not_hide_recorded_searches(tmp_path):
    ledger = tmp_path / "tool_calls.jsonl"
    ledger.write_text('\n'.join(json.dumps({"tool": "cve_search", "result": []}) for _ in range(13)))
    before = ledger.read_bytes()
    _, context = build_cards(tmp_path)
    assert context["execution_facts"]["cve_search_calls"] == 13
    assert context["execution_facts"]["recorded_calls"] == 13
    assert ledger.read_bytes() == before


@pytest.mark.parametrize("contents", [None, '{bad-json', '[]', '{"result": "ok"}'])
def test_missing_or_malformed_ledger_is_not_zero_searches(tmp_path, contents):
    if contents is not None:
        (tmp_path / "tool_calls.jsonl").write_text(contents)
    _, context = build_cards(tmp_path)
    facts = context["execution_facts"]
    assert facts["ledger_readable"] is False
    assert facts["cve_search_calls"] is None


def test_indeterminate_targets_and_reasons_are_bounded_context_not_confirmations(tmp_path):
    tests = [{"vuln_id": f"F{i}", "status": "FAILED", "verification_status": "inconclusive",
              "service": "mqtt-ws", "port": 9001, "device_ip": "192.0.2.1",
              "evidence": "No application exchange observed. " * 200} for i in range(20)]
    path = tmp_path / "04_exploitation.json"
    path.write_text(json.dumps({"tests": tests}))
    (tmp_path / "03_vuln_analysis.json").write_text(json.dumps({"vulnerabilities": [
        {"id": t["vuln_id"], "device_ip": t["device_ip"]} for t in tests
    ]}))
    before = path.read_bytes()
    cards, summary = build_cards(tmp_path)
    findings = [c for c in cards if c["kind"] == "finding"]
    assert len(findings) == 20  # No global inventory cutoff.
    assert findings[0]["facts"]["tests"][0]["record"]["service"] == "mqtt-ws"
    assert summary["recorded_verification_states"] == {"inconclusive": 20}
    assert path.read_bytes() == before
    assert all(len(section_prompt(card).encode()) <= CONTEXT_MAX_BYTES for card in findings)
