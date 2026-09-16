"""Report groupings must never rewrite evidence or improve audit metrics."""
import json

from src.agent.phases.report.rendering import pregenerate_report_sections, render_deterministic_report
from src.agent.phases.report.context import generate_phase6_context
from src.agent.phases.report.grouping import group_findings_for_report
from src.benchmark.evaluator import evaluate
from tests.test_evaluation_audit import _finding, _truth, _confirmed, _evaluate, _proof


def test_related_report_declarations_keep_original_predictions_and_proofs(tmp_path):
    first = _finding(details="A database backup exposes credentials")
    second = _finding(id="V2", product="nginx", details="Anonymous download of that database backup")
    findings = [first, second]
    before = _evaluate(tmp_path, findings, [_truth()],
                       tests=[_confirmed(v) for v in findings], records=[_proof(v) for v in findings])
    sources = {name: (tmp_path / name).read_bytes() for name in (
        "03_vuln_analysis_raw.json", "03_vuln_analysis.json", "04_exploitation.json", "tool_calls.jsonl",
    )}
    pregenerate_report_sections(tmp_path)
    grouped = json.loads((tmp_path / "06_report_groups.json").read_text())
    assert grouped["hypothesis_count"] == 2
    assert grouped["group_count"] == 1
    assert set(grouped["groups"][0]["member_ids"]) == {"V1", "V2"}
    rendered = (tmp_path / "06_report_prefill.md").read_text()
    assert "V1" in rendered and "V2" in rendered
    assert "possible duplicates" in rendered
    generate_phase6_context(tmp_path, {"device_count": 1}, compact=False)
    render_deterministic_report(
        tmp_path, {"device_count": 1}, model="offline",
        analysis_status="absent", analysis_cause="memo_absent",
    )
    assert "V1" in (tmp_path / "06_report.md").read_text()
    after = evaluate(tmp_path, tmp_path / "truth.yaml", policy="strict-v3")
    assert before.funnel == after.funnel
    for name, content in sources.items():
        assert (tmp_path / name).read_bytes() == content


def test_structured_conditions_and_conflicting_aliases_are_not_discarded():
    for left, right in (
        ({"condition": {"role": "Admin"}}, {"condition": {"role": "admin"}}),
        ({"condition": "none"}, {}),
        ({"condition": "A", "conditions": ["B"]}, {"conditions": ["B"]}),
    ):
        findings = [_finding(**left), _finding(id="V2", **right)]
        assert len(group_findings_for_report(findings)) == 2
