"""Report contracts independent of LLM calls and network execution."""
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.agent.pipeline import Pipeline
from src.agent.phases.report import context as report_context, rendering as report_rendering
from src.agent.phases.report.sections import build_cards


def render(pipeline):
    report_rendering.render_deterministic_report(
        pipeline.run_dir, pipeline.context, model=pipeline.provider.model,
        analysis_status="unavailable", analysis_cause="memo_absent",
    )


@pytest.fixture
def pipeline(tmp_path):
    pipeline = Pipeline.__new__(Pipeline)
    pipeline.run_dir = tmp_path
    pipeline.context = {"device_count": 2, "target_subnet": "192.0.2.0/24"}
    pipeline.provider = SimpleNamespace(model="report-test-model")
    pipeline._uses_compact_local_moe = Mock(return_value=False)
    findings = [
        {"id": "V1", "device_id": "device-1", "device_ip": "192.0.2.1", "type": "no_auth", "severity": "HIGH"},
        {"id": "V2", "device_id": "device-2", "device_ip": "192.0.2.2", "type": "data_exposure", "severity": "CRITICAL"},
    ]
    (tmp_path / "03_vuln_analysis.json").write_text(json.dumps({"vulnerabilities": findings}))
    tests = [
        {"vuln_id": f["id"], "device_id": f["device_id"], "device_ip": f["device_ip"],
         "vuln_type": f["type"], "status": "CONFIRMED", "evidence_level": level,
         "evidence": evidence, "tool_used": "test_fixture", "data_extracted": []}
        for f, level, evidence in zip(findings, [2, 1], ["verified observation", "unsupported claim"])
    ]
    (tmp_path / "04_exploitation.json").write_text(json.dumps({
        "summary": {"total_tested": 2, "confirmed": 2, "not_exploitable": 0, "errors": 0}, "tests": tests,
    }))
    return pipeline


def test_report_context_excludes_unsupported_confirmations(pipeline):
    pipeline._generate_phase6_context()
    context = json.loads((pipeline.run_dir / "06_phase6_context.json").read_text())
    assert context["device_count"] == 2
    assert context["phase4_summary"]["verified_confirmed"] == 1
    assert [item["vuln_id"] for item in context["phase4_tests"]] == ["V1"]


def test_prefill_contains_verified_finding_only(pipeline):
    pipeline._pregenerate_report_sections()
    text = (pipeline.run_dir / "06_report_prefill.md").read_text()
    assert "device-1" in text
    assert "device-2" not in text
    assert "unsupported claim" not in text


def test_analysis_context_tolerates_absent_or_malformed_optional_files(pipeline):
    (pipeline.run_dir / "01_graph_evidence.json").write_text("malformed")
    (pipeline.run_dir / "02_recon_evidence.json").write_text("[]")
    cards, summary = build_cards(pipeline.run_dir)
    assert len([c for c in cards if c["kind"] == "finding"]) == 2
    assert summary["intrusion"]["available"] is False
    assert summary["intrusion"]["observed_access_count"] is None


def test_fallback_report_uses_run_metadata(pipeline):
    pipeline._generate_phase6_context()
    pipeline._pregenerate_report_sections()
    render(pipeline)
    text = (pipeline.run_dir / "06_report.md").read_text()
    assert "report-test-model" in text
    assert "192.0.2.0/24" in text
    assert "{{SECTION_5_TABLE}}" not in text


def test_report_is_rebuilt_from_facts_not_an_old_narrative(pipeline):
    report = pipeline.run_dir / "06_report.md"
    report.write_text("Author narrative\n{{SECTION_5_TABLE}}\n{{SECTION_6_TABLES}}")
    pipeline._generate_phase6_context()
    pipeline._pregenerate_report_sections()
    render(pipeline)
    first = report.read_text()
    render(pipeline)
    assert report.read_text() == first
    assert "Author narrative" not in first
    assert "device-1" in first


@pytest.mark.parametrize("invalid", ["(max turns reached)", "invalid model report"])
def test_invalid_report_is_replaced_by_fallback(pipeline, invalid):
    pipeline._generate_phase6_context()
    pipeline._pregenerate_report_sections()
    report = pipeline.run_dir / "06_report.md"
    report.write_text(invalid)
    render(pipeline)
    assert "report-test-model" in report.read_text()


def test_report_modules_support_independent_run_directories(tmp_path):
    for name, count in [("first", 3), ("second", 7)]:
        directory = tmp_path / name
        directory.mkdir()
        context = {"device_count": count, "target_subnet": name}
        report_context.generate_phase6_context(directory, context, compact=False)
        report_rendering.pregenerate_report_sections(directory)
        report_rendering.render_deterministic_report(
            directory, context, model=name,
            analysis_status="unavailable", analysis_cause="memo_absent",
        )
    for name, count in [("first", 3), ("second", 7)]:
        directory = tmp_path / name
        data = json.loads((directory / "06_phase6_context.json").read_text())
        assert data["device_count"] == count
        assert f"**Model:** {name}" in (directory / "06_report.md").read_text()
