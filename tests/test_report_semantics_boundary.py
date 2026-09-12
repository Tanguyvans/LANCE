"""Independent checks of rendered report semantics, not helper-only tests."""
import json
import pytest

from src.agent.phases.registry import run_phase
from src.agent.registry import AGENTS
from tests.test_report_review_regressions import report_run


def test_full_report_separates_claim_observation_and_unresolved_reference(report_run):
    pipeline = report_run("full", "ok")
    path = pipeline.run_dir / "04_exploitation.json"
    data = json.loads(path.read_text())
    data["tests"][0].update({
        "evidence": "OBSERVED_SENTINEL\nsecond|line",
        "evidence_refs": ["MISSING_REF_SENTINEL"],
    })
    path.write_text(json.dumps(data))
    # Present but empty ledger makes this an unresolved reference, not merely
    # unavailable diagnostics. No successful tool flag can repair the absence.
    (pipeline.run_dir / "tool_calls.jsonl").write_text("")
    pipeline._generate_phase6_context()
    pipeline._pregenerate_report_sections()
    original = path.read_bytes()
    assert run_phase(pipeline, AGENTS["report"]) == "completed"
    report = (pipeline.run_dir / "06_report.md").read_text()
    assert "OBSERVED_SENTINEL" in report
    assert "synthetic finding 1" in report
    assert "MISSING_REF_SENTINEL" in report
    assert "missing: 1" in report
    assert "second|line" not in report  # escaped pipe in a single row
    assert "Findings with execution evidence" not in report
    assert "Confirmed exploitable" not in report
    assert "Address all 0 CRITICAL" not in report
    assert "Phases executed:" not in report
    assert "raw" in report and "non-valid" in report
    assert path.read_bytes() == original


def test_source_ssh_address_does_not_become_a_compromised_device(report_run):
    pipeline = report_run("full", "ok")
    from tests.test_report_traceability import record
    (pipeline.run_dir / "tool_calls.jsonl").write_text(json.dumps(record()) + "\n")
    assert run_phase(pipeline, AGENTS["report"]) == "completed"
    report = (pipeline.run_dir / "06_report.md").read_text()
    assert "192.0.2.200" in report
    original_intrusion = json.loads((pipeline.run_dir / "05_intrusion.json").read_text())
    assert original_intrusion["summary"]["devices_compromised"] == 1
    assert len(original_intrusion["compromised_devices"]) == 1
    assert "192.0.2.200" not in json.dumps(original_intrusion)
    assert "not an additional target" in report


@pytest.mark.parametrize("vuln_type,nature", [
    ("missing_header", "configuration"), ("insecure_update", "configuration"),
    ("directory_listing", "exposure"), ("info_disclosure", "exposure"),
    ("data_exposure", "data access"), ("default_credentials", "access"),
    ("no_auth", "access"), ("code_injection", "claimed code execution"),
    ("rce", "claimed code execution"), ("ssrf", "other"),
    ("arbitrary_file_upload", "other"), ("unknown", "other"),
])
def test_nature_never_comes_from_success_flag_or_evidence_level(vuln_type, nature):
    from src.agent.phases.report.rendering import _declaration_nature
    for level in (1, 2, 3):
        assert _declaration_nature({"type": vuln_type, "evidence_level": level, "success": True}) == nature


def test_worker_failure_list_and_no_critical_are_rendered_honestly(report_run):
    pipeline = report_run("full", "ok")
    (pipeline.run_dir / "03_phase3_status.json").write_text(json.dumps({
        "devices_failed": [{"device_id": "router-fixture", "cause": "worker-timeout"}],
        "scanner_errors": [],
    }))
    assert run_phase(pipeline, AGENTS["report"]) == "completed"
    report = (pipeline.run_dir / "06_report.md").read_text()
    assert "1 device worker failure(s)" in report
    assert "router-fixture: worker-timeout" in report
    assert "[{'device_id'" not in report
    assert "No CRITICAL declaration" in report
    assert "not a benchmark score" in report


def test_empty_inventory_does_not_imply_low_risk(report_run):
    pipeline = report_run("full", "ok")
    (pipeline.run_dir / "03_vuln_analysis.json").write_text('{"vulnerabilities": []}')
    (pipeline.run_dir / "04_exploitation.json").write_text('{"tests": []}')
    pipeline._generate_phase6_context()
    pipeline._pregenerate_report_sections()
    run_phase(pipeline, AGENTS["report"])
    report = (pipeline.run_dir / "06_report.md").read_text()
    assert "not established (no supported declaration)" in report
    assert "Overall risk" not in report


def test_missing_topology_does_not_become_zero_devices(report_run):
    pipeline = report_run("full", "ok")
    (pipeline.run_dir / "01_graph_evidence.json").unlink()
    run_phase(pipeline, AGENTS["report"])
    report = (pipeline.run_dir / "06_report.md").read_text()
    assert "nodes: not recorded" in report
    assert "0 nodes" not in report
