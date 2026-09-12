"""Reference resolution is diagnostic, never acceptance of a security proof."""
import json

import pytest

from src.agent.phases.report.context import build_report_analysis_context, REPORT_CONTEXT_MAX_BYTES
from src.agent.phases.report.traceability import ReportTraceIndex


def record(**changes):
    return {
        "evidence_ref": "tc-1", "vuln_id": "V1", "tool": "ssh_exec",
        "args": {"host": "192.0.2.1", "port": 22},
        "result": {"return_code": 0, "stdout": "uid=0(root)\nSSH_CONNECTION=192.0.2.200 51040 192.0.2.1 22\n"},
        **changes,
    }


def index(tmp_path, records):
    (tmp_path / "tool_calls.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
    return ReportTraceIndex(tmp_path)


@pytest.mark.parametrize("records,expected", [
    ([record()], "resolved, ID/destination linked: 1"),
    ([], "missing: 1"),
    ([record(), record()], "ambiguous: 1"),
    ([record(vuln_id="V2")], "finding ID mismatch: 1"),
    ([record(args={"host": "192.0.2.2"})], "destination mismatch or unavailable: 1"),
    ([record(vuln_id=None)], "resolved, attribution incomplete: 1"),
    # A successful reference lookup is still not a positive proof.
    ([record(result={"success": False, "stdout": "failed"})], "resolved, ID/destination linked: 1"),
])
def test_report_references_diagnose_but_never_validate(tmp_path, records, expected):
    diagnostic = index(tmp_path, records).describe({
        "vuln_id": "V1", "device_ip": "192.0.2.1", "evidence_refs": ["tc-1"],
    })
    assert expected in diagnostic
    assert "property/proof acceptance is not evaluated here" in diagnostic


def test_absent_and_corrupt_ledger_are_not_resolved(tmp_path):
    test = {"vuln_id": "V1", "device_ip": "192.0.2.1", "evidence_refs": ["tc-1"]}
    assert "No evidence references" in ReportTraceIndex(tmp_path).describe({})
    assert "unavailable or incomplete" in ReportTraceIndex(tmp_path).describe(test)
    (tmp_path / "tool_calls.jsonl").write_text(json.dumps(record()) + "\n{broken\n")
    assert "unavailable or incomplete" in ReportTraceIndex(tmp_path).describe(test)


def test_source_addresses_are_labelled_without_extending_inventory(tmp_path):
    original = record()
    trace = index(tmp_path, [original])
    source_bytes = (tmp_path / "tool_calls.jsonl").read_bytes()
    sources = trace.ssh_source_observations()
    assert len(sources) == 1
    assert sources[0]["client_source_ip"] == "192.0.2.200"
    assert "not an additional target" in sources[0]["interpretation"]
    context = build_report_analysis_context(tmp_path)
    assert context["execution_observations"] == sources
    assert context["graph"]["nodes"] == []
    assert context["intrusion"] == {}
    assert (tmp_path / "tool_calls.jsonl").read_bytes() == source_bytes


def test_ssh_environment_source_does_not_require_an_unrelated_id_command(tmp_path):
    trace = index(tmp_path, [record(result={
        "return_code": 0, "success": True,
        "stdout": "SSH_CONNECTION=192.0.2.200 51040 192.0.2.1 22\n",
    })])
    assert trace.ssh_source_observations()[0]["client_source_ip"] == "192.0.2.200"


@pytest.mark.parametrize("changes", [
    {"tool": "http_get"},
    {"args": {"host": "192.0.2.2"}},
    {"result": {"return_code": 1, "stdout": "uid=0\nSSH_CONNECTION=192.0.2.200 1 192.0.2.1 22"}},
    {"result": {"return_code": 0, "stdout": "uid=0\nA claim says SSH_CONNECTION=192.0.2.200 1 192.0.2.1 22"}},
    {"result": {"return_code": 0, "stdout": "uid=0\nSSH_CONNECTION=not-an-ip 1 192.0.2.1 22"}},
    {"result": {"return_code": 0, "stdout": "uid=0\nSSH_CONNECTION=192.0.2.200 65536 192.0.2.1 22"}},
])
def test_unattributed_stdout_never_creates_execution_source(tmp_path, changes):
    assert index(tmp_path, [record(**changes)]).ssh_source_observations() == []


def test_source_context_is_bounded_and_duplicate_refs_excluded(tmp_path):
    assert index(tmp_path, [record(), record()]).ssh_source_observations() == []
    index(tmp_path, [record(evidence_ref=f"tc-{n}") for n in range(30)])
    context = build_report_analysis_context(tmp_path)
    assert len(context["execution_observations"]) == 8
    assert context["omissions"]["execution_observations"] == 22
    encoded = json.dumps(context, ensure_ascii=False, separators=(",", ":")).encode()
    assert len(encoded) == context["bounds"]["serialized_bytes"] <= REPORT_CONTEXT_MAX_BYTES
