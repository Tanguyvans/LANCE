"""Independent report regression checks using synthetic evidence, no network."""
import json
import importlib
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.agent.pipeline import Pipeline
from src.agent.core import runtime
from src.agent.cost_tracker import BudgetExceeded
from src.agent.registry import AGENTS
from src.agent.phases.registry import run_phase


@pytest.fixture
def report_run(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "OUTPUT_DIR", tmp_path)
    monkeypatch.setattr("src.agent.cost_tracker._resolve_pricing", lambda *_a, **_kw: (
        {"input": 1.0, "output": 2.0}, "offline-review", True,
    ))
    def create(profile, behavior):
        provider = SimpleNamespace(provider="ollama-umons", model="qwen3.8:27b", chat_with_tools=Mock())
        pipeline = Pipeline(provider=provider, execution_profile=profile, manage_scenario=False)
        pipeline._stop_event = Event()
        pipeline.context = {"target_subnet": "192.168.100.0/24", "device_count": "4"}
        pipeline._run_results = {"exploitation": "completed", "intrusion": "completed"}
        monkeypatch.setattr("src.agent.validators.OUTPUT_DIR", pipeline.run_dir)
        findings = [
            {"id": f"V{n}", "device_id": f"device-{n}", "device_ip": f"192.0.2.{n}",
             "type": "no_auth", "severity": "HIGH", "service": "mqtt", "port": 1883,
             "details": f"synthetic finding {n}"}
            for n in (1, 2)
        ]
        data = {
            "03_vuln_analysis.json": {"vulnerabilities": findings},
            "04_exploitation.json": {
                "summary": {"total_tested": 2, "confirmed": 2, "errors": 0},
                "tests": [
                    {"vuln_id": finding["id"], "device_id": finding["device_id"],
                     "device_ip": finding["device_ip"], "vuln_type": finding["type"],
                     "service": "mqtt", "port": 1883, "status": "CONFIRMED",
                     "evidence_level": level, "evidence": "synthetic observation",
                     "tool_used": "fixture"}
                    for finding, level in zip(findings, (2, 1))
                ],
            },
            "05_intrusion.json": {"summary": {"devices_compromised": 1},
                                  "compromised_devices": [{"device_id": "device-1", "device_ip": "192.0.2.1"}]},
            "03_phase3_status.json": {"devices_failed": 1, "scanner_errors": []},
            "01_graph_evidence.json": {"node_count": 2, "nodes": []},
            "02_recon_evidence.json": {"device_count": 2, "devices": []},
        }
        for filename, content in data.items():
            (pipeline.run_dir / filename).write_text(json.dumps(content), encoding="utf-8")
        pipeline._generate_phase6_context()
        pipeline._pregenerate_report_sections()
        def generate(**kwargs):
            assert kwargs["tools"] == []
            assert kwargs["max_turns"] == 1
            assert 0 < kwargs["max_tokens"] <= 2048
            assert kwargs.get("deadline") is not None
            kwargs["cost_tracker"].record_turn(500, 40)
            if behavior == "timeout":
                raise TimeoutError("offline phase6 timeout")
            if behavior == "budget":
                raise BudgetExceeded("offline budget limit")
            if behavior == "stop_during":
                pipeline._stop_event.set()
                return "(stopped by user)"
            if behavior == "empty":
                return ""
            if behavior == "placeholder":
                return "(max turns reached)"
            if behavior == "late":
                module = importlib.import_module("src.agent.phases.report.run")
                monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: kwargs["deadline"] + 1))
            memo = "Prioritize remediation of verified authentication weaknesses. Network pivots remain unverified."
            kwargs["stream_callback"]({"type": "text_chunk", "text": memo})
            return memo
        provider.chat_with_tools.side_effect = generate
        return pipeline
    return create


@pytest.mark.parametrize("profile", ["compact", "full"])
@pytest.mark.parametrize("behavior,expected", [
    ("ok", "completed"), ("timeout", "partial"), ("empty", "partial"), ("placeholder", "partial"),
])
def test_report_is_composed_once_and_keeps_all_verified_rows(report_run, profile, behavior, expected):
    pipeline = report_run(profile, behavior)
    originals = {name: (pipeline.run_dir / name).read_bytes() for name in (
        "03_vuln_analysis.json", "04_exploitation.json", "05_intrusion.json",
    )}
    events = []
    status = run_phase(pipeline, AGENTS["report"], events.append)
    assert status.partition(":")[0] == expected
    assert pipeline.provider.chat_with_tools.call_count == 1
    valid, reason = runtime.VALIDATORS["final_report_markdown"]("06_report.md")
    assert valid, reason
    report = (pipeline.run_dir / "06_report.md").read_text()
    prefill = (pipeline.run_dir / "06_report_prefill.md").read_text()
    assert prefill in report
    assert "| V1 |" in report
    assert "| V2 |" not in report
    assert "1 device worker failure(s)" in report
    metadata = json.loads((pipeline.run_dir / "run_meta.json").read_text())
    assert metadata["phase6_status"].partition(":")[0] == expected
    if behavior == "timeout":
        assert metadata["phase6_cause"] == "timeout"
    for name, content in originals.items():
        assert (pipeline.run_dir / name).read_bytes() == content
    assert len([e for e in events if e.get("type") == "phase_start"]) == 1
    assert len([e for e in events if e.get("type") == "phase_done"]) == 1
    assert events[-1]["status"].partition(":")[0] == expected
    assert pipeline.tracker.end_phase() is None
    assert pipeline.tracker.total_tokens() == (500, 40)
    if behavior != "ok":
        assert "partial" in report.lower() or "partiel" in report.lower()


@pytest.mark.parametrize("profile", ["compact", "full"])
def test_report_budget_is_not_swallowed_as_an_optional_memo_failure(report_run, profile):
    pipeline = report_run(profile, "budget")
    with pytest.raises(BudgetExceeded):
        run_phase(pipeline, AGENTS["report"])
    assert pipeline.tracker.end_phase() is None


@pytest.mark.parametrize("profile", ["compact", "full"])
@pytest.mark.parametrize("when", ["before", "during"])
def test_stop_never_becomes_a_successful_report(report_run, profile, when):
    pipeline = report_run(profile, "stop_during")
    if when == "before":
        pipeline._stop_event.set()
    assert run_phase(pipeline, AGENTS["report"]) == "stopped"
    assert pipeline.provider.chat_with_tools.call_count == (0 if when == "before" else 1)
    assert pipeline.tracker.end_phase() is None


@pytest.mark.parametrize("profile", ["compact", "full"])
def test_stale_note_and_final_report_cannot_hide_a_new_timeout(report_run, profile):
    pipeline = report_run(profile, "timeout")
    (pipeline.run_dir / "06_report_analysis.md").write_text("STALE-MEMO-SENTINEL")
    (pipeline.run_dir / "06_report.md").write_text("STALE-REPORT-SENTINEL")
    assert run_phase(pipeline, AGENTS["report"]).partition(":")[0] == "partial"
    report = (pipeline.run_dir / "06_report.md").read_text()
    assert "STALE-MEMO-SENTINEL" not in report
    assert "STALE-REPORT-SENTINEL" not in report


@pytest.mark.parametrize("profile", ["compact", "full"])
def test_invalid_report_is_failure_even_with_usable_memo(report_run, profile, monkeypatch):
    pipeline = report_run(profile, "ok")
    monkeypatch.setitem(runtime.VALIDATORS, "final_report_markdown", lambda _: (False, "offline_invalid"))
    events = []
    assert run_phase(pipeline, AGENTS["report"], events.append).startswith("failed:")
    assert events[-1]["status"].startswith("failed:")
    assert pipeline.tracker.end_phase() is None


@pytest.mark.parametrize("profile", ["compact", "full"])
def test_deterministic_report_preserves_large_inventory_and_service_types(report_run, profile):
    pipeline = report_run(profile, "ok")
    graph = {"node_count": 45, "nodes": [
        {"id": f"DEVICE_{n}", "ip": f"192.168.100.{n}", "type": "sensor", "role": "fixture"}
        for n in range(1, 46)
    ]}
    recon = {"device_count": 45, "devices": [
        {"device": f"DEVICE_{n}", "ip": f"192.168.100.{n}", "open_ports": [2222],
         "services": [{"service": "ssh", "port": 2222, "version": "INVENTORY_VERSION_SENTINEL"}]}
        for n in range(1, 46)
    ]}
    (pipeline.run_dir / "01_graph_evidence.json").write_text(json.dumps(graph))
    (pipeline.run_dir / "02_recon_evidence.json").write_text(json.dumps(recon))
    assert run_phase(pipeline, AGENTS["report"]) == "completed"
    report = (pipeline.run_dir / "06_report.md").read_text()
    assert "DEVICE_45" in report
    assert report.count("INVENTORY_VERSION_SENTINEL") == 45


def test_actual_prompt_projection_obeys_utf8_byte_bound_for_large_nested_fields(report_run):
    from src.agent.phases.report.context import build_report_analysis_context, REPORT_CONTEXT_MAX_BYTES
    pipeline = report_run("full", "ok")
    huge = "é🔒" * 18000
    for filename in ("01_graph_evidence.json", "06_phase6_context.json", "05_intrusion.json"):
        source = pipeline.run_dir / filename
        data = json.loads(source.read_text())
        data.update({"note": huge, "generated_for": huge, "summary": {"long": huge}})
        source.write_text(json.dumps(data))
    projection = build_report_analysis_context(pipeline.run_dir)
    encoded = json.dumps(projection, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert len(encoded) <= REPORT_CONTEXT_MAX_BYTES
    assert projection["omissions"]
    assert "05_intrusion.json" in projection["full_evidence_references"]


@pytest.mark.parametrize("profile", ["compact", "full"])
def test_usable_but_late_memo_is_not_promoted(report_run, profile):
    pipeline = report_run(profile, "late")
    assert run_phase(pipeline, AGENTS["report"]) == "partial:timeout"
    assert not (pipeline.run_dir / "06_report_analysis.md").exists()
    report = (pipeline.run_dir / "06_report.md").read_text()
    assert "Prioritize remediation" not in report
    assert "timeout" in report
    assert pipeline.tracker.total_tokens() == (500, 40)


def test_large_key_and_omission_metadata_cannot_overflow_prompt(report_run):
    from src.agent.phases.report.context import build_report_analysis_context, REPORT_CONTEXT_MAX_BYTES
    pipeline = report_run("full", "ok")
    source = pipeline.run_dir / "05_intrusion.json"
    source.write_text(json.dumps({"summary": {"LONG_KEY_" * 12000: "é" * 18000}}))
    projection = build_report_analysis_context(pipeline.run_dir)
    encoded = json.dumps(projection, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert len(encoded) <= REPORT_CONTEXT_MAX_BYTES
    assert projection["bounds"]["serialized_bytes"] == len(encoded)
