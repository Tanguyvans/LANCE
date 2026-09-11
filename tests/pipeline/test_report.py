"""Phase 6: report context, templates, and evidence-grounded composition."""
import json
from threading import Event
from unittest.mock import patch
import pytest
from src.agent.pipeline import Pipeline
from src.agent.report_evidence import (
    is_verified_report_finding as _is_verified_report_finding,
    report_phase4_summary as _report_phase4_summary,
)
from src.agent.phases.report.validation import _local_report_memo_contradicts_context
from src.agent.registry import AGENTS
from src.agent.phases.registry import run_phase


def test_phase6_context_excludes_unsupported_confirmations(mock_provider, output_dir):
    pipeline = Pipeline(provider=mock_provider)
    pipeline.context = {"device_count": 1}
    run_dir = pipeline.run_dir
    (run_dir / "03_vuln_analysis.json").write_text(json.dumps({
        "vulnerabilities": [
            {
                "id": "V1", "device_id": "device-1", "device_ip": "192.0.2.1",
                "type": "no_auth", "severity": "HIGH", "service": "mqtt",
                "port": 1883,
            },
            {
                "id": "V2", "device_id": "device-1", "device_ip": "192.0.2.1",
                "type": "default_credentials", "severity": "HIGH",
                "service": "mqtt", "port": 1883,
            },
        ],
    }))
    tests = [
        {
            "vuln_id": "V1", "device_id": "device-1", "device_ip": "192.0.2.1",
            "vuln_type": "no_auth", "status": "CONFIRMED", "evidence_level": 2,
            "tool_used": "mqtt_listen", "evidence": "anonymous messages",
        },
        {
            "vuln_id": "V2", "device_id": "device-1", "device_ip": "192.0.2.1",
            "vuln_type": "default_credentials", "status": "CONFIRMED",
            "evidence_level": 1, "evidence": "model claim only",
        },
    ]
    (run_dir / "04_exploitation.json").write_text(json.dumps({
        "summary": {"total_tested": 2, "confirmed": 2, "not_exploitable": 0, "errors": 0},
        "tests": tests,
    }))

    assert _report_phase4_summary({"confirmed": 2}, tests) == {
        "confirmed": 1, "verified_confirmed": 1, "unverified_confirmed": 1,
        "inconclusive": 1, "not_tested": 0,
    }

    pipeline._generate_phase6_context()
    context = json.loads((run_dir / "06_phase6_context.json").read_text())
    assert context["phase4_summary"]["confirmed"] == 1
    assert context["phase4_summary"]["unverified_confirmed"] == 1
    assert [test["vuln_id"] for test in context["phase4_tests"]] == ["V1"]
    assert _is_verified_report_finding(tests[0])
    assert not _is_verified_report_finding(tests[1])

    local_context = pipeline._build_local_report_analysis_context()
    assert [test["vuln_id"] for test in local_context["phase6"]["phase4_tests"]] == ["V1"]


@pytest.mark.parametrize("profile", ["full", "compact"])
def test_phase6_injects_its_canonical_template(profile, mock_provider, output_dir):
    pipeline = Pipeline(provider=mock_provider, execution_profile=profile)
    with patch("src.agent.core.runtime.load_prompt", return_value="rendered prompt") as prompt:
        pipeline._run_agent(AGENTS["report"])

    template = prompt.call_args.args[1]["deliverable_template"]
    assert "# Pentest Report" in template
    assert f"**Model:** {mock_provider.model}" in template
    assert "{{run_date}}" not in template
    assert "{{SECTION_5_TABLE}}" in template
    assert mock_provider.chat_with_tools.call_args.kwargs["system_prompt"] == "rendered prompt"


def test_local_report_memo_guard_rejects_false_compromise_claim():
    context = {
        "intrusion": {
            "summary": {"devices_compromised": 0},
            "compromised_devices": [],
        }
    }

    assert _local_report_memo_contradicts_context(
        "The web server was confirmed to be compromised.",
        context,
    )


class TestInformationPreservingArchitecture:
    def test_local_report_phase_is_one_shot_and_composes_final_report(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        memo = "Model memo: recon saw MQTT on 192.168.100.11 and one intrusion path."
        mock_provider.chat_with_tools.return_value = memo
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        pipeline.context = {"target_subnet": "192.168.100.0/24"}
        run_dir = pipeline.run_dir
        (run_dir / "06_phase6_context.json").write_text(json.dumps({
            "device_count": 4,
            "total_vulnerabilities": 2,
            "severity_counts": {"CRITICAL": 1, "HIGH": 1},
            "exploitation_summary": {"confirmed": 1, "failed": 1},
            "top_devices_by_risk": [{"device_id": "s1-web", "score": 9.0}],
            "critical_findings": [{
                "device_id": "s1-web",
                "type": "directory_listing",
                "service": "http",
                "title": "Directory listing exposed",
            }],
            "cve_list": ["CVE-2023-48795"],
        }))
        (run_dir / "01_graph_evidence.json").write_text(json.dumps({
            "scenario": "Reseau plat",
            "subnet": "192.168.100.0/24",
            "node_count": 4,
            "edge_count": 3,
            "service_count": 8,
            "nodes": [
                {"id": "s1-router", "ip": "192.168.100.1", "type": "router", "role": "router"},
                {"id": "s1-mqtt", "ip": "192.168.100.11", "type": "server", "role": "mqtt_broker"},
            ],
        }))
        (run_dir / "02_recon_evidence.json").write_text(json.dumps({
            "device_count": 2,
            "devices": [
                {
                    "device": "s1-router",
                    "ip": "192.168.100.1",
                    "open_ports": [22, 23, 80],
                    "services": [{"service": "ssh", "port": 22, "version": "Dropbear"}],
                },
                {
                    "device": "s1-mqtt",
                    "ip": "192.168.100.11",
                    "open_ports": [1883],
                    "services": [{"service": "mqtt", "port": 1883, "version": "Mosquitto 2.0.21"}],
                },
            ],
        }))
        (run_dir / "05_intrusion.json").write_text(json.dumps({
            "summary": {
                "devices_attempted": 2,
                "devices_compromised": 1,
                "credentials_harvested": 1,
                "crown_jewels_reached": 0,
            },
            "compromised_devices": [{
                "device_id": "s1-web",
                "device_ip": "192.168.100.12",
                "access_method": "http data exposure",
            }],
        }))
        long_table = "\n".join(
            f"| VULN-{index:03d} | s1-web | HIGH | Evidence row {index} |"
            for index in range(1, 18)
        )
        prefill = (
            "## 5. Vulnerability Inventory\n\n"
            "| ID | Device | Severity | Evidence |\n"
            "|----|--------|----------|----------|\n"
            f"{long_table}\n\n"
            "## 6. Exploitation Results\n\n"
            "| Test | Status | Evidence |\n"
            "|------|--------|----------|\n"
            "| directory_listing | EXPLOITED | Index page observed |\n"
        )
        (run_dir / "06_report_prefill.md").write_text(prefill)
        events = []

        status = pipeline._run_local_report_phase(AGENTS["report"], events.append)

        assert status == "completed"
        kwargs = mock_provider.chat_with_tools.call_args.kwargs
        assert kwargs["tools"] == []
        assert kwargs["max_turns"] == 1
        assert kwargs["deadline"] > 0
        assert "192.168.100.11" in kwargs["system_prompt"]
        report = (run_dir / "06_report.md").read_text()
        assert "## 1." in report and "## 10." in report
        assert "{{SECTION_5_TABLE}}" not in report
        assert "{{SECTION_6_TABLES}}" not in report
        assert "192.168.100.11" in report
        assert memo in report
        assert (run_dir / "06_report_analysis.md").read_text().strip() == memo
        assert memo in (run_dir / "model_outputs.jsonl").read_text()
        phase_done = [event for event in events if event.get("type") == "phase_done"]
        assert len(phase_done) == 1
        assert phase_done[0]["status"] == "completed"


@pytest.mark.parametrize("profile,token_budget", [("compact", 1536), ("full", 2048)])
def test_phase6_common_entry_is_toolless_and_one_shot(profile, token_budget, mock_provider, output_dir):
    mock_provider.chat_with_tools.return_value = "Review the evidence-linked authentication findings."
    pipeline = Pipeline(provider=mock_provider, execution_profile=profile)
    pipeline.context = {"device_count": 1, "target_subnet": "192.0.2.0/24"}
    pipeline._stop_event = Event()
    (pipeline.run_dir / "03_vuln_analysis.json").write_text(json.dumps({"vulnerabilities": []}))
    (pipeline.run_dir / "04_exploitation.json").write_text(json.dumps({"summary": {}, "tests": []}))
    pipeline._generate_phase6_context()
    pipeline._pregenerate_report_sections()

    events = []
    status = run_phase(pipeline, AGENTS["report"], events.append)

    assert status == "completed"
    kwargs = mock_provider.chat_with_tools.call_args.kwargs
    assert kwargs["tools"] == []
    assert kwargs["max_turns"] == 1
    assert kwargs["max_tokens"] == token_budget
    assert len([event for event in events if event["type"] == "phase_start"]) == 1
    assert len([event for event in events if event["type"] == "phase_done"]) == 1
    assert pipeline.tracker.end_phase() is None


@pytest.mark.parametrize("result,expected_cause", [("", "memo_empty"), (TimeoutError("late"), "timeout")])
def test_phase6_note_failure_is_partial_and_does_not_reuse_stale_outputs(
    result, expected_cause, mock_provider, output_dir
):
    pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
    pipeline.context = {"device_count": 1}
    pipeline._stop_event = Event()
    (pipeline.run_dir / "06_report.md").write_text("STALE REPORT")
    (pipeline.run_dir / "06_report_analysis.md").write_text("STALE NOTE")
    (pipeline.run_dir / "03_vuln_analysis.json").write_text(json.dumps({"vulnerabilities": []}))
    (pipeline.run_dir / "04_exploitation.json").write_text(json.dumps({"summary": {}, "tests": []}))
    pipeline._generate_phase6_context()
    pipeline._pregenerate_report_sections()
    mock_provider.chat_with_tools.side_effect = result if isinstance(result, Exception) else None
    if not isinstance(result, Exception):
        mock_provider.chat_with_tools.return_value = result

    status = run_phase(pipeline, AGENTS["report"])

    assert status == f"partial:{expected_cause}"
    assert not (pipeline.run_dir / "06_report_analysis.md").exists()
    report = (pipeline.run_dir / "06_report.md").read_text()
    assert "STALE" not in report
    assert f"partial:{expected_cause}" in report
    meta = json.loads((pipeline.run_dir / "run_meta.json").read_text())
    assert meta["phase6_cause"] == expected_cause
