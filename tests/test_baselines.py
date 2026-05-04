import json

from src.baselines.normalizer import normalize_tool_outputs, write_vuln_analysis
from src.baselines.scenarios import load_ground_truth_targets, load_scenario_targets
from src.benchmark.evaluator import evaluate


def test_load_scenario_targets_includes_router_and_services():
    targets = load_scenario_targets("1")

    assert targets[0].ip == "192.168.100.1"
    assert targets[0].role == "router"
    assert [t.ip for t in targets[1:]] == [
        "192.168.100.11",
        "192.168.100.12",
        "192.168.100.13",
    ]


def test_load_ground_truth_targets_returns_unique_eval_ips():
    targets = load_ground_truth_targets("3")

    assert targets[0].source == "ground_truth"
    assert len({t.ip for t in targets}) == len(targets)
    assert "192.168.100.1" in {t.ip for t in targets}


def test_normalize_tool_outputs_accepts_common_aliases(tmp_path):
    raw = tmp_path / "result.json"
    raw.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "host": "192.168.100.12",
                        "category": "default_credentials",
                        "risk": "high",
                        "proof": "login succeeded",
                    }
                ]
            }
        )
    )

    findings = normalize_tool_outputs("pentgpt", [(None, raw)])

    assert findings == [
        {
            "id": "PENTGPT-001",
            "device_id": "192.168.100.12",
            "device_ip": "192.168.100.12",
            "type": "default_credentials",
            "severity": "HIGH",
            "details": "",
            "evidence": "login succeeded",
            "evidence_level": 1,
            "cve_ids": [],
            "source_tool": "pentgpt",
        }
    ]


def test_baseline_vuln_analysis_is_evaluator_compatible(tmp_path):
    run_dir = tmp_path / "baseline"
    gt = tmp_path / "gt.yaml"
    gt.write_text(
        """
scenario_id: 1
vulnerabilities:
  - id: GT-001
    title: MQTT sans auth
    device: mqtt
    ip: 192.168.100.11
    severity: high
    category: no_authentication
    hop_depth: 0
scoring:
  weights:
    critical: 4
    high: 3
    medium: 2
    low: 1
"""
    )
    write_vuln_analysis(
        "cai",
        "1",
        [
            {
                "id": "CAI-001",
                "device_id": "S1-mqtt",
                "device_ip": "192.168.100.11",
                "type": "no_auth",
                "severity": "HIGH",
                "details": "MQTT anonymous access",
                "evidence": "mosquitto_sub succeeded",
                "evidence_level": 2,
                "cve_ids": [],
            }
        ],
        run_dir,
    )

    result = evaluate(run_dir, gt)

    assert result.total_llm_findings == 1
    assert result.true_positives == 1
