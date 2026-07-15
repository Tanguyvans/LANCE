"""Tests for the validated LLM-as-a-judge contract."""
import json
from types import SimpleNamespace

import pytest
import yaml

from src.agent import judge


def assessment(fid, verdict, gid, clarity=4, remediation=None):
    return {
        "llm_finding_id": fid,
        "verdict": verdict,
        "gt_vuln_id": gid,
        "reasoning": "Technical reason",
        "clarity_score": clarity,
        "remediation_score": remediation,
    }


def test_payloads_include_semantic_ground_truth_and_real_evidence():
    gt = [{
        "id": "V1", "title": "Anonymous MQTT", "description": "No authentication",
        "indicators": ["anonymous CONNECT succeeds"], "verification": "mosquitto_sub",
    }]
    findings = [{
        "id": "F1", "type": "no_auth", "details": "Anonymous access",
        "evidence": "CONNACK return_code=0", "evidence_level": 3,
    }]

    gt_payload = judge._ground_truth_payload(gt)
    finding_payload = judge._findings_payload(findings)

    assert gt_payload[0]["description"] == "No authentication"
    assert gt_payload[0]["indicators"] == ["anonymous CONNECT succeeds"]
    assert gt_payload[0]["verification"] == "mosquitto_sub"
    assert finding_payload[0]["evidence"] == "CONNACK return_code=0"
    assert finding_payload[0]["evidence_level"] == 3
    assert finding_payload[0]["remediation"] is None


def test_validated_one_to_one_metrics_penalize_duplicates():
    gt = [{"id": "V1"}, {"id": "V2"}]
    findings = [
        {"remediation": "Disable anonymous access"},
        {},
        {},
    ]
    parsed = {"assessments": [
        assessment(0, "match", 0, clarity=4, remediation=5),
        assessment(1, "duplicate", 0, clarity=3),
        assessment(2, "false_positive", None, clarity=2),
    ]}

    validated = judge._validate_assessments(parsed, gt, findings)
    result = judge._build_result(
        validated, gt, findings, model="judge-model", provider="openrouter"
    )

    assert result["true_positives"] == 1
    assert result["false_positives"] == 2
    assert result["false_negatives"] == 1
    assert result["duplicate_findings"] == 1
    assert result["precision"] == pytest.approx(1 / 3)
    assert result["recall"] == 0.5
    assert result["f1_score"] == pytest.approx(0.4)
    assert result["clarity_score"] == 3.0
    assert result["remediation_score"] == 5.0
    assert result["false_negatives_list"][0]["gt_vuln_id"] == 1


@pytest.mark.parametrize(
    ("parsed", "message"),
    [
        ({"assessments": []}, "0 assessments for 1 findings"),
        ({"assessments": [assessment(3, "match", 0)]}, "finding index"),
        ({"assessments": [assessment(0, "match", 7)]}, "out of range"),
        ({"assessments": [assessment(0, "false_positive", 0)]}, "must have gt_vuln_id null"),
        ({"assessments": [assessment(0, "match", 0, clarity=6)]}, "between 1 and 5"),
    ],
)
def test_invalid_model_outputs_are_rejected(parsed, message):
    with pytest.raises(ValueError, match=message):
        judge._validate_assessments(parsed, [{"id": "V1"}], [{}])


def test_multiple_matches_for_same_gt_are_rejected():
    parsed = {"assessments": [
        assessment(0, "match", 0),
        assessment(1, "match", 0),
    ]}
    with pytest.raises(ValueError, match="Multiple matches"):
        judge._validate_assessments(parsed, [{"id": "V1"}], [{}, {}])


def test_remediation_is_null_when_source_has_none():
    parsed = {"assessments": [assessment(0, "false_positive", None, remediation=4)]}
    with pytest.raises(ValueError, match="must be null"):
        judge._validate_assessments(parsed, [], [{}])


def test_zero_ground_truth_uses_specificity():
    clean = judge._build_result([], [], [], model="m", provider="p")
    noisy_assessment = [assessment(0, "false_positive", None)]
    noisy = judge._build_result(noisy_assessment, [], [{}], model="m", provider="p")

    assert clean["specificity"] == 1.0
    assert clean["scenario_score"] == 1.0
    assert clean["f1_score"] is None
    assert noisy["specificity"] == 0.0
    assert noisy["false_positives"] == 1


def test_no_findings_returns_complete_contract_without_calling_model(tmp_path, monkeypatch):
    gt_file = tmp_path / "gt.yaml"
    gt_file.write_text(yaml.safe_dump({
        "scenario_id": "x",
        "vulnerabilities": [{"id": "V1", "title": "Expected"}],
    }))
    (tmp_path / "03_vuln_analysis.json").write_text(json.dumps({"vulnerabilities": []}))

    def fail_provider(*args, **kwargs):
        raise AssertionError("provider should not be called")

    monkeypatch.setattr(judge, "LLMProvider", fail_provider)
    result = judge.evaluate_with_llm(tmp_path, gt_file, "m", "p")

    assert result["schema_version"] == "2"
    assert result["false_negatives"] == 1
    assert result["precision"] == 0.0
    assert result["recall"] == 0.0
    assert result["clarity_score"] is None


def test_evaluate_sends_evidence_and_records_provenance(tmp_path, monkeypatch):
    gt_file = tmp_path / "gt.yaml"
    gt_file.write_text(yaml.safe_dump({
        "scenario_id": "1",
        "vulnerabilities": [{
            "id": "V1", "title": "MQTT anonymous", "description": "No authentication",
            "indicators": ["CONNACK succeeds"], "ip": "10.0.0.1",
        }],
    }))
    (tmp_path / "03_vuln_analysis.json").write_text(json.dumps({
        "vulnerabilities": [{
            "id": "F1", "type": "no_auth", "device_ip": "10.0.0.1",
            "details": "Anonymous MQTT", "evidence": "CONNACK return_code=0",
            "evidence_level": 3,
        }]
    }))

    captured = {}
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps({
            "assessments": [assessment(0, "match", 0, clarity=5)]
        })))],
        usage=SimpleNamespace(prompt_tokens=100, completion_tokens=20),
    )

    class FakeCompletions:
        def create(self, **kwargs):
            captured.update(kwargs)
            return response

    class FakeProvider:
        provider = "openrouter"
        model = "openai/gpt-4o"
        client = SimpleNamespace(
            chat=SimpleNamespace(completions=FakeCompletions())
        )

        def __init__(self, provider, model):
            pass

    monkeypatch.setattr(judge, "LLMProvider", FakeProvider)
    result = judge.evaluate_with_llm(
        tmp_path, gt_file, "openai/gpt-4o", "openrouter"
    )

    user_message = captured["messages"][1]["content"]
    assert "CONNACK return_code=0" in user_message
    assert "CONNACK succeeds" in user_message
    assert "UNTRUSTED DATA" in captured["messages"][0]["content"]
    assert result["provider"] == "openrouter"
    assert result["prompt_version"] == judge.PROMPT_VERSION
    assert len(result["prompt_sha256"]) == 64
    assert result["input_tokens"] == 100
    assert result["output_tokens"] == 20
    assert result["cost_usd"] == pytest.approx(0.00045)
