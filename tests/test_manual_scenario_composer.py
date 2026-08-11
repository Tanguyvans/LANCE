from __future__ import annotations

from pathlib import Path

import pytest

from src.agent.pipeline import Pipeline
from src.benchmark.scenario_composer import ScenarioComposer
from src.benchmark.scenario_generator import ScenarioGenerator
from src.benchmark.scenario_spec import ScenarioSpecError, load_scenario_spec


ROOT = Path(__file__).resolve().parents[1]
MANUAL = ROOT / "benchmarks" / "scenarios_manual"


def _compose(name: str) -> dict:
    return ScenarioComposer(ROOT).compose(load_scenario_spec(MANUAL / name), artifact_id="gen-custom-test")


def test_flat_logical_chain_is_network_flat_but_has_ordered_dependencies():
    bundle = _compose("flat_logical_chain.yaml")
    gt = bundle["ground_truth"]
    path = gt["attack_paths"][0]

    assert len(gt["vulnerabilities"]) == 3
    assert path["semantics"] == "logical_chain"
    assert path["network_hop_depth"] == 0
    assert path["vulnerabilities_used"] == [
        "MANUAL-WEB-BACKUP@sflat-logical-chain-web",
        "MANUAL-SSH-CREDENTIALS@sflat-logical-chain-ssh",
        "MANUAL-MQTT-EXPORT@sflat-logical-chain-mqtt",
    ]
    assert all(item["required_tools"] for item in gt["vulnerabilities"])
    assert set(gt["tool_policy"]["verification"]) >= {"curl_headers", "ssh_login", "mqtt_listen"}


def test_hardened_manual_scenario_emits_controls_without_positive_findings():
    bundle = _compose("flat_hardened_control.yaml")
    gt = bundle["ground_truth"]

    assert gt["vulnerabilities"] == []
    assert len(gt["controls"]) == 3
    assert {item["security_profile"] for item in gt["controls"]} == {"hardened"}


def test_true_multihop_reference_resolves_path_and_vantage_metadata():
    bundle = _compose("true_multihop_reference.yaml")
    gt = bundle["ground_truth"]
    path = gt["attack_paths"][0]

    assert len(gt["vulnerabilities"]) == 4
    assert path["semantics"] == "network_pivot"
    assert path["network_hop_depth"] == 2
    assert [step["device"] for step in path["chain"]] == [
        "strue-multihop-reference-entry",
        "strue-multihop-reference-relay",
        "strue-multihop-reference-vault",
    ]


def test_manual_composition_is_stored_as_an_executable_bundle(tmp_path: Path):
    generator = ScenarioGenerator(ROOT, tmp_path / "generated", tmp_path / "exports")
    result = generator.compose_custom(load_scenario_spec(MANUAL / "flat_logical_chain.yaml"))

    assert result["id"].startswith("gen-custom-")
    assert result["deployable"] is True
    assert result["execution"]["adapter"] == "ansible-proxmox"
    assert result["execution"]["profile"] == "flat_roles"
    assert (generator.storage_root / result["id"] / "execution_plan.yaml").is_file()
    assert (generator.storage_root / result["id"] / "matching_contracts.yaml").is_file()
    assert generator.get_variant(result["id"])["ground_truth"]["attack_path_count"] == 1


def test_unknown_manual_tool_is_rejected():
    spec = load_scenario_spec(MANUAL / "flat_logical_chain.yaml")
    spec["tool_policy"]["verification"].append("not_a_real_tool")
    with pytest.raises(ScenarioSpecError, match="unknown tools"):
        ScenarioComposer(ROOT).compose(spec)


def test_manual_tool_policy_narrows_runtime_tools_but_keeps_pipeline_controls():
    pipeline = Pipeline.__new__(Pipeline)
    pipeline.scenario_tool_policy = {
        "verification": ["curl_headers", "save_deliverable"],
    }
    tools = [
        {"name": "curl_headers"},
        {"name": "ssh_login"},
        {"name": "save_deliverable"},
    ]

    selected = pipeline._apply_scenario_tool_policy(tools, "4")

    assert [tool["name"] for tool in selected] == ["curl_headers", "save_deliverable"]


def test_manual_bundle_is_not_published_to_the_dashboard_export_store(tmp_path: Path):
    generator = ScenarioGenerator(ROOT, tmp_path / "generated", tmp_path / "exports")
    result = generator.compose_custom(load_scenario_spec(MANUAL / "flat_logical_chain.yaml"))

    with pytest.raises(ValueError, match="dashboard export"):
        generator.export_variant(result["id"])
