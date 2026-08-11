from pathlib import Path

import pytest

from src.benchmark.scenario_alterations import (
    ALTERATION_CATALOG,
    alteration_catalog,
    apply_precomposition,
)
from src.benchmark.scenario_composer import ScenarioComposer
from src.benchmark.scenario_spec import (
    ScenarioSpecError,
    load_scenario_spec,
    normalize_scenario_spec,
)


ROOT = Path(__file__).resolve().parents[1]
MANUAL = ROOT / "benchmarks" / "scenarios_manual"


def test_catalog_contains_all_alteration_families():
    catalog = alteration_catalog()
    ids = {item["id"] for item in catalog}

    assert ids == set(ALTERATION_CATALOG)
    assert {"topology", "security", "ground_truth", "attack_path", "tools", "runtime"} <= {
        item["category"] for item in catalog
    }
    assert all(item["phase"] in {"topology", "ground_truth", "spec"} for item in catalog)


def test_manual_composer_applies_combined_alterations_and_records_them():
    spec = load_scenario_spec(MANUAL / "flat_logical_chain.yaml")
    spec["alterations"] = [
        {"type": "rotate_ips"},
        {"type": "add_decoys", "parameters": {"target": "web", "count": 2}},
        {"type": "add_noise", "parameters": {"count": 2}},
        {"type": "degrade_evidence"},
        {"type": "severity_shift", "parameters": {"mapping": {"critical": "high"}}},
        {
            "type": "restrict_tools",
            "parameters": {
                "phase": "verification",
                "tools": ["curl_headers", "ssh_login", "mqtt_listen"],
            },
        },
    ]

    bundle = ScenarioComposer(ROOT).compose(spec, artifact_id="gen-custom-alterations")
    gt = bundle["ground_truth"]

    assert len(bundle["topology"]["services"]) == 5
    assert len(gt["noise_findings"]) == 2
    assert all(item.get("evidence_mode") == "indirect" for item in gt["vulnerabilities"])
    assert all(item["severity"] == "high" for item in gt["vulnerabilities"])
    assert bundle["alteration_plan"]["status"] == "ready"
    assert len(bundle["alteration_plan"]["alterations"]) == 6
    assert bundle["execution_plan"]["profile"] == "flat_roles"


def test_segmented_alteration_is_rejected_by_flat_runtime_provider():
    spec = load_scenario_spec(MANUAL / "flat_logical_chain.yaml")
    spec["alterations"] = [{"type": "topology_segment"}]

    with pytest.raises(ScenarioSpecError, match="segmented"):
        ScenarioComposer(ROOT).compose(spec, artifact_id="gen-custom-segmented")


def test_finding_selection_prunes_only_the_affected_attack_path():
    spec = load_scenario_spec(MANUAL / "flat_logical_chain.yaml")
    spec["alterations"] = [{
        "type": "finding_selection",
        "parameters": {"exclude": ["MANUAL-MQTT-EXPORT"]},
    }]

    bundle = ScenarioComposer(ROOT).compose(spec, artifact_id="gen-custom-selection")

    assert len(bundle["ground_truth"]["vulnerabilities"]) == 2
    assert bundle["ground_truth"]["attack_paths"][0]["vulnerabilities_used"] == [
        "MANUAL-WEB-BACKUP@sflat-logical-chain-web",
        "MANUAL-SSH-CREDENTIALS@sflat-logical-chain-ssh",
    ]


def test_segmented_alteration_moves_services_to_distinct_vlan_subnets():
    topology = {
        "router": {"name": "router", "ip": "192.168.100.1"},
        "services": [
            {"name": "web", "ip": "192.168.100.11", "role": "web_server", "vmid_offset": 1},
            {"name": "ssh", "ip": "192.168.100.12", "role": "ssh_server", "vmid_offset": 2},
        ],
    }

    _, altered, mutation = apply_precomposition(
        {}, topology, [{"type": "topology_segment", "parameters": {}}], 7
    )

    assert [item["ip"] for item in altered["services"]] == [
        "192.168.110.11", "192.168.111.12"
    ]
    assert altered["network_mode"] == "segmented"
    assert mutation["ips"]["192.168.100.11"] == "192.168.110.11"


def test_spec_seed_is_preserved_for_deterministic_alterations():
    spec = normalize_scenario_spec({
        "scenario_id": "seeded",
        "seed": 37,
        "topology": {
            "inline": {
                "router": {"ip": "192.168.100.1"},
                "services": [{
                    "name": "web", "ip": "192.168.100.11", "role": "web_server",
                }],
            }
        },
    })

    assert spec["seed"] == 37


def test_preview_profile_carries_advanced_scenario_dimensions():
    spec = load_scenario_spec(MANUAL / "flat_logical_chain.yaml")
    spec["execution"] = {"profile": "preview"}
    spec["alterations"] = [
        {"type": "network_impairment", "parameters": {"latency_ms": 80}},
        {"type": "data_fixture", "parameters": {"target": "web", "records": 3}},
        {"type": "exploit_precondition", "parameters": {
            "targets": ["MANUAL-WEB-BACKUP"], "condition": "fixture_present",
        }},
        {"type": "detection_rule", "parameters": {"name": "ssh-alert"}},
        {"type": "false_positive", "parameters": {
            "findings": ["MANUAL-MQTT-EXPORT"],
        }},
        {"type": "scenario_objective", "parameters": {"id": "reach-ssh"}},
    ]

    bundle = ScenarioComposer(ROOT).compose(spec, artifact_id="gen-custom-preview-test")

    assert bundle["execution_plan"]["status"] == "preview"
    assert bundle["topology"]["network_conditions"]["network_impairment"][0]["latency_ms"] == 80
    assert bundle["ground_truth"]["detection"]["rules"][0]["name"] == "ssh-alert"
    assert bundle["ground_truth"]["scoring"]["false_positive_count"] == 1
    assert bundle["scenario"]["objectives"][0]["id"] == "reach-ssh"


def test_declared_compatibility_and_variant_constraints_are_enforced():
    spec = load_scenario_spec(MANUAL / "flat_logical_chain.yaml")
    spec["compatibility"] = {"profiles": ["true_multihop"]}
    with pytest.raises(ScenarioSpecError, match="compatibility"):
        ScenarioComposer(ROOT).compose(spec, artifact_id="gen-custom-incompatible")

    spec = load_scenario_spec(MANUAL / "flat_logical_chain.yaml")
    spec["constraints"] = {"min_services": 99}
    with pytest.raises(ScenarioSpecError, match="min_services"):
        ScenarioComposer(ROOT).compose(spec, artifact_id="gen-custom-constraint")
