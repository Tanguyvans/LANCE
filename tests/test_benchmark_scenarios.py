from __future__ import annotations

import importlib.util
import re
from itertools import combinations
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS = REPO_ROOT / "benchmarks"
SCENARIOS = BENCHMARKS / "scenarios"
TOPOLOGIES = BENCHMARKS / "topologies"
PACKS = BENCHMARKS / "packs" / "definitions"
GROUND_TRUTH = BENCHMARKS / "ground_truth"
EVAL_PROFILES = BENCHMARKS / "eval_profiles"
GROUP_VARS = BENCHMARKS / "ansible" / "group_vars" / "all" / "main.yml"
GROUP_VARS_V2 = BENCHMARKS / "ansible" / "group_vars" / "all" / "scenarios_v2.yml"

PUBLIC_V2_IDS = tuple(str(scenario_id) for scenario_id in range(14, 30))
HARDENED_PROFILES = {"hardened", "near_miss"}


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path} must contain a YAML mapping"
    return data


def _load_ansible_group_vars() -> dict[str, Any]:
    """Return the same merged scenario view consumed by Ansible playbooks."""
    group_vars = _load_yaml(GROUP_VARS)
    group_vars_v2 = _load_yaml(GROUP_VARS_V2)
    return {
        **group_vars,
        "scenario_vmid_ranges": {
            **group_vars["scenario_vmid_ranges"],
            **group_vars_v2["scenario_vmid_ranges_v2"],
        },
        "scenarios": {
            **group_vars["scenarios"],
            **group_vars_v2["scenarios_v2"],
        },
    }


def _load_compose_gt() -> ModuleType:
    path = BENCHMARKS / "tools" / "compose_gt.py"
    spec = importlib.util.spec_from_file_location("benchmark_compose_gt", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COMPOSE_GT = _load_compose_gt()


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def test_every_public_scenario_references_existing_topology_and_packs():
    for scenario_path in sorted(SCENARIOS.glob("S*.yaml")):
        scenario = _load_yaml(scenario_path)
        assert (TOPOLOGIES / f"{scenario['topology']}.yaml").is_file(), scenario_path
        for pack_id in scenario.get("packs", []):
            assert (PACKS / f"{pack_id}.yaml").is_file(), (
                f"{scenario_path.name} references missing pack {pack_id}"
            )


@pytest.mark.parametrize("scenario_id", PUBLIC_V2_IDS)
def test_public_v2_scenario_references_existing_topology_and_packs(scenario_id: str):
    scenario_path = SCENARIOS / f"S{scenario_id}.yaml"
    assert scenario_path.is_file()
    scenario = _load_yaml(scenario_path)

    assert scenario["schema_version"] == 2
    assert str(scenario["scenario_id"]) == scenario_id
    assert (TOPOLOGIES / f"{scenario['topology']}.yaml").is_file()
    assert scenario.get("packs"), f"S{scenario_id} must reference at least one pack"
    for pack_id in scenario["packs"]:
        assert (PACKS / f"{pack_id}.yaml").is_file(), (
            f"S{scenario_id} references missing pack {pack_id}"
        )


@pytest.mark.parametrize("scenario_id", PUBLIC_V2_IDS)
def test_composer_exactly_reproduces_committed_ground_truth(scenario_id: str):
    scenario_path = SCENARIOS / f"S{scenario_id}.yaml"
    expected_path = GROUND_TRUTH / f"scenario_{scenario_id}.yaml"
    expected = _load_yaml(expected_path)

    first = COMPOSE_GT.compose_scenario(scenario_path)
    second = COMPOSE_GT.compose_scenario(scenario_path)

    assert first == second, f"S{scenario_id} composition is not deterministic"
    assert first == expected, f"S{scenario_id} committed ground truth has drifted"


def test_public_v2_finding_and_control_ids_are_stable_unique_and_resolvable():
    all_ids: set[str] = set()
    all_attack_path_ids: set[str] = set()

    for scenario_id in PUBLIC_V2_IDS:
        gt = COMPOSE_GT.compose_scenario(SCENARIOS / f"S{scenario_id}.yaml")
        vulnerabilities = gt["vulnerabilities"]
        controls = gt["controls"]
        items = vulnerabilities + controls
        item_ids = [item["id"] for item in items]

        assert len(item_ids) == len(set(item_ids)), f"duplicate ID in S{scenario_id}"
        assert all_ids.isdisjoint(item_ids), f"cross-scenario duplicate ID in S{scenario_id}"
        all_ids.update(item_ids)

        for item in items:
            assert item.get("template_key"), f"{item['id']} has no stable template key"
            assert item["id"] == f"{item['template_key']}@{_slug(item['device'])}"
            assert item["device"].startswith(f"s{scenario_id}-")

        vulnerability_ids = {item["id"] for item in vulnerabilities}
        for attack_path in gt["attack_paths"]:
            path_id = attack_path["id"]
            assert path_id not in all_attack_path_ids
            all_attack_path_ids.add(path_id)
            assert set(attack_path["vulnerabilities_used"]) <= vulnerability_ids


@pytest.mark.parametrize("scenario_id", ("15", "16", "17", "18"))
def test_flat_chains_expose_dependency_not_network_depth(scenario_id: str):
    gt = COMPOSE_GT.compose_scenario(SCENARIOS / f"S{scenario_id}.yaml")
    dependency_depths = {
        int(item.get("dependency_depth", 0)) for item in gt["vulnerabilities"]
    }
    network_depths = {
        int(item.get("network_pivot_depth", 0)) for item in gt["vulnerabilities"]
    }

    assert max(dependency_depths) >= 2
    assert network_depths == {0}
    assert gt["attack_paths"]


def test_true_multihop_scenario_exposes_enforced_network_depth():
    gt = COMPOSE_GT.compose_scenario(SCENARIOS / "S20.yaml")

    assert max(
        int(item["network_pivot_depth"]) for item in gt["vulnerabilities"]
    ) == 2
    assert gt["attack_paths"]


@pytest.mark.parametrize("scenario_id", ("24", "25", "26", "27"))
def test_new_public_heldout_network_scenarios_require_real_pivots(scenario_id: str):
    gt = COMPOSE_GT.compose_scenario(SCENARIOS / f"S{scenario_id}.yaml")

    assert max(int(item["network_pivot_depth"]) for item in gt["vulnerabilities"]) >= 1
    assert gt["attack_paths"]


def test_three_pivot_cascade_reaches_network_depth_three():
    gt = COMPOSE_GT.compose_scenario(SCENARIOS / "S27.yaml")

    assert max(int(item["network_pivot_depth"]) for item in gt["vulnerabilities"]) == 3


def test_s28_is_dependency_depth_not_network_depth():
    gt = COMPOSE_GT.compose_scenario(SCENARIOS / "S28.yaml")

    assert max(int(item["dependency_depth"]) for item in gt["vulnerabilities"]) == 3
    assert {int(item["network_pivot_depth"]) for item in gt["vulnerabilities"]} == {0}


def test_independent_ot_protocol_checks_are_not_reported_as_a_chain():
    gt = COMPOSE_GT.compose_scenario(SCENARIOS / "S19.yaml")

    assert gt["attack_paths"] == []
    assert {int(item["dependency_depth"]) for item in gt["vulnerabilities"]} == {0}
    assert {int(item["network_pivot_depth"]) for item in gt["vulnerabilities"]} == {0}


def test_flat_dependency_chain_is_not_counted_as_network_pivots():
    scenario_id = "23"
    gt = COMPOSE_GT.compose_scenario(SCENARIOS / f"S{scenario_id}.yaml")
    assert max(int(item["dependency_depth"]) for item in gt["vulnerabilities"]) >= 2
    assert {int(item["network_pivot_depth"]) for item in gt["vulnerabilities"]} == {0}
    assert {int(item["hop_depth"]) for item in gt["vulnerabilities"]} == {0}


def test_independent_exploit_primitives_are_not_reported_as_a_chain():
    gt = COMPOSE_GT.compose_scenario(SCENARIOS / "S22.yaml")
    assert gt["attack_paths"] == []
    assert {int(item["dependency_depth"]) for item in gt["vulnerabilities"]} == {0}
    assert {int(item["network_pivot_depth"]) for item in gt["vulnerabilities"]} == {0}


@pytest.mark.parametrize("scenario_id", PUBLIC_V2_IDS)
def test_public_v2_scenarios_do_not_exempt_unexpected_findings(scenario_id: str):
    gt = COMPOSE_GT.compose_scenario(SCENARIOS / f"S{scenario_id}.yaml")
    assert gt["bonus_types"] == []


@pytest.mark.parametrize("scenario_id", PUBLIC_V2_IDS)
def test_vulnerable_profiles_and_control_assertions_are_consistent(scenario_id: str):
    scenario = _load_yaml(SCENARIOS / f"S{scenario_id}.yaml")
    gt = COMPOSE_GT.compose_scenario(SCENARIOS / f"S{scenario_id}.yaml")
    services = {service["name"]: service for service in gt["topology"]["services"]}
    profiles = {service["security_profile"] for service in services.values()}

    # Each mixed scenario has real positives and explicit hardened comparators.
    assert "hardened" in profiles
    assert profiles - HARDENED_PROFILES
    assert gt["vulnerabilities"]
    assert gt["controls"]

    for vulnerability in gt["vulnerabilities"]:
        service = services[vulnerability["device"]]
        assert vulnerability["ip"] == service["ip"]
        assert vulnerability["role"] == service["role"]
        assert vulnerability["security_profile"] == service["security_profile"]
        assert service["security_profile"] not in HARDENED_PROFILES, (
            f"{vulnerability['id']} is incorrectly attached to a hardened comparator"
        )

    for control in gt["controls"]:
        service = services[control["device"]]
        assert control["ip"] == service["ip"]
        assert control["role"] == service["role"]
        assert control["security_profile"] == service["security_profile"]
        assert control.get("assertion")
        assert control.get("verification")

    # A vulnerability selector must never opt a hardened/near-miss profile in.
    for pack_id in scenario["packs"]:
        pack = _load_yaml(PACKS / f"{pack_id}.yaml")
        for templates in pack.get("vulnerabilities", {}).values():
            for template in templates:
                assert template.get("key")
                selected_profiles = set((template.get("applies_to") or {}).get("profiles", []))
                assert selected_profiles.isdisjoint(HARDENED_PROFILES)
        for templates in pack.get("controls", {}).values():
            for template in templates:
                assert template.get("key")
                assert template.get("assertion")
                assert template.get("verification")


@pytest.mark.parametrize("scenario_id", PUBLIC_V2_IDS)
def test_topology_matches_ansible_inventory_service_for_service(scenario_id: str):
    group_vars = _load_ansible_group_vars()
    scenario = _load_yaml(SCENARIOS / f"S{scenario_id}.yaml")
    topology = _load_yaml(TOPOLOGIES / f"{scenario['topology']}.yaml")
    ansible = group_vars["scenarios"][scenario_id]
    ansible_base = group_vars["scenario_vmid_ranges"][scenario_id]

    assert topology["base_vmid"] == ansible_base
    assert topology["router"]["name_template"].format(sid=scenario_id) == (
        f"s{scenario_id}-router"
    )
    assert topology["router"]["ip"] == group_vars["benchmark_gateway"]

    topology_services = {
        service["name_template"].format(sid=scenario_id): service
        for service in topology["services"]
    }
    ansible_services = {
        f"s{scenario_id}-{service['name']}": service
        for service in ansible["services"]
    }
    assert topology_services.keys() == ansible_services.keys()

    for name, topology_service in topology_services.items():
        ansible_service = ansible_services[name]
        assert topology_service["ip"] == ansible_service["ip"]
        assert topology_service["role"] == ansible_service["role"]
        assert topology_service["security_profile"] == ansible_service["security_profile"]
        assert topology_service.get("simulator") == ansible_service.get("simulator")
        assert topology_service["vmid_offset"] == ansible_service["vmid_offset"]
        for network_key in (
            "vlan_id",
            "no_gateway",
            "bootstrap_ip",
            "secondary_ip",
            "secondary_vlan_id",
            "pivot_next_ip",
        ):
            assert topology_service.get(network_key) == ansible_service.get(network_key)
        assert topology["base_vmid"] + topology_service["vmid_offset"] == (
            ansible_base + ansible_service["vmid_offset"]
        )


def test_ansible_vmid_ranges_do_not_overlap():
    group_vars = _load_ansible_group_vars()
    ranges: dict[str, tuple[int, int]] = {}

    for scenario_id, scenario in group_vars["scenarios"].items():
        base = group_vars["scenario_vmid_ranges"][str(scenario_id)]
        offsets = [service["vmid_offset"] for service in scenario["services"]]
        assert offsets
        assert len(offsets) == len(set(offsets))
        assert min(offsets) > 0
        ranges[str(scenario_id)] = (base, base + max(offsets))

    for (left_id, left), (right_id, right) in combinations(ranges.items(), 2):
        left_start, left_end = left
        right_start, right_end = right
        assert left_end < right_start or right_end < left_start, (
            f"VMID ranges overlap: S{left_id}={left_start}-{left_end}, "
            f"S{right_id}={right_start}-{right_end}"
        )


def test_current_release_has_no_sealed_profile_placeholders():
    assert list(EVAL_PROFILES.glob("*.yaml")) == []
    for scenario_id in range(24, 30):
        assert (SCENARIOS / f"S{scenario_id}.yaml").is_file()
        assert (GROUND_TRUTH / f"scenario_{scenario_id}.yaml").is_file()


def test_catalog_has_exact_canonical_public_splits():
    catalog = _load_yaml(BENCHMARKS / "catalog.yaml")
    scenarios = catalog["scenarios"]

    assert [entry["id"] for entry in scenarios] == [str(i) for i in range(1, 30)]
    assert [entry["id"] for entry in scenarios if entry["split"] == "dev-public"] == [
        str(i) for i in range(1, 20)
    ]
    assert [entry["id"] for entry in scenarios if entry["split"] == "test-public"] == [
        str(i) for i in range(20, 30)
    ]
    assert [entry["id"] for entry in scenarios if entry["split"] == "eval-sealed"] == []

    for entry in scenarios:
        assert set(entry) == {"id", "label", "split"}


def test_paper_campaign_uses_the_complete_frozen_public_test_split():
    campaign = _load_yaml(BENCHMARKS / "campaigns" / "paper_v3_4.yaml")
    confirmatory = campaign["confirmatory"]
    informed = campaign["public_held_out_informed_diagnostic"]

    assert campaign["benchmark_version"] == "3.2.0"
    assert confirmatory["split"] == "test-public"
    assert confirmatory["scenarios"] == [str(i) for i in range(20, 30)]
    assert confirmatory["systems"] == ["lance", "cai", "vulnbot"]
    assert confirmatory["mode"] == "blind"
    assert confirmatory["repetitions"] == 2
    assert confirmatory["planned_runs"] == 10 * 3 * 2
    assert confirmatory["freeze_before_first_run"] is True
    assert confirmatory["tuning_from_results_forbidden"] is True

    assert informed["scenarios"] == confirmatory["scenarios"]
    assert informed["mode"] == "informed"
    assert informed["run_after_blind_confirmatory"] is True
    assert informed["repetitions"] == 2
    assert informed["planned_runs"] == 10 * 2

    development = campaign["development_diagnostics"]
    assert development["scenarios"] == [str(i) for i in range(1, 20)]
    assert development["modes"] == ["informed", "blind"]
    assert development["repetitions"] == 2
    assert development["planned_runs"] == 19 * 2 * 2
    assert campaign["execution"]["reset_between_conditions"] is True

    published = (
        confirmatory["planned_runs"]
        + development["planned_runs"]
        + informed["planned_runs"]
    )
    assert campaign["planned_published_runs"] == published == 156


def test_multihop_starting_credentials_are_not_scored_findings():
    for scenario_id in (20, 24, 25, 26, 27):
        scenario = _load_yaml(SCENARIOS / f"S{scenario_id}.yaml")
        ground_truth = _load_yaml(GROUND_TRUTH / f"scenario_{scenario_id}.yaml")
        credentials = scenario.get("initial_credentials") or []
        excluded = set(scenario.get("excluded_vulnerabilities") or [])

        assert credentials, f"S{scenario_id} has no reproducible starting foothold"
        assert excluded, f"S{scenario_id} scores its supplied starting foothold"
        assert excluded.isdisjoint({v["id"] for v in ground_truth["vulnerabilities"]})
        for credential in credentials:
            assert credential["service"] == "ssh"
            assert credential["port"] == 22
            assert credential["ip"].startswith("192.168.100.")
            assert credential["user"]
            assert credential["password"]
