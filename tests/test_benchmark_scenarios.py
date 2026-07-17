from __future__ import annotations

import importlib.util
import re
from itertools import combinations
from pathlib import Path
from types import ModuleType
from typing import Any, Iterator

import pytest
import yaml

from src.agent.vuln_taxonomy import CANONICAL_TYPES


REPO_ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS = REPO_ROOT / "benchmarks"
SCENARIOS = BENCHMARKS / "scenarios"
TOPOLOGIES = BENCHMARKS / "topologies"
PACKS = BENCHMARKS / "packs" / "definitions"
GROUND_TRUTH = BENCHMARKS / "ground_truth"
EVAL_PROFILES = BENCHMARKS / "eval_profiles"
GROUP_VARS = BENCHMARKS / "ansible" / "group_vars" / "all" / "main.yml"
GROUP_VARS_V2 = BENCHMARKS / "ansible" / "group_vars" / "all" / "scenarios_v2.yml"

PUBLIC_V2_IDS = tuple(str(scenario_id) for scenario_id in range(14, 20))
SEALED_IDS = tuple(str(scenario_id) for scenario_id in range(20, 26))
HARDENED_PROFILES = {"hardened", "near_miss"}
PROFILE_FIELDS = {
    "schema_version",
    "scenario_id",
    "split",
    "controller_required",
    "blind_required",
    "score_visibility",
}
FORBIDDEN_SEALED_FIELDS = {
    "topology",
    "packs",
    "ground_truth",
    "vulnerabilities",
    "controls",
    "attack_paths",
    "seed",
    "roles",
    "services",
    "verification",
    "credentials",
}


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


def _scenario_selectors(value: Any) -> Iterator[str]:
    """Yield scenario IDs explicitly selected anywhere in a pack."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "scenarios":
                selected = child if isinstance(child, list) else [child]
                yield from (str(item) for item in selected)
            else:
                yield from _scenario_selectors(child)
    elif isinstance(value, list):
        for child in value:
            yield from _scenario_selectors(child)


def test_every_public_scenario_references_existing_topology_and_packs():
    for scenario_path in sorted(SCENARIOS.glob("S*.yaml")):
        scenario = _load_yaml(scenario_path)
        assert (TOPOLOGIES / f"{scenario['topology']}.yaml").is_file(), scenario_path
        for pack_id in scenario.get("packs", []):
            assert (PACKS / f"{pack_id}.yaml").is_file(), (
                f"{scenario_path.name} references missing pack {pack_id}"
            )


def test_every_public_gt_vulnerability_has_one_canonical_expected_type():
    total = 0
    for gt_path in sorted(GROUND_TRUTH.glob("scenario_*.yaml")):
        ground_truth = _load_yaml(gt_path)
        for vulnerability in ground_truth.get("vulnerabilities", []):
            assert vulnerability.get("expected_type") in CANONICAL_TYPES, (
                f"{gt_path.name}:{vulnerability.get('id')} has no canonical "
                "expected_type"
            )
            total += 1
    assert total == 252


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


@pytest.mark.parametrize("scenario_id", tuple(str(i) for i in range(15, 20)))
def test_chain_scenarios_expose_measurable_multihop_depths(scenario_id: str):
    """The public chain scenarios must exercise MHR, not only document a path."""
    gt = COMPOSE_GT.compose_scenario(SCENARIOS / f"S{scenario_id}.yaml")
    depths = {int(item.get("hop_depth", 0)) for item in gt["vulnerabilities"]}

    assert any(depth >= 1 for depth in depths)
    assert max(depths) >= 2
    assert gt["attack_paths"]


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


def test_sealed_scenarios_publish_only_policy_metadata():
    profile_files = sorted(path.name for path in EVAL_PROFILES.glob("*.yaml"))
    assert profile_files == [f"S{scenario_id}.yaml" for scenario_id in SEALED_IDS]

    for scenario_id in SEALED_IDS:
        assert not (SCENARIOS / f"S{scenario_id}.yaml").exists()
        assert not (GROUND_TRUTH / f"scenario_{scenario_id}.yaml").exists()
        for directory in (TOPOLOGIES, PACKS):
            assert not any(
                re.search(rf"(?:^|[_-])s(?:cenario[_-]?)?{scenario_id}(?:[_-]|$)", path.stem, re.I)
                for path in directory.glob("*.yaml")
            )

        profile = _load_yaml(EVAL_PROFILES / f"S{scenario_id}.yaml")
        assert set(profile) == PROFILE_FIELDS
        assert profile["scenario_id"] == scenario_id
        assert profile["split"] == "eval-sealed"
        assert profile["controller_required"] is True
        assert profile["blind_required"] is True
        assert profile["score_visibility"] == "aggregate"
        assert FORBIDDEN_SEALED_FIELDS.isdisjoint(profile)

    # Public packs may describe reusable attack families, but must not bind any
    # concrete definition to a sealed scenario ID.
    selected_by_public_packs = {
        selected
        for pack_path in PACKS.glob("*.yaml")
        for selected in _scenario_selectors(_load_yaml(pack_path))
    }
    assert selected_by_public_packs.isdisjoint(SEALED_IDS)


def test_catalog_has_exact_canonical_splits_and_only_profile_links_for_sealed_ids():
    catalog = _load_yaml(BENCHMARKS / "catalog.yaml")
    scenarios = catalog["scenarios"]

    assert [entry["id"] for entry in scenarios] == [str(i) for i in range(1, 26)]
    assert [entry["id"] for entry in scenarios if entry["split"] == "dev-public"] == [
        str(i) for i in range(1, 20)
    ]
    assert [entry["id"] for entry in scenarios if entry["split"] == "eval-sealed"] == [
        str(i) for i in range(20, 26)
    ]

    for entry in scenarios[:19]:
        assert set(entry) == {"id", "label", "split"}
    for entry in scenarios[19:]:
        assert set(entry) == {"id", "label", "split", "profile"}
        assert entry["profile"] == f"eval_profiles/S{entry['id']}.yaml"
        assert FORBIDDEN_SEALED_FIELDS.isdisjoint(entry)
