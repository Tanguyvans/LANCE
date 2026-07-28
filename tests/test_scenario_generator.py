from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

import pytest
import yaml

from src.benchmark.scenario_generator import (
    GENERATOR_MARKER,
    ScenarioGenerator,
    ScenarioGeneratorError,
)
from src.benchmark.scenario_exports import ScenarioExportError


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def generator(tmp_path: Path) -> ScenarioGenerator:
    return ScenarioGenerator(
        REPO_ROOT,
        tmp_path / "generated",
        tmp_path / "exported",
    )


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_generate_creates_isolated_complete_bundle(generator: ScenarioGenerator):
    protected = [
        REPO_ROOT / "benchmarks" / "scenarios" / "S15.yaml",
        REPO_ROOT / "benchmarks" / "topologies" / "api_authorization.yaml",
        REPO_ROOT / "benchmarks" / "ground_truth" / "scenario_15.yaml",
    ]
    before = {path: path.read_bytes() for path in protected}

    generated = generator.generate("api-authorization", 42, "rotate_ips")
    bundle_dir = generator.storage_root / generated["id"]

    assert generated["deployable"] is False
    assert generated["deployment_status"] == "preview"
    assert generated["vulnerability_count"] == 3
    assert generated["control_count"] == 4
    assert generated["attack_path_count"] == 1
    assert {path.name for path in bundle_dir.iterdir()} == {
        "manifest.yaml",
        "scenario.yaml",
        "topology.yaml",
        "ground_truth.yaml",
        "injection_plan.yaml",
        "verification_plan.yaml",
        "matching_contracts.yaml",
    }
    assert {path: path.read_bytes() for path in protected} == before

    manifest = _load(bundle_dir / "manifest.yaml")
    assert manifest["generated_by"] == GENERATOR_MARKER
    assert manifest["mutation_policy"] == "generated-only"
    assert manifest["source_scenario_id"] == "15"
    assert len(manifest["source_blueprint_hash"]) == 64
    assert manifest["generator_version"] == 2


def test_generated_topology_preserves_blueprint_structure(generator: ScenarioGenerator):
    generated = generator.generate("api-authorization", 91, "rename_hosts")
    bundle = generator._load_bundle(generated["id"])
    topology = bundle["topology"]
    source = _load(REPO_ROOT / "benchmarks" / "topologies" / "api_authorization.yaml")

    assert Counter(item["role"] for item in topology["services"]) == Counter(
        item["role"] for item in source["services"]
    )
    assert Counter(item.get("simulator") for item in topology["services"]) == Counter(
        item.get("simulator") for item in source["services"]
    )
    assert len(topology["services"]) == len(source["services"])
    assert topology["subnets"] == ["192.168.100.0/24"]

    router = topology["router"]["name"]
    router_targets = {
        link["target"]
        for link in topology["links"]
        if link["source"] == router and link.get("protocol") == "ethernet"
    }
    assert router_targets == {item["name"] for item in topology["services"]}


def test_ground_truth_paths_and_injection_resolve_against_topology(generator: ScenarioGenerator):
    generated = generator.generate("ota-lifecycle", 123, "rotate_ips")
    bundle = generator._load_bundle(generated["id"])
    topology = bundle["topology"]
    ground_truth = bundle["ground_truth"]
    injection = bundle["injection_plan"]

    targets = {
        topology["router"]["name"]: topology["router"]["ip"],
        **{item["name"]: item["ip"] for item in topology["services"]},
    }
    for item in [*ground_truth["vulnerabilities"], *ground_truth["controls"]]:
        assert targets[item["device"]] == item["ip"]

    finding_ids = {item["id"] for item in ground_truth["vulnerabilities"]}
    for attack_path in ground_truth["attack_paths"]:
        assert set(attack_path["vulnerabilities_used"]) <= finding_ids
        devices = [hop["device"] for hop in attack_path["chain"]]
        assert all(device in targets for device in devices)
        assert all(
            generator._is_reachable(left, right, topology["links"])
            for left, right in zip(devices, devices[1:])
        )

    planned = {
        key
        for fixture in injection["fixtures"]
        for key in fixture["vulnerability_keys"]
    }
    assert planned == {
        item["template_key"] for item in ground_truth["vulnerabilities"]
    }


def test_ip_rotation_never_crosses_network_zones(generator: ScenarioGenerator):
    topology = {
        "services": [
            {"name": "a", "ip": "10.0.1.10"},
            {"name": "b", "ip": "10.0.1.11"},
            {"name": "c", "ip": "10.0.2.10"},
            {"name": "d", "ip": "10.0.2.11"},
        ],
        "links": [],
    }
    original_zones = {
        item["name"]: ".".join(item["ip"].split(".")[:3])
        for item in topology["services"]
    }

    mutated, _ = generator._apply_operation(topology, "rotate_ips", 5)

    assert {
        item["name"]: ".".join(item["ip"].split(".")[:3])
        for item in mutated["services"]
    } == original_zones


def test_mutation_is_immutable_and_generated_only(generator: ScenarioGenerator):
    parent = generator.generate("api-authorization", 7, "rotate_ips")
    parent_dir = generator.storage_root / parent["id"]
    parent_snapshot = {
        path.name: path.read_bytes() for path in parent_dir.iterdir()
    }

    child = generator.mutate(parent["id"], 8, "swap_profiles")

    assert child["id"] != parent["id"]
    assert child["parent_variant_id"] == parent["id"]
    assert {path.name: path.read_bytes() for path in parent_dir.iterdir()} == parent_snapshot
    with pytest.raises(ScenarioGeneratorError, match="Invalid generated scenario identifier"):
        generator.mutate("15", 9, "rotate_ips")
    with pytest.raises(ScenarioGeneratorError, match="Invalid generated scenario identifier"):
        generator.mutate("../S15", 9, "rotate_ips")


def test_tampered_bundle_cannot_be_mutated(generator: ScenarioGenerator):
    generated = generator.generate("api-authorization", 18, "rename_hosts")
    topology_path = generator.storage_root / generated["id"] / "topology.yaml"
    topology_path.write_text(topology_path.read_text() + "\n# modified\n", encoding="utf-8")

    with pytest.raises(ScenarioGeneratorError, match="was modified"):
        generator.mutate(generated["id"], 19, "rotate_ips")


def test_same_spec_returns_same_variant_without_overwrite(generator: ScenarioGenerator):
    first = generator.generate("api-authorization", 77, "rotate_ips")
    manifest = generator.storage_root / first["id"] / "manifest.yaml"
    first_bytes = manifest.read_bytes()

    second = generator.generate("api-authorization", 77, "rotate_ips")

    assert second["id"] == first["id"]
    assert manifest.read_bytes() == first_bytes


def test_export_publishes_dashboard_bundle_and_preserves_source(generator: ScenarioGenerator):
    generated = generator.generate("api-authorization", 78, "rotate_ips")

    exported = generator.export_variant(generated["id"])
    stored = generator.export_store.load(generated["id"])

    assert exported["exported"] is True
    assert exported["deletable"] is True
    assert exported["deployment_supported"] is False
    assert stored["scenario"]["topology"] == generated["id"]
    assert (
        stored["topology"]["router"]["name_template"]
        == stored["topology"]["router"]["name"]
    )
    assert all(
        item["name_template"] == item["name"]
        for item in stored["topology"]["services"]
    )
    ground_truth_path = generator.export_store.artifact_path(generated["id"], "ground_truth")
    contracts = _load(
        generator.export_store.artifact_path(generated["id"], "matching_contracts")
    )
    assert contracts["source_hashes"][generated["id"]] == hashlib.sha256(
        ground_truth_path.read_bytes()
    ).hexdigest()
    assert generator.list_variants()[0]["exported"] is True

    deleted = generator.delete_export(generated["id"])

    assert deleted["id"] == generated["id"]
    assert generator.get_variant(generated["id"])["id"] == generated["id"]
    assert generator.export_store.exists(generated["id"]) is False


def test_export_delete_rejects_non_exports_and_tampered_exports(generator: ScenarioGenerator):
    with pytest.raises(ScenarioExportError, match="Invalid Scenario Lab export identifier"):
        generator.delete_export("15")

    generated = generator.generate("ota-lifecycle", 79, "rename_hosts")
    generator.export_variant(generated["id"])
    scenario_path = generator.export_store.artifact_path(generated["id"], "scenario")
    scenario_path.write_text("scenario_id: tampered\n", encoding="utf-8")

    with pytest.raises(ScenarioExportError, match="was modified"):
        generator.delete_export(generated["id"])


def test_generator_router_is_registered_in_api_main():
    source = (REPO_ROOT / "src" / "api" / "main.py").read_text(encoding="utf-8")
    assert "scenario_generator.router" in source
    assert "prefix=\"/api/scenario-generator\"" in source
