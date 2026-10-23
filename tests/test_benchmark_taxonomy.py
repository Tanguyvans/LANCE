from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from src.benchmark.taxonomy import (
    DEFAULT_BENCHMARKS_ROOT,
    TaxonomyError,
    build_index,
    load_taxonomy,
    main,
    measure_architecture,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _service(ip: str, **extra) -> dict:
    return {"name_template": "s{sid}-x", "vmid_offset": 1, "ip": ip, "role": "web_server", **extra}


def test_measure_flat_topology():
    topology = {"router": {"ip": "192.168.100.1"},
                "services": [_service("192.168.100.11"), _service("192.168.100.12")]}
    assert measure_architecture(topology)["measured"] == "flat"


def test_measure_segmented_topology_without_relays():
    topology = {"router": {"ip": "192.168.100.1"},
                "services": [_service("192.168.10.11", vlan_id=10), _service("192.168.20.11", vlan_id=20)]}
    measured = measure_architecture(topology)
    assert measured["measured"] == "segmented"
    assert measured["segments"] == 3
    assert measured["relay_depth"] == 0


def test_measure_gateway_and_multi_hop_from_relays():
    gateway = {"router": {"ip": "192.168.100.1"}, "services": [
        _service("192.168.100.11", secondary_ip="192.168.110.11"),
        _service("192.168.110.12", no_gateway=True),
    ]}
    assert measure_architecture(gateway)["measured"] == "gateway"
    multi_hop = {"router": {"ip": "192.168.100.1"}, "services": [
        _service("192.168.100.11", secondary_ip="192.168.110.11"),
        _service("192.168.110.12", no_gateway=True, secondary_ip="192.168.120.12"),
        _service("192.168.120.13", no_gateway=True),
    ]}
    measured = measure_architecture(multi_hop)
    assert measured["measured"] == "multi_hop"
    assert measured["relay_depth"] == 2


def test_every_corpus_value_is_classified():
    # build_index raises TaxonomyError on any unclassified role, topology or category.
    index = build_index()
    assert index["summary"]["official_scenarios"] == 29
    assert all(s["architecture"]["target"] for s in index["scenarios"])


def test_taxonomy_has_no_stale_entries():
    taxonomy = load_taxonomy(DEFAULT_BENCHMARKS_ROOT / "taxonomy.yaml")
    index = build_index()
    used_topologies = {s["topology"] for s in index["scenarios"]}
    used_categories = {v["category"] for v in index["vulnerabilities"]}
    used_roles = {v["role"] for v in index["vulnerabilities"]}
    for path in (DEFAULT_BENCHMARKS_ROOT / "topologies").glob("*.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        used_roles |= {service["role"] for service in data.get("services") or []}
    assert set(taxonomy["architectures"]) - used_topologies == set()
    assert set(taxonomy["weaknesses"]) - used_categories == set()
    assert set(taxonomy["roles"]) - used_roles == set()


def test_versioned_outputs_are_up_to_date():
    assert main(["--check"]) == 0


def test_index_sources_match_the_files_on_disk():
    for relative, digest in build_index()["sources_sha256"].items():
        assert hashlib.sha256((REPO_ROOT / relative).read_bytes()).hexdigest() == digest


def _mini_corpus(tmp_path: Path, *, role: str = "web_server", category: str = "data_exposure") -> Path:
    root = tmp_path / "benchmarks"
    (root / "scenarios" / "dev").mkdir(parents=True)
    (root / "ground_truth" / "dev").mkdir(parents=True)
    (root / "topologies").mkdir()
    (root / "catalog.yaml").write_text(yaml.safe_dump({
        "schema_version": "1", "benchmark_version": "0",
        "scenarios": [{"id": "1", "label": "Mini", "split": "dev-public"}],
    }), encoding="utf-8")
    (root / "scenarios" / "dev" / "S1.yaml").write_text(
        yaml.safe_dump({"scenario_id": "1", "topology": "mini"}), encoding="utf-8")
    (root / "topologies" / "mini.yaml").write_text(yaml.safe_dump({
        "id": "mini", "router": {"ip": "192.168.100.1"},
        "services": [_service("192.168.100.11", role=role)],
    }), encoding="utf-8")
    (root / "ground_truth" / "dev" / "scenario_1.yaml").write_text(yaml.safe_dump({
        "scenario_id": "1",
        "vulnerabilities": [{"id": "V1", "role": role, "category": category}],
    }), encoding="utf-8")
    (root / "taxonomy.yaml").write_text(yaml.safe_dump({
        "schema_version": 1,
        "classes": {"device": {"web_app": "-"}, "architecture": {"flat": "-"},
                    "weakness": {"data_exposure": "-"}},
        "roles": {"web_server": {"device": "web_app"}},
        "architectures": {"mini": "flat"},
        "weaknesses": {"data_exposure": "data_exposure"},
    }), encoding="utf-8")
    return root


def test_mini_corpus_is_labelled(tmp_path):
    index = build_index(_mini_corpus(tmp_path))
    assert index["vulnerabilities"][0]["device"] == "web_app"
    assert index["vulnerabilities"][0]["weakness"] == "data_exposure"
    assert index["scenarios"][0]["architecture"]["conforms"] is True


@pytest.mark.parametrize("kwargs, needle", [
    ({"role": "mqtt_broker"}, "role mqtt_broker"),
    ({"category": "weak_crypto"}, "category weak_crypto"),
])
def test_unclassified_values_are_rejected(tmp_path, kwargs, needle):
    with pytest.raises(TaxonomyError, match=needle):
        build_index(_mini_corpus(tmp_path, **kwargs))
