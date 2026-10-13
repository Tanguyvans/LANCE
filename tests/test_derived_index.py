from __future__ import annotations

from pathlib import Path

import yaml

from src.benchmark.catalog import load_catalog
from src.benchmark.derived_index import build_index, derive_type


def _write_gt(tmp_path: Path, scenario_id: str, vulns: list[dict]) -> Path:
    gt_dir = tmp_path / "gt"
    gt_dir.mkdir(exist_ok=True)
    path = gt_dir / f"scenario_{scenario_id}.yaml"
    path.write_text(yaml.safe_dump(
        {"scenario_id": scenario_id, "vulnerabilities": vulns},
        allow_unicode=True, sort_keys=False), encoding="utf-8")
    return gt_dir


def test_derive_type_logic_vs_signature():
    assert derive_type("broken_access_control") == "logique"
    assert derive_type("auth_bypass") == "logique"
    assert derive_type("misconfiguration") == "signature"
    assert derive_type("default_credentials") == "signature"
    assert derive_type(None) == "signature"


def test_build_index_axes_and_summary(tmp_path):
    gt_dir = _write_gt(tmp_path, "99", [
        {"id": "V1", "device": "d1", "category": "broken_access_control",
         "severity": "high", "hop_depth": 2},
        {"id": "V2", "device": "d2", "category": "misconfiguration",
         "severity": "low", "hop_depth": 0},
    ])
    index = build_index(gt_dirs=(gt_dir,))
    assert index["summary"]["scenarios"] == 1
    assert index["summary"]["vulnerabilities"] == 2
    assert index["summary"]["by_type"] == {"logique": 1, "signature": 1}
    assert index["summary"]["by_chainage"] == {"0": 1, "2": 1}
    by_id = {e["vuln_id"]: e for e in index["entries"]}
    assert by_id["V1"]["type"] == "logique"
    assert by_id["V1"]["surface"] == "base"
    assert by_id["V1"]["protocole"] == "connu"
    assert index["sources_sha256"]  # every source is hashed


def test_build_index_alterations_override(tmp_path):
    gt_dir = _write_gt(tmp_path, "7", [
        {"id": "V1", "device": "d1", "category": "data_exposure",
         "severity": "medium", "hop_depth": 1},
    ])
    index = build_index(
        gt_dirs=(gt_dir,),
        alterations={"7": {"surface": "rotate_ips", "bruit": "decoys"}})
    (entry,) = index["entries"]
    assert entry["surface"] == "rotate_ips"
    assert entry["bruit"] == "decoys"


def test_catalog_still_loads_unchanged():
    catalog = load_catalog()
    assert catalog is not None
