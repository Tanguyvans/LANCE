from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from src.benchmark.catalog import (
    DEFAULT_CATALOG_PATH,
    DEV_PUBLIC,
    DEV_PUBLIC_SCENARIO_IDS,
    EVAL_SEALED,
    CatalogError,
    PUBLIC_SCENARIO_IDS,
    SEALED_SCENARIO_IDS,
    TEST_PUBLIC,
    TEST_PUBLIC_SCENARIO_IDS,
    load_catalog,
    load_eval_profile,
)


def _catalog_copy(tmp_path: Path) -> tuple[Path, dict]:
    data = yaml.safe_load(DEFAULT_CATALOG_PATH.read_text(encoding="utf-8"))
    catalog_path = tmp_path / "catalog.yaml"
    profiles_dir = tmp_path / "eval_profiles"
    profiles_dir.mkdir(parents=True)
    for scenario_id in SEALED_SCENARIO_IDS:
        source = DEFAULT_CATALOG_PATH.parent / "eval_profiles" / f"S{scenario_id}.yaml"
        shutil.copy2(source, profiles_dir / source.name)
    catalog_path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return catalog_path, data


def test_default_catalog_has_exact_development_test_and_sealed_splits():
    catalog = load_catalog()

    assert [scenario.id for scenario in catalog.scenarios] == [str(i) for i in range(1, 30)]
    assert [scenario.id for scenario in catalog.for_split(DEV_PUBLIC)] == list(DEV_PUBLIC_SCENARIO_IDS)
    assert [scenario.id for scenario in catalog.for_split(TEST_PUBLIC)] == list(TEST_PUBLIC_SCENARIO_IDS)
    assert [scenario.id for scenario in catalog.for_split(EVAL_SEALED)] == list(SEALED_SCENARIO_IDS)
    assert catalog.benchmark_version == "3.1.0"
    assert catalog.get("S24").sealed is True
    assert catalog.get(23).sealed is False
    assert catalog.get(20).split == TEST_PUBLIC


def test_catalog_selectors_are_stable_and_deduplicate_ids():
    catalog = load_catalog()

    assert [item.id for item in catalog.resolve_selector("dev")] == list(DEV_PUBLIC_SCENARIO_IDS)
    assert [item.id for item in catalog.resolve_selector("test")] == list(TEST_PUBLIC_SCENARIO_IDS)
    assert [item.id for item in catalog.resolve_selector("public")] == list(PUBLIC_SCENARIO_IDS)
    assert [item.id for item in catalog.resolve_selector("eval")] == list(SEALED_SCENARIO_IDS)
    assert [item.id for item in catalog.resolve_selector("24,25,24")] == ["24", "25"]
    assert len(catalog.resolve_selector("all")) == 29


def test_sealed_profiles_are_policy_only_and_force_blind_controller_execution():
    catalog = load_catalog()
    forbidden = {
        "topology",
        "packs",
        "ground_truth",
        "vulnerabilities",
        "attack_paths",
        "seed",
        "roles",
        "services",
        "verification",
        "credentials",
    }

    for descriptor in catalog.for_split(EVAL_SEALED):
        profile = load_eval_profile(descriptor, catalog=catalog)
        public = profile.to_public_dict()
        assert profile.controller_required is True
        assert profile.blind_required is True
        assert profile.score_visibility == "aggregate"
        assert forbidden.isdisjoint(public)
        raw = yaml.safe_load(descriptor.profile_path.read_text(encoding="utf-8"))
        assert forbidden.isdisjoint(raw)
        # The catalogue API representation never exposes a local profile path.
        assert "profile" not in descriptor.to_public_dict()
        assert "profile_path" not in descriptor.to_public_dict()


def test_catalog_rejects_unknown_oracle_field(tmp_path: Path):
    catalog_path, data = _catalog_copy(tmp_path)
    data["ground_truth"] = "should-never-be-here"
    catalog_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    with pytest.raises(CatalogError, match="forbidden/unknown"):
        load_catalog(catalog_path)


def test_catalog_rejects_wrong_split_and_missing_coverage(tmp_path: Path):
    catalog_path, data = _catalog_copy(tmp_path)
    data["scenarios"][23]["split"] = DEV_PUBLIC
    catalog_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    with pytest.raises(CatalogError, match="must use split"):
        load_catalog(catalog_path)

    catalog_path, data = _catalog_copy(tmp_path / "missing")
    data["scenarios"].pop()
    catalog_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    with pytest.raises(CatalogError, match="exactly S1-S29"):
        load_catalog(catalog_path)


def test_catalog_rejects_enriched_or_weakened_sealed_profile(tmp_path: Path):
    catalog_path, _ = _catalog_copy(tmp_path)
    profile_path = tmp_path / "eval_profiles" / "S24.yaml"
    profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    profile["topology"] = {"services": ["oracle"]}
    profile_path.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")

    with pytest.raises(CatalogError, match="forbidden/unknown"):
        load_catalog(catalog_path)

    del profile["topology"]
    profile["blind_required"] = False
    profile_path.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")
    with pytest.raises(CatalogError, match="require both"):
        load_catalog(catalog_path)
