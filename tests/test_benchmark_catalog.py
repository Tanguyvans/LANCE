from __future__ import annotations

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
    catalog_path.parent.mkdir(parents=True, exist_ok=True)
    catalog_path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return catalog_path, data


def test_default_catalog_has_exact_development_and_public_test_splits():
    catalog = load_catalog()

    assert [scenario.id for scenario in catalog.scenarios] == [str(i) for i in range(1, 30)]
    assert [scenario.id for scenario in catalog.for_split(DEV_PUBLIC)] == list(DEV_PUBLIC_SCENARIO_IDS)
    assert [scenario.id for scenario in catalog.for_split(TEST_PUBLIC)] == list(TEST_PUBLIC_SCENARIO_IDS)
    assert [scenario.id for scenario in catalog.for_split(EVAL_SEALED)] == list(SEALED_SCENARIO_IDS)
    assert catalog.benchmark_version == "3.2.0"
    assert catalog.get("S24").sealed is False
    assert catalog.get("S29").split == TEST_PUBLIC
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


def test_current_release_declares_no_sealed_profiles():
    catalog = load_catalog()

    assert SEALED_SCENARIO_IDS == ()
    assert catalog.for_split(EVAL_SEALED) == ()
    with pytest.raises(CatalogError, match="not an eval-sealed"):
        load_eval_profile("24", catalog=catalog)


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


def test_catalog_rejects_profile_link_on_public_test_scenario(tmp_path: Path):
    catalog_path, data = _catalog_copy(tmp_path)
    data["scenarios"][23]["profile"] = "eval_profiles/S24.yaml"
    catalog_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    with pytest.raises(CatalogError, match="must not declare a sealed profile"):
        load_catalog(catalog_path)
