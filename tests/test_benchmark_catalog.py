from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.benchmark.catalog import (
    DEFAULT_CATALOG_PATH,
    DEV_PUBLIC,
    EVAL_SEALED,
    CatalogError,
    TEST_PUBLIC,
    load_catalog,
    load_eval_profile,
    public_asset_path,
)

# Release expectations live in tests, not in the catalogue loader.
DEV_PUBLIC_SCENARIO_IDS = tuple(str(i) for i in range(1, 20))
TEST_PUBLIC_SCENARIO_IDS = tuple(str(i) for i in range(20, 30))
PUBLIC_SCENARIO_IDS = DEV_PUBLIC_SCENARIO_IDS + TEST_PUBLIC_SCENARIO_IDS
SEALED_SCENARIO_IDS = ()


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


def test_catalog_is_the_authority_for_membership_and_split(tmp_path: Path):
    catalog_path, data = _catalog_copy(tmp_path)
    data["scenarios"][23]["split"] = DEV_PUBLIC
    catalog_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert load_catalog(catalog_path).get("24").split == DEV_PUBLIC
    assert public_asset_path("24", "scenarios", benchmarks_root=tmp_path) == tmp_path / "scenarios/dev/S24.yaml"

    catalog_path, data = _catalog_copy(tmp_path / "missing")
    data["scenarios"].pop()
    catalog_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert len(load_catalog(catalog_path).scenarios) == 28


@pytest.mark.parametrize("split", ["training", "", "dev"])
def test_catalog_rejects_invalid_split(tmp_path: Path, split: str):
    path, data = _catalog_copy(tmp_path)
    data["scenarios"][0]["split"] = split
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(CatalogError):
        load_catalog(path)


@pytest.mark.parametrize("sid,group", [("1", "dev"), ("1h", "dev"), ("4h", "dev"), ("20", "test"), ("29", "test")])
def test_public_asset_paths_follow_catalogue(sid: str, group: str):
    root = DEFAULT_CATALOG_PATH.parent
    for kind in ("scenarios", "ground_truth"):
        path = public_asset_path(sid, kind)
        assert path.parent == root / kind / group
        assert path.is_file()


def test_catalog_rejects_profile_link_on_public_test_scenario(tmp_path: Path):
    catalog_path, data = _catalog_copy(tmp_path)
    data["scenarios"][23]["profile"] = "eval_profiles/S24.yaml"
    catalog_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    with pytest.raises(CatalogError, match="must not declare a sealed profile"):
        load_catalog(catalog_path)


def test_catalog_matches_every_public_asset_and_its_directory():
    root = DEFAULT_CATALOG_PATH.parent
    expected = {s.id for s in load_catalog().scenarios if not s.sealed} | {"1h", "4h"}
    for kind, prefix in (("scenarios", "S"), ("ground_truth", "scenario_")):
        paths = list((root / kind).rglob(f"{prefix}*.yaml"))
        assert len(paths) == len(expected)
        assert {p.stem.removeprefix(prefix) for p in paths} == expected
        for path in paths:
            assert path == public_asset_path(path.stem.removeprefix(prefix), kind)
        assert not list((root / kind).glob(f"{prefix}*.yaml"))
    assert (root / "ground_truth/matching_contracts.yaml").is_file()


@pytest.mark.parametrize("sid", ["../1", "0", "01", "30", "1/../../20", "20.yaml"])
def test_asset_resolver_rejects_unknown_or_unsafe_ids(sid):
    with pytest.raises(CatalogError):
        public_asset_path(sid, "scenarios")
