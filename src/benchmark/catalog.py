"""Strict catalogue for development, public-test, and future sealed scenarios.

The current benchmark release is fully public: S1-S19 are development scenarios
and S20-S29 are held out from tuning. Sealed-profile support remains available
for a future release.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Literal, Mapping

import yaml


CATALOG_SCHEMA_VERSION = "1"
DEFAULT_CATALOG_PATH = Path(__file__).resolve().parents[2] / "benchmarks" / "catalog.yaml"

DEV_PUBLIC: Literal["dev-public"] = "dev-public"
TEST_PUBLIC: Literal["test-public"] = "test-public"
EVAL_SEALED: Literal["eval-sealed"] = "eval-sealed"
ScenarioSplit = Literal["dev-public", "test-public", "eval-sealed"]

_CATALOG_KEYS = frozenset({"schema_version", "benchmark_version", "scenarios"})
_SCENARIO_KEYS = frozenset({"id", "label", "split", "profile"})
_PROFILE_KEYS = frozenset(
    {
        "schema_version",
        "scenario_id",
        "split",
        "controller_required",
        "blind_required",
        "score_visibility",
    }
)
DEV_PUBLIC_SCENARIO_IDS = tuple(str(i) for i in range(1, 20))
TEST_PUBLIC_SCENARIO_IDS = tuple(str(i) for i in range(20, 30))
PUBLIC_SCENARIO_IDS = DEV_PUBLIC_SCENARIO_IDS + TEST_PUBLIC_SCENARIO_IDS
SEALED_SCENARIO_IDS: tuple[str, ...] = ()
_EXPECTED_IDS = PUBLIC_SCENARIO_IDS + SEALED_SCENARIO_IDS


class CatalogError(ValueError):
    """Raised when public benchmark metadata is incomplete or unsafe."""


def _require_mapping(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CatalogError(f"{where} must be a mapping")
    if not all(isinstance(key, str) for key in value):
        raise CatalogError(f"{where} contains a non-string key")
    return value


def _require_exact_keys(
    data: Mapping[str, object],
    *,
    allowed: frozenset[str],
    required: frozenset[str],
    where: str,
) -> None:
    keys = frozenset(data)
    unknown = keys - allowed
    missing = required - keys
    if unknown:
        raise CatalogError(f"{where} contains forbidden/unknown keys: {sorted(unknown)}")
    if missing:
        raise CatalogError(f"{where} is missing required keys: {sorted(missing)}")


def _require_nonempty_string(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogError(f"{where} must be a non-empty string")
    return value.strip()


@dataclass(frozen=True, slots=True)
class EvalProfile:
    """Public policy for a sealed scenario, containing no challenge content."""

    scenario_id: str
    controller_required: bool = True
    blind_required: bool = True
    score_visibility: Literal["aggregate"] = "aggregate"
    schema_version: str = CATALOG_SCHEMA_VERSION
    split: Literal["eval-sealed"] = EVAL_SEALED

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "split": self.split,
            "controller_required": self.controller_required,
            "blind_required": self.blind_required,
            "score_visibility": self.score_visibility,
        }


@dataclass(frozen=True, slots=True)
class ScenarioDescriptor:
    id: str
    label: str
    split: ScenarioSplit
    profile_path: Path | None = None

    @property
    def sealed(self) -> bool:
        return self.split == EVAL_SEALED

    def to_public_dict(self) -> dict[str, object]:
        # The profile's filesystem location is intentionally not exposed.
        return {"id": self.id, "label": self.label, "split": self.split}


@dataclass(frozen=True, slots=True)
class BenchmarkCatalog:
    schema_version: str
    benchmark_version: str
    scenarios: tuple[ScenarioDescriptor, ...]

    def get(self, scenario_id: int | str) -> ScenarioDescriptor:
        normalized = str(scenario_id).removeprefix("S")
        for scenario in self.scenarios:
            if scenario.id == normalized:
                return scenario
        raise CatalogError(f"unknown benchmark scenario: {scenario_id}")

    def for_split(self, split: ScenarioSplit) -> tuple[ScenarioDescriptor, ...]:
        if split not in (DEV_PUBLIC, TEST_PUBLIC, EVAL_SEALED):
            raise CatalogError(f"unsupported benchmark split: {split}")
        return tuple(item for item in self.scenarios if item.split == split)

    def resolve_selector(self, selector: str | Iterable[int | str]) -> tuple[ScenarioDescriptor, ...]:
        if isinstance(selector, str):
            normalized = selector.strip().lower()
            if normalized in {"dev", DEV_PUBLIC}:
                return self.for_split(DEV_PUBLIC)
            if normalized in {"test", TEST_PUBLIC}:
                return self.for_split(TEST_PUBLIC)
            if normalized == "public":
                return tuple(item for item in self.scenarios if not item.sealed)
            if normalized in {"eval", EVAL_SEALED}:
                return self.for_split(EVAL_SEALED)
            if normalized == "all":
                return self.scenarios
            raw_ids: Iterable[int | str] = normalized.split(",")
        else:
            raw_ids = selector

        resolved: list[ScenarioDescriptor] = []
        seen: set[str] = set()
        for raw_id in raw_ids:
            item = self.get(str(raw_id).strip())
            if item.id not in seen:
                resolved.append(item)
                seen.add(item.id)
        if not resolved:
            raise CatalogError("scenario selector resolved to an empty set")
        return tuple(resolved)


def _safe_profile_path(base_dir: Path, scenario_id: str, raw_path: object) -> Path:
    relative = _require_nonempty_string(raw_path, f"scenario S{scenario_id}.profile")
    posix = PurePosixPath(relative)
    if posix.is_absolute() or ".." in posix.parts or "\\" in relative:
        raise CatalogError(f"scenario S{scenario_id}.profile must be a safe relative path")
    expected = PurePosixPath("eval_profiles") / f"S{scenario_id}.yaml"
    if posix != expected:
        raise CatalogError(f"scenario S{scenario_id}.profile must be {expected.as_posix()}")

    base_resolved = base_dir.resolve()
    profile_path = (base_dir / Path(*posix.parts)).resolve()
    try:
        profile_path.relative_to(base_resolved)
    except ValueError as exc:
        raise CatalogError(f"scenario S{scenario_id}.profile escapes the catalogue directory") from exc
    if not profile_path.is_file():
        raise CatalogError(f"sealed profile not found: {profile_path}")
    return profile_path


def load_eval_profile(
    scenario: ScenarioDescriptor | int | str,
    *,
    catalog: BenchmarkCatalog | None = None,
) -> EvalProfile:
    descriptor = scenario if isinstance(scenario, ScenarioDescriptor) else (catalog or load_catalog()).get(scenario)
    if not descriptor.sealed or descriptor.profile_path is None:
        raise CatalogError(f"scenario S{descriptor.id} is not an eval-sealed scenario")

    try:
        raw = yaml.safe_load(descriptor.profile_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CatalogError(f"cannot load sealed profile for S{descriptor.id}: {exc}") from exc
    data = _require_mapping(raw, f"profile S{descriptor.id}")
    _require_exact_keys(
        data,
        allowed=_PROFILE_KEYS,
        required=_PROFILE_KEYS,
        where=f"profile S{descriptor.id}",
    )

    schema_version = _require_nonempty_string(data["schema_version"], "profile.schema_version")
    scenario_id = _require_nonempty_string(data["scenario_id"], "profile.scenario_id")
    split = _require_nonempty_string(data["split"], "profile.split")
    score_visibility = _require_nonempty_string(data["score_visibility"], "profile.score_visibility")
    if schema_version != CATALOG_SCHEMA_VERSION:
        raise CatalogError(f"unsupported profile schema_version: {schema_version}")
    if scenario_id != descriptor.id:
        raise CatalogError(f"profile scenario_id {scenario_id!r} does not match S{descriptor.id}")
    if split != EVAL_SEALED:
        raise CatalogError("sealed profile split must be eval-sealed")
    if data["controller_required"] is not True or data["blind_required"] is not True:
        raise CatalogError("sealed profiles must require both the controller and blind execution")
    if score_visibility != "aggregate":
        raise CatalogError("sealed profiles may expose aggregate scores only")

    return EvalProfile(scenario_id=scenario_id)


def load_catalog(path: str | Path = DEFAULT_CATALOG_PATH) -> BenchmarkCatalog:
    catalog_path = Path(path)
    try:
        raw = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CatalogError(f"cannot load benchmark catalogue {catalog_path}: {exc}") from exc

    data = _require_mapping(raw, "catalogue")
    _require_exact_keys(
        data,
        allowed=_CATALOG_KEYS,
        required=_CATALOG_KEYS,
        where="catalogue",
    )
    schema_version = _require_nonempty_string(data["schema_version"], "catalogue.schema_version")
    benchmark_version = _require_nonempty_string(data["benchmark_version"], "catalogue.benchmark_version")
    if schema_version != CATALOG_SCHEMA_VERSION:
        raise CatalogError(f"unsupported catalogue schema_version: {schema_version}")

    raw_scenarios = data["scenarios"]
    if not isinstance(raw_scenarios, list):
        raise CatalogError("catalogue.scenarios must be a list")

    scenarios: list[ScenarioDescriptor] = []
    seen: set[str] = set()
    for index, raw_scenario in enumerate(raw_scenarios):
        item = _require_mapping(raw_scenario, f"catalogue.scenarios[{index}]")
        _require_exact_keys(
            item,
            allowed=_SCENARIO_KEYS,
            required=frozenset({"id", "label", "split"}),
            where=f"catalogue.scenarios[{index}]",
        )
        scenario_id = _require_nonempty_string(item["id"], f"scenario[{index}].id")
        label = _require_nonempty_string(item["label"], f"scenario S{scenario_id}.label")
        split = _require_nonempty_string(item["split"], f"scenario S{scenario_id}.split")
        if not scenario_id.isdigit() or str(int(scenario_id)) != scenario_id:
            raise CatalogError(f"scenario id must be a canonical positive integer string: {scenario_id!r}")
        if scenario_id in seen:
            raise CatalogError(f"duplicate scenario id: {scenario_id}")
        seen.add(scenario_id)

        expected_split = (
            DEV_PUBLIC
            if scenario_id in DEV_PUBLIC_SCENARIO_IDS
            else TEST_PUBLIC
            if scenario_id in TEST_PUBLIC_SCENARIO_IDS
            else EVAL_SEALED
            if scenario_id in SEALED_SCENARIO_IDS
            else None
        )
        if expected_split is None or split != expected_split:
            raise CatalogError(f"scenario S{scenario_id} must use split {expected_split!r}, got {split!r}")

        profile_path: Path | None = None
        if split == EVAL_SEALED:
            if "profile" not in item:
                raise CatalogError(f"sealed scenario S{scenario_id} is missing its public policy profile")
            profile_path = _safe_profile_path(catalog_path.parent, scenario_id, item["profile"])
        elif "profile" in item:
            raise CatalogError(f"public scenario S{scenario_id} must not declare a sealed profile")

        scenarios.append(
            ScenarioDescriptor(
                id=scenario_id,
                label=label,
                split=split,  # type: ignore[arg-type]
                profile_path=profile_path,
            )
        )

    ids = tuple(item.id for item in scenarios)
    if set(ids) != set(_EXPECTED_IDS) or len(ids) != len(_EXPECTED_IDS):
        missing = sorted(set(_EXPECTED_IDS) - set(ids), key=int)
        extra = sorted(set(ids) - set(_EXPECTED_IDS), key=int)
        raise CatalogError(f"catalogue must contain exactly S1-S29 (missing={missing}, extra={extra})")
    scenarios.sort(key=lambda item: int(item.id))

    catalog = BenchmarkCatalog(
        schema_version=schema_version,
        benchmark_version=benchmark_version,
        scenarios=tuple(scenarios),
    )
    # Loading the catalogue also validates every sealed profile. A malformed or
    # accidentally enriched profile therefore prevents any sealed run.
    for descriptor in catalog.for_split(EVAL_SEALED):
        load_eval_profile(descriptor, catalog=catalog)
    return catalog


def get_scenario(scenario_id: int | str, *, catalog: BenchmarkCatalog | None = None) -> ScenarioDescriptor:
    return (catalog or load_catalog()).get(scenario_id)


def list_scenarios(
    split: ScenarioSplit | None = None,
    *,
    catalog: BenchmarkCatalog | None = None,
) -> tuple[ScenarioDescriptor, ...]:
    loaded = catalog or load_catalog()
    return loaded.scenarios if split is None else loaded.for_split(split)
