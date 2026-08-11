"""Normalization and validation for manually authored Scenario Lab specs."""
from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import yaml

from src.benchmark.tool_registry import PHASES, available_tool_names


SCENARIO_SPEC_VERSION = 4
SCENARIO_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$")


class ScenarioSpecError(ValueError):
    """Raised when a manually authored scenario is invalid."""


def _mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScenarioSpecError(f"{where} must be a mapping")
    return value


def _list(value: Any, where: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ScenarioSpecError(f"{where} must be a list")
    return value


def load_scenario_spec(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ScenarioSpecError(f"Invalid scenario YAML: {path}") from exc
    return normalize_scenario_spec(raw)


def normalize_scenario_spec(raw: dict[str, Any]) -> dict[str, Any]:
    raw = copy.deepcopy(_mapping(raw, "scenario"))
    scenario_id = str(raw.get("scenario_id") or raw.get("id") or "").strip()
    if not SCENARIO_ID_RE.fullmatch(scenario_id):
        raise ScenarioSpecError(
            "scenario_id must contain 2-64 letters, digits, '_' or '-' and start with a letter/digit"
        )

    topology = raw.get("topology")
    if isinstance(topology, str):
        topology = {"ref": topology}
    elif isinstance(topology, dict):
        topology = copy.deepcopy(topology)
        if "ref" not in topology and "inline" not in topology and "router" in topology:
            topology = {"inline": topology}
    else:
        raise ScenarioSpecError("topology must be a reference string or a mapping")

    packs = _list(raw.get("packs"), "packs")
    normalized_packs = []
    for pack in packs:
        if isinstance(pack, str) and pack.strip():
            normalized_packs.append(pack.strip())
        else:
            raise ScenarioSpecError("packs entries must be non-empty strings")

    policy = _mapping(raw.get("tool_policy", {}), "tool_policy")
    for phase, value in policy.items():
        if phase not in PHASES:
            raise ScenarioSpecError(f"tool_policy contains unknown phase: {phase}")
        if isinstance(value, dict):
            value = value.get("tools", [])
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ScenarioSpecError(f"tool_policy.{phase} must be a list of tool names")

    execution = _mapping(raw.get("execution", {}), "execution")
    seed = raw.get("seed", 0)
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2**31 - 1:
        raise ScenarioSpecError("seed must be between 0 and 2147483647")

    structured_fields = {
        "lifecycle": "mapping",
        "environment": "mapping",
        "identity": "mapping",
        "detection": "mapping",
        "evaluation": "mapping",
        "compatibility": "mapping",
        "constraints": "mapping",
        "objectives": "list",
        "data_fixtures": "list",
        "failure_modes": "list",
    }
    for field, kind in structured_fields.items():
        if field not in raw:
            continue
        value = raw[field]
        if kind == "mapping" and not isinstance(value, dict):
            raise ScenarioSpecError(f"{field} must be a mapping")
        if kind == "list" and not isinstance(value, list):
            raise ScenarioSpecError(f"{field} must be a list")

    result = {
        "schema_version": max(SCENARIO_SPEC_VERSION, int(raw.get("schema_version", 1) or 1)),
        "scenario_id": scenario_id,
        "name": str(raw.get("name") or scenario_id),
        "difficulty": str(raw.get("difficulty") or "custom"),
        "posture": str(raw.get("posture") or "mixed"),
        "description": str(raw.get("description") or ""),
        "seed": seed,
        "topology": topology,
        "packs": normalized_packs,
        "tool_policy": policy,
        "execution": execution,
        "alterations": copy.deepcopy(_list(raw.get("alterations"), "alterations")),
        "attack_paths": copy.deepcopy(_list(raw.get("attack_paths"), "attack_paths")),
        "extra_vulnerabilities": copy.deepcopy(_list(raw.get("extra_vulnerabilities"), "extra_vulnerabilities")),
        "extra_controls": copy.deepcopy(_list(raw.get("extra_controls"), "extra_controls")),
        "bonus_types": copy.deepcopy(_list(raw.get("bonus_types"), "bonus_types")),
    }
    for key in (
        "lifecycle", "environment", "identity", "detection", "evaluation",
        "compatibility", "constraints", "objectives", "data_fixtures",
        "failure_modes",
    ):
        if key in raw:
            result[key] = copy.deepcopy(raw[key])
    for key in ("initial_credentials", "excluded_vulnerabilities", "metadata"):
        if key in raw:
            result[key] = copy.deepcopy(raw[key])
    validate_scenario_spec(result)
    return result


def validate_scenario_spec(spec: dict[str, Any], repo_root: Path | None = None) -> None:
    """Validate syntax and references before any bundle is written."""
    root = repo_root or Path(__file__).resolve().parents[2]
    topology = _mapping(spec.get("topology"), "topology")
    if "ref" in topology:
        topology_id = str(topology["ref"])
        path = root / "benchmarks" / "topologies" / f"{topology_id}.yaml"
        if not path.is_file():
            raise ScenarioSpecError(f"Unknown topology reference: {topology_id}")
    elif "inline" in topology:
        _validate_topology_mapping(_mapping(topology["inline"], "topology.inline"))
    else:
        raise ScenarioSpecError("topology requires ref or inline")

    pack_dir = root / "benchmarks" / "packs" / "definitions"
    for pack_id in spec.get("packs", []):
        if not (pack_dir / f"{pack_id}.yaml").is_file():
            raise ScenarioSpecError(f"Unknown vulnerability pack: {pack_id}")

    known_tools = available_tool_names(root)
    for phase, value in spec.get("tool_policy", {}).items():
        tools = value.get("tools", []) if isinstance(value, dict) else value
        unknown = sorted(set(tools) - known_tools)
        if unknown:
            raise ScenarioSpecError(
                f"tool_policy.{phase} contains unknown tools: {', '.join(unknown)}"
            )

    for index, path in enumerate(spec.get("attack_paths", []), 1):
        path = _mapping(path, f"attack_paths[{index}]")
        if not path.get("id"):
            raise ScenarioSpecError(f"attack_paths[{index}] requires id")
        if "chain" not in path and "steps" not in path:
            raise ScenarioSpecError(f"attack_paths[{index}] requires chain or steps")


def _validate_topology_mapping(topology: dict[str, Any]) -> None:
    router = _mapping(topology.get("router"), "topology.router")
    if not router.get("ip"):
        raise ScenarioSpecError("topology.router.ip is required")
    services = _list(topology.get("services"), "topology.services")
    if not services:
        raise ScenarioSpecError("topology.services must contain at least one service")
    names: set[str] = set()
    ips: set[str] = {str(router["ip"])}
    for index, item in enumerate(services, 1):
        item = _mapping(item, f"topology.services[{index}]")
        if not item.get("name") and not item.get("name_template"):
            raise ScenarioSpecError(f"topology.services[{index}] requires name or name_template")
        if not item.get("ip"):
            raise ScenarioSpecError(f"topology.services[{index}] requires ip")
        name = str(item.get("name") or item.get("name_template"))
        if name in names:
            raise ScenarioSpecError(f"Duplicate topology service: {name}")
        names.add(name)
        if str(item["ip"]) in ips:
            raise ScenarioSpecError(f"Duplicate topology IP: {item['ip']}")
        ips.add(str(item["ip"]))


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result
