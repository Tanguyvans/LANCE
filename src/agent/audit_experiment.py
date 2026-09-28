"""Validated public inputs for the bounded analysis/verification experiment.

This module never loads scenario definitions or ground truth. Environment hashes
are declarations by the experiment operator, not laboratory attestations.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
from pathlib import Path

EXPERIMENT_SCOPE = "analysis-verification"
POLICY_SCHEMA_VERSION = 1
EXECUTION_LEDGER_VERSION = 2


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def positive_limit(value, name: str, *, integer: bool = False):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int if integer else (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive {'integer' if integer else 'number'}")
    return value


def validate_inventory(raw: dict) -> dict:
    """Accept only public inventory fields, rejecting answer-key-shaped inputs."""
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "provenance", "target_network", "devices", "experiment"}:
        raise ValueError("Public inventory requires schema_version, provenance, target_network, devices and experiment only")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ValueError("Unsupported public inventory schema")
    if not isinstance(raw["provenance"], str) or not raw["provenance"].strip():
        raise ValueError("Public inventory provenance is required")
    if not isinstance(raw["target_network"], str):
        raise ValueError("target_network must be a CIDR string")
    try:
        network = ipaddress.ip_network(raw["target_network"], strict=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Public inventory requires one canonical target network") from exc
    experiment = raw["experiment"]
    fields = {"id", "family_id", "instance_id", "trial_id", "environment_sha256"}
    if not isinstance(experiment, dict) or set(experiment) != fields:
        raise ValueError("experiment requires id, family_id, instance_id, trial_id and environment_sha256")
    if any(not isinstance(v, str) or not v.strip() for v in experiment.values()):
        raise ValueError("Experiment identifiers must be nonempty strings")
    if not re.fullmatch(r"[0-9a-f]{64}", experiment["environment_sha256"]):
        raise ValueError("environment_sha256 must identify the declared initial environment")
    devices = raw["devices"]
    if not isinstance(devices, list) or not devices:
        raise ValueError("Public inventory must contain devices")
    ids, addresses = set(), set()
    for device in devices:
        if not isinstance(device, dict) or set(device) - {"id", "ip", "role", "services", "public_context"} or not {"id", "ip", "services"} <= set(device):
            raise ValueError("Device fields are id, ip, services, optional role and public_context")
        name = device["id"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name) or name in ids:
            raise ValueError("Device ids must be unique safe filenames")
        ids.add(name)
        if not isinstance(device["ip"], str):
            raise ValueError("Inventory IP must be a string")
        try:
            address = ipaddress.ip_address(device["ip"])
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid inventory IP") from exc
        if address not in network or str(address) in addresses:
            raise ValueError("Inventory addresses must be unique and inside target_network")
        addresses.add(str(address))
        for key in ("role", "public_context"):
            if key in device and not isinstance(device[key], str):
                raise ValueError(f"Device {key} must be text")
        if not isinstance(device["services"], list) or not device["services"]:
            raise ValueError("Each inventory device needs declared services")
        for service in device["services"]:
            if not isinstance(service, dict) or set(service) - {"name", "port", "protocol"} or not {"name", "port"} <= set(service):
                raise ValueError("Services require name, port and optional protocol")
            if not isinstance(service["name"], str) or not service["name"].strip():
                raise ValueError("Service name is required")
            if type(service["port"]) is not int or not 1 <= service["port"] <= 65535:
                raise ValueError("Service port is invalid")
            if "protocol" in service and service["protocol"] not in {"tcp", "udp"}:
                raise ValueError("Service protocol must be tcp or udp")
    return json.loads(json.dumps(raw, allow_nan=False))


def load_inventory(path: str | Path) -> dict:
    return validate_inventory(json.loads(Path(path).read_text(encoding="utf-8")))


def validate_configuration(*, decision_policy, experiment_scope, inventory,
                           execution_profile, phases, max_tool_calls,
                           max_duration_s, max_cost_usd, incompatible=False):
    """Validate before constructing a provider or creating execution artifacts."""
    if decision_policy not in {"rules", "llm"}:
        raise ValueError("decision_policy must be rules or llm")
    positive_limit(max_tool_calls, "max_tool_calls", integer=True)
    positive_limit(max_duration_s, "max_duration_s")
    if experiment_scope is None:
        if decision_policy != "llm" or inventory is not None:
            raise ValueError("rules and audit_inventory require experiment_scope=analysis-verification")
        return None
    if experiment_scope != EXPERIMENT_SCOPE:
        raise ValueError("Unsupported experiment_scope")
    if incompatible:
        raise ValueError("Inventory experiments cannot use scenarios, deployment contracts, custom configurations, dry-run, blind mode, splits, target-network or phase-model overrides")
    if execution_profile != "full" or (phases is not None and list(phases) != [3, 4]):
        raise ValueError("Inventory experiments require an explicit full profile and phases 3 4 only")
    if max_tool_calls is None or max_duration_s is None:
        raise ValueError("Inventory experiments require max_tool_calls and max_duration_s")
    positive_limit(max_cost_usd, "max_cost_usd")
    return validate_inventory(inventory)


def resource_manifest(root: Path | None = None) -> str:
    """Hash actual source/resources, including uncommitted edits, without secrets."""
    root = root or Path(__file__).resolve().parents[2]
    files = sorted({p for base in ("src/agent", "src/benchmark") for p in (root / base).rglob("*")
                    if p.is_file() and p.suffix in {".py", ".txt", ".yaml", ".md", ".json"} and "__pycache__" not in p.parts})
    hasher = hashlib.sha256()
    for path in files:
        hasher.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
    return hasher.hexdigest()


def analysis_limits() -> dict:
    """Capture effective environment-dependent recovery settings, without secrets."""
    from src.agent.phases.analysis.block_recovery import block_config
    try:
        timeout = float(os.environ.get("LANCE_PHASE3_DEVICE_TIMEOUT_S", "240"))
        timeout = max(30.0, timeout) if math.isfinite(timeout) else 240.0
    except ValueError:
        timeout = 240.0
    return {"device_timeout_s": timeout, "block_recovery": block_config()}
