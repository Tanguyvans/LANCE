"""Runtime deployment context for exported Scenario Lab variants.

Scenario Lab exports deliberately do not modify the official Ansible catalogue.
This module translates one trusted export into the small, scenario-shaped vars
file expected by the existing playbooks and reserves a private VMID range for
the lifetime of the deployment.
"""
from __future__ import annotations

import copy
import fcntl
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from src.benchmark.scenario_exports import (
    REPO_ROOT,
    ExportedScenarioStore,
    ScenarioExportError,
    default_export_store,
)


DEPLOYMENT_ROOT = REPO_ROOT / "output" / "scenario_deployments"
MANUAL_SCENARIO_ROOT = REPO_ROOT / "output" / "generated_scenarios"
MANUAL_SCENARIO_ID_RE = re.compile(r"^gen-custom-[a-f0-9]{10}$")
LEASES_DIRNAME = "leases"
OVERLAYS_DIRNAME = "overlays"
DYNAMIC_BASE_VMID = 700
MANUAL_ARTIFACTS = {
    "scenario": "scenario.yaml",
    "topology": "topology.yaml",
    "ground_truth": "ground_truth.yaml",
    "injection_plan": "injection_plan.yaml",
    "verification_plan": "verification_plan.yaml",
    "matching_contracts": "matching_contracts.yaml",
    "execution_plan": "execution_plan.yaml",
    "alteration_plan": "alteration_plan.yaml",
}


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(value, dict):
        raise ScenarioExportError(f"Expected a YAML mapping: {path.name}")
    return value


def _catalog(repo_root: Path = REPO_ROOT) -> tuple[dict[str, int], dict[str, dict[str, Any]]]:
    """Load the host-local Ansible catalogue without evaluating Jinja."""
    main = _load_yaml(repo_root / "benchmarks/ansible/group_vars/all/main.yml")
    v2 = _load_yaml(repo_root / "benchmarks/ansible/group_vars/all/scenarios_v2.yml")
    ranges = {
        str(key): int(value)
        for key, value in {
            **(main.get("scenario_vmid_ranges") or {}),
            **(v2.get("scenario_vmid_ranges_v2") or {}),
        }.items()
    }
    scenarios = {
        str(key): copy.deepcopy(value)
        for key, value in {
            **(main.get("scenarios") or {}),
            **(v2.get("scenarios_v2") or {}),
        }.items()
    }
    return ranges, scenarios


def _service_suffix(source_name: str, source_scenario_id: str, fallback: str) -> str:
    prefix = f"s{source_scenario_id}-"
    if source_name.startswith(prefix):
        return source_name[len(prefix):]
    match = re.match(r"^s\d+-(.+)$", source_name)
    return match.group(1) if match else fallback


@dataclass
class GeneratedScenarioDeployment:
    """An allocated, Ansible-compatible deployment for one exported variant."""

    scenario_id: str
    source_scenario_id: str
    base_vmid: int
    max_vmid_offset: int
    overlay_path: Path
    lease_path: Path
    state_root: Path

    @property
    def vmid_range(self) -> range:
        return range(self.base_vmid, self.base_vmid + self.max_vmid_offset + 1)

    @property
    def is_generated(self) -> bool:
        return True

    @classmethod
    def prepare(
        cls,
        scenario_id: str,
        *,
        export_store: ExportedScenarioStore | None = None,
        state_root: Path | None = None,
        repo_root: Path = REPO_ROOT,
    ) -> "GeneratedScenarioDeployment":
        """Validate an export, allocate VMIDs and write its runtime vars file."""
        sid = str(scenario_id)
        store = export_store or default_export_store()
        bundle = store.load(sid)
        manifest = bundle["manifest"]
        source_sid = str(manifest.get("source_scenario_id", ""))
        if not source_sid.isdigit():
            raise ScenarioExportError("Exported scenario has no numeric source scenario")

        topology = bundle["topology"]
        router = topology.get("router") or {}
        services = topology.get("services") or []
        if not router.get("name") or not router.get("ip") or not services:
            raise ScenarioExportError("Exported topology cannot be deployed")

        ranges, scenarios = _catalog(repo_root)
        source_scenario = scenarios.get(source_sid)
        if source_scenario is None:
            raise ScenarioExportError(f"Source scenario S{source_sid} is absent from the Ansible catalogue")

        normalized_services = []
        for raw in services:
            item = copy.deepcopy(raw)
            concrete_name = str(item.get("name", ""))
            source_name = str(item.get("source_name", concrete_name))
            item["name"] = _service_suffix(source_name, source_sid, concrete_name)
            # The playbooks use ``name`` for the historical suffix in labels and
            # role logic.  ``deploy_name`` is the concrete generated hostname.
            item["deploy_name"] = concrete_name
            item.pop("name_template", None)
            normalized_services.append(item)

        max_offset = max(int(item.get("vmid_offset", 0)) for item in normalized_services)
        root = (state_root or DEPLOYMENT_ROOT).resolve()
        leases = root / LEASES_DIRNAME
        overlays = root / OVERLAYS_DIRNAME
        leases.mkdir(parents=True, exist_ok=True)
        overlays.mkdir(parents=True, exist_ok=True)
        lease_path = leases / f"{sid}.yaml"

        lock_path = root / ".allocation.lock"
        with lock_path.open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            lease = _read_optional(lease_path)
            if lease and (
                str(lease.get("scenario_id")) != sid
                or str(lease.get("source_scenario_id")) != source_sid
                or int(lease.get("max_vmid_offset", -1)) != max_offset
            ):
                raise ScenarioExportError(f"VMID lease for {sid} does not match the exported topology")
            base_vmid = int(lease["base_vmid"]) if lease else _allocate_base(
                ranges, scenarios, leases, max_offset
            )
            lease_data = {
                "schema_version": 1,
                "scenario_id": sid,
                "source_scenario_id": source_sid,
                "base_vmid": base_vmid,
                "max_vmid_offset": max_offset,
                "router_name": str(router["name"]),
                "export_root": str(store.root),
            }
            lease_path.write_text(
                yaml.safe_dump(lease_data, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            overlay_path = overlays / f"{sid}.yaml"
            cloud_metadata_ip = next(
                (str(item["ip"]) for item in normalized_services
                 if item.get("simulator") == "cloud_metadata"),
                "192.168.100.12",
            )
            cloud_web_ip = next(
                (str(item["ip"]) for item in normalized_services
                 if item.get("simulator") == "cloud_web"),
                "192.168.100.11",
            )
            overlay = {
                "scenario_id": sid,
                "source_scenario_id": source_sid,
                "generated_scenario": True,
                "router_name": str(router["name"]),
                "cloud_metadata_ip": cloud_metadata_ip,
                "cloud_web_ip": cloud_web_ip,
                "benchmark_scenario_vmid_ranges": {sid: base_vmid},
                "benchmark_scenarios": {
                    sid: {
                        "name": bundle["scenario"].get("name", topology.get("name", sid)),
                        "router_vulns": copy.deepcopy(source_scenario.get("router_vulns", [])),
                        "router_name": str(router["name"]),
                        "services": normalized_services,
                    }
                },
            }
            overlay_path.write_text(
                yaml.safe_dump(overlay, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

        return cls(sid, source_sid, base_vmid, max_offset, overlay_path, lease_path, root)

    @classmethod
    def from_lease(
        cls,
        scenario_id: str,
        *,
        state_root: Path | None = None,
    ) -> "GeneratedScenarioDeployment" | None:
        root = (state_root or DEPLOYMENT_ROOT).resolve()
        lease_path = root / LEASES_DIRNAME / f"{scenario_id}.yaml"
        lease = _read_optional(lease_path)
        if not lease:
            return None
        overlay_path = root / OVERLAYS_DIRNAME / f"{scenario_id}.yaml"
        if not overlay_path.is_file():
            return None
        return cls(
            str(lease["scenario_id"]),
            str(lease["source_scenario_id"]),
            int(lease["base_vmid"]),
            int(lease["max_vmid_offset"]),
            overlay_path,
            lease_path,
            root,
        )

    @classmethod
    def active_leases(cls, *, state_root: Path | None = None) -> list["GeneratedScenarioDeployment"]:
        root = (state_root or DEPLOYMENT_ROOT).resolve()
        directory = root / LEASES_DIRNAME
        if not directory.is_dir():
            return []
        result = []
        for path in sorted(directory.glob("gen-*.yaml")):
            deployment = cls.from_lease(path.stem, state_root=root)
            if deployment is not None:
                result.append(deployment)
        return result

    def release(self) -> None:
        """Release the local lease after a successful or attempted teardown."""
        lock_path = self.state_root / ".allocation.lock"
        with lock_path.open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            self.lease_path.unlink(missing_ok=True)
            self.overlay_path.unlink(missing_ok=True)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _yaml_bytes(value: Any) -> bytes:
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=False).encode("utf-8")


def _canonical_hash(value: Any) -> str:
    import json
    return __import__("hashlib").sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _load_manual_bundle(scenario_id: str, generated_root: Path) -> dict[str, Any]:
    sid = str(scenario_id)
    if not MANUAL_SCENARIO_ID_RE.fullmatch(sid):
        raise ScenarioExportError("Invalid manual generated scenario identifier")
    root = generated_root.resolve()
    path = (root / sid).resolve()
    if path.parent != root or path.is_symlink() or not path.is_dir():
        raise ScenarioExportError(f"Manual generated scenario not found: {sid}")
    manifest = _load_yaml(path / "manifest.yaml")
    if (
        manifest.get("kind"),
        manifest.get("generated_by"),
        manifest.get("variant_id"),
        manifest.get("mutation_policy"),
    ) != ("generated-scenario", "lance.scenario-generator", sid, "manual"):
        raise ScenarioExportError("Scenario is not a trusted manual generated bundle")
    if not manifest.get("deployable"):
        raise ScenarioExportError("Manual generated scenario has no executable adapter")
    artifacts: dict[str, Any] = {}
    hashes = manifest.get("artifact_hashes", {})
    for key, filename in MANUAL_ARTIFACTS.items():
        artifact = path / filename
        if artifact.is_symlink() or not artifact.is_file():
            raise ScenarioExportError(f"Missing manual generated artifact: {filename}")
        if __import__("hashlib").sha256(artifact.read_bytes()).hexdigest() != hashes.get(filename):
            raise ScenarioExportError(f"Manual generated artifact was modified: {filename}")
        artifacts[key] = _load_yaml(artifact)
    if _canonical_hash(hashes) != manifest.get("bundle_hash"):
        raise ScenarioExportError("Manual generated bundle hash is invalid")
    return {"manifest": manifest, **artifacts}


@dataclass
class ManualScenarioDeployment(GeneratedScenarioDeployment):
    """Runtime lease produced directly from a manually composed bundle."""

    execution_profile: str = ""

    @property
    def is_manual(self) -> bool:
        return True

    @classmethod
    def exists(
        cls,
        scenario_id: str,
        *,
        generated_root: Path | None = None,
    ) -> bool:
        sid = str(scenario_id)
        root = (generated_root or MANUAL_SCENARIO_ROOT).resolve()
        path = root / sid
        return bool(
            MANUAL_SCENARIO_ID_RE.fullmatch(sid)
            and path.parent == root
            and path.is_dir()
            and not path.is_symlink()
            and (path / "manifest.yaml").is_file()
        )

    @classmethod
    def prepare(
        cls,
        scenario_id: str,
        *,
        generated_root: Path | None = None,
        export_store: ExportedScenarioStore | None = None,
        state_root: Path | None = None,
        repo_root: Path = REPO_ROOT,
    ) -> "ManualScenarioDeployment":
        sid = str(scenario_id)
        if export_store is not None:
            bundle = export_store.load(sid)
            if bundle["manifest"].get("mutation_policy") != "manual":
                raise ScenarioExportError("Exported scenario is not a manual builder scenario")
        else:
            bundle = _load_manual_bundle(sid, (generated_root or MANUAL_SCENARIO_ROOT))
        topology = bundle["topology"]
        router = topology.get("router") or {}
        services = topology.get("services") or []
        plan = bundle["execution_plan"]
        source_sid = str(plan.get("source_scenario_id", ""))
        if plan.get("adapter") != "ansible-proxmox" or plan.get("status") != "ready":
            raise ScenarioExportError("Manual scenario execution plan is not ready")
        if not source_sid.isdigit():
            raise ScenarioExportError("Manual execution plan has no numeric provider profile")
        if not router.get("name") or not router.get("ip") or not services:
            raise ScenarioExportError("Manual topology cannot be deployed")
        ranges, scenarios = _catalog(repo_root)
        source_scenario = scenarios.get(source_sid)
        if source_scenario is None:
            raise ScenarioExportError(f"Provider source scenario S{source_sid} is absent from the Ansible catalogue")

        normalized_services = []
        for raw in services:
            item = copy.deepcopy(raw)
            concrete_name = str(item.get("name", ""))
            if not concrete_name:
                raise ScenarioExportError("Manual service has no concrete name")
            item["name"] = _service_suffix(concrete_name, source_sid, concrete_name)
            item["deploy_name"] = concrete_name
            item.pop("name_template", None)
            normalized_services.append(item)

        try:
            max_offset = max(int(item["vmid_offset"]) for item in normalized_services)
        except (KeyError, TypeError, ValueError) as exc:
            raise ScenarioExportError("Manual topology contains an invalid vmid_offset") from exc
        root = (state_root or DEPLOYMENT_ROOT).resolve()
        leases = root / LEASES_DIRNAME
        overlays = root / OVERLAYS_DIRNAME
        leases.mkdir(parents=True, exist_ok=True)
        overlays.mkdir(parents=True, exist_ok=True)
        lease_path = leases / f"{sid}.yaml"
        lock_path = root / ".allocation.lock"
        with lock_path.open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            lease = _read_optional(lease_path)
            if lease and (
                str(lease.get("scenario_id")) != sid
                or str(lease.get("source_scenario_id")) != source_sid
                or int(lease.get("max_vmid_offset", -1)) != max_offset
            ):
                raise ScenarioExportError(f"VMID lease for {sid} does not match the manual topology")
            base_vmid = int(lease["base_vmid"]) if lease else _allocate_base(
                ranges, scenarios, leases, max_offset
            )
            lease_data = {
                "schema_version": 1,
                "kind": "manual-scenario-deployment",
                "scenario_id": sid,
                "source_scenario_id": source_sid,
                "execution_adapter": plan["adapter"],
                "execution_profile": plan["profile"],
                "base_vmid": base_vmid,
                "max_vmid_offset": max_offset,
                "router_name": str(router["name"]),
                "bundle_root": str((generated_root or MANUAL_SCENARIO_ROOT).resolve()),
            }
            lease_path.write_text(
                yaml.safe_dump(lease_data, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            overlay_path = overlays / f"{sid}.yaml"
            cloud_metadata_ip = next(
                (str(item["ip"]) for item in normalized_services
                 if item.get("simulator") == "cloud_metadata"),
                "192.168.100.12",
            )
            cloud_web_ip = next(
                (str(item["ip"]) for item in normalized_services
                 if item.get("simulator") == "cloud_web"),
                "192.168.100.11",
            )
            overlay = {
                "scenario_id": sid,
                "source_scenario_id": source_sid,
                "generated_scenario": True,
                "manual_scenario": True,
                "manual_execution_adapter": plan["adapter"],
                "manual_execution_profile": plan["profile"],
                "manual_expected_control_count": int(plan.get("manual_expected_control_count", 0)),
                "scenario_lab_config": {
                    key: copy.deepcopy(bundle["scenario"].get(key, {}))
                    for key in (
                        "lifecycle", "environment", "identity", "detection", "evaluation",
                        "objectives", "constraints", "compatibility", "data_fixtures",
                        "failure_modes",
                    )
                    if bundle["scenario"].get(key) not in (None, {}, [])
                },
                "router_name": str(router["name"]),
                "cloud_metadata_ip": cloud_metadata_ip,
                "cloud_web_ip": cloud_web_ip,
                "benchmark_scenario_vmid_ranges": {sid: base_vmid},
                "benchmark_scenarios": {
                    sid: {
                        "name": bundle["scenario"].get("name", topology.get("name", sid)),
                        "router_vulns": [],
                        "router_name": str(router["name"]),
                        "services": normalized_services,
                    }
                },
            }
            overlay_path.write_text(
                yaml.safe_dump(overlay, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

        return cls(
            sid, source_sid, base_vmid, max_offset, overlay_path, lease_path, root,
            str(plan["profile"]),
        )


def _read_optional(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = _load_yaml(path)
    except (OSError, UnicodeError, yaml.YAMLError, ScenarioExportError, ValueError, TypeError):
        return None
    return value


def _allocate_base(
    ranges: dict[str, int],
    scenarios: dict[str, dict[str, Any]],
    leases_dir: Path,
    max_offset: int,
) -> int:
    occupied: list[tuple[int, int]] = []
    for sid, base in ranges.items():
        services = scenarios.get(str(sid), {}).get("services", [])
        end = base + max((int(item.get("vmid_offset", 0)) for item in services), default=0)
        occupied.append((base, end))
    for path in leases_dir.glob("*.yaml"):
        lease = _read_optional(path)
        if not lease:
            continue
        try:
            base = int(lease["base_vmid"])
            end = base + int(lease["max_vmid_offset"])
        except (KeyError, TypeError, ValueError):
            continue
        occupied.append((base, end))

    candidate = DYNAMIC_BASE_VMID
    while any(candidate <= end and candidate + max_offset >= start for start, end in occupied):
        candidate = min(end for start, end in occupied if candidate <= end and candidate + max_offset >= start) + 1
    return candidate
