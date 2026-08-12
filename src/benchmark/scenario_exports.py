"""Trusted storage and path resolution for Scenario Lab dashboard exports.

Official benchmark scenarios remain immutable under ``benchmarks/``.  A Lab
variant is published as a self-contained, checksummed bundle under ``output/``
and can therefore be removed without ever touching an official scenario.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


EXPORT_MARKER = "lance.scenario-lab-export"
EXPORT_VERSION = 1
EXPORTED_ID_RE = re.compile(r"^gen-[a-z0-9]+-[a-f0-9]{10}$")
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXPORT_ROOT = REPO_ROOT / "output" / "exported_scenarios"
DEFAULT_GENERATED_ROOT = REPO_ROOT / "output" / "generated_scenarios"
MANUAL_GENERATED_ID_RE = re.compile(r"^gen-custom-[a-f0-9]{10}$")

_ARTIFACTS = {
    "scenario": "scenario.yaml",
    "topology": "topology.yaml",
    "ground_truth": "ground_truth.yaml",
    "injection_plan": "injection_plan.yaml",
    "verification_plan": "verification_plan.yaml",
    "matching_contracts": "matching_contracts.yaml",
}
_MANUAL_ARTIFACTS = {
    "execution_plan": "execution_plan.yaml",
    "alteration_plan": "alteration_plan.yaml",
}


class ScenarioExportError(ValueError):
    """Raised when an exported bundle is missing, unsafe, or corrupted."""


def _yaml_bytes(value: Any) -> bytes:
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=False).encode("utf-8")


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ScenarioExportError(f"Invalid exported artifact: {path.name}") from exc
    if not isinstance(value, dict):
        raise ScenarioExportError(f"Expected a YAML mapping: {path.name}")
    return value


class ExportedScenarioStore:
    """Publish, validate, resolve, and remove dashboard scenario exports."""

    def __init__(self, root: Path | None = None):
        self.root = (root or DEFAULT_EXPORT_ROOT).resolve()

    def publish(self, bundle: dict[str, Any]) -> dict[str, Any]:
        manifest = bundle["manifest"]
        variant_id = str(manifest["variant_id"])
        mutation_policy = str(manifest.get("mutation_policy") or "generated-only")
        artifact_map = dict(_ARTIFACTS)
        if mutation_policy == "manual":
            if not manifest.get("deployable"):
                raise ScenarioExportError(
                    "Manual scenario is not deployable; choose an executable profile before exporting"
                )
            artifact_map.update(_MANUAL_ARTIFACTS)
            if any(key not in bundle for key in _MANUAL_ARTIFACTS):
                raise ScenarioExportError("Manual scenario execution artifacts are incomplete")
        target = self._export_dir(variant_id)
        if target.exists():
            current = self.load(variant_id)
            if current["manifest"].get("source_bundle_hash") != manifest.get("bundle_hash"):
                raise ScenarioExportError("An export with this ID already targets another bundle")
            return self._summary(current)

        scenario = copy.deepcopy(bundle["scenario"])
        scenario.update({
            "schema_version": 2,
            "scenario_id": variant_id,
            "kind": "scenario-lab-export",
            "topology": variant_id,
            "exported_from_lab": True,
        })
        scenario.pop("topology_file", None)

        topology = copy.deepcopy(bundle["topology"])
        topology.update({
            "id": variant_id,
            "deployment_status": "dashboard",
        })
        # Existing dashboard/pipeline readers consume ``name_template``.  A
        # concrete generated name is itself a valid template (no placeholders).
        if topology.get("router", {}).get("name"):
            topology["router"]["name_template"] = topology["router"]["name"]
        for service in topology.get("services", []):
            if service.get("name"):
                service["name_template"] = service["name"]

        ground_truth = copy.deepcopy(bundle["ground_truth"])
        artifacts = {
            "scenario": scenario,
            "topology": topology,
            "ground_truth": ground_truth,
            "injection_plan": copy.deepcopy(bundle["injection_plan"]),
            "verification_plan": copy.deepcopy(bundle["verification_plan"]),
            "matching_contracts": copy.deepcopy(bundle["matching_contracts"]),
        }
        if mutation_policy == "manual":
            artifacts.update({
                key: copy.deepcopy(bundle[key]) for key in _MANUAL_ARTIFACTS
            })
        hashes = {
            filename: hashlib.sha256(_yaml_bytes(artifacts[key])).hexdigest()
            for key, filename in artifact_map.items()
        }
        execution_plan = bundle.get("execution_plan") or {}
        export_manifest = {
            "schema_version": 1,
            "kind": "scenario-lab-export",
            "exported_by": EXPORT_MARKER,
            "export_version": EXPORT_VERSION,
            "variant_id": variant_id,
            "source_bundle_hash": manifest["bundle_hash"],
            "source_scenario_id": (
                execution_plan.get("source_scenario_id")
                if mutation_policy == "manual"
                else manifest["source_scenario_id"]
            ),
            "blueprint_id": manifest["blueprint_id"],
            "mutation_policy": mutation_policy,
            "deployment_status": manifest.get("deployment_status", "ready"),
            "execution_adapter": manifest.get("execution_adapter") or execution_plan.get("adapter"),
            "execution_profile": manifest.get("execution_profile") or execution_plan.get("profile"),
            "exported_at": datetime.now(timezone.utc).isoformat(),
            # The pipeline provisions exports through a runtime Ansible
            # overlay; the immutable official catalogue remains untouched.
            "deployment_supported": (
                bool(manifest.get("deployable", True))
                if mutation_policy == "manual"
                else True
            ),
            "artifact_hashes": hashes,
            "export_hash": _canonical_hash(hashes),
        }

        self.root.mkdir(parents=True, exist_ok=True)
        temp = Path(tempfile.mkdtemp(prefix=f".{variant_id}-", dir=self.root))
        try:
            for key, filename in artifact_map.items():
                (temp / filename).write_bytes(_yaml_bytes(artifacts[key]))
            (temp / "manifest.yaml").write_bytes(_yaml_bytes(export_manifest))
            os.replace(temp, target)
        finally:
            if temp.exists():
                shutil.rmtree(temp)
        return self._summary(self.load(variant_id))

    def load(self, scenario_id: str) -> dict[str, Any]:
        path = self._export_dir(scenario_id)
        if path.is_symlink() or not path.is_dir():
            raise ScenarioExportError(f"Exported scenario not found: {scenario_id}")
        manifest_path = path / "manifest.yaml"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ScenarioExportError("Export manifest is missing")
        manifest = _load_yaml(manifest_path)
        if (
            manifest.get("kind"),
            manifest.get("exported_by"),
            manifest.get("export_version"),
            manifest.get("variant_id"),
        ) != ("scenario-lab-export", EXPORT_MARKER, EXPORT_VERSION, scenario_id):
            raise ScenarioExportError("Scenario is not a trusted Scenario Lab export")

        artifacts: dict[str, Any] = {}
        hashes = manifest.get("artifact_hashes", {})
        artifact_map = dict(_ARTIFACTS)
        if manifest.get("mutation_policy") == "manual":
            artifact_map.update(_MANUAL_ARTIFACTS)
        for key, filename in artifact_map.items():
            artifact = path / filename
            if artifact.is_symlink() or not artifact.is_file():
                raise ScenarioExportError(f"Missing exported artifact: {filename}")
            if hashlib.sha256(artifact.read_bytes()).hexdigest() != hashes.get(filename):
                raise ScenarioExportError(f"Exported artifact was modified: {filename}")
            artifacts[key] = _load_yaml(artifact)
        if _canonical_hash(hashes) != manifest.get("export_hash"):
            raise ScenarioExportError("Export manifest hash is invalid")
        if artifacts["scenario"].get("scenario_id") != scenario_id:
            raise ScenarioExportError("Exported scenario ID does not match its manifest")
        return {"manifest": manifest, **artifacts}

    def list(self) -> list[dict[str, Any]]:
        if not self.root.exists():
            return []
        exports = []
        for path in self.root.iterdir():
            if path.is_symlink() or not path.is_dir() or not EXPORTED_ID_RE.fullmatch(path.name):
                continue
            try:
                exports.append(self._summary(self.load(path.name)))
            except ScenarioExportError:
                continue
        return sorted(exports, key=lambda item: (item["exported_at"], item["id"]), reverse=True)

    def exists(self, scenario_id: str) -> bool:
        try:
            self.load(str(scenario_id))
            return True
        except ScenarioExportError:
            return False

    def has_entry(self, scenario_id: str) -> bool:
        """Return whether an export path exists, including an invalid entry."""
        path = self._export_dir(str(scenario_id))
        return path.exists() or path.is_symlink()

    def artifact_path(self, scenario_id: str, artifact: str) -> Path:
        if artifact not in _ARTIFACTS:
            raise ScenarioExportError(f"Unknown exported artifact: {artifact}")
        self.load(str(scenario_id))
        return self._export_dir(str(scenario_id)) / _ARTIFACTS[artifact]

    def delete(self, scenario_id: str) -> dict[str, Any]:
        bundle = self.load(str(scenario_id))  # validates provenance before deletion
        summary = self._summary(bundle)
        shutil.rmtree(self._export_dir(str(scenario_id)))
        return summary

    def _export_dir(self, scenario_id: str) -> Path:
        scenario_id = str(scenario_id)
        if not EXPORTED_ID_RE.fullmatch(scenario_id):
            raise ScenarioExportError("Invalid Scenario Lab export identifier")
        path = (self.root / scenario_id).resolve()
        if path.parent != self.root:
            raise ScenarioExportError("Scenario Lab export escapes storage")
        return path

    @staticmethod
    def _summary(bundle: dict[str, Any]) -> dict[str, Any]:
        manifest = bundle["manifest"]
        scenario = bundle["scenario"]
        topology = bundle["topology"]
        ground_truth = bundle["ground_truth"]
        return {
            "id": manifest["variant_id"],
            "name": scenario.get("name", manifest["variant_id"]),
            "difficulty": scenario.get("difficulty", "custom"),
            "posture": scenario.get("posture", "mixed"),
            "topology": topology.get("id", manifest["variant_id"]),
            "packs": scenario.get("packs", []),
            "source_scenario_id": manifest.get("source_scenario_id"),
            "blueprint_id": manifest.get("blueprint_id"),
            "mutation_policy": manifest.get("mutation_policy", "generated-only"),
            "exported_at": manifest["exported_at"],
            "exported": True,
            "deletable": True,
            "deployment_supported": bool(manifest.get("deployment_supported", True)),
            "vulnerability_count": len(ground_truth.get("vulnerabilities", [])),
            "control_count": len(ground_truth.get("controls", [])),
        }


def default_export_store() -> ExportedScenarioStore:
    return ExportedScenarioStore()


def _manual_artifact_path(scenario_id: int | str, artifact: str) -> Path | None:
    sid = str(scenario_id)
    if not MANUAL_GENERATED_ID_RE.fullmatch(sid):
        return None
    filename = _ARTIFACTS.get(artifact)
    if filename is None:
        return None
    root = DEFAULT_GENERATED_ROOT.resolve()
    directory = (root / sid).resolve()
    if directory.parent != root or directory.is_symlink() or not directory.is_dir():
        return None
    path = directory / filename
    return path if path.is_file() and not path.is_symlink() else None


def resolve_scenario_path(scenario_id: int | str) -> Path:
    sid = str(scenario_id).removeprefix("S").removeprefix("s")
    store = default_export_store()
    if store.exists(sid):
        return store.artifact_path(sid, "scenario")
    manual = _manual_artifact_path(sid, "scenario")
    if manual is not None:
        return manual
    return REPO_ROOT / "benchmarks" / "scenarios" / f"S{sid}.yaml"


def resolve_topology_path(scenario_id: int | str, topology_id: str) -> Path:
    sid = str(scenario_id).removeprefix("S").removeprefix("s")
    store = default_export_store()
    if store.exists(sid):
        return store.artifact_path(sid, "topology")
    manual = _manual_artifact_path(sid, "topology")
    if manual is not None:
        return manual
    return REPO_ROOT / "benchmarks" / "topologies" / f"{topology_id}.yaml"


def resolve_ground_truth_path(scenario_id: int | str) -> Path:
    sid = str(scenario_id).removeprefix("S").removeprefix("s")
    store = default_export_store()
    if store.exists(sid):
        return store.artifact_path(sid, "ground_truth")
    manual = _manual_artifact_path(sid, "ground_truth")
    if manual is not None:
        return manual
    return REPO_ROOT / "benchmarks" / "ground_truth" / f"scenario_{sid}.yaml"
